#include "mdns.h"

#include "dns.h"
#include "util.h"

#include <stdlib.h>
#include <string.h>

#define SD_META "_services._dns-sd._udp.local"
#define NEVER UINT64_MAX
#define REFRESH_MS 60000u
#define MAX_ATTEMPTS 4
#define MAX_ORPHANS 128

/* Retransmit ramp; index by attempt count. */
static const uint64_t RETRY_MS[MAX_ATTEMPTS] = {0, 1000, 3000, 7000};

typedef struct {
    char *name;
    uint16_t type;
    unsigned attempts;
    uint64_t base; /* when this query was first sent; the ramp hangs off it */
    uint64_t next;
    bool durable; /* keeps refreshing after the ramp (browse queries) */
} query_t;

/* TXT data that arrived before the matching SRV, parked until the service
   exists. Rare, but real: the two can land in different packets. */
typedef struct {
    char *data;
    size_t len;
} blob_t;

typedef struct orphan {
    struct orphan *next;
    char *fqdn;
    blob_t *lines;
    size_t n_lines;
} orphan_t;

struct mdns {
    store_t *store;
    const iface_t *ifs;
    size_t nifs;
    int fd4, fd6;
    query_t *q;
    size_t nq, capq;
    orphan_t *orphans;
    size_t n_orphans;
    uint64_t start;
    uint16_t txid;
};

static query_t *find_query(mdns_t *m, const char *name, uint16_t type)
{
    for (size_t i = 0; i < m->nq; i++)
        if (m->q[i].type == type && str_casecmp(m->q[i].name, name) == 0)
            return &m->q[i];
    return NULL;
}

static void enqueue(mdns_t *m, const char *name, uint16_t type, bool durable, uint64_t when)
{
    if (find_query(m, name, type))
        return;
    if (m->nq == m->capq) {
        m->capq = m->capq ? m->capq * 2 : 32;
        m->q = xrealloc(m->q, m->capq * sizeof *m->q);
    }
    query_t *q = &m->q[m->nq++];
    q->name = xstrdup(name);
    q->type = type;
    q->attempts = 0;
    q->base = when;
    q->next = when;
    q->durable = durable;
}

/* A record answered a question, so stop asking. Browse queries are exempt:
   more instances can still answer, so they always run the full ramp. */
static void mark_answered(mdns_t *m, const char *name, uint16_t type, uint64_t now)
{
    (void)now;
    query_t *q = find_query(m, name, type);
    if (q && !q->durable)
        q->next = NEVER;
}

mdns_t *mdns_new(store_t *store, const iface_t *ifs, size_t nifs, int fd4, int fd6)
{
    mdns_t *m = xcalloc(1, sizeof *m);
    m->store = store;
    m->ifs = ifs;
    m->nifs = nifs;
    m->fd4 = fd4;
    m->fd6 = fd6;
    m->start = now_ms();
    enqueue(m, SD_META, DNS_T_PTR, true, m->start);
    return m;
}

static void orphans_free(mdns_t *m)
{
    orphan_t *o = m->orphans;
    while (o) {
        orphan_t *next = o->next;
        for (size_t i = 0; i < o->n_lines; i++)
            free(o->lines[i].data);
        free(o->lines);
        free(o->fqdn);
        free(o);
        o = next;
    }
    m->orphans = NULL;
    m->n_orphans = 0;
}

void mdns_destroy(mdns_t *m)
{
    if (!m)
        return;
    for (size_t i = 0; i < m->nq; i++)
        free(m->q[i].name);
    free(m->q);
    orphans_free(m);
    free(m);
}

void mdns_rescan(mdns_t *m)
{
    uint64_t now = now_ms();
    m->start = now;
    for (size_t i = 0; i < m->nq; i++) {
        m->q[i].attempts = 0;
        m->q[i].base = now;
        m->q[i].next = now;
    }
    enqueue(m, SD_META, DNS_T_PTR, true, now);
}

bool mdns_scanning(const mdns_t *m)
{
    for (size_t i = 0; i < m->nq; i++)
        if (m->q[i].attempts < MAX_ATTEMPTS && m->q[i].next != NEVER)
            return true;
    return false;
}

uint64_t mdns_next_deadline(const mdns_t *m)
{
    uint64_t best = NEVER;
    for (size_t i = 0; i < m->nq; i++)
        if (m->q[i].next < best)
            best = m->q[i].next;
    return best;
}

static void send_query(mdns_t *m, const dns_query_t *q)
{
    for (size_t i = 0; i < m->nifs; i++) {
        if (m->fd4 >= 0 && m->ifs[i].has_v4)
            if (net_send_v4(m->fd4, &m->ifs[i], q->buf, q->len, MDNS_GROUP4, MDNS_PORT) < 0)
                log_msg("mdns: v4 send on %s failed", m->ifs[i].name);
        if (m->fd6 >= 0 && m->ifs[i].has_v6)
            net_send_v6(m->fd6, &m->ifs[i], q->buf, q->len, MDNS_GROUP6, MDNS_PORT);
    }
}

void mdns_tick(mdns_t *m, uint64_t now)
{
    dns_query_t pkt;
    dns_query_init(&pkt, 0); /* mDNS queries use a zero transaction id */
    bool any = false;

    for (size_t i = 0; i < m->nq; i++) {
        query_t *q = &m->q[i];
        if (q->next == NEVER || now + 1 < q->next)
            continue;
        if (dns_query_add(&pkt, q->name, q->type, false) != 0) {
            /* Packet is full: flush and start another. */
            send_query(m, &pkt);
            dns_query_init(&pkt, 0);
            if (dns_query_add(&pkt, q->name, q->type, false) != 0) {
                log_msg("mdns: cannot encode query for %s", q->name);
                q->next = NEVER;
                continue;
            }
        }
        any = true;
        if (q->attempts == 0)
            q->base = now;
        q->attempts++;
        if (q->attempts < MAX_ATTEMPTS)
            q->next = q->base + RETRY_MS[q->attempts];
        else
            q->next = q->durable ? now + REFRESH_MS : NEVER;
    }
    if (any)
        send_query(m, &pkt);
}

static orphan_t *orphan_find(mdns_t *m, const char *fqdn, bool create)
{
    for (orphan_t *o = m->orphans; o; o = o->next)
        if (strcmp(o->fqdn, fqdn) == 0)
            return o;
    if (!create || m->n_orphans >= MAX_ORPHANS)
        return NULL;
    orphan_t *o = xcalloc(1, sizeof *o);
    o->fqdn = xstrdup(fqdn);
    o->next = m->orphans;
    m->orphans = o;
    m->n_orphans++;
    return o;
}

static void orphan_flush(mdns_t *m, service_t *sv)
{
    orphan_t **pp = &m->orphans;
    while (*pp) {
        orphan_t *o = *pp;
        if (strcmp(o->fqdn, sv->fqdn) == 0) {
            for (size_t i = 0; i < o->n_lines; i++) {
                service_set_txt(sv, o->lines[i].data, o->lines[i].len);
                free(o->lines[i].data);
            }
            free(o->lines);
            free(o->fqdn);
            *pp = o->next;
            free(o);
            m->n_orphans--;
            return;
        }
        pp = &o->next;
    }
}

static void handle_ptr(mdns_t *m, const dns_msg_t *msg, const dns_rr_t *rr, uint64_t now)
{
    char target[DNS_MAX_NAME];
    if (dns_rdata_name(msg, rr, target, sizeof target) != 0)
        return;

    if (str_casecmp(rr->name, SD_META) == 0) {
        /* Service-type enumeration: browse each type we learn about. */
        enqueue(m, target, DNS_T_PTR, true, now);
        return;
    }
    mark_answered(m, rr->name, DNS_T_PTR, now);

    if (rr->ttl == 0) {
        /* Goodbye: the instance is leaving. */
        device_t *owner = NULL;
        if (store_find_service(m->store, target, &owner) && owner)
            device_drop_service(m->store, owner, target);
        return;
    }
    enqueue(m, target, DNS_T_SRV, false, now);
    enqueue(m, target, DNS_T_TXT, false, now);
}

static void handle_srv(mdns_t *m, const dns_msg_t *msg, const dns_rr_t *rr, uint64_t now)
{
    uint16_t port = 0;
    char host[DNS_MAX_NAME];
    if (dns_rdata_srv(msg, rr, NULL, NULL, &port, host, sizeof host) != 0)
        return;
    mark_answered(m, rr->name, DNS_T_SRV, now);
    if (rr->ttl == 0 || !*host)
        return;

    device_t *d = store_device_for_host(m->store, host, now, SRC_MDNS);
    service_t *sv = device_service(m->store, d, rr->name, now);
    str_set(&sv->host, host);
    sv->port = port;
    sv->have_srv = true;
    sv->ttl = rr->ttl;
    sv->last_seen = now;
    orphan_flush(m, sv);

    /* Only chase the address if we do not have one for this host yet. */
    if (d->n_addrs == 0) {
        if (m->fd4 >= 0)
            enqueue(m, host, DNS_T_A, false, now);
        if (m->fd6 >= 0)
            enqueue(m, host, DNS_T_AAAA, false, now);
    }
    store_touch(m->store);
}

static void handle_txt(mdns_t *m, const dns_rr_t *rr, uint64_t now)
{
    mark_answered(m, rr->name, DNS_T_TXT, now);
    if (rr->ttl == 0)
        return;

    device_t *owner = NULL;
    service_t *sv = store_find_service(m->store, rr->name, &owner);
    dns_txt_iter_t it;
    dns_txt_iter_init(&it, rr);
    char line[512];

    if (!sv) {
        /* Park it: the SRV that names the host has not arrived yet. */
        orphan_t *o = orphan_find(m, rr->name, true);
        if (!o)
            return;
        for (size_t i = 0; i < o->n_lines; i++)
            free(o->lines[i].data);
        o->n_lines = 0;
        size_t llen = 0;
        while (dns_txt_next(&it, line, sizeof line, &llen) == 1) {
            o->lines = xrealloc(o->lines, (o->n_lines + 1) * sizeof *o->lines);
            o->lines[o->n_lines].data = xstrndup(line, llen);
            o->lines[o->n_lines].len = llen;
            o->n_lines++;
        }
        enqueue(m, rr->name, DNS_T_SRV, false, now);
        return;
    }

    /* A cache-flush TXT replaces the whole set rather than merging into it. */
    if (rr->cache_flush)
        service_clear_txt(sv);
    size_t llen = 0;
    while (dns_txt_next(&it, line, sizeof line, &llen) == 1)
        service_set_txt(sv, line, llen);
    sv->last_seen = now;
    if (owner)
        owner->last_seen = now;
    store_touch(m->store);
}

static void handle_addr(mdns_t *m, const dns_rr_t *rr, const struct sockaddr_storage *from,
                        uint64_t now)
{
    addr_t a;
    if (rr->type == DNS_T_A) {
        uint8_t b[4];
        if (dns_rdata_a(rr, b) != 0 || !addr_from_v4(&a, b))
            return;
    } else {
        uint8_t b[16];
        unsigned scope = 0;
        if (from->ss_family == AF_INET6)
            scope = ((const struct sockaddr_in6 *)from)->sin6_scope_id;
        if (dns_rdata_aaaa(rr, b) != 0 || !addr_from_v6(&a, b, scope))
            return;
    }
    mark_answered(m, rr->name, rr->type, now);
    if (rr->ttl == 0)
        return;

    device_t *d = store_device_for_addr(m->store, &a, now, SRC_MDNS);
    d = store_set_host(m->store, d, rr->name, now);
    store_touch(m->store);
}

void mdns_handle(mdns_t *m, const uint8_t *pkt, size_t len, const struct sockaddr_storage *from,
                 uint64_t now)
{
    dns_msg_t msg;
    if (dns_msg_begin(&msg, pkt, len) != 0)
        return;
    if (!dns_is_response(&msg))
        return; /* another client's query */

    for (unsigned i = 0; i < msg.qdcount; i++)
        if (dns_read_question(&msg, NULL, 0, NULL, NULL) != 0)
            return;

    /* Two passes over the same records: SRV/A must be seen before the TXT that
       belongs to them, and a single packet does not guarantee that order. */
    size_t records_start = msg.pos;
    unsigned total = dns_rr_total(&msg);
    dns_rr_t rr;

    for (unsigned i = 0; i < total; i++) {
        if (dns_read_rr(&msg, &rr) != 0)
            return;
        switch (rr.type) {
        case DNS_T_PTR:
            handle_ptr(m, &msg, &rr, now);
            break;
        case DNS_T_SRV:
            handle_srv(m, &msg, &rr, now);
            break;
        case DNS_T_A:
        case DNS_T_AAAA:
            handle_addr(m, &rr, from, now);
            break;
        default:
            break;
        }
    }

    msg.pos = records_start;
    for (unsigned i = 0; i < total; i++) {
        if (dns_read_rr(&msg, &rr) != 0)
            return;
        if (rr.type == DNS_T_TXT)
            handle_txt(m, &rr, now);
    }
}
