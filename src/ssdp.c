#include "ssdp.h"

#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Burst schedule: devices stagger their replies across MX seconds, and a
   single burst reliably misses some of them. After the ramp, refresh slowly. */
static const uint64_t BURST_MS[] = {0, 1000, 3000, 7000};
#define N_BURSTS (sizeof BURST_MS / sizeof BURST_MS[0])
#define REFRESH_MS 60000u
#define SSDP_MX 2

struct ssdp {
    store_t *store;
    const iface_t *ifs;
    size_t nifs;
    int search4, search6;
    uint64_t start;
    size_t burst; /* index into BURST_MS, then refresh mode */
    uint64_t next_refresh;
};

ssdp_t *ssdp_new(store_t *store, const iface_t *ifs, size_t nifs, int search4, int search6)
{
    ssdp_t *s = xcalloc(1, sizeof *s);
    s->store = store;
    s->ifs = ifs;
    s->nifs = nifs;
    s->search4 = search4;
    s->search6 = search6;
    s->start = now_ms();
    return s;
}

void ssdp_destroy(ssdp_t *s)
{
    free(s);
}

void ssdp_rescan(ssdp_t *s)
{
    s->start = now_ms();
    s->burst = 0;
}

bool ssdp_scanning(const ssdp_t *s)
{
    return s->burst < N_BURSTS;
}

uint64_t ssdp_next_deadline(const ssdp_t *s)
{
    if (s->burst < N_BURSTS)
        return s->start + BURST_MS[s->burst];
    return s->next_refresh;
}

static void send_search(ssdp_t *s, const char *st)
{
    char msg[256];
    int n4 = snprintf(msg, sizeof msg,
                      "M-SEARCH * HTTP/1.1\r\n"
                      "HOST: %s:%d\r\n"
                      "MAN: \"ssdp:discover\"\r\n"
                      "MX: %d\r\n"
                      "ST: %s\r\n"
                      "USER-AGENT: Linux/1.0 UPnP/1.1 mdns-cli/1.0\r\n"
                      "\r\n",
                      SSDP_GROUP4, SSDP_PORT, SSDP_MX, st);
    for (size_t i = 0; i < s->nifs && s->search4 >= 0; i++) {
        if (!s->ifs[i].has_v4)
            continue;
        if (net_send_v4(s->search4, &s->ifs[i], msg, (size_t)n4, SSDP_GROUP4, SSDP_PORT) < 0)
            log_msg("ssdp: send on %s failed", s->ifs[i].name);
    }
    if (s->search6 < 0)
        return;
    int n6 = snprintf(msg, sizeof msg,
                      "M-SEARCH * HTTP/1.1\r\n"
                      "HOST: [%s]:%d\r\n"
                      "MAN: \"ssdp:discover\"\r\n"
                      "MX: %d\r\n"
                      "ST: %s\r\n"
                      "USER-AGENT: Linux/1.0 UPnP/1.1 mdns-cli/1.0\r\n"
                      "\r\n",
                      SSDP_GROUP6, SSDP_PORT, SSDP_MX, st);
    for (size_t i = 0; i < s->nifs; i++) {
        if (!s->ifs[i].has_v6)
            continue;
        net_send_v6(s->search6, &s->ifs[i], msg, (size_t)n6, SSDP_GROUP6, SSDP_PORT);
    }
}

void ssdp_tick(ssdp_t *s, uint64_t now)
{
    if (s->burst < N_BURSTS) {
        if (now + 1 < s->start + BURST_MS[s->burst])
            return;
        s->burst++;
        /* ssdp:all is the superset, but some stacks only answer rootdevice. */
        send_search(s, "ssdp:all");
        send_search(s, "upnp:rootdevice");
        if (s->burst >= N_BURSTS)
            s->next_refresh = now + REFRESH_MS;
        return;
    }
    if (now + 1 >= s->next_refresh) {
        send_search(s, "ssdp:all");
        s->next_refresh = now + REFRESH_MS;
    }
}

/* Header lookup over a raw SSDP message. Returns the value in out. */
static bool header(const char *pkt, size_t len, const char *name, char *out, size_t outsz)
{
    size_t nlen = strlen(name);
    const char *p = pkt;
    const char *end = pkt + len;
    /* Skip the start line. */
    while (p < end && *p != '\n')
        p++;
    if (p < end)
        p++;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol)
            eol = end;
        if ((size_t)(eol - p) > nlen && str_ncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            const char *v = p + nlen + 1;
            while (v < eol && (*v == ' ' || *v == '\t'))
                v++;
            const char *ve = eol;
            while (ve > v && (ve[-1] == '\r' || ve[-1] == ' ' || ve[-1] == '\t'))
                ve--;
            size_t n = (size_t)(ve - v);
            if (n >= outsz)
                n = outsz - 1;
            memcpy(out, v, n);
            out[n] = '\0';
            /* Header values come straight off the wire; keep them printable. */
            str_sanitize(out);
            return true;
        }
        p = eol + 1;
    }
    out[0] = '\0';
    return false;
}

static uint32_t parse_max_age(const char *cc)
{
    const char *p = cc;
    while (*p) {
        if (str_ncasecmp(p, "max-age", 7) == 0) {
            p += 7;
            while (*p == ' ' || *p == '=')
                p++;
            return (uint32_t)strtoul(p, NULL, 10);
        }
        p++;
    }
    return 0;
}

static void ingest(ssdp_t *s, const char *pkt, size_t len, const struct sockaddr_storage *from,
                   uint64_t now, bool is_notify)
{
    char usn[512], st[256], location[512], server[256], cc[128], nts[64];
    header(pkt, len, "USN", usn, sizeof usn);
    header(pkt, len, is_notify ? "NT" : "ST", st, sizeof st);
    header(pkt, len, "LOCATION", location, sizeof location);
    header(pkt, len, "SERVER", server, sizeof server);
    header(pkt, len, "CACHE-CONTROL", cc, sizeof cc);
    header(pkt, len, "NTS", nts, sizeof nts);

    if (!*usn && !*st)
        return;

    addr_t a;
    if (!addr_from_sockaddr(&a, from))
        return;

    if (is_notify && str_casecmp(nts, "ssdp:byebye") == 0) {
        device_t *d = store_find_addr(s->store, &a);
        if (d && *usn)
            device_drop_ssdp(s->store, d, usn);
        return;
    }

    /* Prefer the device already announcing this UUID: the same box answers
       from its IPv4 and its IPv6 address, which otherwise look unrelated. */
    device_t *d = NULL;
    char uuid[256];
    const char *sep = strstr(usn, "::");
    snprintf(uuid, sizeof uuid, "%.*s", sep ? (int)(sep - usn) : (int)strlen(usn), usn);
    if (*uuid)
        d = store_find_udn(s->store, uuid);
    if (d) {
        d = store_add_addr(s->store, d, &a, now);
        d->sources |= SRC_SSDP;
    } else {
        d = store_device_for_addr(s->store, &a, now, SRC_SSDP);
    }
    ssdp_entry_t *e = device_ssdp(s->store, d, usn, st, now);
    if (*st && (!e->st || strcmp(e->st, st) != 0))
        str_set(&e->st, st);
    if (*location && (!e->location || strcmp(e->location, location) != 0)) {
        str_set(&e->location, location);
        /* A changed LOCATION invalidates anything already fetched. */
        e->fetch = FETCH_NONE;
    }
    if (*server)
        str_set(&e->server, server);
    if (*cc)
        e->max_age = parse_max_age(cc);
    store_touch(s->store);
}

void ssdp_handle(ssdp_t *s, const char *pkt, size_t len, const struct sockaddr_storage *from,
                 uint64_t now)
{
    if (len < 12)
        return;
    if (str_ncasecmp(pkt, "HTTP/1.", 7) == 0)
        ingest(s, pkt, len, from, now, false);
    else if (str_ncasecmp(pkt, "NOTIFY", 6) == 0)
        ingest(s, pkt, len, from, now, true);
    /* M-SEARCH from another client on the network: not ours to answer. */
}
