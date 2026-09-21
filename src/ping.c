#include "ping.h"

#include "util.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define PING_INTERVAL_MS 1000u
#define PING_TIMEOUT_MS 2000u
#define MAX_OUTSTANDING 8 /* interval x timeout can never exceed this */
#define MAX_RUNS 16
#define ECHO_PAYLOAD 24

#define ICMP4_ECHO 8
#define ICMP4_ECHOREPLY 0
#define ICMP6_ECHO 128
#define ICMP6_ECHOREPLY 129

typedef struct {
    uint16_t seq;
    uint64_t sent_us; /* microseconds: a LAN reply often beats 1 ms */
    bool used;
} probe_t;

typedef struct {
    unsigned dev_id;
    addr_t target;
    uint16_t seq_base; /* this run owns [seq_base, seq_base + 4096) */
    uint16_t next_seq;
    uint64_t next_send;
    probe_t probes[MAX_OUTSTANDING];
} run_t;

struct pinger {
    store_t *store;
    int fd4, fd6;
    bool tried4, tried6;
    run_t runs[MAX_RUNS];
    size_t nruns;
    uint16_t next_base;
    int slot4, slot6;
};

pinger_t *pinger_new(store_t *store)
{
    pinger_t *p = xcalloc(1, sizeof *p);
    p->store = store;
    p->fd4 = p->fd6 = -1;
    p->slot4 = p->slot6 = -1;
    return p;
}

void pinger_destroy(pinger_t *p)
{
    if (!p)
        return;
    if (p->fd4 >= 0)
        close(p->fd4);
    if (p->fd6 >= 0)
        close(p->fd6);
    free(p);
}

size_t pinger_active(const pinger_t *p)
{
    return p->nruns;
}

/* Sockets are opened on first use: a scan that never pings never asks for
   one, and the failure is reported where the user can see it. */
static int socket_for(pinger_t *p, int family, const char **why)
{
    int *fd = family == AF_INET ? &p->fd4 : &p->fd6;
    bool *tried = family == AF_INET ? &p->tried4 : &p->tried6;
    if (*fd >= 0)
        return *fd;
    if (*tried) {
        *why = "no ICMP socket";
        return -1;
    }
    *tried = true;
    int proto = family == AF_INET ? IPPROTO_ICMP : IPPROTO_ICMPV6;
    *fd = socket(family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, proto);
    if (*fd < 0) {
        log_msg("ping: socket(%s): %s", family == AF_INET ? "icmp" : "icmpv6", strerror(errno));
        *why = (errno == EACCES || errno == EPERM)
                   ? "ICMP not permitted (see net.ipv4.ping_group_range)"
                   : strerror(errno);
        return -1;
    }
    return *fd;
}

static run_t *find_run(pinger_t *p, unsigned dev_id)
{
    for (size_t i = 0; i < p->nruns; i++)
        if (p->runs[i].dev_id == dev_id)
            return &p->runs[i];
    return NULL;
}

static void drop_run(pinger_t *p, run_t *r)
{
    device_t *d = store_find_id(p->store, r->dev_id);
    if (d) {
        /* Nothing is listening for the outstanding probes any more, so book
           them as lost: a stopped run always reads sent = received + lost. */
        for (size_t i = 0; i < MAX_OUTSTANDING; i++)
            if (r->probes[i].used)
                ping_record_loss(&d->ping);
        d->ping.active = false;
        store_touch(p->store);
    }
    *r = p->runs[--p->nruns];
}

void pinger_stop_all(pinger_t *p)
{
    while (p->nruns)
        drop_run(p, &p->runs[p->nruns - 1]);
}

/* The device address to ping: the one the list shows, IPv4 first. */
static const addr_t *pick_target(const device_t *d)
{
    for (size_t i = 0; i < d->n_addrs; i++)
        if (d->addrs[i].family == AF_INET)
            return &d->addrs[i];
    return d->n_addrs ? &d->addrs[0] : NULL;
}

const char *pinger_toggle(pinger_t *p, device_t *d)
{
    run_t *existing = find_run(p, d->id);
    if (existing) {
        drop_run(p, existing);
        return NULL;
    }

    const addr_t *target = pick_target(d);
    if (!target) {
        str_set(&d->ping.error, "no address to ping yet");
        store_touch(p->store);
        return d->ping.error;
    }
    const char *why = NULL;
    if (socket_for(p, target->family, &why) < 0) {
        str_set(&d->ping.error, why);
        store_touch(p->store);
        return d->ping.error;
    }
    if (p->nruns >= MAX_RUNS)
        return "too many pings running";

    run_t *r = &p->runs[p->nruns++];
    memset(r, 0, sizeof *r);
    r->dev_id = d->id;
    r->target = *target;
    r->seq_base = p->next_base;
    r->next_seq = r->seq_base;
    p->next_base += 4096;
    r->next_send = now_ms();

    ping_reset(&d->ping);
    snprintf(d->ping.target, sizeof d->ping.target, "%s", target->str);
    d->ping.active = true;
    d->ping.started = now_ms();
    store_touch(p->store);
    return NULL;
}

static uint16_t checksum16(const uint8_t *data, size_t len)
{
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    if (len & 1)
        sum += (uint32_t)(data[len - 1] << 8);
    while (sum >> 16)
        sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static void send_probe(pinger_t *p, run_t *r, device_t *d)
{
    uint8_t pkt[8 + ECHO_PAYLOAD];
    memset(pkt, 0, sizeof pkt);
    bool v4 = r->target.family == AF_INET;
    uint16_t seq = r->next_seq++;
    if ((uint16_t)(r->next_seq - r->seq_base) >= 4096)
        r->next_seq = r->seq_base;

    pkt[0] = v4 ? ICMP4_ECHO : ICMP6_ECHO;
    pkt[1] = 0;
    /* The kernel owns the identifier on a ping socket and rewrites it, so the
       sequence number is what ties a reply back to a probe. */
    pkt[6] = (uint8_t)(seq >> 8);
    pkt[7] = (uint8_t)(seq & 0xff);
    memcpy(pkt + 8, "mdns-cli", 8);
    uint64_t stamp = now_us();
    memcpy(pkt + 16, &stamp, sizeof stamp);
    if (v4) {
        uint16_t csum = checksum16(pkt, sizeof pkt);
        pkt[2] = (uint8_t)(csum >> 8);
        pkt[3] = (uint8_t)(csum & 0xff);
    }
    /* ICMPv6 checksums cover a pseudo-header, so the kernel computes those. */

    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t slen;
    int fd;
    if (v4) {
        struct sockaddr_in *s = (struct sockaddr_in *)&ss;
        s->sin_family = AF_INET;
        s->sin_addr = r->target.a.v4;
        slen = sizeof *s;
        fd = p->fd4;
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&ss;
        s->sin6_family = AF_INET6;
        s->sin6_addr = r->target.a.v6;
        s->sin6_scope_id = r->target.scope_id;
        slen = sizeof *s;
        fd = p->fd6;
    }

    if (sendto(fd, pkt, sizeof pkt, 0, (struct sockaddr *)&ss, slen) < 0) {
        str_set(&d->ping.error, strerror(errno));
        log_msg("ping: send to %s: %s", r->target.str, strerror(errno));
        return;
    }

    /* Record the probe, replacing the oldest slot if they are all in use. */
    probe_t *slot = NULL;
    for (size_t i = 0; i < MAX_OUTSTANDING; i++)
        if (!r->probes[i].used) {
            slot = &r->probes[i];
            break;
        }
    if (!slot) {
        slot = &r->probes[0];
        for (size_t i = 1; i < MAX_OUTSTANDING; i++)
            if (r->probes[i].sent_us < slot->sent_us)
                slot = &r->probes[i];
        ping_record_loss(&d->ping);
    }
    slot->used = true;
    slot->seq = seq;
    slot->sent_us = now_us();
    d->ping.sent++;
    str_set(&d->ping.error, NULL);
    store_touch(p->store);
}

static void reap_timeouts(pinger_t *p, run_t *r, device_t *d, uint64_t now_micros)
{
    for (size_t i = 0; i < MAX_OUTSTANDING; i++) {
        probe_t *pr = &r->probes[i];
        if (pr->used && now_micros - pr->sent_us > (uint64_t)PING_TIMEOUT_MS * 1000) {
            pr->used = false;
            ping_record_loss(&d->ping);
            store_touch(p->store);
        }
    }
}

/* Match a reply to the run that sent it and fold the round trip in. */
static void handle_reply(pinger_t *p, uint16_t seq, uint64_t now_micros)
{
    for (size_t i = 0; i < p->nruns; i++) {
        run_t *r = &p->runs[i];
        for (size_t k = 0; k < MAX_OUTSTANDING; k++) {
            probe_t *pr = &r->probes[k];
            if (!pr->used || pr->seq != seq)
                continue;
            device_t *d = store_find_id(p->store, r->dev_id);
            pr->used = false;
            if (d) {
                ping_record_reply(&d->ping, (double)(now_micros - pr->sent_us) / 1000.0);
                store_touch(p->store);
            }
            return;
        }
    }
}

static void drain(pinger_t *p, int fd, bool v4, uint64_t now_micros)
{
    for (;;) {
        uint8_t buf[1500];
        struct sockaddr_storage from;
        socklen_t flen = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from, &flen);
        if (n < 0)
            return;
        size_t off = 0;
        /* Datagram ICMP sockets hand over the ICMP header directly, but be
           tolerant of an IPv4 header showing up in front of it. */
        if (v4 && n >= 28 && (buf[0] >> 4) == 4) {
            size_t ihl = (size_t)(buf[0] & 0x0f) * 4;
            if (ihl >= 20 && (size_t)n > ihl)
                off = ihl;
        }
        if ((size_t)n < off + 8)
            continue;
        uint8_t type = buf[off];
        if (type != (v4 ? ICMP4_ECHOREPLY : ICMP6_ECHOREPLY))
            continue; /* not an echo reply: unreachables show up as loss */
        uint16_t seq = (uint16_t)((buf[off + 6] << 8) | buf[off + 7]);
        handle_reply(p, seq, now_micros);
    }
}

size_t pinger_pollfds(pinger_t *p, struct pollfd *out, size_t max)
{
    size_t n = 0;
    p->slot4 = p->slot6 = -1;
    if (p->nruns == 0)
        return 0;
    if (p->fd4 >= 0 && n < max) {
        out[n].fd = p->fd4;
        out[n].events = POLLIN;
        out[n].revents = 0;
        p->slot4 = (int)n++;
    }
    if (p->fd6 >= 0 && n < max) {
        out[n].fd = p->fd6;
        out[n].events = POLLIN;
        out[n].revents = 0;
        p->slot6 = (int)n++;
    }
    return n;
}

void pinger_step(pinger_t *p, const struct pollfd *fds, size_t n, uint64_t now)
{
    /* Replies are timed off the microsecond clock; scheduling stays on ms. */
    uint64_t now_micros = now_us();
    if (p->slot4 >= 0 && (size_t)p->slot4 < n && (fds[p->slot4].revents & POLLIN))
        drain(p, p->fd4, true, now_micros);
    if (p->slot6 >= 0 && (size_t)p->slot6 < n && (fds[p->slot6].revents & POLLIN))
        drain(p, p->fd6, false, now_micros);

    for (size_t i = 0; i < p->nruns;) {
        run_t *r = &p->runs[i];
        device_t *d = store_find_id(p->store, r->dev_id);
        if (!d) {
            /* The device was merged away or expired; stop pinging it. */
            *r = p->runs[--p->nruns];
            continue;
        }
        reap_timeouts(p, r, d, now_micros);
        if (now + 1 >= r->next_send) {
            send_probe(p, r, d);
            r->next_send = now + PING_INTERVAL_MS;
        }
        i++;
    }
}

uint64_t pinger_next_deadline(const pinger_t *p)
{
    uint64_t best = UINT64_MAX;
    for (size_t i = 0; i < p->nruns; i++) {
        const run_t *r = &p->runs[i];
        if (r->next_send < best)
            best = r->next_send;
        for (size_t k = 0; k < MAX_OUTSTANDING; k++)
            if (r->probes[k].used) {
                uint64_t due = r->probes[k].sent_us / 1000 + PING_TIMEOUT_MS + 1;
                if (due < best)
                    best = due;
            }
    }
    return best;
}
