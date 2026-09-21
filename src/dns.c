#include "dns.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#define MAX_JUMPS 32

static int rd16(const uint8_t *buf, size_t len, size_t off, uint16_t *out)
{
    if (off + 2 > len)
        return -1;
    *out = (uint16_t)((buf[off] << 8) | buf[off + 1]);
    return 0;
}

static int rd32(const uint8_t *buf, size_t len, size_t off, uint32_t *out)
{
    if (off + 4 > len)
        return -1;
    *out = ((uint32_t)buf[off] << 24) | ((uint32_t)buf[off + 1] << 16) |
           ((uint32_t)buf[off + 2] << 8) | (uint32_t)buf[off + 3];
    return 0;
}

/* Append one label in escaped presentation form. Returns -1 if out fills up. */
static int emit_label(const uint8_t *lab, size_t n, char *out, size_t outsz, size_t *o)
{
    for (size_t i = 0; i < n; i++) {
        uint8_t c = lab[i];
        char tmp[5];
        size_t w;
        if (c == '.' || c == '\\') {
            tmp[0] = '\\';
            tmp[1] = (char)c;
            w = 2;
        } else if (c < 0x20 || c >= 0x7f) {
            snprintf(tmp, sizeof tmp, "\\%03u", c);
            w = 4;
        } else {
            tmp[0] = (char)c;
            w = 1;
        }
        if (*o + w + 1 > outsz)
            return -1;
        memcpy(out + *o, tmp, w);
        *o += w;
    }
    return 0;
}

int dns_decode_name(const uint8_t *buf, size_t len, size_t off, char *out, size_t outsz,
                    size_t *next_off)
{
    if (outsz == 0)
        return -1;
    size_t o = 0;
    size_t jumps = 0;
    size_t limit = off; /* every pointer must aim strictly before the previous one */
    bool jumped = false;
    out[0] = '\0';

    for (;;) {
        if (off >= len)
            return -1;
        uint8_t b = buf[off];
        if ((b & 0xC0u) == 0xC0u) {
            uint16_t ptr;
            if (rd16(buf, len, off, &ptr) != 0)
                return -1;
            size_t target = ptr & 0x3FFFu;
            if (!jumped && next_off)
                *next_off = off + 2;
            jumped = true;
            if (++jumps > MAX_JUMPS || target >= limit)
                return -1; /* loop or forward pointer: refuse */
            limit = target;
            off = target;
            continue;
        }
        if (b & 0xC0u)
            return -1; /* reserved label type */
        off++;
        if (b == 0) {
            if (!jumped && next_off)
                *next_off = off;
            out[o] = '\0';
            return 0;
        }
        if (off + b > len)
            return -1;
        if (o != 0) {
            if (o + 2 > outsz)
                return -1;
            out[o++] = '.';
        }
        if (emit_label(buf + off, b, out, outsz, &o) != 0)
            return -1;
        off += b;
    }
}

int dns_msg_begin(dns_msg_t *m, const uint8_t *buf, size_t len)
{
    if (len < 12)
        return -1;
    m->buf = buf;
    m->len = len;
    m->pos = 12;
    m->id = (uint16_t)((buf[0] << 8) | buf[1]);
    m->flags = (uint16_t)((buf[2] << 8) | buf[3]);
    m->qdcount = (uint16_t)((buf[4] << 8) | buf[5]);
    m->ancount = (uint16_t)((buf[6] << 8) | buf[7]);
    m->nscount = (uint16_t)((buf[8] << 8) | buf[9]);
    m->arcount = (uint16_t)((buf[10] << 8) | buf[11]);
    return 0;
}

int dns_read_question(dns_msg_t *m, char *name, size_t namesz, uint16_t *type, uint16_t *cls)
{
    size_t next = 0;
    char scratch[DNS_MAX_NAME];
    char *dst = name ? name : scratch;
    size_t dstsz = name ? namesz : sizeof scratch;
    if (dns_decode_name(m->buf, m->len, m->pos, dst, dstsz, &next) != 0)
        return -1;
    uint16_t t, c;
    if (rd16(m->buf, m->len, next, &t) != 0 || rd16(m->buf, m->len, next + 2, &c) != 0)
        return -1;
    m->pos = next + 4;
    if (type)
        *type = t;
    if (cls)
        *cls = c;
    return 0;
}

int dns_read_rr(dns_msg_t *m, dns_rr_t *rr)
{
    size_t next = 0;
    if (dns_decode_name(m->buf, m->len, m->pos, rr->name, sizeof rr->name, &next) != 0)
        return -1;
    uint16_t type, cls, rdlen;
    uint32_t ttl;
    if (rd16(m->buf, m->len, next, &type) != 0 || rd16(m->buf, m->len, next + 2, &cls) != 0 ||
        rd32(m->buf, m->len, next + 4, &ttl) != 0 || rd16(m->buf, m->len, next + 8, &rdlen) != 0)
        return -1;
    size_t rdstart = next + 10;
    if (rdstart + rdlen > m->len)
        return -1;
    rr->type = type;
    rr->cache_flush = (cls & DNS_CACHE_FLUSH) != 0;
    rr->cls = cls & (uint16_t)~DNS_CACHE_FLUSH;
    rr->ttl = ttl;
    rr->rdata = m->buf + rdstart;
    rr->rdlen = rdlen;
    m->pos = rdstart + rdlen;
    return 0;
}

int dns_rdata_name(const dns_msg_t *m, const dns_rr_t *rr, char *out, size_t outsz)
{
    size_t off = (size_t)(rr->rdata - m->buf);
    return dns_decode_name(m->buf, m->len, off, out, outsz, NULL);
}

int dns_rdata_srv(const dns_msg_t *m, const dns_rr_t *rr, uint16_t *priority, uint16_t *weight,
                  uint16_t *port, char *target, size_t targetsz)
{
    if (rr->rdlen < 7)
        return -1;
    size_t off = (size_t)(rr->rdata - m->buf);
    uint16_t pr, wt, po;
    if (rd16(m->buf, m->len, off, &pr) != 0 || rd16(m->buf, m->len, off + 2, &wt) != 0 ||
        rd16(m->buf, m->len, off + 4, &po) != 0)
        return -1;
    if (dns_decode_name(m->buf, m->len, off + 6, target, targetsz, NULL) != 0)
        return -1;
    if (priority)
        *priority = pr;
    if (weight)
        *weight = wt;
    if (port)
        *port = po;
    return 0;
}

int dns_rdata_a(const dns_rr_t *rr, uint8_t out[4])
{
    if (rr->rdlen != 4)
        return -1;
    memcpy(out, rr->rdata, 4);
    return 0;
}

int dns_rdata_aaaa(const dns_rr_t *rr, uint8_t out[16])
{
    if (rr->rdlen != 16)
        return -1;
    memcpy(out, rr->rdata, 16);
    return 0;
}

void dns_txt_iter_init(dns_txt_iter_t *it, const dns_rr_t *rr)
{
    it->p = rr->rdata;
    it->end = rr->rdata + rr->rdlen;
}

int dns_txt_next(dns_txt_iter_t *it, char *out, size_t outsz, size_t *outlen)
{
    if (outsz == 0)
        return -1;
    if (outlen)
        *outlen = 0;
    /* A zero-length string is legal padding; skip over any run of them. */
    for (;;) {
        if (it->p >= it->end)
            return 0;
        size_t n = *it->p++;
        if (it->p + n > it->end)
            return -1;
        if (n == 0)
            continue;
        size_t copy = n < outsz - 1 ? n : outsz - 1;
        memcpy(out, it->p, copy);
        out[copy] = '\0';
        it->p += n;
        if (outlen)
            *outlen = copy;
        return 1;
    }
}

void dns_query_init(dns_query_t *q, uint16_t id)
{
    memset(q->buf, 0, 12);
    q->buf[0] = (uint8_t)(id >> 8);
    q->buf[1] = (uint8_t)(id & 0xff);
    q->len = 12;
    q->qdcount = 0;
}

/* Write an escaped presentation name in wire format. Returns bytes written, or -1. */
static int encode_name(const char *name, uint8_t *out, size_t outsz)
{
    size_t o = 0;
    const char *p = name;
    while (*p) {
        size_t lenpos = o;
        if (o + 1 > outsz)
            return -1;
        o++; /* length byte, filled in below */
        size_t n = 0;
        while (*p && *p != '.') {
            uint8_t c;
            if (*p == '\\') {
                p++;
                if (isdigit((unsigned char)p[0]) && isdigit((unsigned char)p[1]) &&
                    isdigit((unsigned char)p[2])) {
                    c = (uint8_t)((p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0'));
                    p += 3;
                } else if (*p) {
                    c = (uint8_t)*p++;
                } else {
                    return -1;
                }
            } else {
                c = (uint8_t)*p++;
            }
            if (n >= 63 || o + 1 > outsz)
                return -1;
            out[o++] = c;
            n++;
        }
        if (n == 0)
            return -1; /* empty label: malformed */
        out[lenpos] = (uint8_t)n;
        if (*p == '.')
            p++;
    }
    if (o + 1 > outsz)
        return -1;
    out[o++] = 0;
    return (int)o;
}

int dns_query_add(dns_query_t *q, const char *name, uint16_t type, bool unicast_reply)
{
    uint8_t tmp[DNS_MAX_NAME];
    int n = encode_name(name, tmp, sizeof tmp);
    if (n < 0)
        return -1;
    if (q->len + (size_t)n + 4 > sizeof q->buf)
        return -1;
    memcpy(q->buf + q->len, tmp, (size_t)n);
    q->len += (size_t)n;
    uint16_t cls = DNS_C_IN | (unicast_reply ? DNS_UNICAST_REPLY : 0);
    q->buf[q->len++] = (uint8_t)(type >> 8);
    q->buf[q->len++] = (uint8_t)(type & 0xff);
    q->buf[q->len++] = (uint8_t)(cls >> 8);
    q->buf[q->len++] = (uint8_t)(cls & 0xff);
    q->qdcount++;
    q->buf[4] = (uint8_t)(q->qdcount >> 8);
    q->buf[5] = (uint8_t)(q->qdcount & 0xff);
    return 0;
}

/* Split an escaped name into labels, in place of the caller's buffer. */
static size_t split_labels(const char *name, const char **starts, size_t *lens, size_t max)
{
    size_t n = 0;
    const char *p = name;
    const char *start = p;
    while (n < max) {
        if (*p == '\\' && p[1]) {
            p += 2;
            continue;
        }
        if (*p == '.' || *p == '\0') {
            starts[n] = start;
            lens[n] = (size_t)(p - start);
            n++;
            if (*p == '\0')
                break;
            start = ++p;
            continue;
        }
        p++;
    }
    return n;
}

static void copy_out(char *dst, size_t dstsz, const char *src, size_t len)
{
    if (!dst || dstsz == 0)
        return;
    size_t n = len < dstsz - 1 ? len : dstsz - 1;
    memcpy(dst, src, n);
    dst[n] = '\0';
}

int dns_split_instance(const char *fqdn, char *instance, size_t isz, char *type, size_t tsz)
{
    const char *starts[16];
    size_t lens[16];
    size_t n = split_labels(fqdn, starts, lens, 16);
    if (instance && isz)
        instance[0] = '\0';
    if (type && tsz)
        type[0] = '\0';
    /* <instance>.<_app>.<_proto>.<domain> */
    if (n >= 4 && lens[1] && starts[1][0] == '_' && lens[2] && starts[2][0] == '_') {
        copy_out(instance, isz, starts[0], lens[0]);
        copy_out(type, tsz, starts[1], lens[1] + 1 + lens[2]);
        return 0;
    }
    /* <_app>.<_proto>.<domain>: a bare service type */
    if (n >= 3 && lens[0] && starts[0][0] == '_' && lens[1] && starts[1][0] == '_') {
        copy_out(type, tsz, starts[0], lens[0] + 1 + lens[1]);
        return 0;
    }
    return -1;
}

void dns_unescape(const char *in, char *out, size_t outsz)
{
    size_t o = 0;
    for (const char *p = in; *p && o + 1 < outsz;) {
        unsigned char c;
        if (*p == '\\') {
            p++;
            if (isdigit((unsigned char)p[0]) && isdigit((unsigned char)p[1]) &&
                isdigit((unsigned char)p[2])) {
                c = (unsigned char)((p[0] - '0') * 100 + (p[1] - '0') * 10 + (p[2] - '0'));
                p += 3;
            } else if (*p) {
                c = (unsigned char)*p++;
            } else {
                break;
            }
        } else {
            c = (unsigned char)*p++;
        }
        /* Keep UTF-8 sequences intact, drop control characters. */
        out[o++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
    }
    out[o] = '\0';
}
