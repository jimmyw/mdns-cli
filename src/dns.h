/* DNS wire-format encode/decode.
 *
 * Deliberately pure: nothing here touches a socket, so the whole parser can be
 * exercised from tests/test_dns.c with captured and malformed packets. Every
 * read is bounds checked against the packet end; name decompression cannot
 * loop (pointers must strictly decrease and are capped).
 */
#ifndef MDNS_CLI_DNS_H
#define MDNS_CLI_DNS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define DNS_T_A 1
#define DNS_T_PTR 12
#define DNS_T_TXT 16
#define DNS_T_AAAA 28
#define DNS_T_SRV 33
#define DNS_T_NSEC 47
#define DNS_T_OPT 41
#define DNS_T_ANY 255

#define DNS_C_IN 1
#define DNS_CACHE_FLUSH 0x8000u /* high bit of the class field in responses */
#define DNS_UNICAST_REPLY 0x8000u /* same bit in a question: "QU" */

#define DNS_MAX_NAME 1024 /* escaped presentation form can outgrow 255 bytes */

typedef struct {
    const uint8_t *buf;
    size_t len;
    size_t pos;
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount, ancount, nscount, arcount;
} dns_msg_t;

typedef struct {
    char name[DNS_MAX_NAME];
    uint16_t type;
    uint16_t cls; /* cache-flush bit already stripped */
    bool cache_flush;
    uint32_t ttl;
    const uint8_t *rdata;
    size_t rdlen;
} dns_rr_t;

/* True when the message is a response (QR bit set). */
static inline bool dns_is_response(const dns_msg_t *m) { return (m->flags & 0x8000u) != 0; }

/* Parse the 12-byte header and position at the first question.
   Returns 0 on success, -1 if the buffer is too short. */
int dns_msg_begin(dns_msg_t *m, const uint8_t *buf, size_t len);

/* Read one question. Returns 0, or -1 on malformed input. */
int dns_read_question(dns_msg_t *m, char *name, size_t namesz, uint16_t *type, uint16_t *cls);

/* Read one resource record. Returns 0, or -1 on malformed input. */
int dns_read_rr(dns_msg_t *m, dns_rr_t *rr);

/* Total record count across the answer, authority and additional sections. */
static inline unsigned dns_rr_total(const dns_msg_t *m)
{
    return (unsigned)m->ancount + m->nscount + m->arcount;
}

/* Decode a (possibly compressed) name at off into escaped presentation form.
   next_off, when non-NULL, receives the offset just past the name. */
int dns_decode_name(const uint8_t *buf, size_t len, size_t off, char *out, size_t outsz,
                    size_t *next_off);

/* Typed rdata accessors. Each returns 0 on success, -1 on malformed rdata. */
int dns_rdata_name(const dns_msg_t *m, const dns_rr_t *rr, char *out, size_t outsz);
int dns_rdata_srv(const dns_msg_t *m, const dns_rr_t *rr, uint16_t *priority, uint16_t *weight,
                  uint16_t *port, char *target, size_t targetsz);
int dns_rdata_a(const dns_rr_t *rr, uint8_t out[4]);
int dns_rdata_aaaa(const dns_rr_t *rr, uint8_t out[16]);

/* Iterate the length-prefixed strings of a TXT record. */
typedef struct {
    const uint8_t *p;
    const uint8_t *end;
} dns_txt_iter_t;

void dns_txt_iter_init(dns_txt_iter_t *it, const dns_rr_t *rr);
/* Returns 1 and fills out on success, 0 at the end, -1 on malformed rdata.
   out is always NUL-terminated, but TXT values can contain NUL and other raw
   bytes, so outlen (optional) carries the true length. */
int dns_txt_next(dns_txt_iter_t *it, char *out, size_t outsz, size_t *outlen);

/* Query construction. Build, append questions, then send the byte range. */
typedef struct {
    uint8_t buf[1400]; /* stay under the typical 1500-byte MTU */
    size_t len;
    uint16_t qdcount;
} dns_query_t;

void dns_query_init(dns_query_t *q, uint16_t id);
/* Returns 0 if the question fit, -1 if the packet is full (send and start a new one). */
int dns_query_add(dns_query_t *q, const char *name, uint16_t type, bool unicast_reply);
/* Splits a DNS-SD instance fqdn into its instance label and "_type._proto" part.
   Returns 0 on success. Both outputs are optional. */
int dns_split_instance(const char *fqdn, char *instance, size_t isz, char *type, size_t tsz);

/* Turn escaped presentation form ("Brother\\032HL-2030") back into the raw
   bytes a human expects to read. Non-printable results are replaced with '?'. */
void dns_unescape(const char *in, char *out, size_t outsz);

#endif /* MDNS_CLI_DNS_H */
