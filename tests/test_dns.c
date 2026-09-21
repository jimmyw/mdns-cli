/* Parser tests: one realistic mDNS response, then the malformed packets that
   a parser reading straight off the network has to survive. */
#include "dns.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                                                \
    do {                                                                                           \
        if (!(cond)) {                                                                             \
            printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);                                 \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

#define CHECK_STR(got, want)                                                                       \
    do {                                                                                           \
        if (strcmp((got), (want)) != 0) {                                                          \
            printf("FAIL %s:%d: got \"%s\", want \"%s\"\n", __FILE__, __LINE__, (got), (want));    \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

/* A response carrying PTR, SRV, TXT, A, AAAA and the service-type enumeration
   answer, with the compression pointers a real responder emits. */
static const uint8_t response[] = {
    0x00, 0x00, 0x84, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00,
    0x04, 0x5f, 0x69, 0x70, 0x70, 0x04, 0x5f, 0x74, 0x63, 0x70, 0x05, 0x6c,
    0x6f, 0x63, 0x61, 0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x78, 0x00, 0x0a, 0x07, 0x50, 0x72, 0x69, 0x6e, 0x74, 0x65, 0x72, 0xc0,
    0x0c, 0xc0, 0x27, 0x00, 0x21, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00,
    0x15, 0x00, 0x00, 0x00, 0x00, 0x02, 0x77, 0x07, 0x70, 0x72, 0x69, 0x6e,
    0x74, 0x65, 0x72, 0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00, 0xc0, 0x27,
    0x00, 0x10, 0x80, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x3e, 0x0c, 0x72,
    0x70, 0x3d, 0x69, 0x70, 0x70, 0x2f, 0x70, 0x72, 0x69, 0x6e, 0x74, 0x0e,
    0x74, 0x79, 0x3d, 0x48, 0x50, 0x20, 0x4c, 0x61, 0x73, 0x65, 0x72, 0x4a,
    0x65, 0x74, 0x13, 0x70, 0x64, 0x6c, 0x3d, 0x61, 0x70, 0x70, 0x6c, 0x69,
    0x63, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2f, 0x70, 0x64, 0x66, 0x08, 0x61,
    0x69, 0x72, 0x3d, 0x6e, 0x6f, 0x6e, 0x65, 0x04, 0x66, 0x6c, 0x61, 0x67,
    0xc0, 0x43, 0x00, 0x01, 0x80, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x04,
    0xc0, 0xa8, 0x02, 0x15, 0xc0, 0x43, 0x00, 0x1c, 0x80, 0x01, 0x00, 0x00,
    0x00, 0x78, 0x00, 0x10, 0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x09, 0x5f, 0x73, 0x65,
    0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x07, 0x5f, 0x64, 0x6e, 0x73, 0x2d,
    0x73, 0x64, 0x04, 0x5f, 0x75, 0x64, 0x70, 0x05, 0x6c, 0x6f, 0x63, 0x61,
    0x6c, 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x11, 0x94, 0x00, 0x02,
    0xc0, 0x0c,
};

static void test_response(void)
{
    dns_msg_t m;
    CHECK(dns_msg_begin(&m, response, sizeof response) == 0);
    CHECK(dns_is_response(&m));
    CHECK(m.qdcount == 0);
    CHECK(dns_rr_total(&m) == 6);

    dns_rr_t rr;
    char buf[DNS_MAX_NAME];

    /* 1: PTR _ipp._tcp.local -> Printer._ipp._tcp.local */
    CHECK(dns_read_rr(&m, &rr) == 0);
    CHECK_STR(rr.name, "_ipp._tcp.local");
    CHECK(rr.type == DNS_T_PTR);
    CHECK(rr.ttl == 120);
    CHECK(!rr.cache_flush);
    CHECK(dns_rdata_name(&m, &rr, buf, sizeof buf) == 0);
    CHECK_STR(buf, "Printer._ipp._tcp.local");

    /* 2: SRV, name reached through a compression pointer into rec 1's rdata */
    CHECK(dns_read_rr(&m, &rr) == 0);
    CHECK_STR(rr.name, "Printer._ipp._tcp.local");
    CHECK(rr.type == DNS_T_SRV);
    CHECK(rr.cache_flush);
    CHECK(rr.cls == 1);
    uint16_t prio = 9, weight = 9, port = 0;
    CHECK(dns_rdata_srv(&m, &rr, &prio, &weight, &port, buf, sizeof buf) == 0);
    CHECK(prio == 0 && weight == 0 && port == 631);
    CHECK_STR(buf, "printer.local");

    /* 3: TXT, including a bare boolean key */
    CHECK(dns_read_rr(&m, &rr) == 0);
    CHECK(rr.type == DNS_T_TXT);
    dns_txt_iter_t it;
    dns_txt_iter_init(&it, &rr);
    const char *want[] = {"rp=ipp/print", "ty=HP LaserJet", "pdl=application/pdf", "air=none",
                          "flag"};
    size_t txtlen = 0;
    for (size_t i = 0; i < sizeof want / sizeof want[0]; i++) {
        CHECK(dns_txt_next(&it, buf, sizeof buf, &txtlen) == 1);
        CHECK_STR(buf, want[i]);
        CHECK(txtlen == strlen(want[i]));
    }
    CHECK(dns_txt_next(&it, buf, sizeof buf, &txtlen) == 0);

    /* 4: A */
    CHECK(dns_read_rr(&m, &rr) == 0);
    CHECK_STR(rr.name, "printer.local");
    CHECK(rr.type == DNS_T_A);
    uint8_t v4[4];
    CHECK(dns_rdata_a(&rr, v4) == 0);
    CHECK(v4[0] == 192 && v4[1] == 168 && v4[2] == 2 && v4[3] == 21);

    /* 5: AAAA */
    CHECK(dns_read_rr(&m, &rr) == 0);
    CHECK(rr.type == DNS_T_AAAA);
    uint8_t v6[16];
    CHECK(dns_rdata_aaaa(&rr, v6) == 0);
    CHECK(v6[0] == 0xfe && v6[1] == 0x80 && v6[15] == 0x22);

    /* 6: the service-type enumeration answer */
    CHECK(dns_read_rr(&m, &rr) == 0);
    CHECK_STR(rr.name, "_services._dns-sd._udp.local");
    CHECK(dns_rdata_name(&m, &rr, buf, sizeof buf) == 0);
    CHECK_STR(buf, "_ipp._tcp.local");

    CHECK(m.pos == sizeof response);
}

/* Every one of these must be rejected without reading out of bounds. ASan
   turns any mistake here into a hard failure. */
static void test_malformed(void)
{
    char buf[DNS_MAX_NAME];
    dns_msg_t m;
    dns_rr_t rr;

    /* Shorter than a header. */
    CHECK(dns_msg_begin(&m, response, 11) != 0);
    CHECK(dns_msg_begin(&m, (const uint8_t *)"", 0) != 0);

    /* A name pointing at itself. */
    static const uint8_t loop[] = {0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 0x0c};
    CHECK(dns_msg_begin(&m, loop, sizeof loop) == 0);
    CHECK(dns_read_rr(&m, &rr) != 0);

    /* Two names pointing at each other. */
    static const uint8_t loop2[] = {0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 0x0e, 0xc0, 0x0c};
    CHECK(dns_decode_name(loop2, sizeof loop2, 12, buf, sizeof buf, NULL) != 0);

    /* A forward pointer (legal DNS never emits one, and it enables loops). */
    static const uint8_t fwd[] = {0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0xc0, 0x10, 0, 0, 1, 'a', 0};
    CHECK(dns_decode_name(fwd, sizeof fwd, 12, buf, sizeof buf, NULL) != 0);

    /* Label length runs past the end of the packet. */
    static const uint8_t longlab[] = {0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0x3f, 'a', 'b'};
    CHECK(dns_decode_name(longlab, sizeof longlab, 12, buf, sizeof buf, NULL) != 0);

    /* Reserved label type (0x80). */
    static const uint8_t reserved[] = {0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0x80, 0x01};
    CHECK(dns_decode_name(reserved, sizeof reserved, 12, buf, sizeof buf, NULL) != 0);

    /* rdlength claims more bytes than the packet holds. */
    static const uint8_t bigrd[] = {0,    0,    0x84, 0,    0,    0,    0,    1,   0,
                                    0,    0,    0,    0x01, 'a',  0x00, 0x00, 0x01, 0x00,
                                    0x01, 0x00, 0x00, 0x00, 0x78, 0xff, 0xff};
    CHECK(dns_msg_begin(&m, bigrd, sizeof bigrd) == 0);
    CHECK(dns_read_rr(&m, &rr) != 0);

    /* Truncated mid-header (no ttl/rdlength at all). */
    static const uint8_t trunc[] = {0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0x01, 'a', 0x00, 0x00};
    CHECK(dns_msg_begin(&m, trunc, sizeof trunc) == 0);
    CHECK(dns_read_rr(&m, &rr) != 0);

    /* A TXT string longer than its rdata. */
    static const uint8_t badtxt[] = {0,    0,    0x84, 0,    0,    0,    0,    1,    0,   0,
                                     0,    0,    0x01, 'a',  0x00, 0x00, 0x10, 0x00, 0x01, 0x00,
                                     0x00, 0x00, 0x78, 0x00, 0x03, 0x09, 'x',  'y'};
    CHECK(dns_msg_begin(&m, badtxt, sizeof badtxt) == 0);
    CHECK(dns_read_rr(&m, &rr) == 0);
    dns_txt_iter_t it;
    dns_txt_iter_init(&it, &rr);
    CHECK(dns_txt_next(&it, buf, sizeof buf, NULL) == -1);

    /* Wrong rdata size for A / AAAA. */
    CHECK(dns_rdata_a(&rr, (uint8_t[4]){0}) == -1);
    CHECK(dns_rdata_aaaa(&rr, (uint8_t[16]){0}) == -1);

    /* Every truncation of the good packet must be handled, not crash. */
    for (size_t n = 0; n < sizeof response; n++) {
        dns_msg_t mm;
        if (dns_msg_begin(&mm, response, n) != 0)
            continue;
        unsigned total = dns_rr_total(&mm);
        dns_rr_t r;
        for (unsigned i = 0; i < total; i++)
            if (dns_read_rr(&mm, &r) != 0)
                break;
    }
}

static void test_names(void)
{
    char inst[DNS_MAX_NAME], type[128], pretty[DNS_MAX_NAME];

    CHECK(dns_split_instance("Printer._ipp._tcp.local", inst, sizeof inst, type, sizeof type) == 0);
    CHECK_STR(inst, "Printer");
    CHECK_STR(type, "_ipp._tcp");

    /* An instance name containing an escaped dot must stay one label. */
    CHECK(dns_split_instance("Jim\\.s\\032Mac._smb._tcp.local", inst, sizeof inst, type,
                             sizeof type) == 0);
    CHECK_STR(inst, "Jim\\.s\\032Mac");
    dns_unescape(inst, pretty, sizeof pretty);
    CHECK_STR(pretty, "Jim.s Mac");

    /* A bare service type has no instance label. */
    CHECK(dns_split_instance("_http._tcp.local", inst, sizeof inst, type, sizeof type) == 0);
    CHECK_STR(inst, "");
    CHECK_STR(type, "_http._tcp");

    /* Not a DNS-SD name at all. */
    CHECK(dns_split_instance("printer.local", inst, sizeof inst, type, sizeof type) != 0);
}

static void test_query_roundtrip(void)
{
    dns_query_t q;
    dns_query_init(&q, 0);
    CHECK(dns_query_add(&q, "_services._dns-sd._udp.local", DNS_T_PTR, false) == 0);
    CHECK(dns_query_add(&q, "Jim\\.s\\032Mac._smb._tcp.local", DNS_T_SRV, true) == 0);
    CHECK(q.qdcount == 2);

    dns_msg_t m;
    CHECK(dns_msg_begin(&m, q.buf, q.len) == 0);
    CHECK(m.qdcount == 2);
    CHECK(!dns_is_response(&m));

    char name[DNS_MAX_NAME];
    uint16_t type = 0, cls = 0;
    CHECK(dns_read_question(&m, name, sizeof name, &type, &cls) == 0);
    CHECK_STR(name, "_services._dns-sd._udp.local");
    CHECK(type == DNS_T_PTR);
    CHECK(cls == DNS_C_IN);

    CHECK(dns_read_question(&m, name, sizeof name, &type, &cls) == 0);
    /* \\032 decodes to a literal space, which needs no escape on the way back. */
    CHECK_STR(name, "Jim\\.s Mac._smb._tcp.local");
    CHECK(type == DNS_T_SRV);
    CHECK((cls & DNS_UNICAST_REPLY) != 0);
    CHECK(m.pos == q.len);

    /* An empty label is not encodable. */
    dns_query_t bad;
    dns_query_init(&bad, 0);
    CHECK(dns_query_add(&bad, "a..b", DNS_T_A, false) != 0);

    /* Filling the packet must be reported, not overflow it. */
    dns_query_t full;
    dns_query_init(&full, 0);
    int added = 0;
    while (dns_query_add(&full, "averylongservicename._sub._http._tcp.local", DNS_T_PTR, false) ==
           0)
        added++;
    CHECK(added > 10);
    CHECK(full.len <= sizeof full.buf);
}

int main(void)
{
    test_response();
    test_malformed();
    test_names();
    test_query_roundtrip();
    if (failures)
        printf("%d check(s) failed\n", failures);
    else
        printf("all dns parser checks passed\n");
    return failures ? 1 : 0;
}
