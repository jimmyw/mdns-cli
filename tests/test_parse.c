/* Store-merge, XML and URL handling: the logic that decides whether two
   sightings are the same box, and what gets read out of a UPnP description. */
#include "device.h"
#include "http.h"
#include "neigh.h"
#include "oui.h"
#include "util.h"
#include "xmlmini.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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
        const char *g_ = (got);                                                                    \
        if (!g_ || strcmp(g_, (want)) != 0) {                                                      \
            printf("FAIL %s:%d: got \"%s\", want \"%s\"\n", __FILE__, __LINE__, g_ ? g_ : "(null)",\
                   (want));                                                                        \
            failures++;                                                                            \
        }                                                                                          \
    } while (0)

static addr_t v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    addr_t out;
    uint8_t raw[4] = {a, b, c, d};
    addr_from_v4(&out, raw);
    return out;
}

static void test_addr(void)
{
    addr_t a = v4(192, 168, 2, 21);
    addr_t b = v4(192, 168, 2, 21);
    addr_t c = v4(192, 168, 2, 22);
    CHECK(addr_equal(&a, &b));
    CHECK(!addr_equal(&a, &c));
    CHECK_STR(a.str, "192.168.2.21");

    uint8_t zero[4] = {0, 0, 0, 0};
    addr_t z;
    CHECK(!addr_from_v4(&z, zero));

    /* The same link-local address on two interfaces is two different hosts. */
    uint8_t ll[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    addr_t l1, l2;
    CHECK(addr_from_v6(&l1, ll, 2));
    CHECK(addr_from_v6(&l2, ll, 3));
    CHECK(!addr_equal(&l1, &l2));
}

/* The core merge: SSDP finds the address first, mDNS then resolves a hostname
   with a service on it. One device must come out, carrying both. */
static void test_merge(void)
{
    store_t s;
    store_init(&s);
    uint64_t now = 1000;

    addr_t a = v4(192, 168, 2, 21);
    device_t *ssdp_dev = store_device_for_addr(&s, &a, now, SRC_SSDP);
    ssdp_entry_t *e = device_ssdp(&s, ssdp_dev, "uuid:1234::upnp:rootdevice", "upnp:rootdevice",
                                  now);
    str_set(&e->location, "http://192.168.2.21:8080/desc.xml");
    CHECK(s.n_devices == 1);

    /* mDNS side: a service whose SRV names a host we have no address for yet. */
    device_t *host_dev = store_device_for_host(&s, "printer.local", now, SRC_MDNS);
    CHECK(s.n_devices == 2);
    service_t *sv = device_service(&s, host_dev, "Printer._ipp._tcp.local", now);
    sv->port = 631;
    sv->have_srv = true;
    service_set_txt(sv, "rp=ipp/print", 12);
    service_set_txt(sv, "ty=HP LaserJet", 14);
    CHECK_STR(sv->type, "_ipp._tcp");

    /* A MAC learned on one half of the merge must survive it. */
    snprintf(host_dev->mac, sizeof host_dev->mac, "aa:bb:cc:dd:ee:ff");

    /* Ping counters recorded before the merge must survive it. */
    ping_record_reply(&host_dev->ping, 3.0);
    host_dev->ping.sent = 1;
    snprintf(host_dev->ping.target, sizeof host_dev->ping.target, "192.168.2.21");

    /* The A record arrives: the two sightings collapse into one device. */
    device_t *d = store_device_for_addr(&s, &a, now, SRC_MDNS);
    d = store_set_host(&s, d, "printer.local", now);
    CHECK(s.n_devices == 1);
    CHECK(d->sources == (SRC_MDNS | SRC_SSDP));
    CHECK(d->n_services == 1);
    CHECK(d->n_ssdp == 1);
    CHECK_STR(d->hostname, "printer.local");
    CHECK_STR(device_label(d), "printer.local");
    CHECK_STR(device_primary_addr(d), "192.168.2.21");

    char src[16];
    device_sources_str(d, src, sizeof src);
    CHECK_STR(src, "mDNS+SSDP");

    CHECK_STR(d->mac, "aa:bb:cc:dd:ee:ff");
    CHECK(device_matches(d, "AA:BB:CC")); /* the filter reaches the MAC too */

    CHECK(ping_has_data(&d->ping));
    CHECK(d->ping.recv == 1);
    CHECK_STR(d->ping.target, "192.168.2.21");

    /* The service survived the merge and is findable by fqdn. */
    device_t *owner = NULL;
    service_t *found = store_find_service(&s, "Printer._ipp._tcp.local", &owner);
    CHECK(found != NULL && owner == d);
    CHECK(found && found->port == 631);
    CHECK(found && found->n_txt == 2);

    /* Setting an existing TXT key replaces it instead of duplicating. */
    service_set_txt(found, "ty=HP OfficeJet", 15);
    CHECK(found->n_txt == 2);
    CHECK_STR(found->txt->next->val, "HP OfficeJet");

    /* A second address on the same device does not create a second device. */
    addr_t a2 = v4(192, 168, 2, 99);
    d = store_add_addr(&s, d, &a2, now);
    CHECK(s.n_devices == 1);
    CHECK(d->n_addrs == 2);

    /* Filtering reaches into services and UPnP fields. */
    CHECK(device_matches(d, "laserjet") == false); /* replaced above */
    CHECK(device_matches(d, "officejet"));
    CHECK(device_matches(d, "_ipp"));
    CHECK(device_matches(d, "192.168.2.99"));
    CHECK(!device_matches(d, "nothing-like-this"));

    /* byebye removes just that entry. */
    device_drop_ssdp(&s, d, "uuid:1234::upnp:rootdevice");
    CHECK(d->n_ssdp == 0);
    CHECK(store_find_ssdp(&s, "uuid:1234::upnp:rootdevice", NULL) == NULL);

    /* Expiry drops what has not been heard from. */
    store_expire(&s, now + 1000, 100000);
    CHECK(s.n_devices == 1);
    store_expire(&s, now + 200000, 100000);
    CHECK(s.n_devices == 0);

    store_free(&s);
}

static void test_label_fallbacks(void)
{
    store_t s;
    store_init(&s);
    addr_t a = v4(10, 0, 0, 5);
    device_t *d = store_device_for_addr(&s, &a, 1, SRC_SSDP);
    CHECK_STR(device_label(d), "(unnamed)");

    ssdp_entry_t *e = device_ssdp(&s, d, "uuid:abc", "upnp:rootdevice", 1);
    e->friendly_name = xstrdup("Living Room TV");
    CHECK_STR(device_label(d), "Living Room TV");

    d = store_set_host(&s, d, "tv.local", 1);
    CHECK_STR(device_label(d), "tv.local");
    store_free(&s);
}

/* TXT values are not always text: Thread border routers put raw binary in
   them, NUL bytes included. Those must survive as something printable. */
static void test_binary_txt(void)
{
    store_t s;
    store_init(&s);
    addr_t a = v4(10, 0, 0, 7);
    device_t *d = store_device_for_addr(&s, &a, 1, SRC_MDNS);
    service_t *sv = device_service(&s, d, "br._meshcop._udp.local", 1);

    service_set_txt(sv, "id=\x96\x9d\x00\xe9", 7);
    CHECK_STR(sv->txt->key, "id");
    CHECK_STR(sv->txt->val, "0x969d00e9");

    /* Valid UTF-8 is text and must pass through untouched. */
    service_set_txt(sv, "n=caf\xc3\xa9", 7);
    CHECK_STR(sv->txt->next->val, "caf\xc3\xa9");

    /* A bare key with no '=' is a boolean flag, not an empty value. */
    service_set_txt(sv, "flag", 4);
    CHECK(sv->n_txt == 3);
    CHECK(sv->txt->next->next->val == NULL);

    /* An '=' with nothing after it is an empty value, which is different. */
    service_set_txt(sv, "empty=", 6);
    CHECK_STR(sv->txt->next->next->next->val, "");

    CHECK(str_is_printable("plain", 5));
    CHECK(!str_is_printable("a\x01b", 3));
    CHECK(!str_is_printable("\xff\xfe", 2));
    store_free(&s);
}

/* Loss is counted over resolved probes only: a probe still in flight is not
   yet a lost one, or every ping would start out looking 100% lossy. */
static void test_ping_counters(void)
{
    ping_t p;
    memset(&p, 0, sizeof p);
    CHECK(!ping_has_data(&p));
    CHECK(ping_loss_pct(&p) < 0);
    CHECK(ping_avg_ms(&p) < 0);

    p.sent = 1;
    ping_record_reply(&p, 2.0);
    CHECK(p.recv == 1);
    CHECK(p.min_ms == 2.0 && p.max_ms == 2.0 && p.last_ms == 2.0);
    CHECK(ping_avg_ms(&p) == 2.0);
    CHECK(ping_loss_pct(&p) == 0.0);

    p.sent = 2;
    ping_record_reply(&p, 4.0);
    CHECK(ping_avg_ms(&p) == 3.0);
    CHECK(p.min_ms == 2.0 && p.max_ms == 4.0 && p.last_ms == 4.0);

    p.sent = 3;
    ping_record_loss(&p);
    CHECK(fabs(ping_loss_pct(&p) - 100.0 / 3.0) < 0.001);

    /* A fourth probe in flight must not move the loss figure. */
    p.sent = 4;
    CHECK(fabs(ping_loss_pct(&p) - 100.0 / 3.0) < 0.001);
    CHECK(ping_has_data(&p));

    /* Total loss reads as 100%, not as a missing value. */
    ping_t dead;
    memset(&dead, 0, sizeof dead);
    dead.sent = 2;
    ping_record_loss(&dead);
    ping_record_loss(&dead);
    CHECK(ping_loss_pct(&dead) == 100.0);
    CHECK(ping_avg_ms(&dead) < 0);

    p.error = xstrdup("boom");
    ping_reset(&p);
    CHECK(p.sent == 0 && p.recv == 0 && p.lost == 0);
    CHECK(p.error == NULL);
    CHECK(ping_loss_pct(&p) < 0);
    CHECK(!ping_has_data(&p));
}

/* The green / yellow / red tiers the UI paints, checked at every boundary. */
static void test_ping_grades(void)
{
    ping_t p;
    memset(&p, 0, sizeof p);

    /* Nothing resolved yet is not a verdict. */
    p.sent = 1;
    CHECK(ping_loss_grade(&p) == PING_GRADE_NONE);
    CHECK(ping_rtt_grade(&p) == PING_GRADE_NONE);
    CHECK(ping_grade(&p) == PING_GRADE_NONE);

    /* Clean and fast: green. */
    ping_record_reply(&p, 1.0);
    CHECK(ping_loss_grade(&p) == PING_GRADE_GOOD);
    CHECK(ping_rtt_grade(&p) == PING_GRADE_GOOD);
    CHECK(ping_grade(&p) == PING_GRADE_GOOD);

    /* A single dropped packet out of three is a warning, not a failure. */
    p.sent = 3;
    ping_record_reply(&p, 1.0);
    ping_record_loss(&p);
    CHECK(ping_loss_pct(&p) < PING_LOSS_BAD_PCT);
    CHECK(ping_loss_grade(&p) == PING_GRADE_WARN);
    CHECK(ping_grade(&p) == PING_GRADE_WARN);

    /* Half the packets gone is a failure. */
    ping_t half;
    memset(&half, 0, sizeof half);
    half.sent = 2;
    ping_record_reply(&half, 1.0);
    ping_record_loss(&half);
    CHECK(ping_loss_pct(&half) == 50.0);
    CHECK(ping_loss_grade(&half) == PING_GRADE_BAD);

    /* Round trip tiers, checked either side of each threshold. */
    ping_t r;
    memset(&r, 0, sizeof r);
    r.sent = 1;
    ping_record_reply(&r, PING_RTT_WARN_MS - 0.01);
    CHECK(ping_rtt_grade(&r) == PING_GRADE_GOOD);
    memset(&r, 0, sizeof r);
    r.sent = 1;
    ping_record_reply(&r, PING_RTT_WARN_MS);
    CHECK(ping_rtt_grade(&r) == PING_GRADE_WARN);
    memset(&r, 0, sizeof r);
    r.sent = 1;
    ping_record_reply(&r, PING_RTT_BAD_MS);
    CHECK(ping_rtt_grade(&r) == PING_GRADE_BAD);

    /* No loss but a crawling link still grades red overall. */
    CHECK(ping_loss_grade(&r) == PING_GRADE_GOOD);
    CHECK(ping_grade(&r) == PING_GRADE_BAD);

    /* A device that never answered at all. */
    ping_t dead;
    memset(&dead, 0, sizeof dead);
    dead.sent = 1;
    ping_record_loss(&dead);
    CHECK(ping_grade(&dead) == PING_GRADE_BAD);

    /* An error before anything was sent (no ICMP socket, no address). */
    ping_t err;
    memset(&err, 0, sizeof err);
    err.error = xstrdup("ICMP not permitted");
    CHECK(ping_loss_grade(&err) == PING_GRADE_BAD);
    ping_reset(&err);
}

/* The neighbour table is the kernel's, so this checks the plumbing rather
   than any particular contents: a dump must succeed and unknown addresses
   must come back empty rather than confidently wrong. */
static void test_neigh(void)
{
    neigh_cache_t *nc = neigh_new();
    CHECK(nc != NULL);
    neigh_refresh(nc);

    addr_t bogus = v4(0, 0, 0, 1);
    CHECK(neigh_lookup(nc, &bogus) == NULL);

    /* Applying to an empty store must not touch anything. */
    store_t s;
    store_init(&s);
    CHECK(neigh_apply(nc, &s) == 0);

    /* A device whose address the kernel cannot know keeps an empty MAC. */
    addr_t unseen = v4(198, 51, 100, 7);
    device_t *d = store_device_for_addr(&s, &unseen, 1, SRC_MDNS);
    neigh_apply(nc, &s);
    CHECK_STR(d->mac, "");

    store_free(&s);
    neigh_destroy(nc);
    neigh_destroy(NULL); /* must be a no-op */
}

static void test_xml(void)
{
    static const char doc[] =
        "<?xml version=\"1.0\"?>\n"
        "<root xmlns=\"urn:schemas-upnp-org:device-1-0\">\n"
        "  <specVersion><major>1</major><minor>0</minor></specVersion>\n"
        "  <device>\n"
        "    <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>\n"
        "    <friendlyName>Jim &amp; Co. &quot;Printer&quot;</friendlyName>\n"
        "    <manufacturer>HP Inc.</manufacturer>\n"
        "    <modelName>M283fdw</modelName>\n"
        "    <serialNumber/>\n"
        "    <UDN>uuid:1234-5678</UDN>\n"
        "  </device>\n"
        "</root>\n";
    size_t n = sizeof doc - 1;

    char *v = xml_tag(doc, n, "friendlyName");
    CHECK_STR(v, "Jim & Co. \"Printer\"");
    free(v);

    v = xml_tag(doc, n, "manufacturer");
    CHECK_STR(v, "HP Inc.");
    free(v);

    /* The namespaced root element must not confuse the scan. */
    v = xml_tag(doc, n, "modelName");
    CHECK_STR(v, "M283fdw");
    free(v);

    v = xml_tag(doc, n, "UDN");
    CHECK_STR(v, "uuid:1234-5678");
    free(v);

    CHECK(xml_tag(doc, n, "serialNumber") == NULL); /* self-closing: no text */
    CHECK(xml_tag(doc, n, "modelNumber") == NULL);  /* absent */
    CHECK(xml_tag("", 0, "friendlyName") == NULL);

    /* An unterminated tag must not run off the end. */
    static const char broken[] = "<device><friendlyName>no close tag";
    CHECK(xml_tag(broken, sizeof broken - 1, "friendlyName") == NULL);

    /* A prefixed element still matches. */
    static const char ns[] = "<d:device><d:friendlyName>Prefixed</d:friendlyName></d:device>";
    v = xml_tag(ns, sizeof ns - 1, "friendlyName");
    CHECK_STR(v, "Prefixed");
    free(v);

    /* Numeric entities. */
    static const char ent[] = "<a>caf&#233; &#x41;&unknown;</a>";
    v = xml_tag(ent, sizeof ent - 1, "a");
    CHECK_STR(v, "caf? A&unknown;");
    free(v);
}

static void test_http_bad_urls(void)
{
    /* Nothing here touches the network: each URL must fail up front. */
    const char *bad[] = {"ftp://1.2.3.4/x", "https://1.2.3.4/x", "http://", "not a url",
                         "http://:80/x"};
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        http_req_t *r = http_get(bad[i], NULL, 1024, 1000, NULL);
        CHECK(r != NULL);
        CHECK(http_step(r, 0, now_ms()) == -1);
        CHECK(*http_error(r) != '\0');
        http_free(r);
    }

    /* A name-based host with no override cannot be resolved without blocking. */
    http_req_t *r = http_get("http://printer.local:8080/desc.xml", NULL, 1024, 1000, NULL);
    CHECK(http_step(r, 0, now_ms()) == -1);
    CHECK_STR(http_error(r), "host is not a literal address");
    http_free(r);

    /* With an override address the same URL is usable (connect is in flight). */
    r = http_get("http://printer.local:8080/desc.xml", "192.0.2.1", 1024, 1000, NULL);
    CHECK(http_step(r, 0, now_ms()) == 0);
    CHECK(http_fd(r) >= 0);
    http_free(r);

    /* The deadline is honoured even when the socket never becomes ready. */
    r = http_get("http://192.0.2.1:8080/desc.xml", NULL, 1024, 0, NULL);
    CHECK(http_step(r, 0, now_ms() + 1) == -1);
    CHECK_STR(http_error(r), "timed out");
    http_free(r);
}

static void test_util(void)
{
    char buf[32];
    fmt_age(999, buf, sizeof buf);
    CHECK_STR(buf, "0s");
    fmt_age(65000, buf, sizeof buf);
    CHECK_STR(buf, "1m05s");
    fmt_age(3725000, buf, sizeof buf);
    CHECK_STR(buf, "1h02m");

    char s[] = "  padded\t\n";
    CHECK_STR(str_trim(s), "padded");
    CHECK(str_casecmp("ABC", "abc") == 0);
    CHECK(str_icontains("Living Room TV", "room"));
    CHECK(!str_icontains("Living Room TV", "kitchen"));
    CHECK(str_icontains("anything", ""));
    CHECK(!str_icontains(NULL, "x"));
}

/* Longest-prefix match over the three OUI prefix lengths, against a hand-
 * built database (the string table is shared by all three tiers). */
static void test_oui_lookup(void)
{
    static char strtab[] = "Alpha\0Beta\0Gamma\0";
    static oui_entry_t e24[1] = { {0x010203, 0, 5} };
    static oui_entry_t e28[1] = { {0x01020300, 6, 4} };
    static oui_entry_t e36[1] = { {0x0102030400, 11, 5} };
    oui_db_t db = { .e24 = e24, .n24 = 1,
                    .e28 = e28, .n28 = 1,
                    .e36 = e36, .n36 = 1,
                    .strtab = strtab, .strtab_size = (uint32_t)(sizeof strtab - 1) };
    uint8_t m36[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
    uint8_t m28[] = { 0x01, 0x02, 0x03, 0x00, 0x05, 0x06 };
    uint8_t m24[] = { 0x01, 0x02, 0x03, 0x99, 0x00, 0x00 };
    uint8_t m0[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    CHECK_STR(oui_lookup_bytes(&db, m36, 6), "Gamma"); /* 36-bit wins */
    CHECK_STR(oui_lookup_bytes(&db, m28, 6), "Beta");  /* 28-bit */
    CHECK_STR(oui_lookup_bytes(&db, m24, 6), "Alpha"); /* 24-bit */
    CHECK(oui_lookup_bytes(&db, m0, 6) == NULL);
    CHECK(oui_lookup_bytes(NULL, m36, 6) == NULL);
    CHECK(oui_lookup_bytes(&db, (uint8_t[]){ 0x01, 0x02 }, 2) == NULL);
}

/* A minimal oui.bin built by hand, loaded through the public API and looked
 * up via the MAC-string helper (which parses the string and chooses the tier). */
static void test_oui_load(void)
{
    static const uint8_t file[] = {
        /* header: magic, ver, n24, n28, n36, strtab_size, strtab_off, pad */
        0x4f, 0x55, 0x49, 0x31,  /* "OUI1" */
        0x01, 0x00, 0x00, 0x00,  /* ver 1 */
        0x01, 0x00, 0x00, 0x00,  /* n24 */
        0x01, 0x00, 0x00, 0x00,  /* n28 */
        0x01, 0x00, 0x00, 0x00,  /* n36 */
        0x11, 0x00, 0x00, 0x00,  /* strtab_size = 17 */
        0x50, 0x00, 0x00, 0x00,  /* strtab_off  = 80 */
        0x00, 0x00, 0x00, 0x00,
        /* e24 key=0x010203  off=0  len=5 */
        0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00,
        /* e28 key=0x01020300  off=6  len=4 */
        0x00, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x06, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00,
        /* e36 key=0x0102030400  off=11  len=5 */
        0x00, 0x04, 0x03, 0x02, 0x01, 0x00, 0x00, 0x00,
        0x0b, 0x00, 0x00, 0x00,
        0x05, 0x00, 0x00, 0x00,
        /* strtab: Alpha\0Beta\0Gamma\0 */
        'A', 'l', 'p', 'h', 'a', 0,
        'B', 'e', 't', 'a', 0,
        'G', 'a', 'm', 'm', 'a', 0
    };
    const char *path = "/tmp/mdnscli_oui_test.bin";
    FILE *f = fopen(path, "wb");
    CHECK(f != NULL);
    if (f) {
        size_t n = fwrite(file, 1, sizeof file, f);
        CHECK(n == sizeof file);
        fclose(f);
    }
    CHECK(oui_load(path));
    CHECK(oui_loaded());
    CHECK_STR(oui_vendor_str("01:02:03:04:05:06"), "Gamma"); /* 36-bit */
    CHECK_STR(oui_vendor_str("01:02:03:00:05:06"), "Beta");  /* 28-bit */
    CHECK_STR(oui_vendor_str("01:02:03:99:00:00"), "Alpha"); /* 24-bit */
    CHECK(oui_vendor_str("ff:ff:ff:ff:ff:ff") == NULL); /* unknown */
    CHECK(oui_vendor_str("01:02") == NULL);             /* too short */
    oui_free();
    unlink(path);
}

int main(void)
{
    test_addr();
    test_merge();
    test_label_fallbacks();
    test_binary_txt();
    test_ping_counters();
    test_ping_grades();
    test_neigh();
    test_xml();
    test_http_bad_urls();
    test_util();
    test_oui_lookup();
    test_oui_load();
    if (failures)
        printf("%d check(s) failed\n", failures);
    else
        printf("all store/xml/http checks passed\n");
    return failures ? 1 : 0;
}
