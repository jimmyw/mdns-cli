/* The device store: one entry per physical device, not per service.
 *
 * mDNS and SSDP see the same box from two angles, so entries are merged on any
 * shared IP address, falling back to the mDNS hostname. Services discovered
 * before their A record resolves live on a hostname-only device and are folded
 * into the addressed one as soon as the address arrives.
 */
#ifndef MDNS_CLI_DEVICE_H
#define MDNS_CLI_DEVICE_H

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_ADDRS 8
#define ADDR_STRLEN (INET6_ADDRSTRLEN + IF_NAMESIZE + 2)
#define MAC_STRLEN 18 /* aa:bb:cc:dd:ee:ff */

#define SRC_MDNS 0x1u
#define SRC_SSDP 0x2u

typedef struct {
    int family; /* AF_INET or AF_INET6 */
    unsigned scope_id;
    union {
        struct in_addr v4;
        struct in6_addr v6;
    } a;
    char str[ADDR_STRLEN];
} addr_t;

bool addr_from_v4(addr_t *out, const uint8_t b[4]);
bool addr_from_v6(addr_t *out, const uint8_t b[16], unsigned scope_id);
bool addr_from_sockaddr(addr_t *out, const struct sockaddr_storage *ss);
bool addr_equal(const addr_t *a, const addr_t *b);

typedef struct txt_pair {
    struct txt_pair *next;
    char *key;
    char *val; /* NULL for a bare boolean key */
} txt_pair_t;

typedef struct service {
    struct service *next;
    char *fqdn;     /* full instance name, escaped presentation form */
    char *instance; /* first label, unescaped for display */
    char *type;     /* "_ipp._tcp" */
    char *host;     /* SRV target */
    uint16_t port;
    bool have_srv;
    txt_pair_t *txt;
    size_t n_txt;
    uint64_t last_seen;
    uint32_t ttl;
    bool expanded;
} service_t;

typedef enum {
    FETCH_NONE = 0,
    FETCH_RUNNING,
    FETCH_DONE,
    FETCH_FAILED,
} fetch_state_t;

typedef struct ssdp_entry {
    struct ssdp_entry *next;
    char *usn;
    char *st;
    char *server;
    char *location;
    uint64_t last_seen;
    uint32_t max_age;
    bool expanded;
    /* Filled in by the description fetch (http.c + xmlmini.c). */
    fetch_state_t fetch;
    char *fetch_error;
    char *friendly_name;
    char *manufacturer;
    char *model_name;
    char *model_number;
    char *serial;
    char *udn;
} ssdp_entry_t;

/* Running ping counters, kept on the device entry so they survive folding,
   sorting and re-merging. The accounting is pure (see ping_record_*), the
   sockets live in ping.c. */
typedef struct {
    bool active; /* a ping run is sending right now */
    char target[ADDR_STRLEN];
    unsigned sent;
    unsigned recv;
    unsigned lost; /* probes that passed their timeout with no reply */
    double last_ms;
    double min_ms;
    double max_ms;
    double total_ms; /* sum of replies, for the average */
    uint64_t started;
    char *error; /* why pinging could not start or had to stop */
} ping_t;

/* How healthy a ping looks, for anything that wants to say so in colour. */
typedef enum {
    PING_GRADE_NONE = 0, /* nothing has resolved yet: no verdict */
    PING_GRADE_GOOD,
    PING_GRADE_WARN,
    PING_GRADE_BAD,
} ping_grade_t;

#define PING_LOSS_BAD_PCT 50.0 /* any loss below this is a warning */
#define PING_RTT_WARN_MS 20.0
#define PING_RTT_BAD_MS 150.0

ping_grade_t ping_loss_grade(const ping_t *p);
ping_grade_t ping_rtt_grade(const ping_t *p);
/* The worse of the two, for a single at-a-glance verdict. */
ping_grade_t ping_grade(const ping_t *p);

void ping_reset(ping_t *p);
void ping_record_reply(ping_t *p, double rtt_ms);
void ping_record_loss(ping_t *p);
/* Loss over resolved probes only: still-outstanding ones are not yet lost.
   Returns -1 when nothing has resolved. */
double ping_loss_pct(const ping_t *p);
/* Mean round trip of the replies received, or -1 when there are none. */
double ping_avg_ms(const ping_t *p);
bool ping_has_data(const ping_t *p);

typedef struct device {
    struct device *next;
    unsigned id;
    addr_t addrs[MAX_ADDRS];
    size_t n_addrs;
    char *hostname;
    char mac[MAC_STRLEN]; /* from the kernel's ARP/NDP table, "" when unknown */
    service_t *services;
    size_t n_services;
    ssdp_entry_t *ssdp;
    size_t n_ssdp;
    unsigned sources;
    uint64_t first_seen;
    uint64_t last_seen;
    bool expanded;
    ping_t ping;
} device_t;

typedef struct {
    device_t *head;
    size_t n_devices;
    unsigned next_id;
    unsigned generation; /* bumped on every mutation so the UI knows to rebuild */
} store_t;

typedef enum {
    SORT_ADDR = 0,
    SORT_NAME,
    SORT_LAST_SEEN,
    SORT_SOURCE,
    SORT__COUNT,
} sort_mode_t;

const char *sort_name(sort_mode_t m);

void store_init(store_t *s);
void store_free(store_t *s);
void store_clear(store_t *s);

device_t *store_find_id(store_t *s, unsigned id);
device_t *store_find_addr(store_t *s, const addr_t *a);
device_t *store_find_host(store_t *s, const char *host);

/* Get (or create) the device owning an address / hostname. */
device_t *store_device_for_addr(store_t *s, const addr_t *a, uint64_t now, unsigned source);
device_t *store_device_for_host(store_t *s, const char *host, uint64_t now, unsigned source);

/* Attach an address to d. If another device already owns it the two are
   merged; the surviving device is returned, so callers must use the result. */
device_t *store_add_addr(store_t *s, device_t *d, const addr_t *a, uint64_t now);

/* Attach a hostname to d, merging if another device already claims it. */
device_t *store_set_host(store_t *s, device_t *d, const char *host, uint64_t now);

service_t *device_service(store_t *s, device_t *d, const char *fqdn, uint64_t now);
/* pair is one raw TXT string ("key=value" or a bare flag); len is its true
   length, since TXT values may contain NUL and other binary bytes. */
void service_set_txt(service_t *sv, const char *pair, size_t len);
void service_clear_txt(service_t *sv);

/* Locate an existing service/SSDP entry anywhere in the store. owner is
   optional and receives the device it belongs to. */
service_t *store_find_service(store_t *s, const char *fqdn, device_t **owner);
ssdp_entry_t *store_find_ssdp(store_t *s, const char *usn, device_t **owner);
/* The device announcing this UPnP UUID ("uuid:1234-..."), whatever address
   family it was heard on. A dual-stack device answers M-SEARCH twice, from
   two addresses that share nothing but this. */
device_t *store_find_udn(store_t *s, const char *uuid);
void device_drop_service(store_t *s, device_t *d, const char *fqdn);

ssdp_entry_t *device_ssdp(store_t *s, device_t *d, const char *usn, const char *st, uint64_t now);
void device_drop_ssdp(store_t *s, device_t *d, const char *usn);

/* Drop devices not seen for drop_ms. */
void store_expire(store_t *s, uint64_t now, uint64_t drop_ms);

size_t store_total_services(const store_t *s);
const char *device_label(const device_t *d);
const char *device_primary_addr(const device_t *d);
void device_sources_str(const device_t *d, char *out, size_t outsz);

/* Flat array of matching devices in sort order. Caller frees the array (not
   the devices). filter may be NULL. */
device_t **store_snapshot(store_t *s, sort_mode_t mode, const char *filter, size_t *count);
bool device_matches(const device_t *d, const char *filter);

void store_touch(store_t *s);

#endif /* MDNS_CLI_DEVICE_H */
