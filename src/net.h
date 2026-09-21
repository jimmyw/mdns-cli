/* Interface enumeration and multicast socket plumbing. */
#ifndef MDNS_CLI_NET_H
#define MDNS_CLI_NET_H

#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MAX_IFACES 32

#define MDNS_PORT 5353
#define MDNS_GROUP4 "224.0.0.251"
#define MDNS_GROUP6 "ff02::fb"
#define SSDP_PORT 1900
#define SSDP_GROUP4 "239.255.255.250"
#define SSDP_GROUP6 "ff02::c"

typedef struct {
    char name[IF_NAMESIZE];
    unsigned index;
    bool loopback;
    bool has_v4;
    bool has_v6;
    struct in_addr v4;
    struct in6_addr v6; /* link-local preferred: that is what mDNS uses */
} iface_t;

/* Enumerate usable interfaces. When nfilter > 0 only the named ones are kept.
   Returns the number written, or -1 on error (errno set). */
ssize_t net_enum_ifaces(iface_t *out, size_t max, bool include_loopback, char *const *filter,
                        size_t nfilter);

/* Open a multicast socket bound to bind_port and joined to group on every
   interface in ifs. join=false skips membership (used for the M-SEARCH socket,
   which only needs to receive unicast replies on an ephemeral port).
   Returns the fd, or -1. */
int net_open_v4(uint16_t bind_port, const char *group, const iface_t *ifs, size_t n, bool join);
int net_open_v6(uint16_t bind_port, const char *group, const iface_t *ifs, size_t n, bool join);

/* Send one datagram out a specific interface. Returns bytes sent, or -1. */
ssize_t net_send_v4(int fd, const iface_t *ifc, const void *buf, size_t len, const char *group,
                    uint16_t port);
ssize_t net_send_v6(int fd, const iface_t *ifc, const void *buf, size_t len, const char *group,
                    uint16_t port);

#endif /* MDNS_CLI_NET_H */
