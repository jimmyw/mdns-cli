/* ICMP echo, in-process and inside the main poll loop.
 *
 * Linux and macOS both hand out unprivileged ICMP datagram sockets (Linux
 * gates this on net.ipv4.ping_group_range; macOS allows it unconditionally),
 * so no root, no capabilities and no ping(8) subprocess: the echo requests
 * are built and matched here, and the counters land on the device entry.
 */
#ifndef MDNS_CLI_PING_H
#define MDNS_CLI_PING_H

#include "device.h"

#include <poll.h>
#include <stdint.h>

typedef struct pinger pinger_t;

pinger_t *pinger_new(store_t *store);
void pinger_destroy(pinger_t *p);

/* Start pinging this device, or stop it if it is already running. want picks
   the address to probe; NULL means the one the list shows. Asking for a
   different address than the run in progress retargets it rather than
   stopping. Returns NULL on success, or a short reason it could not start
   (which is also recorded on the device). */
const char *pinger_toggle(pinger_t *p, device_t *d, const addr_t *want);
void pinger_stop_all(pinger_t *p);
size_t pinger_active(const pinger_t *p);

size_t pinger_pollfds(pinger_t *p, struct pollfd *out, size_t max);
void pinger_step(pinger_t *p, const struct pollfd *fds, size_t n, uint64_t now);
uint64_t pinger_next_deadline(const pinger_t *p);

#endif /* MDNS_CLI_PING_H */
