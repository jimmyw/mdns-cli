/* mDNS / DNS-SD discovery: query scheduling and response ingestion. */
#ifndef MDNS_CLI_MDNS_H
#define MDNS_CLI_MDNS_H

#include "device.h"
#include "net.h"

#include <stdint.h>

typedef struct mdns mdns_t;

/* fd4/fd6 may be -1 when that family is disabled. */
mdns_t *mdns_new(store_t *store, const iface_t *ifs, size_t nifs, int fd4, int fd6);
void mdns_destroy(mdns_t *m);

/* Start the query ramp again from the top (the 'r' key). */
void mdns_rescan(mdns_t *m);

uint64_t mdns_next_deadline(const mdns_t *m);
void mdns_tick(mdns_t *m, uint64_t now);
void mdns_handle(mdns_t *m, const uint8_t *pkt, size_t len, const struct sockaddr_storage *from,
                 uint64_t now);

/* True while queries are still ramping (used for the UI's activity hint). */
bool mdns_scanning(const mdns_t *m);

#endif /* MDNS_CLI_MDNS_H */
