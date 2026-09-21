/* SSDP / UPnP discovery: M-SEARCH bursts plus passive NOTIFY listening. */
#ifndef MDNS_CLI_SSDP_H
#define MDNS_CLI_SSDP_H

#include "device.h"
#include "net.h"

#include <stdint.h>

typedef struct ssdp ssdp_t;

/* Any fd may be -1 (that family or role is simply not used). */
ssdp_t *ssdp_new(store_t *store, const iface_t *ifs, size_t nifs, int search4, int search6);
void ssdp_destroy(ssdp_t *s);

/* Restart the burst schedule (the 'r' key). */
void ssdp_rescan(ssdp_t *s);

/* When the next M-SEARCH is due, in monotonic ms. */
uint64_t ssdp_next_deadline(const ssdp_t *s);
void ssdp_tick(ssdp_t *s, uint64_t now);

/* Feed one received datagram (search reply or NOTIFY). */
void ssdp_handle(ssdp_t *s, const char *pkt, size_t len, const struct sockaddr_storage *from,
                 uint64_t now);

/* True while the initial burst schedule is still running. */
bool ssdp_scanning(const ssdp_t *s);

#endif /* MDNS_CLI_SSDP_H */
