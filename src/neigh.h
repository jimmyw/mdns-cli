/* Hardware addresses, read from the kernel's neighbour table.
 *
 * The MAC is not in any mDNS or SSDP payload: it comes from ARP/NDP, which the
 * kernel already keeps for every host this machine has exchanged a packet
 * with. Discovery traffic and a ping are both enough to populate it.
 */
#ifndef MDNS_CLI_NEIGH_H
#define MDNS_CLI_NEIGH_H

#include "device.h"

typedef struct neigh_cache neigh_cache_t;

neigh_cache_t *neigh_new(void);
void neigh_destroy(neigh_cache_t *nc);

/* Re-read the table (one netlink dump, no network traffic). */
void neigh_refresh(neigh_cache_t *nc);

/* "aa:bb:cc:dd:ee:ff" for this address, or NULL if the kernel has no entry. */
const char *neigh_lookup(const neigh_cache_t *nc, const addr_t *a);

/* Fill in the MAC of every device that has one. Returns how many changed. */
size_t neigh_apply(neigh_cache_t *nc, store_t *store);

#endif /* MDNS_CLI_NEIGH_H */
