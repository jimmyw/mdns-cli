/* Manages UPnP description fetches inside the main poll loop.
 *
 * Jobs are keyed by USN rather than by pointer: a device merge or an
 * ssdp:byebye can free the entry while its fetch is still in flight, so the
 * result is matched back to whatever entry exists when it lands.
 */
#ifndef MDNS_CLI_FETCHER_H
#define MDNS_CLI_FETCHER_H

#include "device.h"

#include <poll.h>
#include <stdint.h>

typedef struct fetcher fetcher_t;

fetcher_t *fetcher_new(store_t *store, size_t max_inflight);
void fetcher_destroy(fetcher_t *f);

/* Ask for this entry's description. Ignored when it has no LOCATION, or when
   a fetch already ran or is running. */
void fetcher_request(fetcher_t *f, const ssdp_entry_t *e);

size_t fetcher_inflight(const fetcher_t *f);

/* Append one pollfd per active job. Returns how many were written. */
size_t fetcher_pollfds(fetcher_t *f, struct pollfd *out, size_t max);
/* fds must be the array fetcher_pollfds wrote into, unmoved. */
void fetcher_step(fetcher_t *f, const struct pollfd *fds, size_t n, uint64_t now);
uint64_t fetcher_next_deadline(const fetcher_t *f);

#endif /* MDNS_CLI_FETCHER_H */
