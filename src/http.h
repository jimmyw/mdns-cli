/* A one-shot, non-blocking HTTP/1.1 GET.
 *
 * It exists so the UPnP description fetch can live inside the program's single
 * poll() loop: no threads, no blocking, and the UI keeps redrawing while a
 * device takes its time (or never answers at all).
 */
#ifndef MDNS_CLI_HTTP_H
#define MDNS_CLI_HTTP_H

#include <poll.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct http_req http_req_t;

/* url must be http:// (no TLS). When the URL host is not a literal address,
   override_ip is connected to instead, with the original Host: preserved.
   user is an opaque tag returned by http_user(). Never returns NULL: a bad URL
   produces a request that immediately reports failure. */
http_req_t *http_get(const char *url, const char *override_ip, size_t max_body,
                     uint64_t timeout_ms, void *user);

int http_fd(const http_req_t *r);
short http_poll_events(const http_req_t *r);
uint64_t http_deadline(const http_req_t *r);
void *http_user(const http_req_t *r);

/* Advance the state machine. Returns 0 while in progress, 1 when the body is
   complete, -1 on failure (see http_error). Call with revents=0 to let the
   timeout fire. */
int http_step(http_req_t *r, short revents, uint64_t now);

const char *http_body(const http_req_t *r, size_t *len);
const char *http_error(const http_req_t *r);
void http_free(http_req_t *r);

#endif /* MDNS_CLI_HTTP_H */
