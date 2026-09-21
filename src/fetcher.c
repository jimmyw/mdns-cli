#include "fetcher.h"

#include "http.h"
#include "util.h"
#include "xmlmini.h"

#include <stdlib.h>
#include <string.h>

#define FETCH_TIMEOUT_MS 6000u
#define MAX_BODY (256u * 1024u)

typedef struct {
    http_req_t *req;
    char *usn;
    size_t slot; /* index into the pollfd array handed out this round */
    bool polled;
} job_t;

struct fetcher {
    store_t *store;
    job_t *jobs;
    size_t njobs, capjobs, max_inflight;
    char **queue; /* USNs waiting for a free slot */
    size_t nqueue, capqueue;
};

fetcher_t *fetcher_new(store_t *store, size_t max_inflight)
{
    fetcher_t *f = xcalloc(1, sizeof *f);
    f->store = store;
    f->max_inflight = max_inflight ? max_inflight : 1;
    return f;
}

void fetcher_destroy(fetcher_t *f)
{
    if (!f)
        return;
    for (size_t i = 0; i < f->njobs; i++) {
        http_free(f->jobs[i].req);
        free(f->jobs[i].usn);
    }
    free(f->jobs);
    for (size_t i = 0; i < f->nqueue; i++)
        free(f->queue[i]);
    free(f->queue);
    free(f);
}

size_t fetcher_inflight(const fetcher_t *f)
{
    return f->njobs;
}

static bool usn_active(const fetcher_t *f, const char *usn)
{
    for (size_t i = 0; i < f->njobs; i++)
        if (strcmp(f->jobs[i].usn, usn) == 0)
            return true;
    for (size_t i = 0; i < f->nqueue; i++)
        if (strcmp(f->queue[i], usn) == 0)
            return true;
    return false;
}

static void start_job(fetcher_t *f, const char *usn)
{
    device_t *owner = NULL;
    ssdp_entry_t *e = store_find_ssdp(f->store, usn, &owner);
    if (!e || !e->location || !*e->location)
        return;

    const char *override = owner ? device_primary_addr(owner) : NULL;
    http_req_t *req = http_get(e->location, override, MAX_BODY, FETCH_TIMEOUT_MS, NULL);
    if (f->njobs == f->capjobs) {
        f->capjobs = f->capjobs ? f->capjobs * 2 : 8;
        f->jobs = xrealloc(f->jobs, f->capjobs * sizeof *f->jobs);
    }
    job_t *j = &f->jobs[f->njobs++];
    j->req = req;
    j->usn = xstrdup(usn);
    j->slot = 0;
    j->polled = false;
    e->fetch = FETCH_RUNNING;
    str_set(&e->fetch_error, NULL);
    store_touch(f->store);
    log_msg("fetch start %s", e->location);
}

void fetcher_request(fetcher_t *f, const ssdp_entry_t *e)
{
    if (!e || !e->usn || !*e->usn)
        return;
    if (!e->location || !*e->location)
        return;
    if (e->fetch == FETCH_RUNNING || e->fetch == FETCH_DONE)
        return;
    if (usn_active(f, e->usn))
        return;

    if (f->njobs < f->max_inflight) {
        start_job(f, e->usn);
        return;
    }
    if (f->nqueue == f->capqueue) {
        f->capqueue = f->capqueue ? f->capqueue * 2 : 8;
        f->queue = xrealloc(f->queue, f->capqueue * sizeof *f->queue);
    }
    f->queue[f->nqueue++] = xstrdup(e->usn);
}

size_t fetcher_pollfds(fetcher_t *f, struct pollfd *out, size_t max)
{
    size_t n = 0;
    for (size_t i = 0; i < f->njobs; i++) {
        job_t *j = &f->jobs[i];
        int fd = http_fd(j->req);
        short ev = http_poll_events(j->req);
        j->polled = false;
        if (fd < 0 || ev == 0 || n >= max)
            continue;
        out[n].fd = fd;
        out[n].events = ev;
        out[n].revents = 0;
        j->slot = n;
        j->polled = true;
        n++;
    }
    return n;
}

static void apply_result(fetcher_t *f, job_t *j, int rc)
{
    device_t *owner = NULL;
    ssdp_entry_t *e = store_find_ssdp(f->store, j->usn, &owner);
    if (!e) {
        log_msg("fetch result for vanished entry %s", j->usn);
        return;
    }
    if (rc < 0) {
        e->fetch = FETCH_FAILED;
        str_set(&e->fetch_error, http_error(j->req));
        log_msg("fetch failed %s: %s", j->usn, http_error(j->req));
    } else {
        size_t len = 0;
        const char *body = http_body(j->req, &len);
        e->fetch = FETCH_DONE;
        if (body && len) {
            free(e->friendly_name);
            free(e->manufacturer);
            free(e->model_name);
            free(e->model_number);
            free(e->serial);
            free(e->udn);
            e->friendly_name = xml_tag(body, len, "friendlyName");
            e->manufacturer = xml_tag(body, len, "manufacturer");
            e->model_name = xml_tag(body, len, "modelName");
            e->model_number = xml_tag(body, len, "modelNumber");
            e->serial = xml_tag(body, len, "serialNumber");
            e->udn = xml_tag(body, len, "UDN");
        }
        log_msg("fetch ok %s (%zu bytes)", j->usn, len);
    }
    store_touch(f->store);
}

void fetcher_step(fetcher_t *f, const struct pollfd *fds, size_t n, uint64_t now)
{
    for (size_t i = 0; i < f->njobs;) {
        job_t *j = &f->jobs[i];
        short revents = (j->polled && j->slot < n) ? fds[j->slot].revents : 0;
        int rc = http_step(j->req, revents, now);
        if (rc == 0) {
            i++;
            continue;
        }
        apply_result(f, j, rc);
        http_free(j->req);
        free(j->usn);
        f->jobs[i] = f->jobs[--f->njobs];
    }

    /* Promote queued requests into the slots that just freed up. */
    while (f->nqueue && f->njobs < f->max_inflight) {
        char *usn = f->queue[0];
        memmove(f->queue, f->queue + 1, (--f->nqueue) * sizeof *f->queue);
        start_job(f, usn);
        free(usn);
    }
}

uint64_t fetcher_next_deadline(const fetcher_t *f)
{
    uint64_t best = UINT64_MAX;
    for (size_t i = 0; i < f->njobs; i++) {
        uint64_t d = http_deadline(f->jobs[i].req);
        if (d < best)
            best = d;
    }
    return best;
}
