#include "ui.h"

#include "clip.h"
#include "oui.h"
#include "util.h"

#include <ctype.h>
#include <locale.h>
#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STALE_MS 120000u
#define COPIED_SHOW_MS 4000u
#define KEYLEN 320
#define TEXTLEN 768

/* Selected rows get a background colour rather than reverse video: reversing
   a line that is already several colours turns it into a rainbow bar. Each
   pair therefore has a selected twin at cp + CP_SEL.
 *
 * The background is a neutral dark grey, not a hue: green, yellow, red and
 * cyan all have to stay legible on top of it, and blue in particular left the
 * green tags muddy. Terminals with fewer than 16 colours have no grey to use,
 * so those fall back to plain reverse video. */
#define CP_SEL 16
#define SEL_BG_256 236 /* a fixed dark grey, independent of the theme */
#define SEL_BG_16 8    /* "bright black" */

enum {
    CP_HEADER = 1, /* the title bar */
    CP_LABEL,      /* the key half of a key/value row */
    CP_MDNS,       /* anything sourced from mDNS */
    CP_SSDP,       /* anything sourced from SSDP */
    CP_DIM,        /* de-emphasised text */
    CP_STALE,      /* a device that has gone quiet */
    CP_ADDR,       /* IP addresses */
    CP_NAME,       /* the name a human would call the device */
    CP_PORT,       /* port numbers */
    CP_OK,         /* healthy: no loss, low round trip */
    CP_WARN,       /* degraded: some loss, or a slow round trip */
    CP_BAD,        /* broken: heavy loss, no reply, an error */
    CP_KEY,        /* the key letters in the footer */
};

typedef enum {
    ROW_DEVICE,
    ROW_KV,
    ROW_SERVICE,
    ROW_TXT,
    ROW_SSDP,
} row_kind_t;

typedef struct {
    int addrw; /* widths recomputed on every rebuild, from the data on screen */
    int namew;
    int stw;
} cols_t;

/* A coloured run of bytes within a row's text. Spans are built in order and
   never overlap, so drawing is one walk from left to right. */
#define MAX_SPANS 6
typedef struct {
    int off;
    int len;
    int cp;
    attr_t attr;
} span_t;

/* A value on the row that c can copy. Several rows carry more than one (a
   device with two addresses, say), and right/left step between them. */
#define MAX_TARGETS 8
typedef struct {
    int off; /* where it sits in the row text, for the highlight */
    int len;
    char *value;  /* what actually gets copied; NULL means the text itself */
    bool is_addr; /* an address, so p can ping this one specifically */
    addr_t addr;
} target_t;

typedef struct {
    row_kind_t kind;
    int indent;
    const char *marker; /* fold glyph, or NULL */
    char key[KEYLEN];   /* stable identity, survives a rebuild */
    char text[TEXTLEN];
    int voff; /* where the value half of a key/value row starts */
    span_t spans[MAX_SPANS];
    int nspans;
    target_t targets[MAX_TARGETS];
    int ntargets;
    unsigned dev_id;
    service_t *sv;
    ssdp_entry_t *e;
    bool stale;
    int tag; /* color pair for the fold glyph, 0 for none */
} row_t;

struct ui {
    store_t *store;
    ui_hooks_t hooks;

    row_t *rows;
    size_t nrows, caprows;
    size_t ndevices_shown;
    unsigned built_gen;
    int built_cols;
    bool dirty;

    size_t sel;
    char sel_key[KEYLEN];
    size_t top;
    int sel_target; /* which value on the selected row is picked, -1 for none */
    char copied[160];
    uint64_t copied_at;

    sort_mode_t sort;
    char filter[128];
    bool filter_editing;
    bool show_help;
    bool has_color;
    bool sel_bg; /* false when the terminal has no grey to select with */
    uint64_t now;
};

/* ------------------------------------------------------------------ rows */

static void free_targets(ui_t *u)
{
    for (size_t i = 0; i < u->nrows; i++)
        for (int k = 0; k < u->rows[i].ntargets; k++)
            free(u->rows[i].targets[k].value);
}

static row_t *row_add(ui_t *u)
{
    if (u->nrows == u->caprows) {
        u->caprows = u->caprows ? u->caprows * 2 : 64;
        u->rows = xrealloc(u->rows, u->caprows * sizeof *u->rows);
    }
    row_t *r = &u->rows[u->nrows++];
    memset(r, 0, sizeof *r);
    return r;
}

static target_t *add_target(row_t *r, int off, int len, const char *value)
{
    if (r->ntargets >= MAX_TARGETS || len <= 0)
        return NULL;
    target_t *t = &r->targets[r->ntargets++];
    memset(t, 0, sizeof *t);
    t->off = off;
    t->len = len;
    t->value = value ? xstrdup(value) : NULL;
    return t;
}

static void target_set_addr(target_t *t, const addr_t *a)
{
    if (!t)
        return;
    t->is_addr = true;
    t->addr = *a;
}

/* The text a target copies: its own value, or the slice it highlights. */
static void target_value(const row_t *r, int idx, char *out, size_t outsz)
{
    out[0] = '\0';
    if (idx < 0 || idx >= r->ntargets)
        return;
    const target_t *t = &r->targets[idx];
    if (t->value) {
        snprintf(out, outsz, "%s", t->value);
        return;
    }
    int len = t->len;
    if ((size_t)len >= outsz)
        len = (int)outsz - 1;
    memcpy(out, r->text + t->off, (size_t)len);
    out[len] = '\0';
    str_trim(out);
}

static void add_span(row_t *r, int off, int len, int cp, attr_t attr)
{
    if (r->nspans >= MAX_SPANS || len <= 0 || (!cp && !attr))
        return;
    r->spans[r->nspans].off = off;
    r->spans[r->nspans].len = len;
    r->spans[r->nspans].cp = cp;
    r->spans[r->nspans].attr = attr;
    r->nspans++;
}

/* Append to a row's text, returning the new offset. Truncation is clamped so
   span offsets can never point past the end of the string. */
static int appendf(row_t *r, int off, const char *fmt, ...) __attribute__((format(printf, 3, 4)));

static int appendf(row_t *r, int off, const char *fmt, ...)
{
    if (off < 0 || (size_t)off >= sizeof r->text - 1)
        return off;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(r->text + off, sizeof r->text - (size_t)off, fmt, ap);
    va_end(ap);
    if (n < 0)
        return off;
    off += n;
    return (size_t)off >= sizeof r->text ? (int)sizeof r->text - 1 : off;
}

static void kv_row(ui_t *u, unsigned dev_id, int indent, const char *key_id, const char *label,
                   const char *fmt, ...) __attribute__((format(printf, 6, 7)));

static void kv_row(ui_t *u, unsigned dev_id, int indent, const char *key_id, const char *label,
                   const char *fmt, ...)
{
    row_t *r = row_add(u);
    r->kind = ROW_KV;
    r->indent = indent;
    r->dev_id = dev_id;
    snprintf(r->key, sizeof r->key, "d:%u/%s", dev_id, key_id);
    int n = snprintf(r->text, sizeof r->text, "%-13s ", label);
    r->voff = n > 0 ? n : 0;
    add_span(r, 0, r->voff, CP_LABEL, 0);
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->text + r->voff, sizeof r->text - (size_t)r->voff, fmt, ap);
    va_end(ap);
    add_target(r, r->voff, (int)strlen(r->text) - r->voff, NULL);
}

/* A key/value row the caller fills in itself, so it can register a target per
   value instead of one covering the whole line. */
static row_t *kv_open(ui_t *u, unsigned dev_id, int indent, const char *key_id, const char *label)
{
    row_t *r = row_add(u);
    r->kind = ROW_KV;
    r->indent = indent;
    r->dev_id = dev_id;
    snprintf(r->key, sizeof r->key, "d:%u/%s", dev_id, key_id);
    int n = snprintf(r->text, sizeof r->text, "%-13s ", label);
    r->voff = n > 0 ? n : 0;
    add_span(r, 0, r->voff, CP_LABEL, 0);
    return r;
}

/* Colour the value half of the key/value row just added. */
static void kv_value_color(ui_t *u, int cp, attr_t attr)
{
    row_t *r = &u->rows[u->nrows - 1];
    add_span(r, r->voff, (int)strlen(r->text) - r->voff, cp, attr);
}

static const char *short_st(const char *st)
{
    /* "urn:schemas-upnp-org:device:MediaRenderer:1" reads better as
       "device:MediaRenderer:1"; vendor URNs get the same treatment. */
    const char *p = st;
    if (str_ncasecmp(p, "urn:", 4) == 0)
        p += 4;
    const char *colon = strchr(p, ':');
    if (colon && strstr(p, "schemas") && (size_t)(colon - p) < 40)
        p = colon + 1;
    return p;
}

static void build_service_rows(ui_t *u, device_t *d, service_t *sv, const cols_t *c)
{
    row_t *r = row_add(u);
    r->kind = ROW_SERVICE;
    r->indent = 2;
    r->dev_id = d->id;
    r->sv = sv;
    r->marker = sv->expanded ? "\xe2\x96\xbe" : "\xe2\x96\xb8";
    r->tag = CP_MDNS;
    snprintf(r->key, sizeof r->key, "d:%u/s:%s", d->id, sv->fqdn);
    char col[128];
    str_pad(col, sizeof col, sv->type, c->stw);
    int off = 0, start = 0;
    off = appendf(r, off, "%s ", col);
    add_span(r, start, off - start - 1, CP_MDNS, 0);
    off = appendf(r, off, "%s", sv->instance);
    start = off;
    if (sv->have_srv) {
        off = appendf(r, off, ":%u", sv->port);
        add_span(r, start, off - start, CP_PORT, 0);
    } else {
        off = appendf(r, off, " (resolving)");
        add_span(r, start, off - start, CP_DIM, A_DIM);
    }
    if (!sv->expanded)
        return;

    if (sv->host) {
        kv_row(u, d->id, 6, "svc-host", "host", "%s:%u", sv->host, sv->port);
        kv_value_color(u, CP_ADDR, 0);
    }
    if (sv->n_txt == 0) {
        kv_row(u, d->id, 6, "svc-notxt", "txt", "(none)");
        return;
    }
    size_t i = 0;
    for (txt_pair_t *t = sv->txt; t; t = t->next, i++) {
        row_t *tr = row_add(u);
        tr->kind = ROW_TXT;
        tr->indent = 6;
        tr->dev_id = d->id;
        tr->sv = sv;
        snprintf(tr->key, sizeof tr->key, "d:%u/s:%s/t:%zu", d->id, sv->fqdn, i);
        int toff = appendf(tr, 0, "%s", t->key);
        add_span(tr, 0, toff, CP_LABEL, 0);
        if (t->val)
            appendf(tr, toff, " = %s", t->val);
    }
}

static void build_ssdp_rows(ui_t *u, device_t *d, ssdp_entry_t *e, const cols_t *c)
{
    row_t *r = row_add(u);
    r->kind = ROW_SSDP;
    r->indent = 2;
    r->dev_id = d->id;
    r->e = e;
    r->marker = e->expanded ? "\xe2\x96\xbe" : "\xe2\x96\xb8";
    r->tag = CP_SSDP;
    snprintf(r->key, sizeof r->key, "d:%u/x:%s", d->id, e->usn ? e->usn : e->st);
    const char *title = e->friendly_name    ? e->friendly_name
                        : (e->server && *e->server) ? e->server
                                                    : "";
    char col[128];
    str_pad(col, sizeof col, short_st(e->st ? e->st : "?"), c->stw);
    int off = appendf(r, 0, "%s ", col);
    add_span(r, 0, off - 1, CP_SSDP, 0);
    int start = off;
    off = appendf(r, off, "%s", title);
    /* A fetched friendlyName is the device's own name; a SERVER string is
       just what the stack calls itself, so it stays quiet. */
    add_span(r, start, off - start, e->friendly_name ? CP_NAME : CP_DIM,
             e->friendly_name ? A_BOLD : A_DIM);
    if (!e->expanded)
        return;

    if (e->usn && *e->usn)
        kv_row(u, d->id, 6, "usn", "usn", "%s", e->usn);
    if (e->server && *e->server)
        kv_row(u, d->id, 6, "server", "server", "%s", e->server);
    if (e->location && *e->location) {
        kv_row(u, d->id, 6, "location", "location", "%s", e->location);
        kv_value_color(u, CP_ADDR, 0);
    }
    switch (e->fetch) {
    case FETCH_NONE:
        if (e->location && *e->location) {
            kv_row(u, d->id, 6, "desc", "description", "queued");
            kv_value_color(u, CP_DIM, A_DIM);
        }
        break;
    case FETCH_RUNNING:
        kv_row(u, d->id, 6, "desc", "description", "fetching...");
        kv_value_color(u, CP_WARN, 0);
        break;
    case FETCH_FAILED:
        kv_row(u, d->id, 6, "desc", "description", "unavailable (%s)",
               e->fetch_error ? e->fetch_error : "error");
        kv_value_color(u, CP_BAD, 0);
        break;
    case FETCH_DONE:
        if (e->friendly_name) {
            kv_row(u, d->id, 6, "fname", "friendlyName", "%s", e->friendly_name);
            kv_value_color(u, CP_NAME, A_BOLD);
        }
        if (e->manufacturer)
            kv_row(u, d->id, 6, "manu", "manufacturer", "%s", e->manufacturer);
        if (e->model_name || e->model_number)
            kv_row(u, d->id, 6, "model", "model", "%s %s", e->model_name ? e->model_name : "",
                   e->model_number ? e->model_number : "");
        if (e->serial)
            kv_row(u, d->id, 6, "serial", "serial", "%s", e->serial);
        if (e->udn)
            kv_row(u, d->id, 6, "udn", "udn", "%s", e->udn);
        if (!e->friendly_name && !e->manufacturer && !e->model_name)
            kv_row(u, d->id, 6, "desc", "description", "(no recognisable fields)");
        break;
    }
}

/* Green while the device answers cleanly, yellow once it starts dropping
   packets or answering slowly, red when it has effectively stopped replying.
   The thresholds live with the counters in device.c; this only paints them. */
static int grade_color(ping_grade_t g)
{
    switch (g) {
    case PING_GRADE_GOOD:
        return CP_OK;
    case PING_GRADE_WARN:
        return CP_WARN;
    case PING_GRADE_BAD:
        return CP_BAD;
    default:
        return 0;
    }
}

/* The ping counters live on the device entry, so they stay on screen after a
   run is stopped and are there to compare against the next one. */
static void build_ping_rows(ui_t *u, device_t *d)
{
    const ping_t *pg = &d->ping;
    if (!ping_has_data(pg) && !pg->active) {
        kv_row(u, d->id, 4, "ping", "ping", "not pinged yet - press p");
        kv_value_color(u, CP_DIM, A_DIM);
        return;
    }
    if (pg->error && pg->sent == 0) {
        kv_row(u, d->id, 4, "ping", "ping", "%s", pg->error);
        kv_value_color(u, CP_BAD, 0);
        return;
    }

    double loss = ping_loss_pct(pg);
    unsigned pending = pg->sent - pg->recv - pg->lost;
    char extra[64] = "";
    if (pending)
        snprintf(extra, sizeof extra, ", %u in flight", pending);
    char lossbuf[24];
    if (loss < 0)
        snprintf(lossbuf, sizeof lossbuf, "loss n/a");
    else
        snprintf(lossbuf, sizeof lossbuf, "%.0f%% loss", loss);
    kv_row(u, d->id, 4, "ping", "ping", "%s  %u sent, %u received, %s%s  (%s)", pg->target,
           pg->sent, pg->recv, lossbuf, extra, pg->active ? "running, p to stop" : "stopped");
    kv_value_color(u, grade_color(ping_loss_grade(pg)), pg->active ? A_BOLD : 0);

    if (pg->recv) {
        kv_row(u, d->id, 4, "rtt", "rtt", "last %.2f ms, min %.2f, avg %.2f, max %.2f",
               pg->last_ms, pg->min_ms, ping_avg_ms(pg), pg->max_ms);
        kv_value_color(u, grade_color(ping_rtt_grade(pg)), 0);
    } else {
        kv_row(u, d->id, 4, "rtt", "rtt", "%s",
               pg->active ? "waiting for the first reply" : "no reply");
        kv_value_color(u, pg->active ? CP_WARN : CP_BAD, 0);
    }
    if (pg->error && pg->sent) {
        kv_row(u, d->id, 4, "pingerr", "ping error", "%s", pg->error);
        kv_value_color(u, CP_BAD, 0);
    }
}

static void build_device_rows(ui_t *u, device_t *d, const cols_t *c)
{
    row_t *r = row_add(u);
    r->kind = ROW_DEVICE;
    r->indent = 0;
    r->dev_id = d->id;
    r->marker = d->expanded ? "\xe2\x96\xbe" : "\xe2\x96\xb8";
    bool stale = (u->now - d->last_seen) > STALE_MS;
    r->stale = stale;
    r->tag = stale ? CP_STALE : CP_HEADER;
    snprintf(r->key, sizeof r->key, "d:%u", d->id);
    /* Adding rows below can move the array, so nothing may dereference r
       after the first kv_row call. */

    char src[16];
    device_sources_str(d, src, sizeof src);
    char acol[ADDR_STRLEN], fitted[ADDR_STRLEN], ncol[256];
    str_fit_addr(fitted, sizeof fitted, device_primary_addr(d), c->addrw);
    str_pad(acol, sizeof acol, fitted, c->addrw);
    str_pad(ncol, sizeof ncol, device_label(d), c->namew);

    /* Offsets are taken as the text is appended, so a multi-byte name cannot
       shift the colouring of everything after it. */
    int off = 0, start;
    start = off;
    off = appendf(r, off, "%s ", acol);
    add_span(r, start, off - start - 1, d->n_addrs ? CP_ADDR : CP_DIM, 0);
    if (d->n_addrs) {
        /* The column may show a shortened address, so copy the real one. */
        target_t *t = add_target(r, start, (int)strlen(fitted), device_primary_addr(d));
        for (size_t i = 0; i < d->n_addrs; i++)
            if (strcmp(d->addrs[i].str, device_primary_addr(d)) == 0)
                target_set_addr(t, &d->addrs[i]);
    }

    start = off;
    off = appendf(r, off, "%s ", ncol);
    add_span(r, start, off - start - 1, CP_NAME, A_BOLD);
    add_target(r, start, (int)strlen(device_label(d)), device_label(d));
    /* No MAC target here: it would share the name's screen range and look
       like the cursor had not moved. It has a row of its own once expanded. */

    start = off;
    off = appendf(r, off, "%-9.9s ", src);
    int srccp = d->sources == SRC_MDNS ? CP_MDNS : (d->sources == SRC_SSDP ? CP_SSDP : CP_HEADER);
    add_span(r, start, off - start - 1, srccp, 0);

    size_t n = d->n_services + d->n_ssdp;
    off = appendf(r, off, "%zu service%s", n, n == 1 ? "" : "s");

    if (ping_has_data(&d->ping)) {
        /* The whole point of the counters is to be readable while folded. */
        double loss = ping_loss_pct(&d->ping);
        start = off;
        if (d->ping.recv)
            off = appendf(r, off, "   ping %.2fms %.0f%%", d->ping.last_ms, loss < 0 ? 0 : loss);
        else
            off = appendf(r, off, "   ping no reply");
        add_span(r, start, off - start, grade_color(ping_grade(&d->ping)),
                 d->ping.active ? A_BOLD : 0);
    }
    if (!d->expanded)
        return;

    if (d->n_addrs) {
        /* Each address is its own copy target, so right/left can pick one. */
        row_t *ar = kv_open(u, d->id, 4, "addrs", "addresses");
        int aoff = ar->voff;
        for (size_t i = 0; i < d->n_addrs; i++) {
            if (i)
                aoff = appendf(ar, aoff, ", ");
            int astart = aoff;
            aoff = appendf(ar, aoff, "%s", d->addrs[i].str);
            add_span(ar, astart, aoff - astart, CP_ADDR, 0);
            target_set_addr(add_target(ar, astart, aoff - astart, NULL), &d->addrs[i]);
        }
    } else {
        kv_row(u, d->id, 4, "addrs", "addresses", "(none yet)");
        kv_value_color(u, CP_DIM, A_DIM);
    }
    if (d->mac[0]) {
        kv_row(u, d->id, 4, "mac", "mac", "%s", d->mac);
        kv_value_color(u, CP_PORT, 0);
        if (oui_loaded()) {
            const char *vendor = oui_vendor_str(d->mac);
            kv_row(u, d->id, 4, "vendor", "vendor", "%s", vendor ? vendor : "(unknown)");
            kv_value_color(u, CP_NAME, 0);
        }
    }
    if (d->hostname) {
        kv_row(u, d->id, 4, "host", "hostname", "%s", d->hostname);
        kv_value_color(u, CP_NAME, 0);
    }

    char first[16], last[16], age[16];
    fmt_clock(d->first_seen, first, sizeof first);
    fmt_clock(d->last_seen, last, sizeof last);
    fmt_age(u->now - d->last_seen, age, sizeof age);
    kv_row(u, d->id, 4, "seen", "seen", "first %s, last %s (%s ago)", first, last, age);
    if (stale)
        kv_value_color(u, CP_STALE, 0);
    build_ping_rows(u, d);

    for (service_t *sv = d->services; sv; sv = sv->next)
        build_service_rows(u, d, sv, c);
    for (ssdp_entry_t *e = d->ssdp; e; e = e->next)
        build_ssdp_rows(u, d, e, c);
}

/* A row can lose values between rebuilds (a ping stops, an address goes). */
static void clamp_target(ui_t *u)
{
    if (u->sel >= u->nrows) {
        u->sel_target = -1;
        return;
    }
    if (u->sel_target >= u->rows[u->sel].ntargets)
        u->sel_target = u->rows[u->sel].ntargets - 1;
}

static void rebuild(ui_t *u, int cols)
{
    free_targets(u);
    u->nrows = 0;
    u->now = now_ms();
    size_t n = 0;
    device_t **devs = store_snapshot(u->store, u->sort, u->filter, &n);

    /* Size the columns to what is actually on screen: an IPv6-only network
       needs a much wider address column than a v4 one. */
    cols_t c = {15, 24, 24};
    for (size_t i = 0; i < n; i++) {
        int w = (int)strlen(device_primary_addr(devs[i]));
        if (w > c.addrw)
            c.addrw = w;
    }
    /* A full IPv6 address would eat half the line, so long ones get shortened
       to this width instead; the expanded view still lists them in full. */
    if (c.addrw > 21)
        c.addrw = 21;
    c.namew = cols - c.addrw - 28;
    if (c.namew > 44)
        c.namew = 44;
    if (c.namew < 12)
        c.namew = 12;
    c.stw = cols - 32 < 24 ? 24 : (cols - 32 > 32 ? 32 : cols - 32);

    for (size_t i = 0; i < n; i++)
        build_device_rows(u, devs[i], &c);
    u->ndevices_shown = n;
    free(devs);
    u->built_gen = u->store->generation;
    u->built_cols = cols;
    u->dirty = false;

    /* Re-resolve the selection so a device appearing mid-scan cannot move it. */
    if (u->sel_key[0]) {
        for (size_t i = 0; i < u->nrows; i++)
            if (strcmp(u->rows[i].key, u->sel_key) == 0) {
                u->sel = i;
                clamp_target(u);
                return;
            }
    }
    if (u->sel >= u->nrows)
        u->sel = u->nrows ? u->nrows - 1 : 0;
    if (u->nrows)
        snprintf(u->sel_key, sizeof u->sel_key, "%s", u->rows[u->sel].key);
    else
        u->sel_key[0] = '\0';
    clamp_target(u);
}

static void remember_sel(ui_t *u)
{
    if (u->sel < u->nrows)
        snprintf(u->sel_key, sizeof u->sel_key, "%s", u->rows[u->sel].key);
    else
        u->sel_key[0] = '\0';
}

/* ------------------------------------------------------------- lifecycle */

ui_t *ui_new(store_t *store, const ui_hooks_t *hooks)
{
    ui_t *u = xcalloc(1, sizeof *u);
    u->store = store;
    u->sel_target = -1;
    if (hooks)
        u->hooks = *hooks;
    u->dirty = true;

    setlocale(LC_ALL, "");
    /* Wide characters follow the user's locale, numbers do not: a round trip
       reads as 1.25 ms everywhere, not 1,25 ms on some machines. */
    setlocale(LC_NUMERIC, "C");
    initscr();
    cbreak();
    noecho();
    nonl();
    curs_set(0);
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);
    set_escdelay(25);

    u->has_color = has_colors();
    if (u->has_color) {
        start_color();
        use_default_colors();
        /* fg on the default background, and the fg used for the same thing on
           a selected row (blue on blue would vanish, so labels turn white). */
        static const struct {
            short fg, fg_sel;
        } defs[] = {
            [CP_HEADER] = {COLOR_CYAN, COLOR_CYAN},
            [CP_LABEL] = {COLOR_BLUE, COLOR_WHITE},
            [CP_MDNS] = {COLOR_GREEN, COLOR_GREEN},
            [CP_SSDP] = {COLOR_MAGENTA, COLOR_MAGENTA},
            [CP_DIM] = {COLOR_WHITE, COLOR_WHITE},
            [CP_STALE] = {COLOR_YELLOW, COLOR_YELLOW},
            [CP_ADDR] = {COLOR_CYAN, COLOR_CYAN},
            [CP_NAME] = {COLOR_WHITE, COLOR_WHITE},
            [CP_PORT] = {COLOR_YELLOW, COLOR_YELLOW},
            [CP_OK] = {COLOR_GREEN, COLOR_GREEN},
            [CP_WARN] = {COLOR_YELLOW, COLOR_YELLOW},
            [CP_BAD] = {COLOR_RED, COLOR_RED},
            [CP_KEY] = {COLOR_CYAN, COLOR_CYAN},
        };
        short selbg = COLORS >= 256 ? SEL_BG_256 : (COLORS >= 16 ? SEL_BG_16 : -1);
        u->sel_bg = selbg >= 0;
        for (size_t i = 1; i < sizeof defs / sizeof defs[0]; i++) {
            init_pair((short)i, defs[i].fg, -1);
            if (u->sel_bg)
                init_pair((short)(i + CP_SEL), defs[i].fg_sel, selbg);
        }
    }
    return u;
}

void ui_destroy(ui_t *u)
{
    if (!u)
        return;
    endwin();
    free_targets(u);
    free(u->rows);
    free(u);
}

int ui_getch(void)
{
    return getch();
}

/* ------------------------------------------------------------------ keys */

static void move_sel(ui_t *u, int delta)
{
    if (!u->nrows)
        return;
    long s = (long)u->sel + delta;
    if (s < 0)
        s = 0;
    if (s >= (long)u->nrows)
        s = (long)u->nrows - 1;
    u->sel = (size_t)s;
    u->sel_target = -1;
    remember_sel(u);
}

static void request_fetches_for_device(ui_t *u, device_t *d)
{
    if (!u->hooks.fetch)
        return;
    for (ssdp_entry_t *e = d->ssdp; e; e = e->next)
        u->hooks.fetch(u->hooks.ctx, e);
}

static void toggle_row(ui_t *u, bool expand_only)
{
    if (u->sel >= u->nrows)
        return;
    row_t *r = &u->rows[u->sel];
    device_t *d = store_find_id(u->store, r->dev_id);
    switch (r->kind) {
    case ROW_DEVICE:
        if (!d)
            return;
        d->expanded = expand_only ? true : !d->expanded;
        if (d->expanded)
            request_fetches_for_device(u, d);
        break;
    case ROW_SERVICE:
        r->sv->expanded = expand_only ? true : !r->sv->expanded;
        break;
    case ROW_SSDP:
        r->e->expanded = expand_only ? true : !r->e->expanded;
        if (r->e->expanded && u->hooks.fetch)
            u->hooks.fetch(u->hooks.ctx, r->e);
        break;
    default:
        return;
    }
    u->dirty = true;
}

static void collapse_or_parent(ui_t *u);

static void collapse_or_parent(ui_t *u)
{
    if (u->sel >= u->nrows)
        return;
    row_t *r = &u->rows[u->sel];
    bool open = (r->kind == ROW_DEVICE && store_find_id(u->store, r->dev_id) &&
                 store_find_id(u->store, r->dev_id)->expanded) ||
                (r->kind == ROW_SERVICE && r->sv->expanded) ||
                (r->kind == ROW_SSDP && r->e->expanded);
    if (open) {
        toggle_row(u, false);
        return;
    }
    /* Already closed (or a leaf): jump to the enclosing row. */
    int indent = r->indent;
    for (size_t i = u->sel; i-- > 0;)
        if (u->rows[i].indent < indent) {
            u->sel = i;
            remember_sel(u);
            return;
        }
}

/* The value the cursor is on, if one is picked; otherwise the row's first. */
static const target_t *current_target(const ui_t *u)
{
    if (u->sel >= u->nrows)
        return NULL;
    const row_t *r = &u->rows[u->sel];
    int idx = u->sel_target >= 0 ? u->sel_target : 0;
    return idx < r->ntargets ? &r->targets[idx] : NULL;
}

/* p pings whatever device the cursor is on, from any of its rows, using the
   address picked with left/right when one is. */
static void ping_selected(ui_t *u)
{
    if (u->sel >= u->nrows || !u->hooks.ping)
        return;
    device_t *d = store_find_id(u->store, u->rows[u->sel].dev_id);
    if (!d)
        return;
    const target_t *t = u->sel_target >= 0 ? current_target(u) : NULL;
    u->hooks.ping(u->hooks.ctx, d, (t && t->is_addr) ? &t->addr : NULL);
    u->dirty = true;
}

/* c copies the picked value, or the row's first one when nothing is picked. */
static void copy_selected(ui_t *u)
{
    if (u->sel >= u->nrows)
        return;
    const row_t *r = &u->rows[u->sel];
    int idx = u->sel_target >= 0 ? u->sel_target : 0;
    u->copied_at = now_ms();
    if (idx >= r->ntargets) {
        snprintf(u->copied, sizeof u->copied, "nothing to copy on this row");
        return;
    }
    char val[1024];
    target_value(r, idx, val, sizeof val);
    const char *how = clip_copy(val);
    if (how)
        snprintf(u->copied, sizeof u->copied, "copied to %s: %.110s", how, val);
    else
        snprintf(u->copied, sizeof u->copied, "could not copy");
}

static bool row_is_open(const ui_t *u, const row_t *r)
{
    switch (r->kind) {
    case ROW_DEVICE: {
        const device_t *d = store_find_id(u->store, r->dev_id);
        return d && d->expanded;
    }
    case ROW_SERVICE:
        return r->sv->expanded;
    case ROW_SSDP:
        return r->e->expanded;
    default:
        return false;
    }
}

/* Right opens a fold, and once there is nothing left to open it steps through
   the row's values. Left steps back, and from the leftmost value it falls
   through to the usual collapse. */
static void step_target(ui_t *u, int dir)
{
    if (u->sel >= u->nrows)
        return;
    row_t *r = &u->rows[u->sel];
    bool foldable = r->kind == ROW_DEVICE || r->kind == ROW_SERVICE || r->kind == ROW_SSDP;

    if (dir > 0) {
        if (foldable && !row_is_open(u, r)) {
            toggle_row(u, true);
            return;
        }
        if (u->sel_target + 1 < r->ntargets)
            u->sel_target++;
        return;
    }
    if (u->sel_target > 0) {
        u->sel_target--;
        return;
    }
    u->sel_target = -1;
    collapse_or_parent(u);
}

static void expand_all(ui_t *u, bool on)
{
    for (device_t *d = u->store->head; d; d = d->next) {
        d->expanded = on;
        if (on)
            request_fetches_for_device(u, d);
        for (service_t *sv = d->services; sv; sv = sv->next)
            sv->expanded = on;
        for (ssdp_entry_t *e = d->ssdp; e; e = e->next)
            e->expanded = on;
    }
    u->dirty = true;
}

ui_action_t ui_key(ui_t *u, int ch)
{
    if (ch == KEY_RESIZE) {
        u->dirty = true;
        return UI_NONE;
    }

    if (u->filter_editing) {
        if (ch == '\n' || ch == KEY_ENTER || ch == '\r') {
            u->filter_editing = false;
        } else if (ch == 27) {
            u->filter[0] = '\0';
            u->filter_editing = false;
            u->dirty = true;
        } else if (ch == KEY_BACKSPACE || ch == 127 || ch == 8) {
            size_t n = strlen(u->filter);
            if (n)
                u->filter[n - 1] = '\0';
            u->dirty = true;
        } else if (ch >= 32 && ch < 127) {
            size_t n = strlen(u->filter);
            if (n + 1 < sizeof u->filter) {
                u->filter[n] = (char)ch;
                u->filter[n + 1] = '\0';
            }
            u->dirty = true;
        }
        return UI_NONE;
    }

    if (u->show_help) {
        /* Any key closes the overlay. */
        u->show_help = false;
        u->dirty = true;
        if (ch == 'q')
            return UI_QUIT;
        return UI_NONE;
    }

    switch (ch) {
    case 27:
        /* Esc backs out of a filter first; only then does it quit. */
        if (u->filter[0]) {
            u->filter[0] = '\0';
            u->dirty = true;
            break;
        }
        return UI_QUIT;
    case 'q':
        return UI_QUIT;
    case KEY_UP:
    case 'k':
        move_sel(u, -1);
        break;
    case KEY_DOWN:
    case 'j':
        move_sel(u, 1);
        break;
    case KEY_PPAGE:
        move_sel(u, -(LINES - 5));
        break;
    case KEY_NPAGE:
        move_sel(u, LINES - 5);
        break;
    case KEY_HOME:
    case 'g':
        move_sel(u, -(int)u->nrows);
        break;
    case KEY_END:
    case 'G':
        move_sel(u, (int)u->nrows);
        break;
    case '\n':
    case '\r':
    case KEY_ENTER:
    case ' ':
        toggle_row(u, false);
        break;
    case KEY_RIGHT:
    case 'l':
        step_target(u, +1);
        break;
    case KEY_LEFT:
    case 'h':
        step_target(u, -1);
        break;
    case 'c':
        copy_selected(u);
        break;
    case 'e':
        expand_all(u, true);
        break;
    case 'E':
        expand_all(u, false);
        break;
    case 's':
        u->sort = (sort_mode_t)((u->sort + 1) % SORT__COUNT);
        u->dirty = true;
        break;
    case '/':
        u->filter_editing = true;
        break;
    case 'p':
        ping_selected(u);
        break;
    case 'r':
        return UI_RESCAN;
    case '?':
        u->show_help = true;
        break;
    default:
        break;
    }
    return UI_NONE;
}

/* ------------------------------------------------------------------ draw */

static void draw_help(const ui_t *u)
{
    static const char *lines[] = {
        "  mdns-cli keys",
        "",
        "  up/down, j/k      move",
        "  PgUp/PgDn         page",
        "  Home/End, g/G     first / last",
        "  Enter, space      fold open or closed",
        "  right / l         fold open, then pick values on the row",
        "  left / h          step back, then fold closed or go to parent",
        "  c                 copy the value under the cursor",
        "  e / E             expand all / collapse all",
        "  p                 ping (uses the address picked with right/left)",
        "  s                 cycle sort order",
        "  /                 filter (Esc clears)",
        "  r                 rescan now",
        "  q                 quit",
        "",
        "  Expanding a UPnP entry fetches its description over HTTP.",
        "  Ping runs once a second; sleepy devices get 12s to answer.",
        "  Press any key to close.",
    };
    size_t n = sizeof lines / sizeof lines[0];
    int h = (int)n + 2;
    int w = 70;
    int y = (LINES - h) / 2;
    int x = (COLS - w) / 2;
    if (y < 0 || x < 0)
        return;
    WINDOW *win = newwin(h, w, y, x);
    if (u->has_color)
        wattrset(win, COLOR_PAIR(CP_HEADER));
    box(win, 0, 0);
    for (size_t i = 0; i < n; i++) {
        /* The key column is everything up to the first run of two spaces
           after the leading indent; blank and prose lines have none. */
        size_t linelen = strlen(lines[i]);
        const char *body = (i > 1 && linelen > 2) ? strstr(lines[i] + 2, "  ") : NULL;
        size_t keylen = body ? (size_t)(body - lines[i]) : 0;
        if (keylen) {
            wattrset(win, A_BOLD | (u->has_color ? COLOR_PAIR(CP_KEY) : 0));
            mvwaddnstr(win, (int)i + 1, 1, lines[i], (int)keylen);
            wattrset(win, A_NORMAL);
            mvwaddnstr(win, (int)i + 1, 1 + (int)keylen, lines[i] + keylen,
                       w - 2 - (int)keylen);
        } else {
            wattrset(win, i == 0 ? (A_BOLD | (u->has_color ? COLOR_PAIR(CP_HEADER) : 0))
                                 : A_NORMAL);
            mvwaddnstr(win, (int)i + 1, 1, lines[i], w - 2);
        }
    }
    wrefresh(win);
    delwin(win);
}

/* Combine a base attribute with a colour pair. The pair number lives in its
   own bit field, so it has to replace what base carries rather than OR into
   it -- pair 24 | pair 23 is pair 31, which is a different colour entirely. */
static attr_t with_cp(attr_t base, int cp, attr_t extra)
{
    attr_t a = (base & ~(attr_t)A_COLOR) | extra;
    return a | (cp ? (attr_t)COLOR_PAIR(cp) : (base & (attr_t)A_COLOR));
}

/* The colour pair to actually use for a span on this row. */
static int row_cp(const ui_t *u, int cp, bool selected)
{
    if (!u->has_color)
        return 0;
    if (!selected)
        return cp;
    /* Without a selection background the row is drawn in reverse video, and
       per-span colours there would fight the inversion. */
    if (!u->sel_bg)
        return 0;
    return (cp ? cp : CP_NAME) + CP_SEL;
}

/* The colour of whatever span covers this offset, so a highlight can keep it. */
static int cp_at(const row_t *r, int off)
{
    for (int i = 0; i < r->nspans; i++)
        if (off >= r->spans[i].off && off < r->spans[i].off + r->spans[i].len)
            return r->spans[i].cp;
    return 0;
}

static void draw_row(ui_t *u, const row_t *r, int y, bool selected, int target_idx)
{
    int x = r->indent;
    attr_t base = A_NORMAL;
    if (r->stale && !selected)
        base |= A_DIM; /* dim on a coloured background just looks muddy */
    if (selected) {
        if (u->has_color && u->sel_bg)
            base |= COLOR_PAIR(CP_NAME + CP_SEL) | A_BOLD; /* lift it off the grey */
        else
            base |= A_REVERSE;
    }

    attrset(base);
    mvhline(y, 0, ' ', COLS); /* paint the whole line so selection spans it */

    if (r->marker) {
        attrset(with_cp(base, row_cp(u, r->tag, selected), 0));
        mvaddstr(y, x, r->marker);
    }
    x += 2;

    int avail = COLS - x;
    if (avail <= 0) {
        attrset(A_NORMAL);
        return;
    }

    int tlen = (int)strlen(r->text);
    int pos = 0;  /* byte offset into text */
    int col = 0;  /* columns already drawn */
    for (int i = 0; i <= r->nspans && col < avail; i++) {
        int next = (i < r->nspans) ? r->spans[i].off : tlen;
        if (next > pos) {
            int n = next - pos;
            if (n > avail - col)
                n = avail - col;
            attrset(base);
            mvaddnstr(y, x + col, r->text + pos, n);
            col += n;
            pos += n;
        }
        if (i == r->nspans || col >= avail)
            break;
        const span_t *sp = &r->spans[i];
        int n = sp->len;
        if (n > tlen - pos)
            n = tlen - pos;
        if (n > avail - col)
            n = avail - col;
        if (n <= 0)
            break;
        attr_t a = with_cp(base, row_cp(u, sp->cp, selected), sp->attr);
        if (selected)
            a &= ~(attr_t)A_DIM;
        attrset(a);
        mvaddnstr(y, x + col, r->text + pos, n);
        col += n;
        pos += n;
    }

    /* Mark the picked value in place, keeping the colour it already has. */
    if (target_idx >= 0 && target_idx < r->ntargets) {
        const target_t *t = &r->targets[target_idx];
        if (t->off < avail) {
            int hlen = t->len;
            if (t->off + hlen > avail)
                hlen = avail - t->off;
            int cp = row_cp(u, cp_at(r, t->off), selected);
            mvchgat(y, x + t->off, hlen, A_BOLD | A_UNDERLINE, (short)cp, NULL);
        }
    }
    attrset(A_NORMAL);
}

/* Draw a footer/hint string, highlighting the key letters inside brackets. */
static void draw_hints(ui_t *u, int y, const char *text)
{
    attr_t dim = A_DIM | (u->has_color ? COLOR_PAIR(CP_DIM) : 0);
    attr_t key = A_BOLD | (u->has_color ? COLOR_PAIR(CP_KEY) : 0);
    int x = 0;
    bool in_key = false;
    for (const char *p = text; *p && x < COLS; p++) {
        if (*p == '[') {
            in_key = true;
        } else if (*p == ']') {
            in_key = false;
        }
        attrset(in_key || *p == ']' ? key : dim);
        mvaddnstr(y, x++, p, 1);
    }
    attrset(A_NORMAL);
}

void ui_draw(ui_t *u, const ui_status_t *st)
{
    if (u->dirty || u->built_gen != u->store->generation || u->built_cols != COLS)
        rebuild(u, COLS);
    u->now = now_ms();

    erase();

    /* Header: the name and counts on the left, scan state on the right. */
    attr_t title = A_BOLD | (u->has_color ? COLOR_PAIR(CP_HEADER) : 0);
    attr_t plain = u->has_color ? COLOR_PAIR(CP_NAME) : A_NORMAL;
    attr_t quiet = A_DIM | (u->has_color ? COLOR_PAIR(CP_DIM) : 0);

    attrset(title);
    mvaddnstr(0, 0, "mdns-cli", COLS);
    char counts[128];
    snprintf(counts, sizeof counts, "  %zu device%s, %zu service%s", st->n_devices,
             st->n_devices == 1 ? "" : "s", st->n_services, st->n_services == 1 ? "" : "s");
    attrset(plain);
    mvaddnstr(0, 8, counts, COLS - 8);

    char elapsed[16];
    fmt_age(st->elapsed_ms, elapsed, sizeof elapsed);
    char state[32], rest[256];
    snprintf(state, sizeof state, "%s", st->scanning ? "scanning" : "idle");
    snprintf(rest, sizeof rest, "  %s  sort:%s  %s", elapsed, sort_name(u->sort), st->ifaces);
    int rx = COLS - (int)strlen(state) - (int)strlen(rest) - 1;
    if (rx > 8 + (int)strlen(counts) + 2) {
        attrset(st->scanning ? (A_BOLD | (u->has_color ? COLOR_PAIR(CP_OK) : 0)) : quiet);
        mvaddnstr(0, rx, state, COLS - rx);
        attrset(quiet);
        mvaddnstr(0, rx + (int)strlen(state), rest, COLS - rx);
    }
    attrset(u->has_color ? COLOR_PAIR(CP_HEADER) : A_NORMAL);
    mvhline(1, 0, ACS_HLINE, COLS);
    attrset(A_NORMAL);

    /* Body. */
    int body_top = 2;
    int body_h = LINES - body_top - 1;
    if (body_h < 1)
        body_h = 1;

    if (u->sel < u->top)
        u->top = u->sel;
    if (u->sel >= u->top + (size_t)body_h)
        u->top = u->sel - (size_t)body_h + 1;
    if (u->nrows <= (size_t)body_h)
        u->top = 0;

    if (u->nrows == 0) {
        const char *msg = u->filter[0] ? "no devices match the filter"
                                       : "listening... no devices discovered yet";
        attrset(A_DIM | (u->has_color ? COLOR_PAIR(CP_DIM) : 0));
        mvaddnstr(body_top + 1, 2, msg, COLS - 2);
        attrset(A_NORMAL);
    }
    for (size_t i = 0; i < (size_t)body_h && u->top + i < u->nrows; i++)
        draw_row(u, &u->rows[u->top + i], body_top + (int)i, u->top + i == u->sel,
                 u->top + i == u->sel ? u->sel_target : -1);

    /* Footer. */
    char foot[256];
    bool multi = u->sel < u->nrows && u->rows[u->sel].ntargets > 1;
    if (u->copied[0] && u->now - u->copied_at < COPIED_SHOW_MS) {
        attrset(A_BOLD | (u->has_color ? COLOR_PAIR(CP_OK) : 0));
        mvaddnstr(LINES - 1, 0, u->copied, COLS);
        attrset(A_NORMAL);
        refresh();
        if (u->show_help)
            draw_help(u);
        return;
    }
    if (u->filter_editing)
        snprintf(foot, sizeof foot, "filter: %s_", u->filter);
    else if (u->filter[0])
        snprintf(foot, sizeof foot,
                 "filter:%s  %zu of %zu devices  [esc] clear  [?] keys  [q] quit", u->filter,
                 u->ndevices_shown, st->n_devices);
    else if (multi)
        snprintf(foot, sizeof foot,
                 "[left/right] pick value  [c] copy  [p] ping it  [enter] fold  [?] keys  "
                 "[q] quit");
    else
        snprintf(foot, sizeof foot,
                 "[enter] fold  [p] ping  [c] copy  [e/E] all  [s] sort  [/] filter  [r] rescan  "
                 "[?] keys  [q] quit%s",
                 st->inflight ? "  (fetching)" : "");
    if (u->filter_editing) {
        attrset(A_BOLD | (u->has_color ? COLOR_PAIR(CP_KEY) : 0));
        mvaddnstr(LINES - 1, 0, foot, COLS);
        attrset(A_NORMAL);
    } else {
        draw_hints(u, LINES - 1, foot);
    }

    refresh();
    /* After stdscr, or the refresh would paint straight over the overlay. */
    if (u->show_help)
        draw_help(u);
}
