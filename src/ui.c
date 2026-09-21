#include "ui.h"

#include "util.h"

#include <ctype.h>
#include <locale.h>
#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define STALE_MS 120000u
#define KEYLEN 320
#define TEXTLEN 768

enum {
    CP_HEADER = 1,
    CP_LABEL,
    CP_MDNS,
    CP_SSDP,
    CP_DIM,
    CP_STALE,
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

typedef struct {
    row_kind_t kind;
    int indent;
    const char *marker; /* fold glyph, or NULL */
    char key[KEYLEN];   /* stable identity, survives a rebuild */
    char text[TEXTLEN];
    int label_len; /* leading characters of text drawn as a label */
    unsigned dev_id;
    service_t *sv;
    ssdp_entry_t *e;
    bool stale;
    int tag;      /* color pair for the marker/kind, 0 for none */
    int value_cp; /* color pair for the value half of a kv row, 0 for none */
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

    sort_mode_t sort;
    char filter[128];
    bool filter_editing;
    bool show_help;
    bool has_color;
    uint64_t now;
};

/* ------------------------------------------------------------------ rows */

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
    r->label_len = n > 0 ? n : 0;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(r->text + r->label_len, sizeof r->text - (size_t)r->label_len, fmt, ap);
    va_end(ap);
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
    if (sv->have_srv)
        snprintf(r->text, sizeof r->text, "%s %s:%u", col, sv->instance, sv->port);
    else
        snprintf(r->text, sizeof r->text, "%s %s (resolving)", col, sv->instance);
    if (!sv->expanded)
        return;

    if (sv->host)
        kv_row(u, d->id, 6, "svc-host", "host", "%s:%u", sv->host, sv->port);
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
        if (t->val)
            snprintf(tr->text, sizeof tr->text, "%s = %s", t->key, t->val);
        else
            snprintf(tr->text, sizeof tr->text, "%s", t->key);
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
    snprintf(r->text, sizeof r->text, "%s %s", col, title);
    if (!e->expanded)
        return;

    if (e->usn && *e->usn)
        kv_row(u, d->id, 6, "usn", "usn", "%s", e->usn);
    if (e->server && *e->server)
        kv_row(u, d->id, 6, "server", "server", "%s", e->server);
    if (e->location && *e->location)
        kv_row(u, d->id, 6, "location", "location", "%s", e->location);
    switch (e->fetch) {
    case FETCH_NONE:
        if (e->location && *e->location)
            kv_row(u, d->id, 6, "desc", "description", "queued");
        break;
    case FETCH_RUNNING:
        kv_row(u, d->id, 6, "desc", "description", "fetching...");
        break;
    case FETCH_FAILED:
        kv_row(u, d->id, 6, "desc", "description", "unavailable (%s)",
               e->fetch_error ? e->fetch_error : "error");
        break;
    case FETCH_DONE:
        if (e->friendly_name)
            kv_row(u, d->id, 6, "fname", "friendlyName", "%s", e->friendly_name);
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

/* The ping counters live on the device entry, so they stay on screen after a
   run is stopped and are there to compare against the next one. */
static void build_ping_rows(ui_t *u, device_t *d)
{
    const ping_t *pg = &d->ping;
    if (!ping_has_data(pg) && !pg->active) {
        kv_row(u, d->id, 4, "ping", "ping", "not pinged yet - press p");
        return;
    }
    if (pg->error && pg->sent == 0) {
        kv_row(u, d->id, 4, "ping", "ping", "%s", pg->error);
        u->rows[u->nrows - 1].value_cp = CP_STALE;
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
    if (loss > 0)
        u->rows[u->nrows - 1].value_cp = CP_STALE;

    if (pg->recv)
        kv_row(u, d->id, 4, "rtt", "rtt", "last %.2f ms, min %.2f, avg %.2f, max %.2f",
               pg->last_ms, pg->min_ms, ping_avg_ms(pg), pg->max_ms);
    else
        kv_row(u, d->id, 4, "rtt", "rtt", "%s", pg->active ? "waiting for the first reply"
                                                           : "no reply");
    if (pg->error && pg->sent)
        kv_row(u, d->id, 4, "pingerr", "ping error", "%s", pg->error);
}

static void build_device_rows(ui_t *u, device_t *d, const cols_t *c)
{
    row_t *r = row_add(u);
    r->kind = ROW_DEVICE;
    r->indent = 0;
    r->dev_id = d->id;
    r->marker = d->expanded ? "\xe2\x96\xbe" : "\xe2\x96\xb8";
    r->stale = (u->now - d->last_seen) > STALE_MS;
    snprintf(r->key, sizeof r->key, "d:%u", d->id);

    char src[16];
    device_sources_str(d, src, sizeof src);
    char tail[96];
    size_t n = d->n_services + d->n_ssdp;
    int tn = snprintf(tail, sizeof tail, "%zu service%s", n, n == 1 ? "" : "s");
    if (tn > 0 && ping_has_data(&d->ping)) {
        /* The whole point of the counters is to be readable while folded. */
        double loss = ping_loss_pct(&d->ping);
        if (d->ping.recv)
            snprintf(tail + tn, sizeof tail - (size_t)tn, "   ping %.2fms %.0f%%",
                     d->ping.last_ms, loss < 0 ? 0 : loss);
        else
            snprintf(tail + tn, sizeof tail - (size_t)tn, "   ping no reply");
    }

    char acol[ADDR_STRLEN], fitted[ADDR_STRLEN], ncol[256];
    str_fit_addr(fitted, sizeof fitted, device_primary_addr(d), c->addrw);
    str_pad(acol, sizeof acol, fitted, c->addrw);
    str_pad(ncol, sizeof ncol, device_label(d), c->namew);
    snprintf(r->text, sizeof r->text, "%s %s %-9.9s %s", acol, ncol, src, tail);
    if (!d->expanded)
        return;

    char addrs[512] = "";
    for (size_t i = 0; i < d->n_addrs; i++) {
        if (i)
            strncat(addrs, ", ", sizeof addrs - strlen(addrs) - 1);
        strncat(addrs, d->addrs[i].str, sizeof addrs - strlen(addrs) - 1);
    }
    kv_row(u, d->id, 4, "addrs", "addresses", "%s", d->n_addrs ? addrs : "(none yet)");
    if (d->hostname)
        kv_row(u, d->id, 4, "host", "hostname", "%s", d->hostname);

    char first[16], last[16], age[16];
    fmt_clock(d->first_seen, first, sizeof first);
    fmt_clock(d->last_seen, last, sizeof last);
    fmt_age(u->now - d->last_seen, age, sizeof age);
    kv_row(u, d->id, 4, "seen", "seen", "first %s, last %s (%s ago)", first, last, age);
    build_ping_rows(u, d);

    for (service_t *sv = d->services; sv; sv = sv->next)
        build_service_rows(u, d, sv, c);
    for (ssdp_entry_t *e = d->ssdp; e; e = e->next)
        build_ssdp_rows(u, d, e, c);
}

static void rebuild(ui_t *u, int cols)
{
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
                return;
            }
    }
    if (u->sel >= u->nrows)
        u->sel = u->nrows ? u->nrows - 1 : 0;
    if (u->nrows)
        snprintf(u->sel_key, sizeof u->sel_key, "%s", u->rows[u->sel].key);
    else
        u->sel_key[0] = '\0';
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
        init_pair(CP_HEADER, COLOR_CYAN, -1);
        init_pair(CP_LABEL, COLOR_BLUE, -1);
        init_pair(CP_MDNS, COLOR_GREEN, -1);
        init_pair(CP_SSDP, COLOR_MAGENTA, -1);
        init_pair(CP_DIM, COLOR_WHITE, -1);
        init_pair(CP_STALE, COLOR_YELLOW, -1);
    }
    return u;
}

void ui_destroy(ui_t *u)
{
    if (!u)
        return;
    endwin();
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

/* p pings whatever device the cursor is on, from any of its rows. */
static void ping_selected(ui_t *u)
{
    if (u->sel >= u->nrows || !u->hooks.ping)
        return;
    device_t *d = store_find_id(u->store, u->rows[u->sel].dev_id);
    if (!d)
        return;
    u->hooks.ping(u->hooks.ctx, d);
    d->expanded = true; /* so the counters are visible straight away */
    u->dirty = true;
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
        toggle_row(u, true);
        break;
    case KEY_LEFT:
    case 'h':
        collapse_or_parent(u);
        break;
    case 'e':
        expand_all(u, true);
        break;
    case 'E':
    case 'c':
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

static void draw_help(void)
{
    static const char *lines[] = {
        "  mdns-cli keys",
        "",
        "  up/down, j/k      move",
        "  PgUp/PgDn         page",
        "  Home/End, g/G     first / last",
        "  Enter, space      fold open or closed",
        "  right / l         fold open",
        "  left / h          fold closed, or go to parent",
        "  e / E             expand all / collapse all",
        "  p                 ping this device (press again to stop)",
        "  s                 cycle sort order",
        "  /                 filter (Esc clears)",
        "  r                 rescan now",
        "  q                 quit",
        "",
        "  Expanding a UPnP entry fetches its description over HTTP.",
        "  Ping runs once a second and counts loss and round trip.",
        "  Press any key to close.",
    };
    size_t n = sizeof lines / sizeof lines[0];
    int h = (int)n + 2;
    int w = 66;
    int y = (LINES - h) / 2;
    int x = (COLS - w) / 2;
    if (y < 0 || x < 0)
        return;
    WINDOW *win = newwin(h, w, y, x);
    box(win, 0, 0);
    for (size_t i = 0; i < n; i++)
        mvwaddnstr(win, (int)i + 1, 1, lines[i], w - 2);
    wrefresh(win);
    delwin(win);
}

static void draw_row(ui_t *u, const row_t *r, int y, bool selected)
{
    int x = r->indent;
    attr_t attr = A_NORMAL;
    if (r->stale) {
        /* Not heard from in a while: dimmed, and amber where colour exists. */
        attr |= A_DIM;
        if (u->has_color)
            attr |= COLOR_PAIR(CP_STALE);
    }
    if (selected)
        attr |= A_REVERSE;

    attrset(attr);
    mvhline(y, 0, ' ', COLS); /* paint the whole line so selection spans it */

    if (r->marker) {
        if (u->has_color && r->tag)
            attron(COLOR_PAIR(r->tag));
        mvaddstr(y, x, r->marker);
        if (u->has_color && r->tag)
            attroff(COLOR_PAIR(r->tag));
        x += 2;
    } else {
        x += 2;
    }

    int avail = COLS - x;
    if (avail <= 0)
        return;

    if (r->kind == ROW_KV && r->label_len > 0) {
        int llen = r->label_len < avail ? r->label_len : avail;
        if (u->has_color && !selected)
            attron(COLOR_PAIR(CP_LABEL));
        mvaddnstr(y, x, r->text, llen);
        if (u->has_color && !selected)
            attroff(COLOR_PAIR(CP_LABEL));
        if (avail > llen) {
            if (u->has_color && r->value_cp && !selected)
                attron(COLOR_PAIR(r->value_cp));
            mvaddnstr(y, x + llen, r->text + llen, avail - llen);
            if (u->has_color && r->value_cp && !selected)
                attroff(COLOR_PAIR(r->value_cp));
        }
    } else {
        mvaddnstr(y, x, r->text, avail);
    }
    attrset(A_NORMAL);
}

void ui_draw(ui_t *u, const ui_status_t *st)
{
    if (u->dirty || u->built_gen != u->store->generation || u->built_cols != COLS)
        rebuild(u, COLS);
    u->now = now_ms();

    erase();

    /* Header. */
    char left[256];
    snprintf(left, sizeof left, "mdns-cli  %zu device%s, %zu service%s", st->n_devices,
             st->n_devices == 1 ? "" : "s", st->n_services, st->n_services == 1 ? "" : "s");
    char right[256];
    char elapsed[16];
    fmt_age(st->elapsed_ms, elapsed, sizeof elapsed);
    snprintf(right, sizeof right, "%s  %s  sort:%s  %s", st->scanning ? "scanning" : "idle",
             elapsed, sort_name(u->sort), st->ifaces);

    if (u->has_color)
        attron(COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvaddnstr(0, 0, left, COLS);
    int rx = COLS - (int)strlen(right) - 1;
    if (rx > (int)strlen(left) + 2)
        mvaddnstr(0, rx, right, COLS - rx);
    if (u->has_color)
        attroff(COLOR_PAIR(CP_HEADER) | A_BOLD);
    mvhline(1, 0, ACS_HLINE, COLS);

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
        if (u->has_color)
            attron(COLOR_PAIR(CP_DIM) | A_DIM);
        mvaddnstr(body_top + 1, 2, msg, COLS - 2);
        if (u->has_color)
            attroff(COLOR_PAIR(CP_DIM) | A_DIM);
    }
    for (size_t i = 0; i < (size_t)body_h && u->top + i < u->nrows; i++)
        draw_row(u, &u->rows[u->top + i], body_top + (int)i, u->top + i == u->sel);

    /* Footer. */
    char foot[256];
    if (u->filter_editing)
        snprintf(foot, sizeof foot, "filter: %s_", u->filter);
    else if (u->filter[0])
        snprintf(foot, sizeof foot,
                 "filter:%s  %zu of %zu devices  [esc] clear  [?] keys  [q] quit", u->filter,
                 u->ndevices_shown, st->n_devices);
    else
        snprintf(foot, sizeof foot,
                 "[enter] fold  [p] ping  [e/E] all  [s] sort  [/] filter  [r] rescan  [?] keys  "
                 "[q] quit%s",
                 st->inflight ? "  (fetching)" : "");
    if (u->has_color)
        attron(COLOR_PAIR(CP_DIM) | A_DIM);
    mvaddnstr(LINES - 1, 0, foot, COLS);
    if (u->has_color)
        attroff(COLOR_PAIR(CP_DIM) | A_DIM);

    refresh();
    /* After stdscr, or the refresh would paint straight over the overlay. */
    if (u->show_help)
        draw_help();
}
