/* mdns-cli: interactive mDNS + SSDP scanner.
 *
 * Everything runs in one poll() loop: both multicast families, the SSDP search
 * socket, every in-flight description fetch and the keyboard. No threads, so
 * no locking around the device store and no ncurses re-entrancy to worry about.
 */
#include "device.h"
#include "fetcher.h"
#include "mdns.h"
#include "net.h"
#include "ssdp.h"
#include "ui.h"
#include "util.h"

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define VERSION "1.0.0"
#define PKT_MAX 9000
#define UI_TICK_MS 400u
#define EXPIRE_EVERY_MS 5000u
#define DROP_AFTER_MS (15u * 60u * 1000u)
#define MAX_FETCHES 4

static volatile sig_atomic_t g_stop;

static void on_signal(int sig)
{
    (void)sig;
    g_stop = 1;
}

typedef struct {
    char *ifaces[MAX_IFACES];
    size_t n_ifaces;
    double timeout_s;
    bool use_mdns, use_ssdp;
    bool use_v4, use_v6;
    bool loopback;
    bool json;
    bool descriptions;
    const char *logfile;
} opts_t;

static void usage(FILE *out)
{
    fprintf(out,
            "usage: mdns-cli [options]\n"
            "\n"
            "Interactive mDNS/DNS-SD and SSDP/UPnP scanner. Arrow keys move,\n"
            "Enter folds a device open, q quits, ? lists every key.\n"
            "\n"
            "  -i, --interface NAME   only scan this interface (repeatable)\n"
            "  -t, --timeout SEC      stop after SEC seconds\n"
            "      --no-mdns          skip mDNS discovery\n"
            "      --no-ssdp          skip SSDP discovery\n"
            "  -4, --ipv4             IPv4 transport only\n"
            "  -6, --ipv6             IPv6 transport only\n"
            "      --loopback         include loopback interfaces\n"
            "      --json             no UI: scan, then print JSON (implies -t 5)\n"
            "      --no-descriptions  do not fetch UPnP description documents\n"
            "  -v, --verbose FILE     append a debug log to FILE\n"
            "  -h, --help             this text\n"
            "  -V, --version          version\n");
}

static bool parse_args(int argc, char **argv, opts_t *o)
{
    static const struct option longopts[] = {
        {"interface", required_argument, 0, 'i'},
        {"timeout", required_argument, 0, 't'},
        {"no-mdns", no_argument, 0, 1},
        {"no-ssdp", no_argument, 0, 2},
        {"loopback", no_argument, 0, 3},
        {"json", no_argument, 0, 4},
        {"no-descriptions", no_argument, 0, 5},
        {"ipv4", no_argument, 0, '4'},
        {"ipv6", no_argument, 0, '6'},
        {"verbose", required_argument, 0, 'v'},
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'V'},
        {0, 0, 0, 0},
    };
    o->use_mdns = o->use_ssdp = true;
    o->use_v4 = o->use_v6 = true;
    o->descriptions = true;
    o->timeout_s = 0;

    int c;
    bool only4 = false, only6 = false;
    while ((c = getopt_long(argc, argv, "i:t:46v:hV", longopts, NULL)) != -1) {
        switch (c) {
        case 'i':
            if (o->n_ifaces < MAX_IFACES)
                o->ifaces[o->n_ifaces++] = optarg;
            break;
        case 't':
            o->timeout_s = atof(optarg);
            if (o->timeout_s <= 0) {
                fprintf(stderr, "mdns-cli: --timeout needs a positive number\n");
                return false;
            }
            break;
        case 1:
            o->use_mdns = false;
            break;
        case 2:
            o->use_ssdp = false;
            break;
        case 3:
            o->loopback = true;
            break;
        case 4:
            o->json = true;
            break;
        case 5:
            o->descriptions = false;
            break;
        case '4':
            only4 = true;
            break;
        case '6':
            only6 = true;
            break;
        case 'v':
            o->logfile = optarg;
            break;
        case 'h':
            usage(stdout);
            exit(0);
        case 'V':
            printf("mdns-cli %s\n", VERSION);
            exit(0);
        default:
            usage(stderr);
            return false;
        }
    }
    if (only4 && !only6)
        o->use_v6 = false;
    if (only6 && !only4)
        o->use_v4 = false;
    if (!o->use_mdns && !o->use_ssdp) {
        fprintf(stderr, "mdns-cli: --no-mdns and --no-ssdp together leave nothing to do\n");
        return false;
    }
    if (o->json && o->timeout_s == 0)
        o->timeout_s = 5;
    return true;
}

/* ------------------------------------------------------------------ JSON */

static void json_str(FILE *f, const char *s)
{
    fputc('"', f);
    for (const unsigned char *p = (const unsigned char *)(s ? s : ""); *p; p++) {
        switch (*p) {
        case '"':
            fputs("\\\"", f);
            break;
        case '\\':
            fputs("\\\\", f);
            break;
        case '\n':
            fputs("\\n", f);
            break;
        case '\r':
            fputs("\\r", f);
            break;
        case '\t':
            fputs("\\t", f);
            break;
        default:
            if (*p < 0x20)
                fprintf(f, "\\u%04x", *p);
            else
                fputc(*p, f);
        }
    }
    fputc('"', f);
}

static void json_field(FILE *f, const char *key, const char *val, bool *first)
{
    if (!val || !*val)
        return;
    fprintf(f, "%s", *first ? "" : ", ");
    *first = false;
    json_str(f, key);
    fputs(": ", f);
    json_str(f, val);
}

static void dump_json(store_t *store, FILE *f)
{
    size_t n = 0;
    device_t **devs = store_snapshot(store, SORT_ADDR, NULL, &n);
    fputs("{\n  \"devices\": [\n", f);
    for (size_t i = 0; i < n; i++) {
        device_t *d = devs[i];
        char src[16];
        device_sources_str(d, src, sizeof src);
        fputs("    {\n      \"addresses\": [", f);
        for (size_t k = 0; k < d->n_addrs; k++) {
            if (k)
                fputs(", ", f);
            json_str(f, d->addrs[k].str);
        }
        fputs("],\n", f);
        fputs("      \"hostname\": ", f);
        json_str(f, d->hostname ? d->hostname : "");
        fprintf(f, ",\n      \"sources\": ");
        json_str(f, src);
        fputs(",\n      \"services\": [", f);
        bool first_sv = true;
        for (service_t *sv = d->services; sv; sv = sv->next) {
            fprintf(f, "%s\n        {", first_sv ? "" : ",");
            first_sv = false;
            bool fst = true;
            json_field(f, "type", sv->type, &fst);
            json_field(f, "instance", sv->instance, &fst);
            json_field(f, "host", sv->host, &fst);
            if (sv->have_srv) {
                fprintf(f, "%s\"port\": %u", fst ? "" : ", ", sv->port);
                fst = false;
            }
            if (sv->txt) {
                fprintf(f, "%s\"txt\": {", fst ? "" : ", ");
                bool ft = true;
                for (txt_pair_t *t = sv->txt; t; t = t->next) {
                    fprintf(f, "%s", ft ? "" : ", ");
                    ft = false;
                    json_str(f, t->key);
                    fputs(": ", f);
                    json_str(f, t->val ? t->val : "");
                }
                fputc('}', f);
            }
            fputc('}', f);
        }
        fputs(first_sv ? "]," : "\n      ],", f);
        fputs("\n      \"upnp\": [", f);
        bool first_e = true;
        for (ssdp_entry_t *e = d->ssdp; e; e = e->next) {
            fprintf(f, "%s\n        {", first_e ? "" : ",");
            first_e = false;
            bool fst = true;
            json_field(f, "st", e->st, &fst);
            json_field(f, "usn", e->usn, &fst);
            json_field(f, "server", e->server, &fst);
            json_field(f, "location", e->location, &fst);
            json_field(f, "friendlyName", e->friendly_name, &fst);
            json_field(f, "manufacturer", e->manufacturer, &fst);
            json_field(f, "modelName", e->model_name, &fst);
            json_field(f, "modelNumber", e->model_number, &fst);
            json_field(f, "serialNumber", e->serial, &fst);
            json_field(f, "udn", e->udn, &fst);
            if (e->fetch == FETCH_FAILED)
                json_field(f, "descriptionError", e->fetch_error, &fst);
            fputc('}', f);
        }
        fputs(first_e ? "]\n" : "\n      ]\n", f);
        fprintf(f, "    }%s\n", i + 1 < n ? "," : "");
    }
    fputs("  ]\n}\n", f);
    free(devs);
}

/* ------------------------------------------------------------------ main */

typedef struct {
    fetcher_t *fetcher;
} fetch_ctx_t;

static void on_fetch_request(void *ctx, const ssdp_entry_t *e)
{
    fetch_ctx_t *fc = ctx;
    fetcher_request(fc->fetcher, e);
}

static uint64_t min_u64(uint64_t a, uint64_t b)
{
    return a < b ? a : b;
}

int main(int argc, char **argv)
{
    opts_t o;
    memset(&o, 0, sizeof o);
    if (!parse_args(argc, argv, &o))
        return 2;
    if (o.logfile)
        log_open(o.logfile);

    iface_t ifs[MAX_IFACES];
    ssize_t nifs = net_enum_ifaces(ifs, MAX_IFACES, o.loopback, o.ifaces, o.n_ifaces);
    if (nifs < 0) {
        fprintf(stderr, "mdns-cli: cannot enumerate interfaces: %s\n", strerror(errno));
        return 1;
    }
    if (nifs == 0) {
        fprintf(stderr, "mdns-cli: no usable multicast interface%s\n",
                o.n_ifaces ? " matched the -i filter" : " found");
        return 1;
    }

    char ifnames[256] = "";
    for (ssize_t i = 0; i < nifs; i++) {
        if (i)
            strncat(ifnames, ",", sizeof ifnames - strlen(ifnames) - 1);
        strncat(ifnames, ifs[i].name, sizeof ifnames - strlen(ifnames) - 1);
    }

    int mdns4 = -1, mdns6 = -1, ssdp4_listen = -1, ssdp6_listen = -1;
    int ssdp4_search = -1, ssdp6_search = -1;

    if (o.use_mdns) {
        if (o.use_v4) {
            mdns4 = net_open_v4(MDNS_PORT, MDNS_GROUP4, ifs, (size_t)nifs, true);
            if (mdns4 < 0)
                fprintf(stderr, "mdns-cli: mDNS IPv4 socket: %s\n", strerror(errno));
        }
        if (o.use_v6) {
            mdns6 = net_open_v6(MDNS_PORT, MDNS_GROUP6, ifs, (size_t)nifs, true);
            if (mdns6 < 0)
                log_msg("mDNS IPv6 socket: %s", strerror(errno));
        }
        if (mdns4 < 0 && mdns6 < 0) {
            fprintf(stderr, "mdns-cli: no mDNS socket could be opened\n");
            return 1;
        }
    }
    if (o.use_ssdp) {
        if (o.use_v4) {
            ssdp4_listen = net_open_v4(SSDP_PORT, SSDP_GROUP4, ifs, (size_t)nifs, true);
            /* Replies to M-SEARCH are unicast to the source port: a socket of
               our own keeps them away from the other listeners on :1900. */
            ssdp4_search = net_open_v4(0, SSDP_GROUP4, ifs, (size_t)nifs, false);
            if (ssdp4_search < 0)
                fprintf(stderr, "mdns-cli: SSDP IPv4 socket: %s\n", strerror(errno));
        }
        if (o.use_v6) {
            ssdp6_listen = net_open_v6(SSDP_PORT, SSDP_GROUP6, ifs, (size_t)nifs, true);
            ssdp6_search = net_open_v6(0, SSDP_GROUP6, ifs, (size_t)nifs, false);
        }
        if (ssdp4_search < 0 && ssdp6_search < 0 && ssdp4_listen < 0 && ssdp6_listen < 0) {
            fprintf(stderr, "mdns-cli: no SSDP socket could be opened\n");
            return 1;
        }
    }

    store_t store;
    store_init(&store);
    mdns_t *mdns = o.use_mdns ? mdns_new(&store, ifs, (size_t)nifs, mdns4, mdns6) : NULL;
    ssdp_t *ssdp = o.use_ssdp ? ssdp_new(&store, ifs, (size_t)nifs, ssdp4_search, ssdp6_search)
                              : NULL;
    fetcher_t *fetcher = fetcher_new(&store, MAX_FETCHES);
    fetch_ctx_t fctx = {fetcher};
    ui_t *ui = o.json ? NULL : ui_new(&store, on_fetch_request, &fctx);

    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sa.sa_handler = on_signal;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    signal(SIGPIPE, SIG_IGN);

    const uint64_t start = now_ms();
    const uint64_t stop_at = o.timeout_s > 0 ? start + (uint64_t)(o.timeout_s * 1000) : UINT64_MAX;
    uint64_t next_expire = start + EXPIRE_EVERY_MS;
    uint64_t next_draw = start;
    uint64_t next_sweep = start;
    uint8_t pkt[PKT_MAX];

    while (!g_stop) {
        uint64_t now = now_ms();
        if (now >= stop_at)
            break;

        if (mdns)
            mdns_tick(mdns, now);
        if (ssdp)
            ssdp_tick(ssdp, now);

        if (o.json && o.descriptions && now >= next_sweep) {
            /* Nobody is pressing Enter, so pull every description we can. */
            for (device_t *d = store.head; d; d = d->next)
                for (ssdp_entry_t *e = d->ssdp; e; e = e->next)
                    fetcher_request(fetcher, e);
            next_sweep = now + 500;
        }

        if (ui && now >= next_draw) {
            ui_status_t st = {
                .scanning = (mdns && mdns_scanning(mdns)) || (ssdp && ssdp_scanning(ssdp)),
                .n_devices = store.n_devices,
                .n_services = store_total_services(&store),
                .inflight = fetcher_inflight(fetcher),
                .ifaces = ifnames,
                .elapsed_ms = now - start,
            };
            ui_draw(ui, &st);
            next_draw = now + UI_TICK_MS;
        }

        struct pollfd pfd[8 + MAX_FETCHES];
        size_t n = 0;
        int idx_stdin = -1, idx_mdns4 = -1, idx_mdns6 = -1;
        int idx_s4l = -1, idx_s4s = -1, idx_s6l = -1, idx_s6s = -1;

/* Parameter names avoid 'fd'/'events': the preprocessor would rewrite the
   struct members of the same name. */
#define ADD(sock, slotvar, evmask)                                                                 \
    do {                                                                                           \
        if ((sock) >= 0) {                                                                         \
            pfd[n].fd = (sock);                                                                    \
            pfd[n].events = (evmask);                                                              \
            pfd[n].revents = 0;                                                                    \
            (slotvar) = (int)n++;                                                                  \
        }                                                                                          \
    } while (0)

        if (ui)
            ADD(STDIN_FILENO, idx_stdin, POLLIN);
        ADD(mdns4, idx_mdns4, POLLIN);
        ADD(mdns6, idx_mdns6, POLLIN);
        ADD(ssdp4_listen, idx_s4l, POLLIN);
        ADD(ssdp4_search, idx_s4s, POLLIN);
        ADD(ssdp6_listen, idx_s6l, POLLIN);
        ADD(ssdp6_search, idx_s6s, POLLIN);
#undef ADD
        size_t fetch_base = n;
        n += fetcher_pollfds(fetcher, pfd + n, MAX_FETCHES);

        uint64_t deadline = min_u64(stop_at, next_expire);
        if (o.json && o.descriptions)
            deadline = min_u64(deadline, next_sweep);
        if (ui)
            deadline = min_u64(deadline, next_draw);
        if (mdns)
            deadline = min_u64(deadline, mdns_next_deadline(mdns));
        if (ssdp)
            deadline = min_u64(deadline, ssdp_next_deadline(ssdp));
        deadline = min_u64(deadline, fetcher_next_deadline(fetcher));

        now = now_ms();
        int wait_ms = deadline == UINT64_MAX ? 1000 : (int)(deadline > now ? deadline - now : 0);
        if (wait_ms > 1000)
            wait_ms = 1000; /* keep the clock in the header honest */

        int rc = poll(pfd, (nfds_t)n, wait_ms);
        now = now_ms();
        if (rc < 0) {
            if (errno == EINTR)
                continue;
            log_msg("poll: %s", strerror(errno));
            break;
        }

        if (idx_stdin >= 0 && (pfd[idx_stdin].revents & POLLIN)) {
            int ch;
            while ((ch = ui_getch()) != UI_KEY_NONE) {
                ui_action_t act = ui_key(ui, ch);
                if (act == UI_QUIT)
                    g_stop = 1;
                else if (act == UI_RESCAN) {
                    if (mdns)
                        mdns_rescan(mdns);
                    if (ssdp)
                        ssdp_rescan(ssdp);
                }
            }
            next_draw = 0; /* redraw immediately after input */
        }

        struct {
            int idx;
            bool is_mdns;
        } socks[] = {
            {idx_mdns4, true}, {idx_mdns6, true},  {idx_s4l, false},
            {idx_s4s, false},  {idx_s6l, false},   {idx_s6s, false},
        };
        for (size_t i = 0; i < sizeof socks / sizeof socks[0]; i++) {
            int idx = socks[i].idx;
            if (idx < 0 || !(pfd[idx].revents & POLLIN))
                continue;
            for (;;) {
                struct sockaddr_storage from;
                socklen_t flen = sizeof from;
                ssize_t len = recvfrom(pfd[idx].fd, pkt, sizeof pkt - 1, 0,
                                       (struct sockaddr *)&from, &flen);
                if (len < 0)
                    break;
                pkt[len] = '\0';
                if (socks[i].is_mdns) {
                    if (mdns)
                        mdns_handle(mdns, pkt, (size_t)len, &from, now);
                } else if (ssdp) {
                    ssdp_handle(ssdp, (const char *)pkt, (size_t)len, &from, now);
                }
            }
        }

        fetcher_step(fetcher, pfd + fetch_base, n - fetch_base, now);

        if (now >= next_expire) {
            store_expire(&store, now, DROP_AFTER_MS);
            next_expire = now + EXPIRE_EVERY_MS;
        }
    }

    if (ui)
        ui_destroy(ui);
    if (o.json)
        dump_json(&store, stdout);

    fetcher_destroy(fetcher);
    mdns_destroy(mdns);
    ssdp_destroy(ssdp);
    store_free(&store);
    if (mdns4 >= 0)
        close(mdns4);
    if (mdns6 >= 0)
        close(mdns6);
    if (ssdp4_listen >= 0)
        close(ssdp4_listen);
    if (ssdp4_search >= 0)
        close(ssdp4_search);
    if (ssdp6_listen >= 0)
        close(ssdp6_listen);
    if (ssdp6_search >= 0)
        close(ssdp6_search);
    log_close();
    return 0;
}
