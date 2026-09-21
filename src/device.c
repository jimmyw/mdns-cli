#include "device.h"

#include "dns.h"
#include "util.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const char *sort_name(sort_mode_t m)
{
    switch (m) {
    case SORT_ADDR:
        return "address";
    case SORT_NAME:
        return "name";
    case SORT_LAST_SEEN:
        return "last seen";
    case SORT_SOURCE:
        return "source";
    default:
        return "?";
    }
}

static void addr_render(addr_t *a)
{
    char tmp[INET6_ADDRSTRLEN];
    if (a->family == AF_INET) {
        inet_ntop(AF_INET, &a->a.v4, tmp, sizeof tmp);
        snprintf(a->str, sizeof a->str, "%s", tmp);
        return;
    }
    inet_ntop(AF_INET6, &a->a.v6, tmp, sizeof tmp);
    char ifname[IF_NAMESIZE];
    if (a->scope_id && IN6_IS_ADDR_LINKLOCAL(&a->a.v6) && if_indextoname(a->scope_id, ifname))
        snprintf(a->str, sizeof a->str, "%s%%%s", tmp, ifname);
    else
        snprintf(a->str, sizeof a->str, "%s", tmp);
}

bool addr_from_v4(addr_t *out, const uint8_t b[4])
{
    memset(out, 0, sizeof *out);
    out->family = AF_INET;
    memcpy(&out->a.v4, b, 4);
    if (out->a.v4.s_addr == 0)
        return false;
    addr_render(out);
    return true;
}

bool addr_from_v6(addr_t *out, const uint8_t b[16], unsigned scope_id)
{
    memset(out, 0, sizeof *out);
    out->family = AF_INET6;
    memcpy(&out->a.v6, b, 16);
    if (IN6_IS_ADDR_UNSPECIFIED(&out->a.v6))
        return false;
    out->scope_id = IN6_IS_ADDR_LINKLOCAL(&out->a.v6) ? scope_id : 0;
    addr_render(out);
    return true;
}

bool addr_from_sockaddr(addr_t *out, const struct sockaddr_storage *ss)
{
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *s = (const struct sockaddr_in *)ss;
        return addr_from_v4(out, (const uint8_t *)&s->sin_addr);
    }
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *s = (const struct sockaddr_in6 *)ss;
        return addr_from_v6(out, (const uint8_t *)&s->sin6_addr, s->sin6_scope_id);
    }
    return false;
}

bool addr_equal(const addr_t *a, const addr_t *b)
{
    if (a->family != b->family)
        return false;
    if (a->family == AF_INET)
        return a->a.v4.s_addr == b->a.v4.s_addr;
    if (memcmp(&a->a.v6, &b->a.v6, 16) != 0)
        return false;
    /* Two link-local addresses on different interfaces are different hosts. */
    if (IN6_IS_ADDR_LINKLOCAL(&a->a.v6) && a->scope_id && b->scope_id)
        return a->scope_id == b->scope_id;
    return true;
}

void store_init(store_t *s)
{
    memset(s, 0, sizeof *s);
    s->next_id = 1;
}

void store_touch(store_t *s)
{
    s->generation++;
}

static void txt_free(txt_pair_t *t)
{
    while (t) {
        txt_pair_t *next = t->next;
        free(t->key);
        free(t->val);
        free(t);
        t = next;
    }
}

static void service_free(service_t *sv)
{
    free(sv->fqdn);
    free(sv->instance);
    free(sv->type);
    free(sv->host);
    txt_free(sv->txt);
    free(sv);
}

static void ssdp_free(ssdp_entry_t *e)
{
    free(e->usn);
    free(e->st);
    free(e->server);
    free(e->location);
    free(e->fetch_error);
    free(e->friendly_name);
    free(e->manufacturer);
    free(e->model_name);
    free(e->model_number);
    free(e->serial);
    free(e->udn);
    free(e);
}

static void device_free(device_t *d)
{
    service_t *sv = d->services;
    while (sv) {
        service_t *next = sv->next;
        service_free(sv);
        sv = next;
    }
    ssdp_entry_t *e = d->ssdp;
    while (e) {
        ssdp_entry_t *next = e->next;
        ssdp_free(e);
        e = next;
    }
    free(d->hostname);
    free(d);
}

void store_clear(store_t *s)
{
    device_t *d = s->head;
    while (d) {
        device_t *next = d->next;
        device_free(d);
        d = next;
    }
    s->head = NULL;
    s->n_devices = 0;
    s->generation++;
}

void store_free(store_t *s)
{
    store_clear(s);
}

device_t *store_find_id(store_t *s, unsigned id)
{
    for (device_t *d = s->head; d; d = d->next)
        if (d->id == id)
            return d;
    return NULL;
}

device_t *store_find_addr(store_t *s, const addr_t *a)
{
    for (device_t *d = s->head; d; d = d->next)
        for (size_t i = 0; i < d->n_addrs; i++)
            if (addr_equal(&d->addrs[i], a))
                return d;
    return NULL;
}

device_t *store_find_host(store_t *s, const char *host)
{
    if (!host || !*host)
        return NULL;
    for (device_t *d = s->head; d; d = d->next)
        if (d->hostname && str_casecmp(d->hostname, host) == 0)
            return d;
    return NULL;
}

static device_t *device_new(store_t *s, uint64_t now, unsigned source)
{
    device_t *d = xcalloc(1, sizeof *d);
    d->id = s->next_id++;
    d->first_seen = now;
    d->last_seen = now;
    d->sources = source;
    d->next = s->head;
    s->head = d;
    s->n_devices++;
    s->generation++;
    return d;
}

static void device_unlink(store_t *s, device_t *victim)
{
    device_t **pp = &s->head;
    while (*pp) {
        if (*pp == victim) {
            *pp = victim->next;
            s->n_devices--;
            return;
        }
        pp = &(*pp)->next;
    }
}

/* Fold src into dst and free src. */
static device_t *device_merge(store_t *s, device_t *dst, device_t *src)
{
    if (dst == src)
        return dst;
    for (size_t i = 0; i < src->n_addrs && dst->n_addrs < MAX_ADDRS; i++) {
        bool dup = false;
        for (size_t j = 0; j < dst->n_addrs; j++)
            dup = dup || addr_equal(&dst->addrs[j], &src->addrs[i]);
        if (!dup)
            dst->addrs[dst->n_addrs++] = src->addrs[i];
    }
    if (!dst->hostname && src->hostname) {
        dst->hostname = src->hostname;
        src->hostname = NULL;
    }
    /* Move services, skipping ones dst already knows. */
    service_t *sv = src->services;
    while (sv) {
        service_t *next = sv->next;
        service_t *existing = NULL;
        for (service_t *o = dst->services; o; o = o->next)
            if (strcmp(o->fqdn, sv->fqdn) == 0)
                existing = o;
        if (existing) {
            service_free(sv);
        } else {
            sv->next = dst->services;
            dst->services = sv;
            dst->n_services++;
        }
        sv = next;
    }
    src->services = NULL;
    src->n_services = 0;

    ssdp_entry_t *e = src->ssdp;
    while (e) {
        ssdp_entry_t *next = e->next;
        ssdp_entry_t *existing = NULL;
        for (ssdp_entry_t *o = dst->ssdp; o; o = o->next)
            if (o->usn && e->usn && strcmp(o->usn, e->usn) == 0)
                existing = o;
        if (existing) {
            ssdp_free(e);
        } else {
            e->next = dst->ssdp;
            dst->ssdp = e;
            dst->n_ssdp++;
        }
        e = next;
    }
    src->ssdp = NULL;
    src->n_ssdp = 0;

    dst->sources |= src->sources;
    dst->expanded = dst->expanded || src->expanded;
    if (src->first_seen < dst->first_seen)
        dst->first_seen = src->first_seen;
    if (src->last_seen > dst->last_seen)
        dst->last_seen = src->last_seen;

    device_unlink(s, src);
    device_free(src);
    s->generation++;
    return dst;
}

device_t *store_add_addr(store_t *s, device_t *d, const addr_t *a, uint64_t now)
{
    device_t *owner = store_find_addr(s, a);
    if (owner && owner != d)
        return device_merge(s, owner, d); /* the addressed device wins */
    for (size_t i = 0; i < d->n_addrs; i++)
        if (addr_equal(&d->addrs[i], a)) {
            d->last_seen = now;
            return d;
        }
    if (d->n_addrs < MAX_ADDRS) {
        d->addrs[d->n_addrs++] = *a;
        s->generation++;
    }
    d->last_seen = now;
    return d;
}

device_t *store_set_host(store_t *s, device_t *d, const char *host, uint64_t now)
{
    if (!host || !*host)
        return d;
    device_t *owner = store_find_host(s, host);
    if (owner && owner != d) {
        /* Keep whichever side already has addresses. */
        device_t *dst = d->n_addrs ? d : owner;
        device_t *src = dst == d ? owner : d;
        d = device_merge(s, dst, src);
    }
    if (!d->hostname || str_casecmp(d->hostname, host) != 0) {
        str_set(&d->hostname, host);
        s->generation++;
    }
    d->last_seen = now;
    return d;
}

device_t *store_device_for_addr(store_t *s, const addr_t *a, uint64_t now, unsigned source)
{
    device_t *d = store_find_addr(s, a);
    if (!d) {
        d = device_new(s, now, source);
        d->addrs[d->n_addrs++] = *a;
    }
    d->sources |= source;
    d->last_seen = now;
    return d;
}

device_t *store_device_for_host(store_t *s, const char *host, uint64_t now, unsigned source)
{
    device_t *d = store_find_host(s, host);
    if (!d) {
        d = device_new(s, now, source);
        d->hostname = xstrdup(host);
    }
    d->sources |= source;
    d->last_seen = now;
    return d;
}

service_t *device_service(store_t *s, device_t *d, const char *fqdn, uint64_t now)
{
    for (service_t *sv = d->services; sv; sv = sv->next)
        if (strcmp(sv->fqdn, fqdn) == 0) {
            sv->last_seen = now;
            return sv;
        }
    service_t *sv = xcalloc(1, sizeof *sv);
    sv->fqdn = xstrdup(fqdn);
    char instance[DNS_MAX_NAME], type[128], pretty[DNS_MAX_NAME];
    if (dns_split_instance(fqdn, instance, sizeof instance, type, sizeof type) == 0) {
        dns_unescape(instance, pretty, sizeof pretty);
        sv->instance = xstrdup(pretty);
        sv->type = xstrdup(type);
    } else {
        dns_unescape(fqdn, pretty, sizeof pretty);
        sv->instance = xstrdup(pretty);
        sv->type = xstrdup("");
    }
    sv->last_seen = now;
    sv->next = d->services;
    d->services = sv;
    d->n_services++;
    d->sources |= SRC_MDNS;
    s->generation++;
    return sv;
}

void service_clear_txt(service_t *sv)
{
    txt_free(sv->txt);
    sv->txt = NULL;
    sv->n_txt = 0;
}

void service_set_txt(service_t *sv, const char *pair, size_t len)
{
    const char *eq = memchr(pair, '=', len);
    char *key = xstrndup(pair, eq ? (size_t)(eq - pair) : len);
    str_sanitize(key);
    char *val = eq ? str_display(eq + 1, len - (size_t)(eq - pair) - 1) : NULL;

    for (txt_pair_t *t = sv->txt; t; t = t->next) {
        if (strcmp(t->key, key) == 0) {
            free(t->val);
            t->val = val;
            free(key);
            return;
        }
    }
    txt_pair_t *t = xcalloc(1, sizeof *t);
    t->key = key;
    t->val = val;
    /* Append so the device's own ordering is preserved. */
    txt_pair_t **pp = &sv->txt;
    while (*pp)
        pp = &(*pp)->next;
    *pp = t;
    sv->n_txt++;
}

ssdp_entry_t *device_ssdp(store_t *s, device_t *d, const char *usn, const char *st, uint64_t now)
{
    for (ssdp_entry_t *e = d->ssdp; e; e = e->next) {
        bool same = usn && e->usn ? strcmp(e->usn, usn) == 0
                                  : (st && e->st && strcmp(e->st, st) == 0);
        if (same) {
            e->last_seen = now;
            d->last_seen = now;
            return e;
        }
    }
    ssdp_entry_t *e = xcalloc(1, sizeof *e);
    e->usn = xstrdup(usn ? usn : "");
    e->st = xstrdup(st ? st : "");
    e->last_seen = now;
    e->next = d->ssdp;
    d->ssdp = e;
    d->n_ssdp++;
    d->sources |= SRC_SSDP;
    d->last_seen = now;
    s->generation++;
    return e;
}

service_t *store_find_service(store_t *s, const char *fqdn, device_t **owner)
{
    for (device_t *d = s->head; d; d = d->next)
        for (service_t *sv = d->services; sv; sv = sv->next)
            if (strcmp(sv->fqdn, fqdn) == 0) {
                if (owner)
                    *owner = d;
                return sv;
            }
    return NULL;
}

ssdp_entry_t *store_find_ssdp(store_t *s, const char *usn, device_t **owner)
{
    if (!usn || !*usn)
        return NULL;
    for (device_t *d = s->head; d; d = d->next)
        for (ssdp_entry_t *e = d->ssdp; e; e = e->next)
            if (e->usn && strcmp(e->usn, usn) == 0) {
                if (owner)
                    *owner = d;
                return e;
            }
    return NULL;
}

device_t *store_find_udn(store_t *s, const char *uuid)
{
    if (!uuid || !*uuid)
        return NULL;
    size_t n = strlen(uuid);
    for (device_t *d = s->head; d; d = d->next)
        for (ssdp_entry_t *e = d->ssdp; e; e = e->next)
            if (e->usn && str_ncasecmp(e->usn, uuid, n) == 0 &&
                (e->usn[n] == '\0' || e->usn[n] == ':'))
                return d;
    return NULL;
}

void device_drop_service(store_t *s, device_t *d, const char *fqdn)
{
    service_t **pp = &d->services;
    while (*pp) {
        if (strcmp((*pp)->fqdn, fqdn) == 0) {
            service_t *dead = *pp;
            *pp = dead->next;
            service_free(dead);
            d->n_services--;
            s->generation++;
            return;
        }
        pp = &(*pp)->next;
    }
}

void device_drop_ssdp(store_t *s, device_t *d, const char *usn)
{
    ssdp_entry_t **pp = &d->ssdp;
    while (*pp) {
        if ((*pp)->usn && strcmp((*pp)->usn, usn) == 0) {
            ssdp_entry_t *dead = *pp;
            *pp = dead->next;
            ssdp_free(dead);
            d->n_ssdp--;
            s->generation++;
            return;
        }
        pp = &(*pp)->next;
    }
}

void store_expire(store_t *s, uint64_t now, uint64_t drop_ms)
{
    device_t **pp = &s->head;
    while (*pp) {
        device_t *d = *pp;
        bool empty = d->n_services == 0 && d->n_ssdp == 0 && d->n_addrs == 0;
        if (now - d->last_seen > drop_ms || empty) {
            *pp = d->next;
            device_free(d);
            s->n_devices--;
            s->generation++;
            continue;
        }
        pp = &d->next;
    }
}

size_t store_total_services(const store_t *s)
{
    size_t n = 0;
    for (device_t *d = s->head; d; d = d->next)
        n += d->n_services + d->n_ssdp;
    return n;
}

const char *device_label(const device_t *d)
{
    if (d->hostname && *d->hostname)
        return d->hostname;
    for (ssdp_entry_t *e = d->ssdp; e; e = e->next)
        if (e->friendly_name && *e->friendly_name)
            return e->friendly_name;
    for (service_t *sv = d->services; sv; sv = sv->next)
        if (sv->instance && *sv->instance)
            return sv->instance;
    return "(unnamed)";
}

const char *device_primary_addr(const device_t *d)
{
    for (size_t i = 0; i < d->n_addrs; i++)
        if (d->addrs[i].family == AF_INET)
            return d->addrs[i].str;
    if (d->n_addrs)
        return d->addrs[0].str;
    return "(unresolved)";
}

void device_sources_str(const device_t *d, char *out, size_t outsz)
{
    snprintf(out, outsz, "%s%s%s", (d->sources & SRC_MDNS) ? "mDNS" : "",
             (d->sources == (SRC_MDNS | SRC_SSDP)) ? "+" : "",
             (d->sources & SRC_SSDP) ? "SSDP" : "");
}

bool device_matches(const device_t *d, const char *filter)
{
    if (!filter || !*filter)
        return true;
    if (str_icontains(d->hostname, filter))
        return true;
    for (size_t i = 0; i < d->n_addrs; i++)
        if (str_icontains(d->addrs[i].str, filter))
            return true;
    for (service_t *sv = d->services; sv; sv = sv->next) {
        if (str_icontains(sv->instance, filter) || str_icontains(sv->type, filter))
            return true;
        for (txt_pair_t *t = sv->txt; t; t = t->next)
            if (str_icontains(t->key, filter) || str_icontains(t->val, filter))
                return true;
    }
    for (ssdp_entry_t *e = d->ssdp; e; e = e->next)
        if (str_icontains(e->st, filter) || str_icontains(e->server, filter) ||
            str_icontains(e->friendly_name, filter) || str_icontains(e->model_name, filter) ||
            str_icontains(e->manufacturer, filter))
            return true;
    return false;
}

static sort_mode_t g_sort;

static int addr_key(const device_t *d, uint8_t out[17])
{
    /* v4 sorts before v6, numerically within family. */
    memset(out, 0, 17);
    for (size_t i = 0; i < d->n_addrs; i++)
        if (d->addrs[i].family == AF_INET) {
            out[0] = 0;
            memcpy(out + 1, &d->addrs[i].a.v4, 4);
            return 0;
        }
    if (d->n_addrs) {
        out[0] = 1;
        memcpy(out + 1, &d->addrs[0].a.v6, 16);
        return 0;
    }
    out[0] = 2; /* unresolved last */
    return 0;
}

static int cmp_dev(const void *pa, const void *pb)
{
    const device_t *a = *(device_t *const *)pa;
    const device_t *b = *(device_t *const *)pb;
    int r = 0;
    switch (g_sort) {
    case SORT_NAME:
        r = str_casecmp(device_label(a), device_label(b));
        break;
    case SORT_LAST_SEEN:
        r = a->last_seen == b->last_seen ? 0 : (a->last_seen > b->last_seen ? -1 : 1);
        break;
    case SORT_SOURCE:
        r = (int)b->sources - (int)a->sources;
        break;
    case SORT_ADDR:
    default:
        break;
    }
    if (r == 0) {
        uint8_t ka[17], kb[17];
        addr_key(a, ka);
        addr_key(b, kb);
        r = memcmp(ka, kb, 17);
    }
    if (r == 0)
        r = (int)a->id - (int)b->id;
    return r;
}

device_t **store_snapshot(store_t *s, sort_mode_t mode, const char *filter, size_t *count)
{
    device_t **arr = xcalloc(s->n_devices ? s->n_devices : 1, sizeof *arr);
    size_t n = 0;
    for (device_t *d = s->head; d; d = d->next)
        if (device_matches(d, filter))
            arr[n++] = d;
    g_sort = mode;
    qsort(arr, n, sizeof *arr, cmp_dev);
    *count = n;
    return arr;
}
