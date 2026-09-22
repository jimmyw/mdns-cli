#include "neigh.h"

#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#ifdef __linux__
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#else
#include <net/if_dl.h>
#include <net/route.h>
#include <netinet/in.h>
#include <sys/sysctl.h>
#endif

#define MAC_STRLEN 18

typedef struct {
    addr_t addr;
    char mac[MAC_STRLEN];
} entry_t;

struct neigh_cache {
    entry_t *entries;
    size_t n, cap;
};

neigh_cache_t *neigh_new(void)
{
    return xcalloc(1, sizeof(neigh_cache_t));
}

void neigh_destroy(neigh_cache_t *nc)
{
    if (!nc)
        return;
    free(nc->entries);
    free(nc);
}

static void add_entry(neigh_cache_t *nc, const addr_t *a, const uint8_t *lladdr, size_t len)
{
    if (len != 6)
        return; /* only ethernet-style addresses are worth showing */
    if (nc->n == nc->cap) {
        nc->cap = nc->cap ? nc->cap * 2 : 64;
        nc->entries = xrealloc(nc->entries, nc->cap * sizeof *nc->entries);
    }
    entry_t *e = &nc->entries[nc->n++];
    e->addr = *a;
    snprintf(e->mac, sizeof e->mac, "%02x:%02x:%02x:%02x:%02x:%02x", lladdr[0], lladdr[1],
             lladdr[2], lladdr[3], lladdr[4], lladdr[5]);
}

#ifdef __linux__

#define DUMP_TIMEOUT_MS 150

static void parse_neigh(neigh_cache_t *nc, const struct nlmsghdr *nh)
{
    const struct ndmsg *nd = NLMSG_DATA(nh);
    /* A failed or still-resolving entry has no usable hardware address. */
    if (nd->ndm_state & (NUD_FAILED | NUD_INCOMPLETE | NUD_NONE))
        return;
    if (nd->ndm_family != AF_INET && nd->ndm_family != AF_INET6)
        return;

    const uint8_t *dst = NULL, *lladdr = NULL;
    size_t dstlen = 0, lllen = 0;
    size_t len = NLMSG_PAYLOAD(nh, sizeof *nd);
    for (const struct rtattr *rta = (const struct rtattr *)((const char *)nd + NLMSG_ALIGN(sizeof *nd));
         RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        if (rta->rta_type == NDA_DST) {
            dst = RTA_DATA(rta);
            dstlen = RTA_PAYLOAD(rta);
        } else if (rta->rta_type == NDA_LLADDR) {
            lladdr = RTA_DATA(rta);
            lllen = RTA_PAYLOAD(rta);
        }
    }
    if (!dst || !lladdr)
        return;

    addr_t a;
    if (nd->ndm_family == AF_INET) {
        if (dstlen != 4 || !addr_from_v4(&a, dst))
            return;
    } else {
        /* Link-local entries are per-interface, so carry the scope. */
        if (dstlen != 16 || !addr_from_v6(&a, dst, (unsigned)nd->ndm_ifindex))
            return;
    }
    add_entry(nc, &a, lladdr, lllen);
}

void neigh_refresh(neigh_cache_t *nc)
{
    nc->n = 0;

    int fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (fd < 0) {
        log_msg("neigh: netlink socket: %s", strerror(errno));
        return;
    }
    /* The dump is answered by the local kernel, so a short deadline is only a
       guard against the loop ever blocking on it. */
    struct timeval tv = {.tv_sec = 0, .tv_usec = DUMP_TIMEOUT_MS * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);

    struct {
        struct nlmsghdr nh;
        struct ndmsg nd;
    } req;
    memset(&req, 0, sizeof req);
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof req.nd);
    req.nh.nlmsg_type = RTM_GETNEIGH;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.nh.nlmsg_seq = 1;
    req.nd.ndm_family = AF_UNSPEC;

    if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) {
        log_msg("neigh: send: %s", strerror(errno));
        close(fd);
        return;
    }

    char buf[16384];
    bool done = false;
    while (!done) {
        ssize_t n = recv(fd, buf, sizeof buf, 0);
        if (n <= 0) {
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                log_msg("neigh: recv: %s", strerror(errno));
            break;
        }
        for (struct nlmsghdr *nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, (size_t)n);
             nh = NLMSG_NEXT(nh, n)) {
            if (nh->nlmsg_type == NLMSG_DONE) {
                done = true;
                break;
            }
            if (nh->nlmsg_type == NLMSG_ERROR) {
                const struct nlmsgerr *err = NLMSG_DATA(nh);
                log_msg("neigh: netlink error %d", err->error);
                done = true;
                break;
            }
            if (nh->nlmsg_type == RTM_NEWNEIGH)
                parse_neigh(nc, nh);
        }
    }
    close(fd);
}

#else /* BSD / macOS: no netlink, so read the routing table's ARP/NDP entries. */

/* Sockaddrs returned by the routing socket API are padded to a long boundary
   (an empty one still takes one long's worth of space). */
#define RTSOCK_ROUNDUP(a) ((a) > 0 ? (1 + (((a)-1) | (sizeof(long) - 1))) : sizeof(long))

static void scan_family(neigh_cache_t *nc, int af)
{
    int mib[6] = {CTL_NET, PF_ROUTE, 0, af, NET_RT_FLAGS, RTF_LLINFO};
    size_t needed = 0;
    if (sysctl(mib, 6, NULL, &needed, NULL, 0) != 0) {
        log_msg("neigh: sysctl size (af %d): %s", af, strerror(errno));
        return;
    }
    if (needed == 0)
        return;

    char *buf = xmalloc(needed);
    if (sysctl(mib, 6, buf, &needed, NULL, 0) != 0) {
        log_msg("neigh: sysctl dump (af %d): %s", af, strerror(errno));
        free(buf);
        return;
    }

    for (char *next = buf; next < buf + needed;) {
        struct rt_msghdr *rtm = (struct rt_msghdr *)next;
        if (rtm->rtm_msglen == 0)
            break;
        next += rtm->rtm_msglen;

        struct sockaddr *rti_info[RTAX_MAX];
        struct sockaddr *sa = (struct sockaddr *)(rtm + 1);
        for (int i = 0; i < RTAX_MAX; i++) {
            if (rtm->rtm_addrs & (1 << i)) {
                rti_info[i] = sa;
                sa = (struct sockaddr *)((char *)sa + RTSOCK_ROUNDUP(sa->sa_len));
            } else {
                rti_info[i] = NULL;
            }
        }

        struct sockaddr *dst = rti_info[RTAX_DST];
        struct sockaddr *gw = rti_info[RTAX_GATEWAY];
        if (!dst || !gw || gw->sa_family != AF_LINK)
            continue;
        struct sockaddr_dl *sdl = (struct sockaddr_dl *)gw;
        if (sdl->sdl_alen != 6)
            continue;
        const uint8_t *lladdr = (const uint8_t *)LLADDR(sdl);

        addr_t a;
        if (af == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)dst;
            if (!addr_from_v4(&a, (const uint8_t *)&sin->sin_addr))
                continue;
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)dst;
            struct in6_addr addr6 = sin6->sin6_addr;
            /* The kernel embeds the outgoing interface index in bytes 2-3 of
               a link-local address handed back over a routing socket; strip
               it back out and carry the real scope separately. */
            unsigned scope = (unsigned)rtm->rtm_index;
            if (IN6_IS_ADDR_LINKLOCAL(&addr6)) {
                addr6.s6_addr[2] = 0;
                addr6.s6_addr[3] = 0;
            }
            if (!addr_from_v6(&a, (const uint8_t *)&addr6, scope))
                continue;
        }
        add_entry(nc, &a, lladdr, sdl->sdl_alen);
    }
    free(buf);
}

void neigh_refresh(neigh_cache_t *nc)
{
    nc->n = 0;
    scan_family(nc, AF_INET);
    scan_family(nc, AF_INET6);
}

#endif

const char *neigh_lookup(const neigh_cache_t *nc, const addr_t *a)
{
    for (size_t i = 0; i < nc->n; i++)
        if (addr_equal(&nc->entries[i].addr, a))
            return nc->entries[i].mac;
    return NULL;
}

size_t neigh_apply(neigh_cache_t *nc, store_t *store)
{
    size_t changed = 0;
    for (device_t *d = store->head; d; d = d->next) {
        for (size_t i = 0; i < d->n_addrs; i++) {
            const char *mac = neigh_lookup(nc, &d->addrs[i]);
            if (!mac || strcmp(d->mac, mac) == 0)
                continue;
            snprintf(d->mac, sizeof d->mac, "%s", mac);
            changed++;
            break; /* one hardware address per device is enough */
        }
    }
    if (changed)
        store_touch(store);
    return changed;
}
