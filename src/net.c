#include "net.h"

#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

int net_socket(int domain, int type, int protocol)
{
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    return socket(domain, type | SOCK_CLOEXEC | SOCK_NONBLOCK, protocol);
#else
    int fd = socket(domain, type, protocol);
    if (fd < 0)
        return -1;
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, (flags < 0 ? 0 : flags) | O_NONBLOCK);
    return fd;
#endif
}

static bool name_wanted(const char *name, char *const *filter, size_t nfilter)
{
    if (nfilter == 0)
        return true;
    for (size_t i = 0; i < nfilter; i++)
        if (strcmp(name, filter[i]) == 0)
            return true;
    return false;
}

static iface_t *find_or_add(iface_t *out, size_t *n, size_t max, const char *name)
{
    for (size_t i = 0; i < *n; i++)
        if (strcmp(out[i].name, name) == 0)
            return &out[i];
    if (*n >= max)
        return NULL;
    iface_t *ifc = &out[(*n)++];
    memset(ifc, 0, sizeof *ifc);
    snprintf(ifc->name, sizeof ifc->name, "%s", name);
    ifc->index = if_nametoindex(name);
    return ifc;
}

ssize_t net_enum_ifaces(iface_t *out, size_t max, bool include_loopback, char *const *filter,
                        size_t nfilter)
{
    struct ifaddrs *list = NULL;
    if (getifaddrs(&list) != 0)
        return -1;

    size_t n = 0;
    for (struct ifaddrs *ia = list; ia; ia = ia->ifa_next) {
        if (!ia->ifa_addr || !(ia->ifa_flags & IFF_UP) || !(ia->ifa_flags & IFF_MULTICAST))
            continue;
        bool lo = (ia->ifa_flags & IFF_LOOPBACK) != 0;
        if (lo && !include_loopback)
            continue;
        if (!name_wanted(ia->ifa_name, filter, nfilter))
            continue;

        if (ia->ifa_addr->sa_family == AF_INET) {
            iface_t *ifc = find_or_add(out, &n, max, ia->ifa_name);
            if (!ifc)
                break;
            ifc->loopback = lo;
            ifc->has_v4 = true;
            ifc->v4 = ((struct sockaddr_in *)ia->ifa_addr)->sin_addr;
        } else if (ia->ifa_addr->sa_family == AF_INET6) {
            struct sockaddr_in6 *s6 = (struct sockaddr_in6 *)ia->ifa_addr;
            iface_t *ifc = find_or_add(out, &n, max, ia->ifa_name);
            if (!ifc)
                break;
            ifc->loopback = lo;
            /* Prefer the link-local address; that is the mDNS source. */
            if (!ifc->has_v6 || IN6_IS_ADDR_LINKLOCAL(&s6->sin6_addr)) {
                ifc->has_v6 = true;
                ifc->v6 = s6->sin6_addr;
            }
        }
    }
    freeifaddrs(list);

    /* An interface with no index cannot be used for per-interface multicast. */
    size_t keep = 0;
    for (size_t i = 0; i < n; i++)
        if (out[i].index != 0)
            out[keep++] = out[i];
    return (ssize_t)keep;
}

static int set_reuse(int fd)
{
    int on = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on) != 0)
        return -1;
#ifdef SO_REUSEPORT
    /* avahi-daemon (and every browser) already holds 5353; without this the
       bind fails outright. */
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof on) != 0)
        return -1;
#endif
    return 0;
}

int net_open_v4(uint16_t bind_port, const char *group, const iface_t *ifs, size_t n, bool join)
{
    int fd = net_socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    if (set_reuse(fd) != 0)
        goto fail;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(bind_port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0)
        goto fail;

    int ttl = 255, loop = 1;
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof ttl);
    setsockopt(fd, IPPROTO_IP, IP_MULTICAST_LOOP, &loop, sizeof loop);

    if (join) {
        struct in_addr ga;
        if (inet_pton(AF_INET, group, &ga) != 1)
            goto fail;
        size_t joined = 0;
        for (size_t i = 0; i < n; i++) {
            if (!ifs[i].has_v4)
                continue;
            struct ip_mreq mreq;
            memset(&mreq, 0, sizeof mreq);
            mreq.imr_multiaddr = ga;
            mreq.imr_interface = ifs[i].v4;
            if (setsockopt(fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof mreq) != 0)
                log_msg("v4 join %s on %s failed: %s", group, ifs[i].name, strerror(errno));
            else
                joined++;
        }
        if (joined == 0)
            log_msg("v4 %s: no interface joined", group);
    }
    return fd;

fail: {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
}
}

int net_open_v6(uint16_t bind_port, const char *group, const iface_t *ifs, size_t n, bool join)
{
    int fd = net_socket(AF_INET6, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;
    int on = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &on, sizeof on) != 0)
        goto fail;
    if (set_reuse(fd) != 0)
        goto fail;

    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_any;
    sa.sin6_port = htons(bind_port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) != 0)
        goto fail;

    int hops = 255, loop = 1;
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_HOPS, &hops, sizeof hops);
    setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_LOOP, &loop, sizeof loop);
    setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof on);

    if (join) {
        struct ipv6_mreq mreq;
        memset(&mreq, 0, sizeof mreq);
        if (inet_pton(AF_INET6, group, &mreq.ipv6mr_multiaddr) != 1)
            goto fail;
        size_t joined = 0;
        for (size_t i = 0; i < n; i++) {
            if (!ifs[i].has_v6)
                continue;
            mreq.ipv6mr_interface = ifs[i].index;
            if (setsockopt(fd, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof mreq) != 0)
                log_msg("v6 join %s on %s failed: %s", group, ifs[i].name, strerror(errno));
            else
                joined++;
        }
        if (joined == 0)
            log_msg("v6 %s: no interface joined", group);
    }
    return fd;

fail: {
    int e = errno;
    close(fd);
    errno = e;
    return -1;
}
}

ssize_t net_send_v4(int fd, const iface_t *ifc, const void *buf, size_t len, const char *group,
                    uint16_t port)
{
    if (setsockopt(fd, IPPROTO_IP, IP_MULTICAST_IF, &ifc->v4, sizeof ifc->v4) != 0)
        return -1;

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(port);
    if (inet_pton(AF_INET, group, &dst.sin_addr) != 1)
        return -1;
    return sendto(fd, buf, len, 0, (struct sockaddr *)&dst, sizeof dst);
}

ssize_t net_send_v6(int fd, const iface_t *ifc, const void *buf, size_t len, const char *group,
                    uint16_t port)
{
    unsigned idx = ifc->index;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_MULTICAST_IF, &idx, sizeof idx) != 0)
        return -1;

    struct sockaddr_in6 dst;
    memset(&dst, 0, sizeof dst);
    dst.sin6_family = AF_INET6;
    dst.sin6_port = htons(port);
    dst.sin6_scope_id = idx;
    if (inet_pton(AF_INET6, group, &dst.sin6_addr) != 1)
        return -1;
    return sendto(fd, buf, len, 0, (struct sockaddr *)&dst, sizeof dst);
}
