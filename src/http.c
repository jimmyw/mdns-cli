#include "http.h"

#include "net.h"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAX_REDIRECTS 1

typedef enum {
    ST_CONNECTING,
    ST_SENDING,
    ST_READING,
    ST_DONE,
    ST_FAILED,
} state_t;

struct http_req {
    int fd;
    state_t state;
    char *host;   /* for the Host: header */
    uint16_t port;
    char *path;
    char *override_ip;
    char *req;
    size_t req_len, req_sent;
    char *buf;
    size_t buf_len, buf_cap, max_body;
    bool headers_done; /* once true, buf holds body bytes only */
    long content_length;
    bool chunked;
    uint64_t deadline;
    uint64_t timeout_ms;
    int redirects;
    char *error;
    void *user;
};

static void fail(http_req_t *r, const char *msg)
{
    if (!r->error)
        r->error = xstrdup(msg);
    if (r->fd >= 0) {
        close(r->fd);
        r->fd = -1;
    }
    r->state = ST_FAILED;
}

/* Parse "http://host[:port][/path]". Returns false on anything else. */
static bool parse_url(const char *url, char **host, uint16_t *port, char **path)
{
    if (str_ncasecmp(url, "http://", 7) != 0)
        return false;
    const char *p = url + 7;
    const char *hstart = p;
    const char *hend;
    if (*p == '[') {
        hstart = ++p;
        while (*p && *p != ']')
            p++;
        if (*p != ']')
            return false;
        hend = p++;
    } else {
        while (*p && *p != ':' && *p != '/')
            p++;
        hend = p;
    }
    if (hend == hstart)
        return false;
    unsigned long prt = 80;
    if (*p == ':') {
        char *end = NULL;
        prt = strtoul(p + 1, &end, 10);
        if (!end || prt == 0 || prt > 65535)
            return false;
        p = end;
    }
    *host = xstrndup(hstart, (size_t)(hend - hstart));
    *port = (uint16_t)prt;
    *path = xstrdup((*p == '/') ? p : "/");
    return true;
}

static void build_request(http_req_t *r)
{
    char hostport[300];
    bool literal_v6 = strchr(r->host, ':') != NULL;
    if (r->port == 80)
        snprintf(hostport, sizeof hostport, literal_v6 ? "[%s]" : "%s", r->host);
    else
        snprintf(hostport, sizeof hostport, literal_v6 ? "[%s]:%u" : "%s:%u", r->host, r->port);

    size_t cap = strlen(r->path) + sizeof hostport + 160;
    char *req = xmalloc(cap);
    int n = snprintf(req, cap,
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "User-Agent: mdns-cli/1.0\r\n"
                     "Accept: text/xml, */*\r\n"
                     "Connection: close\r\n"
                     "\r\n",
                     r->path, hostport);
    free(r->req);
    r->req = req;
    r->req_len = (size_t)(n > 0 ? n : 0);
    r->req_sent = 0;
}

/* Fill ss from a literal address, honouring a "%iface" scope suffix: a
   link-local IPv6 LOCATION is unroutable without one. */
static bool literal_addr(const char *text, uint16_t port, struct sockaddr_storage *ss,
                         socklen_t *slen)
{
    struct in_addr v4;
    if (inet_pton(AF_INET, text, &v4) == 1) {
        struct sockaddr_in *s = (struct sockaddr_in *)ss;
        s->sin_family = AF_INET;
        s->sin_addr = v4;
        s->sin_port = htons(port);
        *slen = sizeof *s;
        return true;
    }

    char buf[INET6_ADDRSTRLEN + IF_NAMESIZE + 2];
    snprintf(buf, sizeof buf, "%s", text);
    unsigned scope = 0;
    char *pct = strchr(buf, '%');
    if (pct) {
        *pct++ = '\0';
        scope = if_nametoindex(pct);
        if (!scope)
            scope = (unsigned)strtoul(pct, NULL, 10);
    }
    struct in6_addr v6;
    if (inet_pton(AF_INET6, buf, &v6) != 1)
        return false;
    struct sockaddr_in6 *s = (struct sockaddr_in6 *)ss;
    s->sin6_family = AF_INET6;
    s->sin6_addr = v6;
    s->sin6_port = htons(port);
    s->sin6_scope_id = scope;
    *slen = sizeof *s;
    return true;
}

static bool start_connect(http_req_t *r)
{
    /* The host in a UPnP LOCATION is virtually always a literal address; refuse
       to do a blocking name lookup in the middle of the event loop. */
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    socklen_t slen = 0;

    if (!literal_addr(r->host, r->port, &ss, &slen) &&
        !(r->override_ip && literal_addr(r->override_ip, r->port, &ss, &slen))) {
        fail(r, "host is not a literal address");
        return false;
    }

    r->fd = net_socket(ss.ss_family, SOCK_STREAM, 0);
    if (r->fd < 0) {
        fail(r, strerror(errno));
        return false;
    }
    if (connect(r->fd, (struct sockaddr *)&ss, slen) != 0 && errno != EINPROGRESS) {
        fail(r, strerror(errno));
        return false;
    }
    r->state = ST_CONNECTING;
    return true;
}

http_req_t *http_get(const char *url, const char *override_ip, size_t max_body,
                     uint64_t timeout_ms, void *user)
{
    http_req_t *r = xcalloc(1, sizeof *r);
    r->fd = -1;
    r->user = user;
    r->max_body = max_body;
    r->content_length = -1;
    r->timeout_ms = timeout_ms;
    r->deadline = now_ms() + timeout_ms;
    r->override_ip = xstrdup(override_ip);

    if (!parse_url(url, &r->host, &r->port, &r->path)) {
        fail(r, "unsupported URL");
        return r;
    }
    build_request(r);
    start_connect(r);
    return r;
}

int http_fd(const http_req_t *r)
{
    return r->fd;
}

short http_poll_events(const http_req_t *r)
{
    switch (r->state) {
    case ST_CONNECTING:
    case ST_SENDING:
        return POLLOUT;
    case ST_READING:
        return POLLIN;
    default:
        return 0;
    }
}

uint64_t http_deadline(const http_req_t *r)
{
    return r->deadline;
}

void *http_user(const http_req_t *r)
{
    return r->user;
}

static void buf_reserve(http_req_t *r, size_t extra)
{
    if (r->buf_len + extra <= r->buf_cap)
        return;
    size_t cap = r->buf_cap ? r->buf_cap * 2 : 4096;
    while (cap < r->buf_len + extra)
        cap *= 2;
    r->buf = xrealloc(r->buf, cap);
    r->buf_cap = cap;
}

/* Case-insensitive header lookup within the header block. */
static const char *find_header(const char *hdr, size_t hlen, const char *name, size_t *vlen)
{
    size_t nlen = strlen(name);
    const char *p = hdr;
    const char *end = hdr + hlen;
    /* Skip the status line. */
    while (p < end && *p != '\n')
        p++;
    if (p < end)
        p++;
    while (p < end) {
        const char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol)
            eol = end;
        if ((size_t)(eol - p) > nlen && str_ncasecmp(p, name, nlen) == 0 && p[nlen] == ':') {
            const char *v = p + nlen + 1;
            while (v < eol && (*v == ' ' || *v == '\t'))
                v++;
            const char *ve = eol;
            while (ve > v && (ve[-1] == '\r' || ve[-1] == ' '))
                ve--;
            *vlen = (size_t)(ve - v);
            return v;
        }
        p = eol + 1;
    }
    return NULL;
}

static int restart_with_redirect(http_req_t *r, const char *loc, size_t loclen)
{
    if (r->redirects >= MAX_REDIRECTS) {
        fail(r, "too many redirects");
        return -1;
    }
    char *url = xstrndup(loc, loclen);
    char *host = NULL, *path = NULL;
    uint16_t port = 80;
    bool ok = parse_url(url, &host, &port, &path);
    free(url);
    if (!ok) {
        fail(r, "bad redirect target");
        return -1;
    }
    r->redirects++;
    close(r->fd);
    r->fd = -1;
    free(r->host);
    free(r->path);
    r->host = host;
    r->path = path;
    r->port = port;
    r->buf_len = 0;
    r->headers_done = false;
    r->content_length = -1;
    r->chunked = false;
    r->deadline = now_ms() + r->timeout_ms;
    build_request(r);
    return start_connect(r) ? 0 : -1;
}

/* De-chunk in place once the whole body has arrived. */
static bool dechunk(http_req_t *r)
{
    char *p = r->buf;
    char *end = r->buf + r->buf_len;
    char *out = p;
    while (p < end) {
        char *eol = memchr(p, '\n', (size_t)(end - p));
        if (!eol)
            return false;
        unsigned long n = strtoul(p, NULL, 16);
        p = eol + 1;
        if (n == 0)
            break;
        if ((size_t)(end - p) < n)
            return false;
        memmove(out, p, n);
        out += n;
        p += n;
        if (p < end && *p == '\r')
            p++;
        if (p < end && *p == '\n')
            p++;
    }
    r->buf_len = (size_t)(out - r->buf);
    return true;
}

static int finish(http_req_t *r)
{
    if (!r->headers_done) {
        fail(r, "no HTTP headers in response");
        return -1;
    }
    if (r->chunked && !dechunk(r)) {
        fail(r, "malformed chunked body");
        return -1;
    }
    buf_reserve(r, 1);
    r->buf[r->buf_len] = '\0';
    if (r->fd >= 0) {
        close(r->fd);
        r->fd = -1;
    }
    r->state = ST_DONE;
    return 1;
}

static int on_readable(http_req_t *r)
{
    for (;;) {
        buf_reserve(r, 4096 + 1);
        ssize_t n = recv(r->fd, r->buf + r->buf_len, 4096, 0);
        if (n < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                return 0;
            if (errno == EINTR)
                continue;
            fail(r, strerror(errno));
            return -1;
        }
        if (n == 0)
            return finish(r); /* server closed: body is whatever we have */
        r->buf_len += (size_t)n;

        if (!r->headers_done) {
            r->buf[r->buf_len] = '\0';
            char *sep = strstr(r->buf, "\r\n\r\n");
            size_t seplen = 4;
            if (!sep) {
                sep = strstr(r->buf, "\n\n");
                seplen = 2;
            }
            if (sep) {
                size_t hlen = (size_t)(sep - r->buf);
                /* Status line: HTTP/1.x NNN */
                int code = 0;
                if (hlen > 12 && str_ncasecmp(r->buf, "HTTP/", 5) == 0)
                    code = atoi(r->buf + 9);
                size_t vlen = 0;
                if (code >= 300 && code < 400) {
                    const char *loc = find_header(r->buf, hlen, "Location", &vlen);
                    if (loc)
                        return restart_with_redirect(r, loc, vlen);
                    fail(r, "redirect without Location");
                    return -1;
                }
                if (code != 200) {
                    char msg[64];
                    snprintf(msg, sizeof msg, "HTTP %d", code);
                    fail(r, msg);
                    return -1;
                }
                const char *te = find_header(r->buf, hlen, "Transfer-Encoding", &vlen);
                r->chunked = te && vlen >= 7 && str_ncasecmp(te, "chunked", 7) == 0;
                const char *cl = find_header(r->buf, hlen, "Content-Length", &vlen);
                r->content_length = cl ? atol(cl) : -1;

                size_t body_off = hlen + seplen;
                memmove(r->buf, r->buf + body_off, r->buf_len - body_off);
                r->buf_len -= body_off;
                r->headers_done = true;
            }
        }
        if (r->headers_done && !r->chunked && r->content_length >= 0 &&
            r->buf_len >= (size_t)r->content_length) {
            r->buf_len = (size_t)r->content_length;
            return finish(r);
        }
        if (r->buf_len >= r->max_body) {
            log_msg("http: body capped at %zu bytes", r->max_body);
            return finish(r);
        }
    }
}

int http_step(http_req_t *r, short revents, uint64_t now)
{
    if (r->state == ST_DONE)
        return 1;
    if (r->state == ST_FAILED)
        return -1;
    if (now >= r->deadline) {
        fail(r, "timed out");
        return -1;
    }
    if (revents & (POLLERR | POLLNVAL)) {
        fail(r, "connection error");
        return -1;
    }

    if (r->state == ST_CONNECTING) {
        if (!(revents & (POLLOUT | POLLHUP)))
            return 0;
        int err = 0;
        socklen_t len = sizeof err;
        if (getsockopt(r->fd, SOL_SOCKET, SO_ERROR, &err, &len) != 0 || err != 0) {
            fail(r, strerror(err ? err : errno));
            return -1;
        }
        r->state = ST_SENDING;
    }

    if (r->state == ST_SENDING) {
        while (r->req_sent < r->req_len) {
            ssize_t n = send(r->fd, r->req + r->req_sent, r->req_len - r->req_sent, MSG_NOSIGNAL);
            if (n < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK)
                    return 0;
                if (errno == EINTR)
                    continue;
                fail(r, strerror(errno));
                return -1;
            }
            r->req_sent += (size_t)n;
        }
        r->state = ST_READING;
        return 0; /* wait for POLLIN */
    }

    if (r->state == ST_READING && (revents & (POLLIN | POLLHUP)))
        return on_readable(r);
    return 0;
}

const char *http_body(const http_req_t *r, size_t *len)
{
    if (r->state != ST_DONE) {
        if (len)
            *len = 0;
        return NULL;
    }
    if (len)
        *len = r->buf_len;
    return r->buf ? r->buf : "";
}

const char *http_error(const http_req_t *r)
{
    return r->error ? r->error : "";
}

void http_free(http_req_t *r)
{
    if (!r)
        return;
    if (r->fd >= 0)
        close(r->fd);
    free(r->host);
    free(r->path);
    free(r->override_ip);
    free(r->req);
    free(r->buf);
    free(r->error);
    free(r);
}
