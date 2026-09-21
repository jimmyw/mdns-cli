#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static FILE *g_log;
static uint64_t g_start_ms;

uint64_t now_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000);
}

void fmt_clock(uint64_t mono_ms, char *out, size_t outsz)
{
    /* Translate a monotonic stamp back onto the wall clock for display. */
    uint64_t now = now_ms();
    time_t wall = time(NULL) - (time_t)((now - mono_ms) / 1000);
    struct tm tm;
    localtime_r(&wall, &tm);
    strftime(out, outsz, "%H:%M:%S", &tm);
}

void fmt_age(uint64_t ms, char *out, size_t outsz)
{
    uint64_t s = ms / 1000;
    if (s < 60)
        snprintf(out, outsz, "%llus", (unsigned long long)s);
    else if (s < 3600)
        snprintf(out, outsz, "%llum%02llus", (unsigned long long)(s / 60),
                 (unsigned long long)(s % 60));
    else
        snprintf(out, outsz, "%lluh%02llum", (unsigned long long)(s / 3600),
                 (unsigned long long)((s % 3600) / 60));
}

void log_open(const char *path)
{
    g_log = fopen(path, "we");
    g_start_ms = now_ms();
    if (g_log)
        setvbuf(g_log, NULL, _IOLBF, 0);
}

void log_close(void)
{
    if (g_log) {
        fclose(g_log);
        g_log = NULL;
    }
}

void log_msg(const char *fmt, ...)
{
    if (!g_log)
        return;
    uint64_t t = now_ms() - g_start_ms;
    fprintf(g_log, "[%3llu.%03llu] ", (unsigned long long)(t / 1000),
            (unsigned long long)(t % 1000));
    va_list ap;
    va_start(ap, fmt);
    vfprintf(g_log, fmt, ap);
    va_end(ap);
    fputc('\n', g_log);
}

static void oom(void)
{
    fputs("mdns-cli: out of memory\n", stderr);
    abort();
}

void *xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);
    if (!p)
        oom();
    return p;
}

void *xcalloc(size_t n, size_t sz)
{
    void *p = calloc(n ? n : 1, sz ? sz : 1);
    if (!p)
        oom();
    return p;
}

void *xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);
    if (!q)
        oom();
    return q;
}

char *xstrdup(const char *s)
{
    if (!s)
        return NULL;
    size_t n = strlen(s) + 1;
    char *p = xmalloc(n);
    memcpy(p, s, n);
    return p;
}

char *xstrndup(const char *s, size_t n)
{
    size_t len = 0;
    while (len < n && s[len])
        len++;
    char *p = xmalloc(len + 1);
    memcpy(p, s, len);
    p[len] = '\0';
    return p;
}

void str_set(char **slot, const char *val)
{
    free(*slot);
    *slot = xstrdup(val);
}

char *str_trim(char *s)
{
    char *p = s;
    while (*p && isspace((unsigned char)*p))
        p++;
    if (p != s)
        memmove(s, p, strlen(p) + 1);
    size_t n = strlen(s);
    while (n && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
    return s;
}

/* Length of the UTF-8 sequence starting at s, or 0 when it is not valid. */
static size_t utf8_len(const unsigned char *s, size_t avail)
{
    unsigned char c = s[0];
    size_t need;
    if (c < 0x80)
        return 1;
    else if ((c & 0xE0) == 0xC0)
        need = 2;
    else if ((c & 0xF0) == 0xE0)
        need = 3;
    else if ((c & 0xF8) == 0xF0)
        need = 4;
    else
        return 0;
    if (need > avail)
        return 0;
    for (size_t i = 1; i < need; i++)
        if ((s[i] & 0xC0) != 0x80)
            return 0;
    return need;
}

bool str_is_printable(const char *data, size_t len)
{
    const unsigned char *p = (const unsigned char *)data;
    for (size_t i = 0; i < len;) {
        if (p[i] < 0x20 || p[i] == 0x7f)
            return false;
        size_t n = utf8_len(p + i, len - i);
        if (n == 0)
            return false;
        i += n;
    }
    return true;
}

char *str_display(const char *data, size_t len)
{
    if (str_is_printable(data, len)) {
        char *out = xmalloc(len + 1);
        memcpy(out, data, len);
        out[len] = '\0';
        return out;
    }
    /* Binary TXT values are real (Thread border routers, for one): hex is the
       only honest way to show them. */
    char *out = xmalloc(len * 2 + 3);
    memcpy(out, "0x", 2);
    for (size_t i = 0; i < len; i++)
        snprintf(out + 2 + i * 2, 3, "%02x", (unsigned char)data[i]);
    out[len * 2 + 2] = '\0';
    return out;
}

void str_sanitize(char *s)
{
    unsigned char *p = (unsigned char *)s;
    size_t len = strlen(s);
    for (size_t i = 0; i < len;) {
        if (p[i] < 0x20 || p[i] == 0x7f) {
            p[i++] = '?';
            continue;
        }
        size_t n = utf8_len(p + i, len - i);
        if (n == 0) {
            p[i++] = '?';
            continue;
        }
        i += n;
    }
}

char *str_pad(char *dst, size_t dstsz, const char *src, int width)
{
    if (dstsz == 0)
        return dst;
    if (width < 0)
        width = 0;
    const unsigned char *p = (const unsigned char *)(src ? src : "");
    size_t len = strlen((const char *)p);
    size_t o = 0;
    int cols = 0;
    for (size_t i = 0; i < len && cols < width;) {
        size_t n = utf8_len(p + i, len - i);
        if (n == 0)
            n = 1;
        if (o + n + 1 > dstsz)
            break;
        memcpy(dst + o, p + i, n);
        o += n;
        i += n;
        cols++;
    }
    while (cols < width && o + 1 < dstsz) {
        dst[o++] = ' ';
        cols++;
    }
    dst[o] = '\0';
    return dst;
}

void str_fit_addr(char *dst, size_t dstsz, const char *src, int width)
{
    size_t len = strlen(src);
    if ((int)len <= width || width < 7) {
        snprintf(dst, dstsz, "%s", src);
        return;
    }
    int tail = (width - 1) / 2;
    int head = width - 1 - tail;
    snprintf(dst, dstsz, "%.*s~%s", head, src, src + len - (size_t)tail);
}

int str_casecmp(const char *a, const char *b)
{
    while (*a && *b) {
        int d = tolower((unsigned char)*a) - tolower((unsigned char)*b);
        if (d)
            return d;
        a++;
        b++;
    }
    return tolower((unsigned char)*a) - tolower((unsigned char)*b);
}

int str_ncasecmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        int d = tolower((unsigned char)a[i]) - tolower((unsigned char)b[i]);
        if (d)
            return d;
        if (!a[i])
            return 0;
    }
    return 0;
}

bool str_icontains(const char *hay, const char *needle)
{
    if (!needle || !*needle)
        return true;
    if (!hay)
        return false;
    size_t n = strlen(needle);
    for (const char *p = hay; *p; p++)
        if (str_ncasecmp(p, needle, n) == 0)
            return true;
    return false;
}
