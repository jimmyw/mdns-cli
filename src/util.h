/* Small shared helpers: monotonic time, debug logging, allocation. */
#ifndef MDNS_CLI_UTIL_H
#define MDNS_CLI_UTIL_H

#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Milliseconds from CLOCK_MONOTONIC; the whole program schedules on this. */
uint64_t now_ms(void);

/* Wall-clock "HH:MM:SS" into out (needs >= 9 bytes). */
void fmt_clock(uint64_t mono_ms, char *out, size_t outsz);

/* Human duration such as "4s", "2m10s". */
void fmt_age(uint64_t ms, char *out, size_t outsz);

/* Debug log. Never writes to stdout/stderr once the UI owns the terminal. */
void log_open(const char *path);
void log_close(void);
void log_msg(const char *fmt, ...) __attribute__((format(printf, 1, 2)));

/* Allocation that aborts rather than returning NULL: an out-of-memory
   scanner has nothing useful to do with the failure. */
void *xmalloc(size_t n);
void *xcalloc(size_t n, size_t sz);
void *xrealloc(void *p, size_t n);
char *xstrdup(const char *s);
char *xstrndup(const char *s, size_t n);

/* Replace *slot with a copy of val (freeing the old value). */
void str_set(char **slot, const char *val);

/* In-place trim of leading/trailing whitespace; returns s. */
char *str_trim(char *s);

/* True when data is printable text (valid UTF-8, no control characters). */
bool str_is_printable(const char *data, size_t len);

/* Display form of possibly-binary data: the text itself when it is printable,
   otherwise a hex rendering like "0x8f2a1c". Always malloc'd. */
char *str_display(const char *data, size_t len);

/* In-place: replace control characters and invalid UTF-8 with '?'. */
void str_sanitize(char *s);

/* Copy src into dst truncated to width display columns, then space-pad to
   exactly that width. UTF-8 aware, so a multi-byte character is never cut in
   half and column alignment survives non-ASCII names. Returns dst. */
char *str_pad(char *dst, size_t dstsz, const char *src, int width);

/* Shorten a long address to fit width columns as "head~tail"; short ones are
   copied unchanged. Full addresses stay visible in the expanded view. */
void str_fit_addr(char *dst, size_t dstsz, const char *src, int width);

/* Case-insensitive compare that does not depend on locale. */
int str_casecmp(const char *a, const char *b);
int str_ncasecmp(const char *a, const char *b, size_t n);
bool str_icontains(const char *hay, const char *needle);

#endif /* MDNS_CLI_UTIL_H */
