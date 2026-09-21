/* The ncurses front end: a two-level tree of devices and what they expose. */
#ifndef MDNS_CLI_UI_H
#define MDNS_CLI_UI_H

#include "device.h"

#include <stdbool.h>

typedef struct ui ui_t;

/* What the UI asks the rest of the program to do. Both are non-blocking: the
   results turn up on the device entry and show up on a later draw. */
typedef struct {
    void *ctx;
    /* The user expanded something whose UPnP description is worth fetching. */
    void (*fetch)(void *ctx, const ssdp_entry_t *e);
    /* The user pressed p: start pinging this device, or stop if it already
       is. addr picks which address to probe, NULL meaning the default one.
       Returns NULL, or a short reason it could not start. */
    const char *(*ping)(void *ctx, device_t *d, const addr_t *addr);
} ui_hooks_t;

typedef struct {
    bool scanning;
    size_t n_devices;
    size_t n_services;
    size_t inflight; /* description fetches in progress */
    const char *ifaces;
    uint64_t elapsed_ms;
} ui_status_t;

typedef enum {
    UI_NONE = 0,
    UI_QUIT,
    UI_RESCAN,
} ui_action_t;

ui_t *ui_new(store_t *store, const ui_hooks_t *hooks);
void ui_destroy(ui_t *u);

#define UI_KEY_NONE (-1)
/* Non-blocking read of one key; UI_KEY_NONE when nothing is pending. */
int ui_getch(void);
ui_action_t ui_key(ui_t *u, int ch);
void ui_draw(ui_t *u, const ui_status_t *st);

#endif /* MDNS_CLI_UI_H */
