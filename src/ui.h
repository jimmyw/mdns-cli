/* The ncurses front end: a two-level tree of devices and what they expose. */
#ifndef MDNS_CLI_UI_H
#define MDNS_CLI_UI_H

#include "device.h"

#include <stdbool.h>

typedef struct ui ui_t;

/* Called when the user expands something whose UPnP description is worth
   fetching. The UI never blocks on it; the result shows up on a later draw. */
typedef void (*ui_fetch_cb)(void *ctx, const ssdp_entry_t *e);

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

ui_t *ui_new(store_t *store, ui_fetch_cb cb, void *ctx);
void ui_destroy(ui_t *u);

#define UI_KEY_NONE (-1)
/* Non-blocking read of one key; UI_KEY_NONE when nothing is pending. */
int ui_getch(void);
ui_action_t ui_key(ui_t *u, int ch);
void ui_draw(ui_t *u, const ui_status_t *st);

#endif /* MDNS_CLI_UI_H */
