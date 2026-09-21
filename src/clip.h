/* Putting text on the system clipboard.
 *
 * There is no syscall for this, so two routes are used together: the OSC 52
 * escape sequence, which the terminal itself acts on and therefore works over
 * SSH and inside tmux, and a local helper (wl-copy / xclip / xsel) when one is
 * installed. Between them almost every setup is covered.
 */
#ifndef MDNS_CLI_CLIP_H
#define MDNS_CLI_CLIP_H

#include <stdbool.h>

/* Copy text. Returns a short description of how it was delivered, or NULL if
   nothing could be used (which the caller should surface). */
const char *clip_copy(const char *text);

#endif /* MDNS_CLI_CLIP_H */
