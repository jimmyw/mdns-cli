/* Ethernet vendor (OUI) lookup.
 *
 * The IEEE OUI registry is a set of *prefix* entries (24, 28 and 36-bit).
 * A 48-bit MAC is resolved by longest prefix match: first try its 36-bit
 * prefix, then its 28-bit, then its 24-bit; the first hit wins. The database
 * is a binary file produced by tools/build_oui.py; it is loaded once at
 * startup and read-only afterwards.
 */
#ifndef MDNS_CLI_OUI_H
#define MDNS_CLI_OUI_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef struct oui_entry {
    uint64_t key;   /* the normalized prefix (24/28/36-bit value) */
    uint32_t str_off; /* byte offset into the string table */
    uint32_t str_len; /* length of the vendor name */
} oui_entry_t;

typedef struct oui_db {
    oui_entry_t *e24; uint32_t n24;
    oui_entry_t *e28; uint32_t n28;
    oui_entry_t *e36; uint32_t n36;
    char *strtab;
    uint32_t strtab_size;
} oui_db_t;

/* Longest prefix match over 36/28/24-bit prefixes. Returns the vendor name
 * (a pointer into db->strtab, valid until the DB is freed) or NULL. */
const char *oui_lookup_bytes(const oui_db_t *db, const uint8_t *mac, size_t n_bytes);

/* Load the database from a file. path may be NULL, in which case the
 * MDNS_OUI environment variable is used, then a file next to the executable,
 * then <prefix>/share/mdns-cli/oui.bin or <prefix>/lib/mdns-cli/oui.bin (where
 * the binary is at <prefix>/bin/mdns-cli), then ./oui.bin. Returns true on
 * success; false otherwise (the tool keeps running without vendors in that
 * case). Calling it again is harmless. */
bool oui_load(const char *path);

void oui_free(void);

bool oui_loaded(void);

/* Vendor for a MAC string like "aa:bb:cc:dd:ee:ff" (case-insensitive,
 * separators ignored). Returns a name, or NULL if none / not loaded. */
const char *oui_vendor_str(const char *mac_str);

#endif /* MDNS_CLI_OUI_H */
