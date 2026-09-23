#include "oui.h"

#include "util.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#define OUI_MAGIC 0x3149554fu /* "OUI1" */

typedef struct {
    uint32_t magic;
    uint32_t version;
    uint32_t n24;
    uint32_t n28;
    uint32_t n36;
    uint32_t strtab_size;
    uint32_t strtab_off;
    uint32_t pad;
} oui_hdr_t;

static_assert(sizeof(oui_entry_t) == 16, "oui_entry_t must be 16 bytes");
static_assert(sizeof(oui_hdr_t) == 32, "oui_hdr_t must be 32 bytes");

static oui_db_t g_oui;
static bool g_loaded = false;
static char *g_oui_buf = NULL;

static int oui_bsearch(const oui_entry_t *e, uint32_t n, uint64_t key)
{
    int lo = 0, hi = (int)n;
    while (lo < hi) {
        int mid = (lo + hi) >> 1;
        if (e[mid].key < key)
            lo = mid + 1;
        else
            hi = mid;
    }
    if (lo < (int)n && e[lo].key == key)
        return lo;
    return -1;
}

static const char *oui_name(const oui_db_t *db, const oui_entry_t *e)
{
    if (e->str_off >= db->strtab_size ||
        (uint32_t)e->str_off + e->str_len > db->strtab_size)
        return NULL;
    return db->strtab + e->str_off;
}

const char *oui_lookup_bytes(const oui_db_t *db, const uint8_t *mac, size_t n_bytes)
{
    if (!db || n_bytes < 3)
        return NULL;
    uint64_t key;
    /* 36-bit first (most specific). */
    if (n_bytes >= 5) {
        key = ((uint64_t)mac[0] << 32) | ((uint64_t)mac[1] << 24) |
              ((uint64_t)mac[2] << 16) | ((uint64_t)mac[3] << 8) |
              ((uint64_t)(mac[4] >> 4));
        int i = oui_bsearch(db->e36, db->n36, key);
        if (i >= 0)
            return oui_name(db, &db->e36[i]);
    }
    /* 28-bit. */
    if (n_bytes >= 4) {
        key = ((uint64_t)mac[0] << 24) | ((uint64_t)mac[1] << 16) |
              ((uint64_t)mac[2] << 8) | ((uint64_t)(mac[3] >> 4));
        int i = oui_bsearch(db->e28, db->n28, key);
        if (i >= 0)
            return oui_name(db, &db->e28[i]);
    }
    /* 24-bit. */
    key = ((uint64_t)mac[0] << 16) | ((uint64_t)mac[1] << 8) | (uint64_t)mac[2];
    int i = oui_bsearch(db->e24, db->n24, key);
    if (i >= 0)
        return oui_name(db, &db->e24[i]);
    return NULL;
}

/* Load and validate the DB from a single file. Returns true on success. */
static bool oui_load_file(const char *path)
{
    if (g_loaded)
        return true;
    FILE *f = fopen(path, "rb");
    if (!f)
        return false; /* no DB; tool runs without vendors */
    if (fseek(f, 0, SEEK_END) != 0 || ftell(f) <= 0) {
        fclose(f);
        return false;
    }
    long size = ftell(f);
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return false;
    }
    char *buf = malloc((size_t)size);
    if (!buf) {
        fclose(f);
        return false;
    }
    if (fread(buf, 1, (size_t)size, f) != (size_t)size) {
        free(buf);
        fclose(f);
        return false;
    }
    fclose(f);

    oui_hdr_t h;
    memcpy(&h, buf, sizeof h);
    if (h.magic != OUI_MAGIC || h.version != 1) {
        free(buf);
        return false;
    }
    if ((uint32_t)(h.strtab_off + h.strtab_size) != (uint32_t)size) {
        free(buf);
        return false;
    }
    g_oui_buf = buf;
    g_oui.e24 = (oui_entry_t *)(buf + 32);
    g_oui.e28 = (oui_entry_t *)(buf + 32 + (uint32_t)h.n24 * sizeof(oui_entry_t));
    g_oui.e36 = (oui_entry_t *)(buf + 32 +
                                (uint32_t)(h.n24 + h.n28) * sizeof(oui_entry_t));
    g_oui.strtab = buf + h.strtab_off;
    g_oui.strtab_size = h.strtab_size;
    g_oui.n24 = h.n24;
    g_oui.n28 = h.n28;
    g_oui.n36 = h.n36;
    g_loaded = true;
    return true;
}

/* Default DB locations, in priority order (first that opens wins). The
 * executable is expected at <prefix>/bin/mdns-cli; the DB is installed at
 * <prefix>/share/<pkg>/oui.bin (or <prefix>/lib/<pkg>/oui.bin).
 * Returns the number of candidates written to cands. */
static int oui_default_candidates(char cands[][PATH_MAX], int max)
{
    int i = 0;
    char exe[PATH_MAX];
    char dir[PATH_MAX];
    const char *pkg = "mdns-cli";   /* keep in sync with CMake PROJECT_NAME */

    ssize_t nexe = readlink("/proc/self/exe", exe, sizeof exe - 1);
    if (nexe > 0) {
        exe[nexe] = '\0';
        char *sl = strrchr(exe, '/');
        if (sl) {
            size_t dirlen = (size_t)(sl - exe);
            if (dirlen < sizeof dir) {
                memcpy(dir, exe, dirlen);
                dir[dirlen] = '\0';

                /* 1) next to the executable (build tree, or bin+data together) */
                if (dirlen > 0 && i < max) {
                    int r = snprintf(cands[i], sizeof cands[i], "%s/oui.bin", dir);
                    if (r >= 0 && r < (int)sizeof cands[i])
                        i++;
                }

                /* 2) <prefix>/share/<pkg>/oui.bin */
                if (i < max) {
                    int r = snprintf(cands[i], sizeof cands[i],
                                     "%s/../share/%s/oui.bin", dir, pkg);
                    if (r >= 0 && r < (int)sizeof cands[i])
                        i++;
                }

                /* 3) <prefix>/lib/<pkg>/oui.bin */
                if (i < max) {
                    int r = snprintf(cands[i], sizeof cands[i],
                                     "%s/../lib/%s/oui.bin", dir, pkg);
                    if (r >= 0 && r < (int)sizeof cands[i])
                        i++;
                }
            }
        }
    }

    /* 4) current directory, last resort */
    if (i < max) {
        int r = snprintf(cands[i], sizeof cands[i], "oui.bin");
        if (r >= 0 && r < (int)sizeof cands[i])
            i++;
    }
    return i;
}

bool oui_load(const char *path)
{
    if (g_loaded)
        return true;

    if (path && *path)
        return oui_load_file(path);

    const char *env = getenv("MDNS_OUI");
    if (env)
        return oui_load_file(env);

    char cands[4][PATH_MAX];
    int n = oui_default_candidates(cands, 4);
    for (int i = 0; i < n; i++)
        if (oui_load_file(cands[i]))
            return true;
    return false;
}

void oui_free(void)
{
    if (!g_loaded)
        return;
    free(g_oui_buf);
    g_oui_buf = NULL;
    g_loaded = false;
}

bool oui_loaded(void)
{
    return g_loaded;
}

/* Parse up to 6 hex bytes out of a MAC string, ignoring separators. */
static size_t oui_parse_mac_bytes(const char *s, uint8_t *out, size_t max)
{
    size_t i = 0;
    for (const char *p = s; *p; ) {
        while (*p && !isxdigit((unsigned char)*p))
            p++;
        if (!*p)
            break;
        uint8_t b = 0;
        int n = 0;
        while (*p && isxdigit((unsigned char)*p) && n < 2) {
            unsigned c = (unsigned char)*p++;
            b = (uint8_t)((b << 4) |
                          (c <= '9' ? c - '0'
                                     : c <= 'f' ? c - 'a' + 10
                                     : c - 'A' + 10));
            n++;
        }
        if (n == 0)
            break;
        if (i < max)
            out[i++] = b;
    }
    return i;
}

const char *oui_vendor_str(const char *mac_str)
{
    if (!g_loaded || !mac_str || !*mac_str)
        return NULL;
    uint8_t mac[6];
    size_t n = oui_parse_mac_bytes(mac_str, mac, sizeof mac);
    if (n < 3)
        return NULL;
    return oui_lookup_bytes(&g_oui, mac, n);
}
