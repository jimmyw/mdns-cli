#include "xmlmini.h"

#include "util.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Does the element name starting at p match tag (ignoring any ns: prefix)? */
static const char *match_open(const char *p, const char *end, const char *tag)
{
    size_t tlen = strlen(tag);
    const char *name = p;
    const char *colon = NULL;
    const char *q = p;
    while (q < end && (isalnum((unsigned char)*q) || *q == ':' || *q == '_' || *q == '-' ||
                       *q == '.')) {
        if (*q == ':')
            colon = q;
        q++;
    }
    if (colon)
        name = colon + 1;
    if ((size_t)(q - name) != tlen || str_ncasecmp(name, tag, tlen) != 0)
        return NULL;
    /* Skip attributes to the closing '>'. */
    while (q < end && *q != '>') {
        if (*q == '/' && q + 1 < end && q[1] == '>')
            return NULL; /* self-closing: no text */
        q++;
    }
    return q < end ? q + 1 : NULL;
}

static char *decode_entities(const char *s, size_t len)
{
    char *out = xmalloc(len + 1);
    size_t o = 0;
    for (size_t i = 0; i < len;) {
        if (s[i] != '&') {
            out[o++] = s[i++];
            continue;
        }
        const char *semi = memchr(s + i, ';', len - i);
        size_t elen = semi ? (size_t)(semi - (s + i)) - 1 : 0;
        if (!semi || elen == 0 || elen > 10) {
            out[o++] = s[i++];
            continue;
        }
        char ent[12];
        memcpy(ent, s + i + 1, elen);
        ent[elen] = '\0';
        if (strcmp(ent, "amp") == 0)
            out[o++] = '&';
        else if (strcmp(ent, "lt") == 0)
            out[o++] = '<';
        else if (strcmp(ent, "gt") == 0)
            out[o++] = '>';
        else if (strcmp(ent, "quot") == 0)
            out[o++] = '"';
        else if (strcmp(ent, "apos") == 0)
            out[o++] = '\'';
        else if (ent[0] == '#') {
            long cp = (ent[1] == 'x' || ent[1] == 'X') ? strtol(ent + 2, NULL, 16)
                                                       : strtol(ent + 1, NULL, 10);
            /* Only ASCII is decoded; anything else becomes '?'. */
            out[o++] = (cp >= 0x20 && cp < 0x7f) ? (char)cp : '?';
        } else {
            /* Unknown entity: keep it verbatim. */
            memcpy(out + o, s + i, elen + 2);
            o += elen + 2;
        }
        i += elen + 2;
    }
    out[o] = '\0';
    str_sanitize(out);
    str_trim(out);
    return out;
}

char *xml_tag(const char *doc, size_t len, const char *tag)
{
    const char *end = doc + len;
    for (const char *p = doc; p < end; p++) {
        if (*p != '<' || p + 1 >= end)
            continue;
        if (p[1] == '/' || p[1] == '?' || p[1] == '!')
            continue;
        const char *text = match_open(p + 1, end, tag);
        if (!text)
            continue;
        /* Find the matching close tag. */
        const char *q = text;
        while (q < end) {
            const char *lt = memchr(q, '<', (size_t)(end - q));
            if (!lt)
                return NULL;
            if (lt + 1 < end && lt[1] == '/') {
                char *val = decode_entities(text, (size_t)(lt - text));
                if (*val)
                    return val;
                free(val);
                return NULL;
            }
            q = lt + 1;
        }
        return NULL;
    }
    return NULL;
}
