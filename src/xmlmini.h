/* Just enough XML to read a UPnP device description.
 *
 * A description document is a handful of known tags in a fixed shape, so a tag
 * scan with entity decoding beats pulling in a real parser as a dependency.
 */
#ifndef MDNS_CLI_XMLMINI_H
#define MDNS_CLI_XMLMINI_H

#include <stddef.h>

/* Text of the first <tag>...</tag>, entity-decoded and trimmed. Namespace
   prefixes are ignored, so "friendlyName" also matches <ns:friendlyName>.
   Returns a malloc'd string, or NULL when the tag is absent or empty. */
char *xml_tag(const char *doc, size_t len, const char *tag);

#endif /* MDNS_CLI_XMLMINI_H */
