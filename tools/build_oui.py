#!/usr/bin/env python3
"""Convert the Wireshark-style OUI master registry (master_oui.txt) into a
binary lookup file that mdns-cli reads at startup.

Input format (one record per line, tab-separated "PREFIX\tVendor"):
    HH:HH:HH                 24-bit (MA-L)
    HH:HH:HH:HH/28           28-bit (MA-M)   (only the high nibble of the last
    HH:HH:HH:HH/36           36-bit (MA-S/IAB) pair is significant)

Output: a little-endian binary file:
    +-------+-------+-------+-------+-------+-------+-------+--------+
    |magic  |version|  n24  |  n28  |  n36  |strtab_size|strtab_off| pad   |
    +-------+-------+-------+-------+-------+-------+-------+--------+
    4*uint32_t + 4*uint32_t + 4*uint32_t(4-byte-aligned to 32 bytes total)
    then, at offset 32:
      [32                ]  n24  x (uint64 key; uint32 str_off; uint32 str_len)
      [32 + 16*n24       ]  n28  x (same)
      [32 + 16*(n24+n28) ]  n36  x (same)
      [strtab_off         ]  string table: names concatenated, '\0'-terminated
    Each entry's key is the normalized prefix:
      24-bit: (b0<<16)|(b1<<8)|b2
      28-bit: (b0<<24)|(b1<<16)|(b2<<8)|(b3>>4)
      36-bit: (b0<<32)|(b1<<24)|(b2<<16)|(b3<<8)|(b4>>4)
    str_off is relative to the start of the string table.
"""

import argparse
import struct
import sys

MAGIC = 0x3149554F  # "OUI1"
VERSION = 1


def parse_prefix(prefix):
    """Return (key, type) where type is 24, 28 or 36."""
    prefix = prefix.strip()
    if not prefix:
        return None, None
    if prefix.endswith("/28"):
        base = prefix[:-3]
        parts = [p for p in base.split(":") if p]
        if len(parts) != 4:
            return None, None
        p0, p1, p2, p3 = (int(x, 16) for x in parts)
        key = (p0 << 24) | (p1 << 16) | (p2 << 8) | (p3 >> 4)
        t = 28
    elif prefix.endswith("/36"):
        base = prefix[:-3]
        parts = [p for p in base.split(":") if p]
        if len(parts) != 5:
            return None, None
        p0, p1, p2, p3, p4 = (int(x, 16) for x in parts)
        key = (p0 << 32) | (p1 << 24) | (p2 << 16) | (p3 << 8) | (p4 >> 4)
        t = 36
    else:
        parts = [p for p in prefix.split(":") if p]
        if len(parts) != 3:
            return None, None
        p0, p1, p2 = (int(x, 16) for x in parts)
        key = (p0 << 16) | (p1 << 8) | p2
        t = 24
    return key, t


def build(inpath, outpath):
    # buckets[key] = longest vendor name seen for that (type, key)
    buckets = {24: {}, 28: {}, 36: {}}
    skipped = 0
    with open(inpath, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.rstrip("\n").rstrip("\r")
            if not line or line.startswith("#"):
                continue
            if "\t" not in line:
                skipped += 1
                continue
            prefix, vendor = line.split("\t", 1)
            vendor = vendor.strip()
            if not vendor:
                skipped += 1
                continue
            key, t = parse_prefix(prefix)
            if key is None:
                skipped += 1
                continue
            name = buckets[t].get(key)
            # Keep the longest (most informative) name per (type, key).
            if name is None or len(vendor) > len(name):
                buckets[t][key] = vendor
    # Intern vendor names -> (str_off, str_len) in bytes. Offsets are relative
    # to the start of the string table.
    name_to = {}
    strtab = bytearray()
    for t in (24, 28, 36):
        for name in buckets[t].values():
            if name not in name_to:
                enc = name.encode("utf-8", "replace")
                off = len(strtab)
                name_to[name] = (off, len(enc))
                strtab += enc
                strtab += b"\x00"
    n24, n28, n36 = len(buckets[24]), len(buckets[28]), len(buckets[36])
    entries = []
    for t, b in ((24, buckets[24]), (28, buckets[28]), (36, buckets[36])):
        for key in sorted(b):
            name = b[key]
            off, ln = name_to[name]
            entries.append((key, off, ln))
    strtab_off = 32 + 16 * (n24 + n28 + n36)
    buf = bytearray()
    buf += struct.pack("<I", MAGIC)
    buf += struct.pack("<I", VERSION)
    buf += struct.pack("<I", n24)
    buf += struct.pack("<I", n28)
    buf += struct.pack("<I", n36)
    buf += struct.pack("<I", len(strtab))
    buf += struct.pack("<I", strtab_off)
    buf += struct.pack("<I", 0)  # pad to 32
    for key, off, ln in entries:
        buf += struct.pack("<QII", key, off, ln)
    buf += strtab
    with open(outpath, "wb") as f:
        f.write(bytes(buf))
    return n24, n28, n36, skipped


def main():
    ap = argparse.ArgumentParser(description="Build mdns-cli's OUI vendor DB.")
    ap.add_argument("input", nargs="?", default="data/master_oui.txt",
                    help="path to master_oui.txt")
    ap.add_argument("-o", "--out", default="data/oui.bin")
    args = ap.parse_args()
    n24, n28, n36, skipped = build(args.input, args.out)
    print("oui: %d 24-bit, %d 28-bit, %d 36-bit vendors; %d lines skipped" %
          (n24, n28, n36, skipped), file=sys.stderr)


if __name__ == "__main__":
    main()
