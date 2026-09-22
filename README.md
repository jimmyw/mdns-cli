# mdns-cli

An interactive terminal scanner for the two protocols that devices use to
announce themselves on a LAN: **mDNS/DNS-SD** (`224.0.0.251:5353`) and
**SSDP/UPnP** (`239.255.255.250:1900`). Both views are merged per device, so a
Chromecast or a Sonos shows up once, with its DNS-SD services and its UPnP
entries side by side.

Move with the arrow keys, press **Enter** to fold a device open.

```
mdns-cli  28 devices, 152 services            scanning  4s  sort:address  enp7s0
────────────────────────────────────────────────────────────────────────────────
▸ 192.168.2.48          brwd85de251589b.local        mDNS      3 services
▾ 192.168.2.66          sonos000E58DDBF98.local      mDNS+SSDP 25 services  ping 0.43ms 0%
      addresses     192.168.2.66
      hostname      sonos000E58DDBF98.local
      seen          first 15:45:27, last 15:45:34 (2s ago)
      mac           00:0e:58:dd:bf:98
      ping          192.168.2.66  18 sent, 18 received, 0% loss  (running, p to stop)
      rtt           last 0.43 ms, min 0.38, avg 0.51, max 1.24
  ▾ _sonos._tcp                      Sonos-000E58DDBF98:1443
        host          sonos000E58DDBF98.local:1443
        info = /api/v1/players/RINCON_000E58DDBF9801400/info
        protovers = 1.18.10
  ▾ service:VirtualLineIn:1          192.168.2.66 - Sonos Connect:Amp
        location      http://192.168.2.66:1400/xml/device_description.xml
        friendlyName  192.168.2.66 - Sonos Connect:Amp
        manufacturer  Sonos, Inc.
        model         Sonos Connect:Amp ZP120
```

## Build

Needs CMake ≥ 3.16, a C11 compiler and ncursesw. Builds on Linux and macOS
(on macOS, install ncurses via Homebrew if pkg-config can't find `ncursesw`:
`brew install ncurses` and pass `-DCMAKE_PREFIX_PATH=$(brew --prefix ncurses)`
if needed).

```sh
cmake -B build
cmake --build build
./build/mdns-cli
```

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug -DENABLE_ASAN=ON   # sanitizers
ctest --test-dir build --output-on-failure                 # parser + store tests
sudo cmake --install build                                 # optional
```

No root is needed: port 5353 is bound with `SO_REUSEPORT`, so it coexists with
`avahi-daemon`, and the SSDP search uses an ephemeral port of its own. The
neighbour table (MAC addresses) is read via netlink on Linux and via the
routing socket (`sysctl(NET_RT_FLAGS)`) on macOS.

## Keys

| Key | Action |
| --- | --- |
| `↑` `↓` / `k` `j` | move |
| `PgUp` `PgDn`, `Home` `End` / `g` `G` | page, first, last |
| `Enter`, `Space` | fold open or closed |
| `→` / `l` | fold open, then step through the values on the row |
| `←` / `h` | step back through the values, then fold closed or jump to the parent |
| `e` / `E` | expand all / collapse all |
| `p` | ping the device, or the address picked with right/left; again to stop |
| `c` | copy the value under the cursor to the clipboard |
| `s` | cycle sort: address, name, last seen, source |
| `/` | filter (matches names, addresses, service types, TXT and UPnP fields) |
| `Esc` | clear the filter, then quit |
| `r` | rescan now |
| `?` | key list |
| `q` | quit |

## Picking a value

A row often holds more than one thing worth having: a device with four
addresses, a service with a host and a port. `→` steps through the values on
the row (after opening the fold, if there is one) and `←` steps back, falling
through to the usual collapse once it reaches the leftmost one. The picked
value is underlined.

`c` copies it. It goes to the clipboard through an OSC 52 escape sequence, so
it works over SSH and inside tmux (with `set-clipboard on`), and also through
`wl-copy`, `xclip` or `xsel` when one of those is installed.

`p` acts on the picked value too: with an address selected it pings that one
rather than the device's primary address, and picking a different address
while a ping is running moves the ping to it.

## Colour

Colour carries information rather than decoration. Addresses are cyan, device
names bold white, ports yellow, and each row is tagged by where it came from:
green for mDNS, magenta for SSDP, cyan when a device was seen by both. Keys in
key/value rows are blue, a device that has gone quiet turns amber, and a failed
description fetch turns red.

Ping is graded green / yellow / red, on the folded row as well as the expanded
one:

| | |
| --- | --- |
| green | replying, no loss, round trip under 20 ms |
| yellow | some loss, or an average round trip of 20-150 ms |
| red | half or more of the probes lost, no reply at all, or the ping could not start |

The thresholds live next to the counters in `src/device.c` (`ping_loss_grade`,
`ping_rtt_grade`), so they are one place to change and are covered by tests.

Selected rows get a neutral dark grey background rather than reverse video,
which would turn a multi-coloured line into a rainbow bar. The grey is
deliberate: green, yellow, red and cyan all have to stay legible on top of it,
and a coloured background (blue, say) leaves the green tags muddy. Terminals
with fewer than 16 colours have no grey to spare and fall back to plain reverse
video; without colour at all the UI uses bold, dim and reverse and stays
readable.

## Options

```
  -i, --interface NAME   only scan this interface (repeatable)
  -t, --timeout SEC      stop after SEC seconds
      --no-mdns          skip mDNS discovery
      --no-ssdp          skip SSDP discovery
  -4, --ipv4             IPv4 transport only
  -6, --ipv6             IPv6 transport only
      --loopback         include loopback interfaces
      --json             no UI: scan, then print JSON (implies -t 5)
      --no-descriptions  do not fetch UPnP description documents
  -v, --verbose FILE     append a debug log to FILE
```

`-4` and `-6` select the *transport*. AAAA records seen over IPv4 are still
recorded, so a `-4` scan can still report IPv6 addresses.

`--json` makes the tool scriptable, and is also how the scanner is tested
without a TTY:

```sh
mdns-cli --json -t 8 | jq '.devices[] | select(.sources | contains("SSDP"))'
```

## How it works

Everything runs in a single `poll()` loop — both multicast families, the SSDP
search socket, every in-flight description fetch and the keyboard. There are no
threads, so no locking around the device store and no ncurses re-entrancy.

**mDNS** (`src/mdns.c`) walks the standard DNS-SD chain: `PTR` on
`_services._dns-sd._udp.local` for the service types in use, `PTR` per type for
instances, then `SRV`/`TXT` and `A`/`AAAA`. Records in the additional section
are ingested opportunistically, which usually resolves an instance in one round
trip, and unsolicited announcements are picked up the same way. Queries
retransmit at 0s, 1s, 3s and 7s, then refresh every 60s.

**SSDP** (`src/ssdp.c`) sends `M-SEARCH` on the same schedule (devices stagger
replies over `MX` seconds, so one burst misses some) and listens on port 1900
for `NOTIFY` announcements, including `ssdp:byebye`. An M-SEARCH reply carries
only `LOCATION`, `ST`, `USN` and `SERVER`; folding an entry open fetches that
`LOCATION` over HTTP (`src/http.c`, non-blocking) and reads `friendlyName`,
`manufacturer`, `modelName`, `serialNumber` and `UDN` out of it
(`src/xmlmini.c`).

**Ping** (`src/ping.c`) is done in-process, not by shelling out to `ping(8)`.
Linux hands out unprivileged ICMP datagram sockets
(`net.ipv4.ping_group_range`), so `p` needs no root and no capabilities: it
sends one echo request a second to the address shown for the device and keeps
running counters — sent, received, loss over resolved probes, and last / min /
avg / max round trip — on the device entry itself. The counters stay on the
entry after the run is stopped, and are visible folded as well as expanded. A
probe still in flight is not counted as loss; one that passes its two-second
timeout is, and that timeout is a generous 12 seconds because sleepy
Matter/Thread and battery devices only answer when they next wake up. Both
IPv4 and IPv6 targets work. If the kernel refuses an ICMP
socket, the reason is shown on the entry instead of the counters.

**MAC addresses** (`src/neigh.c`) are not in any mDNS or SSDP payload. They
come from the kernel's own ARP/NDP table, dumped over netlink (`RTM_GETNEIGH`,
IPv4 and IPv6) every few seconds. Discovery traffic is usually enough to
populate it; pinging a device certainly is.

**Merging** (`src/device.c`) is by shared IP address, falling back to the mDNS
hostname, and to the UPnP UUID — that last one is what joins the IPv4 and IPv6
halves of a dual-stack router, which otherwise look like two devices.

`src/dns.c` is a self-contained DNS wire-format parser: bounds-checked
throughout, with name decompression that cannot loop (pointers must strictly
decrease and are capped). `tests/test_dns.c` feeds it a captured response plus
pointer loops, forward pointers, truncated rdata and every prefix of a valid
packet.
