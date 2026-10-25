# `kismet_cap_cell_diag` — Qualcomm DIAG cell-observation capture source

A Kismet datasource that opens a modem's **DIAG** port, arms a LOG mask, deframes
the HDLC stream, and decodes the DIAG records into `cell_observation` JSON
**in this process**: the C++ decode legs linked into the binary render every
observation, and no other program is started. Observations are merged with the
modem's AT-sourced cells in `phy_cell`, tagged `src=diag`.

Source spec: `celldiag-<15-digit IMEI>` (e.g. `-c celldiag-123456789012345`).
The IMEI is resolved to a modem by an AT probe on a sibling serial port, then
that modem's DIAG interface is opened for the tap.

## Build and run

```sh
make -C capture_cell_diag            # configured tree: the helper, native decode legs linked
make -C capture_cell_diag check      # build and run every selftest
kismet -c celldiag-<IMEI>
```

**`make`** (in a tree that has run `./configure`) builds `./kismet_cap_cell_diag`
with the C shim (`diag_native_decode.cpp`) and the C++ decode legs compiled from
`../diagspec/generated/` and `../diagspec/enrichment/`. A tree without those
sources stops at once with that reason. `libstdc++` is in its `ldd`. A post-link
symbol guard (`../diagspec/check_binary_symbols.sh`, role `helper`) fails the
build if any leg the shim declares is missing from the binary.

**`make -f standalone.mk`** builds the same helper with **no autoconf input at
all**, on a tree that has never run `./configure`, into `build-native/` (its
generated platform `config.h` and `version.c` in `build-native/platform/`). Its
default goal, `check-native`:

1. checks its prerequisites (a C++ compiler that builds `-std=gnu++20`, the
   Kaitai runtime vendored at the tree root, the `../diagspec/` decode sources)
   and stops **before** anything compiles if one is missing, naming the fix;
2. runs `check` (every framework-free selftest);
3. links the helper and runs the `helper` symbol guard on it;
4. runs the native-decode selftest (linked from the same objects) and the
   replay driver's selftest;
5. replays the in-tree capture `fixtures/functional.hdlc` and requires exactly
   `fixtures/functional.native.ndjson`, plus the source's own report
   `decoder: native, in process`.

The fixture is **synthesised, not scrubbed** (its generator,
`fixtures/make_functional_fixture.py`, is committed beside it), so it holds no
real identifiers. libwebsockets is used when present; a build without it loses
only the remote-capture websocket transport. It builds on Linux and Darwin.
`build-native/` is a check artifact, never `./kismet_cap_cell_diag`: a
configured tree's helper has exactly one writer.

Other targets: `make probe` builds [`celldiag_probe`](#debugging-with-a-raw-capture),
`make replay-ndjson` the replay driver, `make logstream-dump` a driver that dumps
the extracted `(log_code, ts64, payload)` record stream of a raw-HDLC capture.

## Decoder

Every DIAG LOG record is extracted in process (`diag_logstream.c`: HDLC, CRC
and the QShrink4 / `0x98`/`0x99`/`0x92` envelopes) and handed to the native
legs (`diag_native_decode.cpp`). The decoder runs on the DIAG reader thread.
At open the source says `decoder: native, in process` and lists the legs:
`<name> nativedecode=only armed; N cell leg(s): 0x…; N GNSS leg(s): 0x…`.

**Options.** `nativedecode=only` and `census=native` are **accepted** for
compatibility: they name the one decoder and the one census producer this
binary has, so an existing definition that spells them keeps opening. **Any
other value is refused at open**, with a message naming the option
(`nativedecode=<x> is not supported: this source has one decoder, the native
one (nativedecode=only)`). `helper=` was removed and is also refused at open,
not ignored: it used to select the decoder.

**Coverage.** A record no native leg reads is counted, never silently lost. The
decoder readout (below), on every stats interval, reports it as `no-leg=`;
the census names the codes as `undecoded_native`.

```
<name> nativedecode=only | records=… native=… (N%) obs=… declined=… enriched=… |
  sib1=… keys=… (N live) | gnss=… fixes=… nofix=… (nopos=… placeholder=… notime=…
  stale=… altitude=… jump=… unparseable=…) unjudged=… | no-leg=N |
  frames=… crc_bad=… wrapped=… | emitted=… emit_declined=… emit_truncated=… gps_emitted=…
```

| field | meaning |
|---|---|
| `records`, `native (N%)` | LOG records extracted, and the share a native leg claimed. Coverage is a share of **records**, not of observations |
| `obs`, `declined` | observations the legs produced; records a leg read and legitimately found nothing in |
| `enriched` | observations that gained identity (MCC/MNC/TAC/CID) from an earlier SIB1 in the stream. `obs` alone looks the same whether enrichment runs or not |
| `sib1`, `keys`, `(N live)` | SIB1 records seen, identity keys they added, what the cache holds now |
| `gnss`, `fixes`, `nofix (…)` | GNSS records, usable fixes, and why the rest were declined. `unjudged` counts records accepted before the plausibility gate had a reference |
| `no-leg` | records no native leg reads |
| `frames`, `crc_bad`, `wrapped` | HDLC frames seen, frames that failed CRC, LOG records unwrapped from an envelope |
| `emitted`, `emit_declined`, `emit_truncated`, `gps_emitted` | lines sent to Kismet; decoded records the serializer has no branch for; renderings too long for the line buffer; `gps_fix` lines sent |

The same counters go into the structured `diag_stats` object as
`native_total_records`, `native_records`, `native_obs`, `native_declined`,
`native_enriched`, `native_gps_fixes` and `native_fallback_records` (`no-leg`),
and `decode_mode` is always `native-only`.

### Health: `helper_alive` means "the decoder is alive"

The health line, every `stats_interval=` seconds:

```
celldiag stats: <VERDICT> | port=open|closed bytes=… rd_err=… last_read=… |
  obs=… (+N R/s) last_obs=… | decoder=alive|stalled|stopped | mask=…
```

| verdict | means |
|---|---|
| `NODATA` | never read a byte from the port |
| `PORT-CLOSED` | the DIAG port is closed (a finished replay, a stopped source); `decoder=stopped` |
| `DECODER-STALLED` | the port is open but the reader has stopped advancing |
| `STALLED` | reads have stopped: a quiet port read by a live reader |
| `RX-NO-OBS` | bytes arriving, no observation within the interval |
| `FLOWING` | a recent observation was relayed |

The producer states are judged before the recency ones, so the verdict never
contradicts the fields printed beside it.

`diag_stats` keeps the field name `helper_alive` (the server registers it, and
the datasources panel shows **DEAD** when it is `0` on a running source). It
means the in-process decoder is alive: its DIAG reader has passed the top of
its loop within the last **10 s**.

The reader loop is `poll()`-bounded at 250 ms, so it stamps its heartbeat
four times a second even on a silent port. A quiet modem therefore reads
`STALLED` (no bytes) with `decoder=alive`, which is not a fault in the
decoder. A watchdog thread judges the heartbeat, because the reader cannot
judge itself: it prints the regular stats line, and a stuck reader prints
nothing. When the heartbeat is more than 10 s old, the watchdog:

- sends a `diag_stats` object holding only `helper_alive: 0` and `decode_mode`,
  so the web panel shows **DEAD** and no counter is touched;
- prints `celldiag stats: DECODER-STALLED | decoder=stalled no_progress=Ns
  bound=10s | the native DIAG reader has stopped advancing: observations have
  stopped` at ERROR, at once and then on every stats interval while the stall
  lasts.

When the reader moves again it sends `helper_alive: 1` and an INFO line,
`nativedecode=only: the decoder is alive again`. On a finished replay or a
stopped source, the last stats line reads `PORT-CLOSED … decoder=stopped` and
`helper_alive` is `0`.

### The `diag_inventory` census

`diag_inventory.c` counts every LOG record by `(log code, payload byte 0)` and
renders a bounded `diag_inventory` line on the stats interval (else every
30 s) and once more at stop. It is never forwarded raw: its `status` goes to
the message bus, its counts into `diag_stats` (`inventory_distinct_codes`,
`inventory_unrecognized`, `inventory_silent`, `inventory_undecoded_native`),
its `table` onto the `diag_census` control line. Until the first census the
keys are omitted, not sent as `0`.

`decoded` means "a native leg claimed the record". A code no leg reads gets one
of three states:

| state | means | escalates |
|---|---|---|
| `unrecognized` | seen, never decoded, and no known record layout: usually new firmware | yes (ERROR) |
| `silent` | an emit-contract code that decoded and emitted nothing — on a live source indistinguishable from "no cells in range" | yes (ERROR) |
| `undecoded_native` | the code's record layout is known and no native leg reads it yet | no: it is the native-coverage **to-do list** |

`undecoded_native` is counted by log **code**: `undecoded_native_total`
beside the other totals, the codes named on the status line
(`… undecoded_native[0x1022, 0x117E +N more]`), the first 32 in the
`undecoded_native` array, flag `n` in the table (sorted after the findings,
so a full-mask stream never pushes a `silent` key off the 24 rows), and
`inventory_undecoded_native` in `diag_stats`.

"Known layout" is `diag_inventory_codes.h`: a frozen, sorted, hand-maintained
table of 1019 log codes. No build step generates it; add a code when its layout
becomes known.

A few codes are counted as decoded without a cell leg: identity sources
(`0xB821`, which seeds the identity cache but emits no observation of its own),
the `0xB197` config cache, and a well-formed `0x14D8` (whose record carries no
usable position and so can never emit; it is excluded from what `silent`
escalates on).

## Common source options

| option | meaning |
|---|---|
| `diagport=/dev/ttyUSBx` | override DIAG-port auto-detection |
| `atport=<path>` | name the AT-identify node and skip the IMEI scan. Optional for an MHI/wwan modem (a bare `celldiag-<imei>` falls back to `/dev/mhi_DUN`, `/dev/wwan*at*`); name it, with `diagport=`, when several PCIe modems make the by-name pick ambiguous |
| `spc=000000` | send a `DIAG_SPC_F` unlock (6 digits) before `LOG_CONFIG` — needed on SPC-gated modems (EG25-G / EC2x); harmless to omit on SDX24/SDX55 |
| `mask=wardrive` | the default `LOG_CONFIG` subscription: the curated cell set (`0xB193`/`0xB0C0`/`0xB192`/`0xB195`/`0xB17F`/`0xB197`/`0xB821`/`0xB97F`), low volume |
| `mask=full` | subscribe to every advertised LOG code — HIGH volume, diagnosis not wardriving. Whichever mask the capture armed is **cleared when it lets go of the port** — on a REST close, a Ctrl-C, or an open that fails after the handshake — with `LOG_CONFIG` DISABLE, so a `mask=full` stop does not leave the modem streaming megabytes per minute at the next DIAG client. `nomask=true` arms nothing and clears nothing |
| `nomask=true` | passive LOG tap — skip the `LOG_CONFIG` handshake (whatever a prior tool enabled) |
| `f3=all` | arm every F3 debug subsystem at every severity (`0x79`/`0x99` flood) — diagnosis not wardriving. **Armed, not relayed**: see [F3](#f3-armed-not-relayed) |
| `f3=high` / `f3=error` | as `f3=all`, minus sites that only ever print below HIGH / below ERROR — ~94% / ~68% of records kept ([why subtractive](#f3-severity-floors)) |
| `qsh=on` | full F3 surface — arm the QSH-trace `0x9001` maskset (`0x9D`/`0x92`) + `0x60` events + a `diag_id` binding request as a **gated tier** over the same DIAG fd. Off by default; for debug captures only. QSH emits no cell observations: its value is in the raw stream. Non-fatal on parts that don't implement it (SDX20 status≠0 / MDM9607 `BAD_CMD`). **Disarmed on stop**, on a REST close or a Ctrl-C: the QSH-trace latch (it survives reboots), F3, and the `0x60` event stream the arm turned on. A passive `celldiag_probe --no-mask` tap after the stop confirms it |
| `profiles=<dir>` | `capture_cell_at` profile JSONs supplying per-modem defaults for `mask=` (`diag.mask_default`), `f3=` (`diag.f3_default`) and `spc=` (`diag.spc`), matched on firmware. An explicit option always wins. Default `$CELLDIAG_PROFILES`, else compiled-in (empty: not consulted) |
| `replay=<file>` | decode a saved raw-HDLC capture instead of a live port (no modem opened, no mask sent) |
| `rawlog=<spec>` | tee the raw DIAG stream to disk (`%m` = model, `%i` = IMEI, `%t` = UTC stamp; a directory gets a synthesized `celldiag-<imei>-<ts>.hdlc`). The file is replay-compatible. **One tee per capture session, never truncated:** a reopen (a restart-to-apply toggle, the whole-modem switch, Kismet's error reopen) that finds the file non-empty tees to `<stem>-<UTC ts><ext>` instead, and the `.capture_meta.json` / `.clock_anchor.jsonl` companions follow it. Each tee then matches exactly one kismetdb DIAG stream |
| `rawpackets=off` | stop sending the raw DIAG stream into Kismet as DLT 147 packets (default **on**; see [below](#raw-diag-in-the-kismetdb-rawpackets)) |
| `gsmtap=on` | live GSMTAP out: every LTE RRC (`0xB0C0`) and LTE NAS (`0xB0Ex`) record is also sent as a UDP datagram to `127.0.0.1:4729`, for a Wireshark beside Kismet. `gsmtap=<ipv4>[:<port>]` sends elsewhere; default **off**. See [below](#live-sibs-in-wireshark-gsmtap) |
| `stats_interval=<s>` | seconds between [health lines](#health-helper_alive-means-the-decoder-is-alive) (default 30; `0` disables) |
| `clock_anchor_sec=<s>` | cadence of the host↔modem clock anchor: a `DIAG_TS_F` request at start, every `<s>` seconds (default 30; `0` = periodic off) and at end, each reply paired with the host clock as a `type="ClockAnchor"` kismetdb row and a line of `<rawlog>.clock_anchor.jsonl`, so a GNSS-off drive can still put absolute UTC on every frame. Live modems only |
| `enabled=false` | register the source but leave it idle (no port opened, no handshake, no decoder started) |
| `debug=true` | verbose message-bus logging |
| `nativedecode=only`, `census=native` | accepted, and the default; any other value is refused (see [Decoder](#decoder)) |

## Runtime options

Kismet ships exactly **one** generic runtime setter for a datasource —
`POST /datasource/by-uuid/<uuid>/set_channel` — so every knob multiplexes
through that single string, in the same `key=value` spelling used above:

| runtime setting | effect |
|---|---|
| `rawlog=<spec>` | start or **redirect** the tee mid-capture. The new sink is opened *before* the old one is closed, so a bad path costs you nothing |
| `rawlog=off` / `rawlog=none` | stop the tee. `rawlog_path` is deliberately **retained** — a stopped tee must stay distinguishable from one that was never configured |

**The retention above is why `rawlog_active` exists.** Keeping the
path across a stop is right — it answers *"where did the bytes I already
captured go?"* — but it means the path answers only that, and never *"is it
writing?"*. `rawlog_active` reports the sink's fd directly, and the three
states are read from the pair:

| `rawlog_path` | `rawlog_active` | meaning |
|---|---|---|
| absent / `""` | absent / `0` | no `rawlog=` was ever configured |
| set | `true` | the tee is open and writing |
| set | `false` | the tee **stopped**; the file named is complete |

A consumer that derives liveness from the path alone collapses the last two
rows and can never offer to restart. `rawlog_bytes` no longer rising is the same
information, but it is a *derivative*: it needs two ticks and a memory of the
previous one, so nothing renderable from a single object can use it.

`mask=`, `f3=` and `gsmtap=` are **recognised and refused** at runtime, with a
message saying so: `mask=` and `f3=` mean re-issuing a `LOG_CONFIG` /
`SET_ALL_RT_MASKS` handshake on the DIAG fd the capture thread is blocked
reading, and the GSMTAP sink is opened with the decoder at open time. Use
`close_source` + `open_source` with a new definition instead. An unknown key is
refused *differently*, so "not settable now" and "no such option" never look
alike — the operator's next action differs.

**A refused setting is reported in the MESSAGE, not the status code.** The
framework maps only a *negative* `chancontrol_cb` return to failure on the
wire, and a negative return also sets `spindown` — so reporting a typo through
the status code would end a running wardrive. celldiag returns 0 (not fatal,
and the bogus string is not adopted as the source's "channel") and sends the
reason as a `MSGFLAG_ERROR` bus line.

**An APPLIED setting returns 0 too**, as in cellat. A return above 0 records
the string as the source's **channel**, so the server would display
`rawlog=/x` as `kismet.datasource.channel` and **replay** it after an error
re-open, re-arming a tee the operator may have stopped since. A runtime setting
is a one-time change to a running process; "channel" is reserved for band/RAT
locks (cellat's).

The web panel has a switch for `rawpackets=` and `qsh=` and a cadence field for
`clock_anchor_sec=`. Each is a close, `update_definition`, and re-open: none
of the three can change under a running capture.

NOTE: `set_tune_capable(true)` is what makes any of this reachable, and it is what
Kismet's generic datasource UI keys on to render **channel** affordances — so
celldiag's source row offers a channel control for a source with no channels.
Accepted deliberately: it is currently the only surface through which the knob
can be driven at all. See the note in `datasource_cell_diag.h`.

### What the source reports about its switches and its bring-up

Beside the fields above, the `diag_stats` line carries:

| field | meaning |
|---|---|
| `switches_reported` | `1` once a line carrying the next three groups has arrived. Read nothing below while it is `0` |
| `rawpackets_on`, `rawpackets_slices`, `rawpackets_dropped` | `rawpackets=` in force, raw DIAG slices delivered to the kismetdb, and slices lost to a full ring |
| `qsh_requested`, `qsh_armed` | `qsh=on` was asked for, and the arm was sent this session. Live sources only |
| `anchor_count`, `anchor_last_epoch` | ClockAnchor rows completed; `0` epoch = none yet. Live sources only |
| `obs_ring_dropped` | rendered observations dropped because Kismet's output ring was full: a live source drops rather than stop reading the DIAG port |
| `bringup_ms`, `bringup_phases`, `bringup_error` | the deferred bring-up: phases finished so far (`at_scan=1204ms port_detect=3ms … decoder_start=…`, sent after each phase), the total, and why it failed |

So that a failed bring-up does not leave the source reading only `IPC
connection closed`, the source sends `bringup_error` (and `mask_preset`
`failed`) before it exits, and the server uses it as the source's error reason:
`bring-up failed: Could not locate DIAG interface … Pass diagport=/dev/ttyUSBx
explicitly.` The fields are cleared at every open, so a retry that succeeds does
not keep the last attempt's error.

### Frames that fail CRC: a stream losing bytes

A busy stream can lose byte runs between the modem and `read()`: the tty
overflows, the kernel logs nothing, and every integrity check on the kismetdb
passes, because the kismetdb faithfully holds what the source *read*. The one
trace is DIAG frames that fail their CRC. The decoder's own stream checks every
frame and counts them.

| where | what |
|---|---|
| `diag_stats`: `crc_checked`, `crc_ok`, `crc_bad`, `crc_damage_alerts` | the running census; the server's `kismet.datasource.celldiag.crc_*` fields. `crc_reported` is `0` until the first report, so a `0` below it is never a measurement |
| ERROR line `… DIAG stream losing bytes: N CRC-bad frame(s) in the last Ts …` | once per `stats_interval` window with **≥ 10** CRC-bad frames, and once more at end-of-stream for the last window |
| the source's **warning** | set by the server when `crc_damage_alerts` grows; it stays until the source reopens |
| `data` row `type="DiagCrcCensus"` | sent once at end-of-stream, after the final flush: `{"schema":"diag-crc-census/1","session_id":N,"frames","crc_checked","crc_ok","crc_bad","short","oversize","damage_alerts","counter":"native"}`. `session_id` (the raw stream's) is present only with `rawpackets=on`. This row, not the `datasources` row, is the record: that one is rewritten every 30 s and its shutdown rewrite does not land |

A healthy stream shows at most the partial first and last frames (≤ 2 bad in
the large majority of captures), so the floor of 10 bad frames per window
never fires on the edges. A damaged frame is counted and dropped, never decoded.

**What causes it:** not host load but DIAG throughput. The decoder runs on the
read loop, so when it falls behind a burst the loop stops reading the tty and
the USB-serial driver drops the overflow.

## Live SIBs in Wireshark (`gsmtap=`)

```sh
wireshark -k -i lo -f "udp port 4729"          # or: tshark -i lo -f "udp port 4729"
kismet -c 'celldiag-<IMEI>:gsmtap=on'
```

Wireshark's `lte-rrc` dissector then shows each broadcast SIB as the modem
reads it (`SystemInformationBlockType1`, `SystemInformation [ SIB2 SIB3 ]`,
`[ SIB4 ]`, `[ SIB5 ]`, ...), plus paging and RRC signalling, and `nas-eps`
the NAS. The sink is a **tap**: what reaches Kismet is identical with it on or
off.

- **Where it runs.** In this process (`diag_gsmtap_sink.c`), framed natively,
  for every eligible code: LTE RRC (`0xB0C0`) and LTE NAS
  (`0xB0E1/E2/E3/EC/ED`). A framer declines a record it cannot frame (a payload
  that does not parse, no PDU bytes, a NAS PDU that fails the TS 24.301
  structure check), and the record is counted as `declined`. An eligible code
  with no framer in this binary is named at ERROR when the source opens and
  counted as `declined` and `(no native framer: N)`.
- **Non-blocking.** The socket never waits: a full buffer is a counted error,
  never a wait on the DIAG read path. A socket that will not open is an ERROR
  at open (`NO GSMTAP frames this session`); decoding continues.
- **What is not sent.** NR RRC (`0xB821`): GSMTAP has no NR-RRC type, and its
  Exported-PDU framing is a pcap link type, not a UDP protocol. A record whose
  channel has no GSMTAP sub-type (BCCH-BCH) is counted as `declined`.
- **Destination.** IPv4 literals and `localhost` only, checked at open (a bad
  value fails the open with a reason). A hostname is refused so that no DNS
  lookup sits between a correct definition and a working sink.
- **Counters.** At end of stream the source sends `gsmtap <dest> sent=N
  declined=N errors=N` (plus `(no native framer: N)` when non-zero) to the
  message bus, and one ERROR line at the first `sendto` failure. A send failure
  never stops decoding and never counts as an enrichment failure in the census.
- **Open-time only.** Changing it through the runtime setter is declined with
  the reopen remedy, like `mask=` and `f3=`.

## Raw DIAG in the kismetdb (`rawpackets=`)

By default celldiag sends the raw DIAG byte stream itself into Kismet, not only
the observations decoded from it. The stream arrives as packets with link type
**147 (`LINKTYPE_USER0`)**, and the server logs them like any link frame:
they land in the kismetdb **`packets`** table, and in a pcapng log if one is
enabled. A drive's `.kismet` therefore carries the raw stream, and `rawlog=` is
not the only copy. `rawlog=` remains as the external file tee;
`rawpackets=off` turns the in-db copy off.

**Each packet is a slice of the stream, not a single frame.** The full contract
is in `diag_rawpkt.h`:

| bytes | field | |
|---|---|---|
| 0–3 | magic | `CDRH` |
| 4 | version | `1` |
| 5 | flags | bit 0 = `FRAGMENT` (slice does not end on a frame boundary); bit 1 = `END` (end of stream, see below) |
| 6–7 | header_len | `24`, little-endian — skip this many bytes to reach the payload |
| 8–15 | session_id | LE, host `CLOCK_REALTIME` ns when this stream began |
| 16–23 | offset | LE, byte offset of the payload within the stream |
| 24– | payload | the bytes exactly as read from the DIAG port (HDLC-escaped, CRC and `0x7E` included) |

For one `(datasource, session_id)`, sort the slices by `offset` and
concatenate the payloads. The result is the stream, byte for byte: the same bytes
a `rawlog=` tee opened at the start of the capture writes. A gap between one
slice's end and the next slice's offset is exactly the bytes that were not
delivered.

**A Kismet stop lets the source finish first (the graceful close).**
The server asks the helper to close and waits for its teardown, so the residual,
the `END` slice and the `END` clock anchor all land. Whether the stop is a REST
`close_source`, a server SIGTERM or a terminal Ctrl-C (SIGINT to the whole
process group), the in-db stream is byte-identical to its `rawlog=` tee and
ends in a confirmed `END` with no gaps. The rest of this note is about a stop
WITHOUT it: an older helper, a close that ran out of its grace, or
`datasource_graceful_close=false`.

**Without the graceful close, the in-db stream can end one read before the
stop.** Every delivered slice still equals the tee at its offset, but the read
in flight when the server closes its pipe is lost: nothing carries it to the
server after that. A SIGTERM to the server can therefore leave a stream short
by the frames read in the last few hundred milliseconds. Helpers built before
the capture framework woke its I/O loop on commit can lose up to about a second
of tail. Keep `rawlog=` when the last frame matters.

**How a reader sees the end of a stream.** A gap needs a delivered slice
after it. So a slice dropped after the last delivered one leaves no gap, and
without a marker a stream that lost its tail would read as whole. There are three
witnesses:

- **The `END` slice.** A stream that reaches its teardown closes with one: an
  empty payload, and `offset` = the final stream length, counting every byte,
  delivered or dropped. Tail loss is then an ordinary gap, the one before `END`.
  - A Kismet-driven stop reaches the teardown through the graceful close, so
    it ends in `END`. A stream still has none when it comes from an older
    helper, a close that ran out of its grace, a server run with
    `datasource_graceful_close=false`, or a source that died (next witness but
    one). Its end is then unconfirmed: whole, or short by the read(s) in flight
    at the close (see above).
- **The `RawDiagDrop` row.** The first time a live source drops a slice, it also
  writes one `data`-table row, `type="RawDiagDrop"`:
  `{"schema":"raw-diag-drop/1","session_id":…,"first_drop_offset":…,"first_drop_len":…}`.
  - This row is the only per-source record of a drop. The `messages` table,
    where the ERROR line lands, records no datasource.
  - With it, a reader knows a live stream is holed even when the drop was the
    tail.
  - Without the graceful close, neither witness covers the reads lost at the
    stop (see above): they were not dropped, so no row fires, and no `END`
    follows them. A first drop in the last moments before such a stop is
    invisible too, when neither the row nor `END` can land.
- **The `RawDiagAbort` row, written by the SERVER.** A source that dies
  mid-stream reaches no teardown: its helper killed by the capture framework's
  15 s PING watchdog while the server stalled, a crash, an OOM kill. There is no
  `END`, and the helper's out-ring (up to 4 MiB) dies with it, queued, not
  dropped, so no `RawDiagDrop` row either. The helper cannot report that, so
  the server's celldiag datasource does. It follows each raw session from the
  slice headers, and when the source fails after data and before `END` (and the
  server is not itself stopping), it writes one `data`-table row:
  `{"schema":"raw-diag-abort/1","session_id":…,"delivered_end":…,"slices":…,"reason":…}`.
  - `delivered_end` is one past the highest stream byte the server received.
    The rest of the stream is gone, and no offset can show how much.
  - A server stall long enough to trip the watchdog writes one row per lost
    session, with `delivered_end` matching the delivered slices exactly. A
    `rawlog=` tee, if one was running, holds the bytes the row says are
    missing.
  - A stop the server asked for is not a death and writes no row.

**Order comes from `offset`, never from row order.** Kismet hands packets to
one of four or more worker threads at random, and each thread inserts its own
rows. Remote sources also have their timestamps overwritten on arrival, and
`kismetdb_to_pcap` selects with no `ORDER BY`. In practice a large fraction of
adjacent rows are out of order, and a row-order concatenation leaves most
frames misplaced.

**Strip `header_len` bytes before deframing.** The header is binary and can
contain `0x7E`. A reader that forgets to strip it merges the header into the
slice's first frame, which then fails its CRC. That loses one frame per packet,
silently.

```python
import sqlite3, struct, collections
db = sqlite3.connect("file:drive.kismet?mode=ro", uri=True)
streams = collections.defaultdict(list)
for src, blob in db.execute("SELECT datasource, packet FROM packets WHERE dlt = 147"):
    magic, ver, flags, hlen, session, offset = struct.unpack_from("<4sBBHQQ", blob)
    streams[(src, session)].append((offset, blob[hlen:]))
for key, slices in streams.items():
    hdlc = b"".join(p for _, p in sorted(slices))   # == the rawlog= .hdlc
```

For real use, `log_tools/kismetdb_to_hdlc` does this properly:

- It reads only celldiag sources, and writes one `.hdlc` per stream, named like
  a `rawlog=` tee.
- It reports gaps, overlaps, and malformed, truncated or unaligned slices on
  every run. It also reports tail loss before an `END`, a bad `END`, and any
  `RawDiagDrop` row. `--strict` refuses to write anything if any are present.
- A stream with no `END` gets a NOTE that its end is unconfirmed and its tail
  may be short (see above). That is not a `--strict` failure, because
  drives recorded by helpers without the graceful close lack `END`;
  `--require-end` makes it one.
- A session with a `RawDiagAbort` row and no `END` gets a WARNING that the
  source DIED mid-stream, and `--strict` refuses it.
- `-l` lists the streams, and `-O <dir>` writes all of them.

Slices hold whole HDLC frames only: every slice ends just after a `0x7E`, so a
lost slice costs whole frames and never corrupts its neighbours. There are two
exceptions, both flagged `FRAGMENT`: a run of more than 12 KiB with no `0x7E` in
it (not DIAG), and the partial frame left when a stream ends. A slice carries the
frames one host read completed, which keeps the per-row overhead to a few
percent. One row per frame would store the stream 2–8× over, since a row has
about 150–200 bytes of fixed columns and the median DIAG frame is 26–107 B.
The 12 KiB cap is set by the **server's** 16 KiB IPC frame limit
(`MAX_EXTERNAL_FRAME_LEN`): a bigger frame gets the whole source errored,
not just dropped.

**Loss policy.**
- **Live source:** when Kismet's capture ring is full, the source drops the
  slice. It writes one `RawDiagDrop` row, then one ERROR line, and counts later
  drops. Waiting would stop the DIAG read, and the overflow would then cost
  `rawlog=` and decoding too.
- **Replay:** the source waits instead, so replaying an `.hdlc` into a
  `.kismet` is lossless.
- **Teardown:** nothing reads the port any more, so the residual and `END` wait
  too (up to about 2 s on a live source).

A replay, or any stop that reaches teardown, ends with a totals line:
`raw DIAG into the packets table (DLT 147): N slice(s), B delivered; …; END at
offset N delivered`. A Kismet-driven stop cancels the capture thread first, so
on that path there is no totals line and no `END`. The stream can also end
short by the read(s) in flight at the close, in whole frames (see above). Setting
`kis_log_packets=false` in `kismet_logging.conf` keeps the slices out of the
kismetdb entirely.

## F3: armed, not relayed

`f3=` arms F3 debug messages on the modem, but this source has **no F3 relay**:
it sends no `diag_f3` record and puts no prints on the message bus. The prints
are still captured — they are in the DIAG byte stream, so read them from a
`rawlog=` tee or from the kismetdb's raw DIAG packets (`rawpackets=on`;
`kismetdb_to_hdlc` extracts them) with an offline F3 decoder. At open the
source says so at ERROR (`f3=<preset>: ARMED BUT NOT RELAYED …`), and its
reported F3 preset reads **`<preset>+norelay`** (e.g. `all+norelay`), so the
health readout is never mistaken for a relayed stream.

## F3 severity floors

`f3=high` and `f3=error` vary one u32 in the `SET_ALL_RT_MASKS` body — the
**runtime level mask**, which the modem ANDs against each emitting site's
compiled-in `ss_mask`. A site prints iff the AND is nonzero.

| preset | mask | records kept |
|---|---|---:|
| `all` | `0xFFFFFFFF` | 100.0% |
| `high` | `0xFFFFFFFC` | 94.2% |
| `error` | `0xFFFFFFF8` | 68.4% |

**The floors are subtractive, and there is deliberately no selective one.**
The low 5 mask bits are a severity ladder (across qdbs from several vendors,
the share of error-worded format strings rises monotonically with the bit);
bits ≥5 are **per-SSID custom** meanings, not higher severities. So the
intuitive reading of "severity floor" — send `ERROR|FATAL`, i.e. `0x00000018`
— is a **mute button**: about two thirds of F3 records come from sites carrying
only custom bits, so that mask keeps roughly **1%** of the stream and drops the
ML1 / tuner / GNSS prints F3 is wanted for. Clearing low ladder bits from
all-ones silences ladder-only sites and keeps every custom-bit site.

`f3=` therefore takes **named presets only** — a raw mask would hand an operator
that footgun with no way to warn. The percentages in the table are typical
retention on a SIM8202G-M2 drive capture.

**The floor is enforced by the modem at arm time, not by the source.** There
is no post-filter, so the floor a capture was taken with is a property of that
capture: `f3=high|error` on a `replay=` source changes nothing in the file.

## Per-modem DIAG quirks

- **EG25-G / EC2x / EG2x (MDM9607):** `LOG_CONFIG` (SET_MASK) is **SPC-gated** —
  the modem rejects the mask until a `DIAG_SPC_F` unlock is sent.
  Pass `spc=000000` (factory default), or set `diag.spc` in the model profile so
  it arms automatically. LM960 (SDX24) and RM500Q (SDX55) do not gate it — omit
  `spc=` there.

## Debugging with a raw capture

`celldiag_probe` (`make probe`; no Kismet dependency) opens a DIAG port, arms the
narrow mask, and streams the raw HDLC byte stream to stdout — the same bytes the
helper decodes. Use it to separate port/HDLC problems from decode problems, then
decode the capture by replaying it through the helper:

```sh
./celldiag_probe /dev/ttyUSB0 > cap.hdlc        # [max_bytes] [--no-mask] [--spc N] [--firmware S] [--profiles D]
./celldiag_replay_ndjson ./kismet_cap_cell_diag celldiag-000000000000000:replay=<absolute path of cap.hdlc>
```

`celldiag_replay_ndjson` speaks the datasource protocol to the helper and prints
what Kismet would receive as canonical NDJSON, one line per observation; status
messages go to stderr as `message: <text>`, census lines as `census: <json>`. It
exits `0` ok, `2` if the source refused to open or reported an ERROR, `3` on
`--timeout`. The probe resolves `--spc` from the same `capture_cell_at` profile
(`diag.spc`, matched on `--firmware`) as the helper.

## Troubleshooting

| symptom | cause | fix |
|---|---|---|
| `nativedecode=<x> is not supported` / `census=<x> is not supported` at open | a definition written for an older version that named another decoder or census producer | remove the option, or set it to `nativedecode=only` / `census=native` |
| `the helper= source option was removed` | a definition written for an older version | delete `helper=…` from the definition |
| `bytes=` climbs but `obs=0` (`RX-NO-OBS`) | the stream carries no record a native leg turns into an observation: no cell in range, a mask without the cell codes, or codes no leg reads | read the [decoder readout](#decoder): `no-leg=` counts records no leg reads and `declined=` records a leg read and found nothing in; the census names `undecoded_native` codes. A stuck reader reads `DECODER-STALLED` instead |
| `LOG_CONFIG handshake failed ... SPC-gated?` | EC2x SPC gate | pass `spc=000000`; see [Per-modem DIAG quirks](#per-modem-diag-quirks) |
| `DIAG SPC unlock (spc=000000) rejected` after ~20 s, in a multi-source open, on a unit whose SPC works alone | another process wrote into the DIAG port before the open (a `cellat` IMEI scan writes `AT\r\n` to every port it can claim); the modem glued those bytes to the SPC frame, whose CRC then failed | fixed in current helpers: the DIAG port open sends one lone `0x7E` first, which ends any such partial frame. Rebuild an older helper |
| the scan reads `AT identify: IMEI … not found while N port(s) were held by another process` | a concurrent source was probing this modem's AT ports at that instant | nothing: one rescan follows after 250–775 ms. `CELLDIAG_SCAN_PORTS="<path> <glob> …"` **replaces** the scanned set (`/dev/ttyUSB*` + `/dev/ttyACM*`); `atport=` names one AT node and skips the scan |
| the scan reads `AT identify: port(s) still closing after another probe, open() gave up at 1000 ms and skipped them: ttyUSB18(open-timeout)` | another probe's close of that tty is still waiting out its 30 s `closing_wait` (a port that never read its `AT\r\n`), and Linux blocks every new `open()` of a tty in its final close | nothing: the scan skips the port after 1 s instead of blocking ~30 s. The port is never the target: an AT port reads what it is sent. cellat logs the same line as `cellat AT scan: port(s) still closing …` |
| the web UI lists `RM520N-GL — AT commands` but no `RM520N-GL — DIAG`, or a bare `celldiag-<imei>` for a PCIe modem fails `Modem IMEI … not found on any serial port or non-USB (MHI/wwan) AT node` | an older helper whose lister and bare-definition bring-up walked USB ttys only. Current helpers fall back to the non-USB AT nodes after the USB pass (a held `/dev/mhi_DUN` is read through its holder's vouch) and pick the DIAG node by name | if the row is still missing, `--list` prints `not listing the non-USB modem(s) at …` with the reason: usually more than one modem's DIAG node by name (two PCIe modems), which no name can disambiguate. Name both nodes: `atport=/dev/mhi_DUN,diagport=/dev/mhi_DIAG` |
| an MHI/wwan `diagport=` source (the PCIe RM520N-GL's `/dev/mhi_DIAG`) reads model `unknown` and says `no non-USB AT node answered as this IMEI (held by the paired cellat source, or absent)` | its only AT node, `/dev/mhi_DUN`, was held for the paired cellat's session when the bring-up scanned it | normally nothing: the bring-up scans the non-USB AT nodes only (`/dev/mhi_DUN`, `/dev/wwan*at*`) and reads the model there, `AT identity from /dev/mhi_DUN`, before the cellat source takes the node. A node held throughout costs one rescan, then the source opens without AT identity as before. `atport=/dev/mhi_DUN` names the node explicitly |
| under `mask=wardrive`, 2G/3G codes flood in after an airplane / `AT+CFUN=4→1` cycle (`0x508F`, `0x5075`, `0x41C1`, `0x4176`, `0x7001` …) | an older helper. `SET_MASK` is per log type, and a narrow arm that writes only the types holding a target code (1 and 0xB) leaves armed whatever mask a PREVIOUS DIAG client left on types 4/5/7/10/13. That mask sits near-silent while the modem idles on LTE and floods once the cycle forces a multi-RAT search, so it looks like the modem dropping the mask. It does not: current helpers send an all-zero mask to every advertised type without a target code, and the cycle then carries no off-mask codes | rebuild the helper; nothing to configure. A WCDMA task may keep emitting `0x4116` for ~30 s after the arm (a cached enable) before it stops |
| `f3=` set, but no F3 on the message bus; the preset reads `all+norelay` | this source arms F3 and does not relay it | read the prints from the raw stream; see [F3](#f3-armed-not-relayed) |
