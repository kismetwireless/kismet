/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    Cell modem DIAG capture source for Kismet.

    Passively taps a Qualcomm modem's DIAG port, applies a narrow DIAG log
    mask (LTE ML1 serving 0xB193 and related codes), and decodes the raw HDLC
    byte stream IN THIS PROCESS: diag_logstream extracts each DIAG LOG_F record
    and the generated C++ legs (diag_native_decode.cpp) render it as
    cell_observation JSON, which this binary relays to Kismet via
    cf_send_json() exactly as capture_cell_at does. No other program is
    started.

    Every observation carries a prov block
    {"src":"diag","origin":"0xB193",...} so phy_cell can merge DIAG signal with
    AT identity on one tower without duplicates.

    The raw byte stream itself also goes to Kismet: cf_send_data()
    packets with DLT 147, offset-stamped slices the server logs into the
    kismetdb `packets` table (rawpackets=, contract in diag_rawpkt.h). The
    server only logs them; decoding stays here.

    Addressing mirrors capture_cell_at: the source is celldiag-<15-digit IMEI>.
    The IMEI is resolved to a modem via an AT probe on a sibling serial port,
    then the DIAG interface (conventionally if00, the lowest USB interface on
    that modem's USB device) is opened for the tap.

    Source options:
      diagport=<path>    explicit DIAG /dev/tty node (overrides auto-detect)
      atport=<path>      explicit AT-identify node (overrides the ttyUSB
                         IMEI scan). Optional for an MHI/wwan modem: a bare
                         celldiag-<imei> that no USB port answers falls back
                         to the non-USB AT nodes (/dev/mhi_DUN, /dev/wwan*at*,
                         or their holder's vouch) and picks the DIAG node by
                         name -- which is what --list and the web UI's Enable
                         click offer. Name it (with diagport=) when several
                         PCIe modems make the by-name pick ambiguous.
      nativedecode=only  the decoder: the native legs, in this process (the
                         only one, and the default). Any other value is
                         refused at open.
      census=native      the census producer: this process (the only one, and
                         the default). Any other value is refused at open.
      replay=<file>      decode a raw-HDLC capture file instead of a live modem
                         (offline test hook; no modem opened, no mask sent)
      rawlog=<path>      tee the raw HDLC DIAG byte stream to <path> while it is
                         also decoded (write-side mirror of replay=). The file
                         is a replay-compatible raw-HDLC capture, written
                         uncompressed (compress it afterwards if wanted).
                         Path tokens: %i=IMEI, %m=model, %t=UTC-timestamp; a
                         directory (or trailing '/') gets a synthesized
                         celldiag-<imei>-<ts>.hdlc filename. Never truncated:
                         if the file already holds an earlier session's
                         bytes, this session tees to a sibling
                         <stem>-<UTC ts><ext> (then -2, -3 ...) and says so.
      enabled=true|false per-source lifecycle switch. false leaves the
                         source defined-but-idle: registered and visible, but no
                         DIAG port opened, no mask/F3 handshake, no decoder
                         started - nothing captured until re-enabled. Runtime
                         enable/disable/restart is driven by the Kismet server
                         reaping/respawning this process; a fresh enabled=true
                         open re-acquires the port and re-runs the handshake.
                         Default true.
      nomask=true        skip the LOG_CONFIG handshake (passive tap of whatever
                         a prior tool already enabled)
      mask=wardrive|full LOG_CONFIG subscription preset. wardrive
                         (default) subscribes the curated WiGLE-relevant set
                         (0xB193/0xB0C0/0xB192/0xB195/0xB17F/0xB197/0xB821/0xB97F) -- low
                         volume. full subscribes EVERY LOG code the modem
                         advertises across all equipment-id ranges -- HIGH
                         volume, for diagnosis not wardriving. Ignored under
                         nomask=true. If unset, the per-modem default from the
                         matched profile's diag.mask_default is used (see
                         profiles=), else wardrive.
      profiles=<dir>     dir of capture_cell_at profile JSONs providing per-modem
                         defaults for mask= (diag.mask_default), f3=
                         (diag.f3_default), and spc= (diag.spc), selected by the
                         modem firmware via each profile's firmware_match glob.
                         An explicit source option always overrides the
                         profile default.
                         Default: $CELLDIAG_PROFILES, else compiled-in (empty =>
                         defaults not consulted).
      spc=<6 digits>     DIAG_SPC_F unlock sent before LOG_CONFIG. Needed
                         on SPC-gated modems (EC2x/EG2x, e.g. EG25-G) whose
                         SET_MASK is refused until unlocked; factory default is
                         000000. Absent by default (no SPC sent) -- unchanged for
                         the ungated SDX24/SDX55 parts. If unset, the per-modem
                         default from the matched profile's diag.spc is used (see
                         profiles=); an explicit spc= overrides it.
      f3=off|all|        F3 debug-message arming, orthogonal to mask=
         high|error      (F3 rides DIAG_EXT_MSG_CONFIG_F, not LOG_CONFIG). off
                         (default) arms no F3. The other three run
                         SET_ALL_RT_MASKS with a different runtime-level mask:
                           all    every subsystem at every severity (0xFFFFFFFF)
                                  -- the modem's full 0x79 / QSR4 0x99 trace.
                                  HIGH volume.
                           high   0xFFFFFFFC -- as all, minus sites that only
                                  ever print at LOW/MED. ~94% of records kept.
                           error  0xFFFFFFF8 -- also drops HIGH-only sites.
                                  ~68% of records kept; the volume-trimming
                                  default if you want one.
                         The floors are SUBTRACTIVE: they silence sites whose
                         mask carries ONLY low ladder bits and keep every
                         per-SSID custom-bit site (ML1 / tuner / GNSS prints).
                         A *selective* "ERROR|FATAL" floor would keep 1.3% of a
                         real F3 stream and is deliberately not offered -- see
                         diag_config.h for the measurements.
                         Composes with any mask= preset (incl. nomask=true). If
                         unset, the per-modem default from the matched profile's
                         diag.f3_default is used (see profiles=), else off.
      qsh=on|off         FULL F3 surface -- the QSH-trace 0x9001 maskset
                         (0x9D/0x92) + 0x60 events + a diag_id binding request,
                         armed as a gated tier over the same DIAG fd (not a
                         second datasource). off (default) so a lean wardrive
                         never pays the QSH volume; on is a development drive
                         that captures every F3 type. Composes with f3= and mask=. QSH emits no
                         cell observations; its value is in the rawlog= tee.
                         Disarmed on stop, REST close or Ctrl-C: the QSH-trace
                         latch (it survives reboots, so it must be cleared),
                         F3, and the 0x60 event stream the arm turned on.
      stats_interval=<s> seconds between "is data flowing?" health status lines
                         on the message bus (default 30; 0 disables). The line
                         reports a health verdict, bytes read, observation count
                         + rolling obs/sec, last-observation age, decoder
                         liveness, and the active mask - so a stalled modem is
                         distinguishable from a healthy one within one interval.
      clock_anchor_sec=<s> cadence of the host<->modem-ts64 clock anchor: a
                         DIAG_TS_F request at START,
                         every <s> seconds (default 30; 0 = periodic off) and at
                         END, each reply paired with the host clock as a
                         type="ClockAnchor" kismetdb row and a line of
                         <rawlog>.clock_anchor.jsonl -- so a GNSS-off drive can
                         still put absolute UTC on every frame. Live modems only.
      rawpackets=on|off  send the raw DIAG stream to Kismet as packets:
                         DLT 147 (LINKTYPE_USER0) offset-stamped slices the
                         server logs into the kismetdb `packets` table, so the
                         .kismet carries the stream itself, not only what was
                         decoded from it. Default on; independent of rawlog=
                         (the file tee). Contract: diag_rawpkt.h. A live source
                         DROPS a slice when Kismet's ring is full rather than
                         stall the port, and records the first drop as a
                         type="RawDiagDrop" row; a replay waits and stays
                         lossless. A stream that reaches its teardown closes
                         with an END slice.
      gsmtap=off|on|<ipv4>[:<port>]
                         live GSMTAP out for Wireshark: every LTE RRC (0xB0C0 --
                         SIB1 and every later SIB, paging, RRC signalling) and
                         LTE NAS (0xB0Ex) record this binary has a framer for
                         is also sent as one UDP datagram to that address, so
                         `wireshark -i lo -f "udp port 4729"` dissects the SIBs
                         with lte-rrc while Kismet runs. on = 127.0.0.1:4729;
                         default off. IPv4 literals (and localhost) only. A tap:
                         what reaches Kismet is unchanged. NR RRC is not sent
                         (GSMTAP has no NR-RRC type). Framed by this process
                         (diag_gsmtap_sink.c); an eligible code with no framer
                         is counted as declined, and named at open.
      debug=true|false   verbose message-bus logging

    Runtime-settable options. Kismet's one generic runtime setter for a
    datasource is `POST /datasource/by-uuid/<uuid>/set_channel`, so every knob
    multiplexes through that single string, in the same key=value spelling:

      rawlog=<path>      start or REDIRECT the tee while capturing. The new sink
                         is opened before the old one is closed, so a bad path
                         costs you nothing.
      rawlog=off|none    stop the tee. rawlog_path is deliberately RETAINED so a
                         stopped tee stays distinguishable from one that was
                         never configured.

    Everything else is open-time only and says so by name when set at runtime --
    `mask=` and `f3=` because applying either means re-issuing a handshake on
    the DIAG fd the capture thread is blocked reading. Use Kismet's
    close_source / open_source with a new definition instead.

    NOTE: a refused runtime option is reported in the message, not the status
    code. The framework maps only a negative chancontrol return to failure on
    the wire, and a negative return also tears the source down -- so reporting
    a typo as a failure would end a running wardrive. See celldiag_chancontrol().
*/

/* config.h comes from the include path, not from a hardcoded "../config.h".
 * A quoted include resolves against this file's own directory first, so a
 * hardcoded parent path cannot be redirected by -I, and the no-autoconf build
 * could not run without ./configure having first generated an (untracked)
 * ../config.h. standalone.mk supplies its own config.h on -I; the
 * autoconf build passes -I.. and still gets the generated one. */
#include "config.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <limits.h>    /* PATH_MAX -- glibc supplies it transitively, Darwin does not */
#include <math.h>      /* round() -- the GNSS geo-tag precision match */
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

#include "../capture_framework.h"

#include "diag_capture.h"
#include "diag_config.h"
#include "diag_portdiag.h"
#include "diag_ifclass.h"
#include "diag_wwanport.h"
#include "diag_profile.h"
#include "diag_optset.h"
#include "diag_rawlog.h"
#include "diag_capmeta.h"
#include "diag_clockanchor.h"
#include "diag_rawpkt.h"
#include "diag_stats.h"
#include "diag_modemident.h"
#include "diag_identvouch.h"
#include "diag_logstream.h"
#include "diag_native_decode.h"
#include "diag_inventory.h"
#include "diag_gpsfix.h"
#include "diag_gsmtap_sink.h"
#include "diag_probeclose.h"
#include "diag_portadmit.h"

/* Compiled-in default dir holding the capture_cell_at/profiles/<model>.json
 * files, overridable via the profiles= source option or $CELLDIAG_PROFILES.
 * Empty default: per-modem mask=/f3= defaults are simply not consulted unless a
 * profiles dir is provided (zero regression - the source option / built-in
 * default stands). Bake a path in with -DCELLDIAG_PROFILES_DEFAULT='"..."'. */
#ifndef CELLDIAG_PROFILES_DEFAULT
#define CELLDIAG_PROFILES_DEFAULT ""
#endif

/* The decode path this binary was built with, reported in its version string
 * (see cf_version_extra). There is one: the native decode legs. */
#ifndef CELLDIAG_NATIVE_MODE
#define CELLDIAG_NATIVE_MODE "native"
#endif

/* One rendered JSON cell_observation line. Observations are small; 8 KiB is
 * generous headroom. */
#define JSON_LINE_MAX       8192
#define ERRBUF_MAX          STATUS_MAX

/* The IMEI stamped into every observation's `prov` block when the modem did not
 * report one (replay sources have no modem to ask). */
#define DIAG_IMEI_UNKNOWN   "000000000000000"

/* -----------------------------------------------------------------------
 * Local state for the capture source
 * ----------------------------------------------------------------------- */

typedef struct {
    char *diag_path;        /* DIAG /dev/tty node (NULL in replay mode) */
    char *replay_path;      /* replay= file, or NULL for a live modem */
    char *rawlog_spec;      /* rawlog= spec as given (pre-templating), or NULL */
    char *rawlog_path;      /* resolved rawlog file path, or NULL */
    char *modem_imei;      /* 15-digit IMEI, stamped into prov.imei */
    char *modem_firmware;
    char *modem_model;
    char *name;             /* human label for message-bus lines */

    /* The modem's own identity as this open read it: make / model /
     * firmware / IMEI over AT, or -- when no AT identity was possible -- the
     * addressed IMEI alone. Sent once per open as a ModemIdentity record, which
     * the server installs as this source's hardware label and kismetdb keeps as
     * a data row, so the .kismet names its modem with no outside lookup.
     * ident_method "" = not resolved (replay, disabled, or not yet brought up). */
    modemident_t ident;
    char ident_method[16];
    /* The open proceeded without AT identity because an AT node was held
     * by another process (on a PCIe modem, the paired cellat source, which holds
     * its only node for the whole capture) -- not because none answered. */
    int  ident_held;
    char ident_at_port[512];

    int   diag_fd;          /* open DIAG port, or -1 (replay) */
    int   rawlog_fd;        /* open rawlog tee sink, or -1 */
    /* A runtime rawlog=off was applied, and no runtime rawlog=<path> since.
     * Recorded as intent, because the stop can land before the capture
     * thread has opened the tee at all: that open must honour it rather than
     * start the tee the operator was told had stopped. Under rawlog_lock. */
    int   rawlog_stopped;

    /* Guards rawlog_fd / rawlog_path / rawlog_bytes only.
     *
     * The runtime option setter runs on the framework's command thread while
     * capture_thread is blocked reading the DIAG fd, and both touch the tee:
     * the setter opens/closes the sink, the reader writes to it and advances
     * the byte counter. Without this the setter could close an fd between the
     * reader's `>= 0` test and its write() -- into a descriptor number the
     * kernel has since handed to something else.
     *
     * Deliberately not a lock over local_diag_t as a whole. Everything else in
     * here is written once at open and read after, so a wider lock would buy
     * nothing and would have to be taken on paths that currently cannot block. */
    pthread_mutex_t rawlog_lock;
    int   no_mask;          /* skip LOG_CONFIG (passive tap) */
    int   f3_relay;         /* f3 != off: the operator asked for DIAG MSG/EXT_MSG
                             * F3 prints. The severity floor is applied by the
                             * MODEM at arm time, so a replay source's floor is
                             * whatever the capture was taken with. This source
                             * arms F3 but does not relay it (f3_norelay). */
    uint32_t f3_levels;     /* DIAG_F3_LEVELS_* runtime mask, 0 = off */
    const char *f3_preset;  /* "off"|"all"|"high"|"error", or f3_preset_buf when
                             * the relay is unavailable -- see f3_mark_norelay */
    /* F3 has three states, not two: off, armed-and-relayed, and
     * armed-but-not-relayed. The last is real because `f3_levels` and
     * `f3_relay` are separate mechanisms -- arming is a mask sent to the modem,
     * relay is forwarding the prints to the message bus -- and this source
     * does not relay them. Reporting "all" in that case would tell the
     * operator they are seeing a relayed stream when nothing consumes the
     * prints.
     *
     * Armed-only is not a failure state, which is why it is a third value
     * rather than a refusal: the F3 prints are still in the byte stream and so
     * still land in any `rawlog=` tee for offline analysis. Only the
     * message-bus relay is impossible. */
    int   f3_norelay;       /* armed, but not relayed */
    char  f3_preset_buf[32];/* "<preset>+norelay", pointed at by f3_preset */
    /* gsmtap=: the live GSMTAP destination. Validated at open
     * (diag_optset_gsmtap_dest). */
    int   gsmtap_on;
    /* Teardown: the port is no longer read, so a full ring may be waited on
     * briefly (ring_send_json). */
    int   emit_finishing;
    int   obs_drop_announced;   /* the first ring-full drop was reported */
    int   obs_drop_pending;     /* ...or is owed, once the ring has room */
    const char *obs_drop_what;  /* the kind of record that dropped first */
    uint64_t anchor_ring_dropped;
    char  gsmtap_dest[DIAG_GSMTAP_DEST_MAX];
    /* The sink (diag_gsmtap_sink.c): every eligible code is offered, and the
     * ones with no framer are declined and counted. Opened with the decoder;
     * fd -1 otherwise. */
    diag_gsmtap_sink_t gsmtap_native;
    int   qsh_on;           /* qsh= gated full-F3-surface tier requested:
                             * arm QSH-trace 0x9D/0x92 + 0x60 events + diag_id
                             * binding. Off by default so a lean wardrive never
                             * pays the QSH volume; seeded on both paths from the
                             * parse, like f3_relay. */
    /* The qsh=on DIAGID-table reply, as its wire bytes. The bring-up
     * handshake reader consumes it, so the capture thread feeds it into the
     * stream (tee, raw packets, decoder) ahead of everything read after it.
     * 0 = none to relay (qsh off, BAD_CMD/timeout, or already fed). */
    uint8_t diagid_wire[DIAG_DIAGID_WIRE_MAX];
    size_t  diagid_wire_len;
    int   qsh_armed;        /* the arm actually fired this session -> the stop
                             * path must disarm the QSH-trace latch (it survives
                             * reboots). Set only at the live arm site, so
                             * a replay/disabled source never disarms. */
    int   mask_armed;       /* this session's LOG_CONFIG handshake armed a mask,
                             * so letting go of the port must clear it:
                             * the mask outlives the capture otherwise. */
    int   disabled;         /* enabled=false: registered but idle --
                             * no port open, no mask/f3 handshake, no decoder */
    int   debug;

    /* Health stats: "is the data flowing?" counters + status cadence. */
    diag_stats_t stats;
    time_t       stats_interval;   /* seconds between status lines; 0 = off */

    /* The half of the stats contract diag_stats does not own:
     * config-owned strings and the census, layered into the same
     * diag_stats JSON object so all eleven registered datasource fields get a
     * real value instead of a permanent zero. See diag_stats_extra_t. */
    uint64_t rawlog_bytes;         /* bytes actually written to the tee.
                                    * Deliberately not stats.bytes_read: the two
                                    * diverge the moment a write error drops the
                                    * sink mid-capture, and "how much did the tee
                                    * actually land on disk" is the question the
                                    * operator is asking. */
    struct {                       /* last diag_inventory census */
        int      valid;            /* 0 until the first census line --
                                    * not the same as a census reporting zero */
        uint64_t distinct;
        uint64_t unrecognized;
        uint64_t silent;
        /* Known-layout codes no native leg reads. Its own valid flag, so
         * "0 undecoded" is never published for a census that has not run. */
        int      undecoded_valid;
        uint64_t undecoded_native;
    } inventory;
    int truncation_reported;       /* one attributed notice per run -- the census
                                    * fires every inv_interval, and an
                                    * unthrottled ERROR becomes the thing
                                    * operators filter out */

    /* The native decoder: the in-process C extractor + the native decode legs.
     * The counters below measure, per record, whether the live stream reaches
     * a leg at all -- a capture source that silently stopped emitting a log
     * code would otherwise look like "no cells in range".
     *
     * The logstream is heap-allocated (it carries two 32 KiB frame buffers)
     * and only when the decoder is armed, so a disabled source pays nothing. */
    diag_logstream_t *native_stream;    /* NULL unless armed */
    /* The census, counted from what the native legs claim. NULL unless armed. */
    diag_inventory_t *native_inv;
    diag_inventory_cadence_t native_inv_cadence;
    /* The CRC census. A byte the modem sent and the capture never read
     * leaves a frame that fails CRC -- the only trace a silent tty overflow
     * leaves; the kernel log stays empty. The usual cause is this read loop
     * falling behind the port during a DIAG burst. The native decoder already
     * checks every frame, so its stream's stats are the census. */
    struct {
        uint64_t bad_at_check;          /* crc_bad at the previous cadence check */
        time_t   since;                 /* ...and when that check ran */
        uint64_t alerts;                /* cadence windows that crossed the floor */
        int      row_sent;              /* the DiagCrcCensus row went out */
    } crc_watch;
    struct {
        uint64_t records;           /* LOG records the C extractor recovered */
        uint64_t native_records;    /* ...claimed by ANY native leg (cell+GNSS) */
        uint64_t native_obs;        /* cell observations those legs produced */
        uint64_t declined;          /* cell leg ran, legitimately found nothing */
        /* GNSS is counted in its own units, never folded into
         * native_obs/declined. A position fix is not a cell observation, and one
         * 0x1476 record yields at most one fix while one 0xB97F record yields
         * many -- summing them would make the obs figure mean nothing, and the
         * whole point of this tap is that its numbers drive the switch-over
         * decision. native_records does include them: "did a native
         * leg claim this record" is one question regardless of domain, and it is
         * the question the coverage percentage answers. */
        uint64_t gps_records;       /* ...of native_records, GNSS-leg records */
        uint64_t gps_fixes;         /* usable positions those records produced */
        uint64_t gps_declined;      /* GNSS leg ran, no usable position.
                                     *
                                     * Not a synonym for "no sky view". The
                                     * leg declines for several different
                                     * reasons (DIAG_NATIVE_GPS_DECLINE_*),
                                     * and two of them are opposite findings:
                                     *
                                     *   no_position     -- (0,0). Benign: the
                                     *     engine is running and cannot see sky.
                                     *   no_time_solution -- gps_week==0xFFFF.
                                     *     The receiver did report a position,
                                     *     at plausible degrees, but it can be
                                     *     ~215 km from truth (seen on SDX62).
                                     *
                                     * On an EG25-G with the engine on and no
                                     * fix, nearly all 0x1476 records are the
                                     * Nevada sentinel with gps_week==0xFFFF,
                                     * so this counter is mostly not the benign
                                     * case. gps_declined is the total; the
                                     * four sub-counters below say which gate
                                     * refused. */
        uint64_t gps_declined_no_position;  /* coord out of band, incl. (0,0) --
                                             * the benign no-sky-view case */
        uint64_t gps_declined_placeholder;  /* vendor "no fix" sentinel
                                             * (Nevada / Telit no-antenna) */
        uint64_t gps_declined_no_time;      /* gps_week==0xFFFF seed position --
                                             * a reported coord, ~215 km off */
        uint64_t gps_declined_stale;        /* older than the stream's newest
                                             * GNSS clock by > the bound:
                                             * a real fix being RE-SERVED
                                             * (an RM500Q-AE serves one
                                             * 13.68 h old) -- not a
                                             * sky-view problem */
        uint64_t gps_declined_altitude;     /* alt outside [-500, 9000] m or
                                             * NaN */
        uint64_t gps_declined_jump;         /* implied speed from the last
                                             * accepted fix > the bound.
                                             * The arm is DISARMED by
                                             * default, so this reads 0 until
                                             * it is redesigned and armed */
        uint64_t gps_declined_unparseable;  /* short/malformed payload */
        uint64_t fallback_records;  /* no native leg reads these: the
                                     * native-coverage gap, by record */
        /* Cross-record SIB1 enrichment. Enrichment changes no observation
         * count, only which fields an observation carries, so `native_obs` is
         * identical with and without it. `enriched` is the number in this tap
         * that moves when identity is gained or lost. */
        uint64_t identity_records;  /* ...of native_records, 0xB0C0/0xB821 seen */
        uint64_t identity_learned;  /* new (pci, earfcn) keys those records added */
        uint64_t enriched;          /* observations that gained MCC/MNC/TAC/CID
                                     * from a SIB1 seen earlier in the stream */
        /* `emitted` is deliberately not the same number as `native_obs`.
         * native_obs counts observations the legs produced; emitted counts the
         * ones that were serialized and accepted by cf_send_json. The gap
         * between them is where data is lost silently -- a code with a decode leg but no serializer branch decodes fine, counts
         * in native_obs, and never reaches Kismet. Folding the two would report
         * that loss as a healthy figure. */
        uint64_t emitted;           /* observations rendered and sent to Kismet */
        uint64_t emit_declined;     /* decoded, but the serializer has no branch
                                     * for the log code (returned -1) */
        uint64_t emit_truncated;    /* rendered longer than the line buffer; the
                                     * caller must not emit a truncated line, so
                                     * these are dropped rather than corrupted */
        uint64_t gps_emitted;       /* gps_fix status lines sent */
    } native_tap;
    /* The cache behind those counters -- heap-allocated with the decoder's
     * stream, so an unarmed source pays nothing. NULL means enrichment is unavailable
     * (allocation failed); the tap keeps decoding, unenriched. */
    diag_native_sib1_map_t *native_sib1_map;
    /* The GNSS freshness reference: the newest GNSS clock this
     * source's stream has carried, against which every 0x1476 fix is judged
     * for staleness. Same lifecycle as the SIB1 map beside it -- one per
     * source, allocated with the tap, freed at its end. NULL means the
     * staleness gate is OFF (allocation failed, and the open said so). */
    diag_native_gnss_tracker_t *native_gnss_tracker;

    /* Last DIAG GNSS fix: cached from the 0x1476/0x14D8 records so each
     * outgoing cell_observation can be stamped with a GPS location, letting
     * Kismet geo-tag the resulting `Cellular` devices from the DIAG source.
     * valid=0 until the first real fix; ts gates out stale fixes.
     *
     * Written by native_tap_cb's GNSS leg, rounded to 6 dp (lat/lon) and
     * 1 dp (alt). */
    struct {
        int    valid;
        double lat;
        double lon;
        float  alt;
        time_t ts;
    } last_gps;

    /* Shared reader threaded through the LOG_CONFIG handshake and the capture
     * loop so bytes buffered during the handshake are not lost at the seam. */
    diag_reader_t reader;

    /* Deferred device bring-up. The live open path -- AT IMEI scan,
     * DIAG port resolve+open, SPC unlock, LOG_CONFIG/F3 handshake, decoder arm
     * -- costs multiple seconds (the handshake alone budgets DIAG_RESP_TIMEOUT_S
     * = 20 s for boot-F3-flooding modems), which exceeds Kismet's open-command
     * deadline. Run inside open_callback, every first open would report
     * "failed to launch: Command did not complete", and with two sources racing
     * a source could stay down indefinitely.
     *
     * So open_callback parses+validates the definition (cheap, no device
     * I/O), returns success immediately, and stashes everything the bring-up
     * needs here; capture_thread runs it before entering the read loop and
     * reports failure via cf_send_error -> the normal per-source retry.
     * defer=false runs the bring-up inline instead. */
    struct {
        int   pending;                  /* bring-up not yet run */
        int   deferred;                 /* defer= resolved value (diagnostics) */
        char  diagport_override[512];   /* diagport=, or "" for auto-detect */
        char  atport_override[512];     /* atport=, or "" -- explicit AT
                                         * identify node for MHI/wwan modems
                                         * the ttyUSB IMEI scan cannot see */
        char *profiles_dir;             /* owned; freed by the bring-up */
        char  spc_val[8];
        int   spc_set;                  /* spc= given explicitly (gates profile) */
        int   mask_full;
        int   mask_set;                 /* mask= given explicitly */
        uint32_t f3_levels;             /* DIAG_F3_LEVELS_*, 0 = off */
        const char *f3_preset;          /* static name for the resolved mask */
        int   f3_set;                   /* f3= given explicitly */
        int   qsh_on;                   /* qsh= gated full-F3 tier */
        long  elapsed_ms;               /* how long the bring-up actually took
                                         * (time that would otherwise be spent
                                         * inside Kismet's open deadline) */
        char  phase_detail[256];        /* per-phase attribution of elapsed_ms
                                         * ("at_scan=..ms log_mask=..ms ...");
                                         * the aggregate alone cannot
                                         * tell a slow AT scan from a
                                         * timed-out LOG_CONFIG exchange */
    } bringup;

    /* Host<->modem-ts64 clock anchor (the DIAG instance of the shared
     * clock-anchor contract). A DIAG_TS_F request goes out at capture START, every
     * interval_ms, and at END; each reply is paired with the host clock and
     * emitted as a type="ClockAnchor" row + a <rawlog>.clock_anchor.jsonl line
     * (see diag_clockanchor.h for the record and why its host stamp is the
     * request/reply MIDPOINT).
     *
     * Asynchronous on purpose: the request is written and the capture loop
     * keeps reading; the reply is fished out of the same byte stream by
     * `scan` as it passes through. A blocking request/response here would stall
     * the log flood behind it for the whole round trip. One request is ever
     * outstanding (`pending`), so a reply is never paired with the wrong send.
     *
     * Live only: a replay has no modem to ask, and enabled=false opened none. */
    struct {
        unsigned long   interval_ms;    /* clock_anchor_sec= x 1000; 0 = periodic off */
        unsigned long   last_ms;        /* monotonic ms of the last request */
        uint64_t        seq;            /* per-source anchor counter */
        int             started;        /* the START request went out -- the END
                                         * path keys on this, not on diag_fd */
        int             end_requested;  /* END asked in-band by a graceful close;
                                         * main()'s anchor_end skips */
        int             pending;
        const char     *edge;           /* "start" | "periodic" | "end" */
        struct timeval  send_tv;
        uint64_t        send_mono_ns;
        uint64_t        deadline_mono_ns;
        diag_tsf_scan_t scan;
        int             off;            /* stop asking: rejected, or never answered */
        unsigned        consecutive_timeouts;
        uint64_t        emitted;        /* anchors completed (row and/or sidecar) */
        time_t          last_wall;      /* host wall time of the last completed
                                         * anchor, for the panel */
        uint64_t        timed_out;
        uint64_t        sidecar_failed;
    } anchor;
    char *source_uuid;                  /* composed datasource uuid -> source_name */

    /* The raw DIAG stream as Kismet packets: every byte feed_bytes
     * sees, sliced into DLT 147 packets for the kismetdb `packets` table.
     * Contract in diag_rawpkt.h; delivery and loss policy at rawpkt_emit.
     *
     * Capture-thread only: feed_bytes and the teardown at `done:` both run
     * there, and main()'s END-anchor drain after the cancel does not touch it
     * (those bytes reach the rawlog= tee only -- the pipe is closed by then). */
    struct {
        int            on;              /* rawpackets= (default on) */
        diag_rawpkt_t *s;               /* heap (~12 KiB); NULL until streaming */
        uint64_t       ring_waits;      /* retries while the ring was full */
        int            announced;       /* first-slice INFO sent */
        int            drop_row_sent;   /* first-drop RawDiagDrop row landed */
        int            drop_reported;   /* first-drop ERROR sent */
    } rawpkt;

    /* Set by a cleanup handler when capture_thread exits or is cancelled.
     * cf_handler_shutdown() cancels the capture thread asynchronously
     * (capture_framework.c sets PTHREAD_CANCEL_ASYNCHRONOUS) and it is
     * detached, so main() cannot join it; this is how main() knows the DIAG fd
     * has no other reader before it issues the END anchor on it. */
    int capture_exited;

    /* nativedecode=only's decoder liveness.
     *
     * `helper_alive` means "the decoder is alive". The decoder runs inside feed_bytes on the
     * capture thread, so it is alive while that thread keeps passing the top
     * of its read loop. The loop stamps `hb_ns` on every pass, idle poll
     * timeouts included.
     *
     * The judge cannot be the capture thread. It prints the regular stats line
     * and would only ever see its own fresh heartbeat; when it is stuck, it
     * prints nothing at all. So a watchdog thread judges the heartbeat against
     * DIAG_STATS_DECODER_STALL_SEC and is the ONLY writer of `stalled`. It sends
     * a liveness-only diag_stats object on each transition (helper_alive 0 on
     * a stall, 1 on recovery) and a DECODER-STALLED line on the stats cadence
     * while the stall lasts.
     *
     * The capture thread's own lines say decoder=alive (stats.helper_alive 1,
     * set at arm time) and that is a measurement, not a default: a line from
     * the reader is proof the reader just passed its loop. It never says
     * "stalled", because a stalled reader prints nothing; that word comes only
     * from the watchdog. At teardown it says "stopped". */
    struct {
        uint64_t        hb_ns;      /* atomic: CLOCK_MONOTONIC ns of the reader
                                     * loop's last pass; 0 = not armed */
        int             armed;      /* capture thread only: stamp hb_ns */
        /* Watchdog-thread only (and the capture thread's first, synchronous
         * tick, which happens-before the thread starts). */
        int             stalled;    /* the verdict: 1 = no pass for > the bound */
        int             reported;   /* liveness last queued to the server, or -1 */
        uint64_t        stall_hb_ns;    /* the heartbeat the stall was judged on */
        uint64_t        last_line_ns;   /* last DECODER-STALLED line */
        /* Guarded by lock: the start/stop handshake. The capture thread's
         * teardown and main() may both stop the watchdog; one of them joins. */
        pthread_mutex_t lock;
        int             started;    /* a watchdog thread exists to be joined */
        pthread_t       tid;
        int             stop;       /* atomic: the watchdog leaves its loop */
        kis_capture_handler_t *caph;
    } live;
} local_diag_t;

/* -----------------------------------------------------------------------
 * f3= preset table
 * ----------------------------------------------------------------------- */

/* One table, consulted by both the source-option parse and the profile
 * diag.f3_default parse, so the two can never drift into accepting different
 * spellings. Ordered loudest-first; `name` is the canonical spelling
 * reported back on the stats object.
 *
 * Do not add a *selective* entry (e.g. levels == 0x18, "ERROR|FATAL"). It is
 * the intuitive reading of "severity floor" and it is a mute button: 67% of
 * real F3 records come from sites carrying only per-SSID custom bits, so a
 * ladder-only mask keeps 1.3% of the stream. Measurements + grounding for the
 * ladder bits: diag_config.h. */
typedef struct {
    const char *name;
    uint32_t    levels;     /* 0 == do not send the handshake at all */
    const char *blurb;      /* one clause for the arm-time bus message */
} f3_preset_t;

static const f3_preset_t F3_PRESETS[] = {
    { "off",   0,                           "no F3 arming" },
    { "none",  0,                           "no F3 arming" },   /* alias */
    { "all",   DIAG_F3_LEVELS_ALL,
      "EVERY F3 subsystem at every severity -- HIGH volume (0x79/0x99 flood), "
      "for diagnosis not wardriving" },
    { "high",  DIAG_F3_LEVELS_HIGH_AND_UP,
      "every F3 subsystem, minus sites that only print at LOW/MED "
      "(~94% of records kept; all per-SSID custom prints retained)" },
    { "error", DIAG_F3_LEVELS_ERROR_AND_UP,
      "every F3 subsystem, minus sites that only print below ERROR "
      "(~68% of records kept; all per-SSID custom prints retained)" },
};

/* Resolve a preset spelling. Returns 0 and leaves the outputs untouched on an
 * unknown name, so a caller can distinguish "invalid" from "off". */
static int f3_preset_lookup(const char *v, uint32_t *levels, const char **name,
                            const char **blurb) {
    size_t i;
    for (i = 0; i < sizeof(F3_PRESETS) / sizeof(F3_PRESETS[0]); i++) {
        if (strcmp(v, F3_PRESETS[i].name) != 0)
            continue;
        if (levels) *levels = F3_PRESETS[i].levels;
        /* "none" reports as "off" -- one canonical spelling on the wire. */
        if (name)   *name   = F3_PRESETS[i].levels ? F3_PRESETS[i].name : "off";
        if (blurb)  *blurb  = F3_PRESETS[i].blurb;
        return 1;
    }
    return 0;
}

#define F3_PRESET_NAMES "off|all|high|error"

/* -----------------------------------------------------------------------
 * Serial helpers (AT identify only) - ported from capture_cell_at.c
 * ----------------------------------------------------------------------- */

/* Handle building on BSD and macOS, which don't define every baud-rate macro
 * the way Linux does (mirrors the guard in upstream Kismet's serial capture
 * sources). Where a platform lacks the name it uses literal rates,
 * so defining the missing macro to its integer value is correct there. */
#ifndef B9600
#define B9600 9600
#endif
#ifndef B19200
#define B19200 19200
#endif
#ifndef B38400
#define B38400 38400
#endif
#ifndef B57600
#define B57600 57600
#endif
#ifndef B115200
#define B115200 115200
#endif
#ifndef B460800
#define B460800 460800
#endif
#ifndef B921600
#define B921600 921600
#endif

static int serial_open(const char *path, int baudrate) {
    int fd;
    struct termios tty;
    speed_t speed;

    /* Bounded: a tty still in its final close -- another prober's
     * detached close of a port that never read its "AT\r\n" -- makes a
     * plain open() block for that port's whole 30 s closing_wait, O_NONBLOCK or
     * not. A port that has not opened by the deadline fails with ETIMEDOUT and
     * is skipped; it is never the target (an AT port reads what it is sent). */
    fd = diag_probe_open(path, O_RDWR | O_NOCTTY | O_NONBLOCK,
                         DIAG_PROBE_OPEN_DEADLINE_MS);
    if (fd < 0)
        return -1;

    /* Same exclusive claim the DIAG port takes. This function is a port of
     * cellat's serial_open(); both route through one helper so a change to
     * the claim cannot land on only one of them. */
    if (diag_port_claim(fd) != 0) {
        /* Keep flock's EWOULDBLOCK across the close: it is how the IMEI scan
         * tells a port another process is probing right now from one that is
         * simply not a modem, and rescans only for the former (the same
         * handling as cellat's at_serial.inc). */
        int claim_errno = errno;
        close(fd);
        errno = claim_errno;
        return -1;
    }

    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags & ~O_NONBLOCK);

    /* Non-tty AT transports -- an MHI char device (/dev/mhi_DUN on a PCIe modem
     * like the RM520N-GL / SDX6x under the OOT driver) or a /dev/wwan* port on
     * the inline driver -- are not terminals: tcgetattr() returns ENOTTY. They
     * are already raw byte pipes with no baud rate or line discipline to
     * configure, so skip termios entirely rather than failing the open. The AT
     * read loop's per-read timeout comes from poll() (at_command), not tty
     * VTIME, so a non-tty port still times out correctly. This mirrors
     * cellat's at_serial.inc handling; without it the bring-up cannot
     * AT-identify an MHI-only modem even with an explicit diagport=. */
    if (!isatty(fd)) {
        diag_probe_termios_forget(fd);   /* no line settings to put back */
        return fd;
    }

    memset(&tty, 0, sizeof(tty));
    if (tcgetattr(fd, &tty) != 0) {
        diag_probe_termios_forget(fd);
        close(fd);
        return -1;
    }

    /* Keep the port's settings as found: every close of this fd is a
     * probe close (probe_release -> diag_probe_close), which writes them back,
     * so the 115200 raw set below never outlives the probe. The same keep as
     * cellat's at_serial.inc -- this function is a port of that one. */
    diag_probe_termios_keep(fd, &tty);

    switch (baudrate) {
        case 9600:   speed = B9600;   break;
        case 19200:  speed = B19200;  break;
        case 38400:  speed = B38400;  break;
        case 57600:  speed = B57600;  break;
        case 460800: speed = B460800; break;
        case 921600: speed = B921600; break;
        default:     speed = B115200; break;
    }

    cfsetispeed(&tty, speed);
    cfsetospeed(&tty, speed);

    tty.c_cflag &= ~PARENB;
    tty.c_cflag &= ~CSTOPB;
    tty.c_cflag &= ~CSIZE;
    tty.c_cflag |= CS8;
    tty.c_cflag &= ~CRTSCTS;
    tty.c_cflag |= CREAD | CLOCAL;

    tty.c_lflag &= ~(ICANON | ECHO | ECHOE | ISIG);
    tty.c_iflag &= ~(IXON | IXOFF | IXANY | IGNBRK | BRKINT | PARMRK |
                      ISTRIP | INLCR | IGNCR | ICRNL);
    tty.c_oflag &= ~OPOST;

    tty.c_cc[VMIN] = 0;
    tty.c_cc[VTIME] = 10;

    tcflush(fd, TCIOFLUSH);
    if (tcsetattr(fd, TCSANOW, &tty) != 0) {
        diag_probe_termios_forget(fd);   /* the settings were not changed */
        close(fd);
        return -1;
    }

    return fd;
}

static void serial_close_fd(int *fd) {
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}

/* Send an AT command and collect the response until OK/ERROR/timeout.
 * Returns response length, or -1 on error. (Transcript-free variant; DIAG
 * capture only needs AT for one-shot IMEI/firmware identification.)
 *
 * Every read is poll()-bounded, as cellat's at_serial.inc reader is: a
 * non-tty AT node (/dev/mhi_DUN) has no VTIME, and serial_open() leaves the fd
 * blocking, so without poll() a reply that never came would block read() for
 * good.
 *
 * `info_idle_ms` > 0 is the info form, for a single-line info read only (see
 * MODEMIDENT_INFO_IDLE_MS): once a value line has arrived, info_idle_ms of
 * silence also ends the exchange, and a bare OK that arrives before any value
 * (the previous exchange's late OK) does not. 0 is the ordinary form. */
static int at_command_ex(int fd, const char *cmd, char *resp_buf,
                         size_t resp_max, int timeout_ms, int info_idle_ms) {
    char line_buf[1024];
    ssize_t n;
    size_t resp_len = 0;
    size_t line_pos = 0;
    struct timeval deadline, now_tv;
    int have_value = 0;     /* info form: a value line has been kept */
    int early_ok = 0;       /* info form: a bare OK came before any value */
    int is_tty;

    if (fd < 0)
        return -1;
    is_tty = isatty(fd);

    /* Drop input waiting from before this exchange: tcflush() on a tty, then
     * a bounded read -- an MHI UCI node passes isatty() and ignores the flush. */
    diag_probe_drain_input(fd);

    size_t cmd_len = strlen(cmd);
    char *send_buf = malloc(cmd_len + 3);
    if (!send_buf)
        return -1;
    snprintf(send_buf, cmd_len + 3, "%s\r\n", cmd);
    ssize_t written = write(fd, send_buf, strlen(send_buf));
    free(send_buf);
    if (written < 0)
        return -1;

    gettimeofday(&deadline, NULL);
    deadline.tv_sec += timeout_ms / 1000;
    deadline.tv_usec += (timeout_ms % 1000) * 1000;
    if (deadline.tv_usec >= 1000000) {
        deadline.tv_sec++;
        deadline.tv_usec -= 1000000;
    }

    resp_buf[0] = '\0';

    while (1) {
        gettimeofday(&now_tv, NULL);
        if (now_tv.tv_sec > deadline.tv_sec ||
            (now_tv.tv_sec == deadline.tv_sec &&
             now_tv.tv_usec >= deadline.tv_usec))
            break;

        long remaining_ms = (deadline.tv_sec - now_tv.tv_sec) * 1000 +
                            (deadline.tv_usec - now_tv.tv_usec) / 1000;
        if (remaining_ms <= 0)
            break;

        int wait_ms = remaining_ms > 1000 ? 1000 : (int)remaining_ms;
        int idle_armed = info_idle_ms > 0 && (have_value || early_ok);
        if (idle_armed && wait_ms > info_idle_ms)
            wait_ms = info_idle_ms;

        if (is_tty) {
            /* A backstop only: poll() below bounds every wait. */
            struct termios tty;
            tcgetattr(fd, &tty);
            int vtime = (wait_ms >= 1000) ? 10 : (wait_ms / 100);
            if (vtime < 1) vtime = 1;
            tty.c_cc[VTIME] = vtime;
            tcsetattr(fd, TCSANOW, &tty);
        }

        struct pollfd pfd = { .fd = fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pfd, 1, wait_ms);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (pr == 0) {
            if (idle_armed)
                break;          /* the port went quiet after the answer */
            continue;
        }

        char c;
        n = read(fd, &c, 1);
        if (n < 0) {
            if (errno == EAGAIN || errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            /* poll() readable + read() 0 is EOF on a non-tty: the node went
             * away. Return what arrived rather than spin to the deadline. */
            if (!is_tty)
                break;
            continue;
        }

        if (c == '\n' || c == '\r') {
            if (line_pos == 0)
                continue;
            line_buf[line_pos] = '\0';
            if (strncmp(line_buf, cmd, strlen(cmd)) == 0) {
                line_pos = 0;
                continue;
            }
            if (resp_len + line_pos + 2 < resp_max) {
                if (resp_len > 0)
                    resp_buf[resp_len++] = '\n';
                memcpy(resp_buf + resp_len, line_buf, line_pos);
                resp_len += line_pos;
                resp_buf[resp_len] = '\0';
            }
            if (strcmp(line_buf, "OK") == 0 ||
                strcmp(line_buf, "ERROR") == 0 ||
                strncmp(line_buf, "+CME ERROR", 10) == 0) {
                if (info_idle_ms > 0 && !have_value &&
                    strcmp(line_buf, "OK") == 0) {
                    early_ok = 1;   /* maybe the last exchange's late OK */
                    line_pos = 0;
                    continue;
                }
                break;
            }
            if (info_idle_ms > 0)
                have_value = 1;
            line_pos = 0;
        } else {
            if (line_pos < sizeof(line_buf) - 1)
                line_buf[line_pos++] = c;
        }
    }

    return (int)resp_len;
}

static int at_command(int fd, const char *cmd, char *resp_buf,
                      size_t resp_max, int timeout_ms) {
    return at_command_ex(fd, cmd, resp_buf, resp_max, timeout_ms, 0);
}

/* A single-line info read (AT+CGMR / +CGSN / +CGMI / +CGMM) in the info form:
 * a modem that never sends the final OK on these (the T99W175) is not
 * charged the whole deadline for each. */
static int at_info_command(int fd, const char *cmd, char *resp_buf,
                           size_t resp_max, int timeout_ms) {
    return at_command_ex(fd, cmd, resp_buf, resp_max, timeout_ms,
                         MODEMIDENT_INFO_IDLE_MS);
}

/* Extract the first non-empty, non-status ("OK"/"+CME…") line from an AT
 * response into out (the value line of a CGMR/CGSN reply). out[0]=='\0' if none. */
static void at_first_value_line(char *resp, char *out, size_t out_sz) {
    out[0] = '\0';
    char *saveptr = NULL;
    char *line = strtok_r(resp, "\n", &saveptr);
    while (line) {
        while (*line == ' ') line++;
        if (*line && strcmp(line, "OK") != 0 && strncmp(line, "+CME", 4) != 0) {
            strncpy(out, line, out_sz - 1);
            out[out_sz - 1] = '\0';
            return;
        }
        line = strtok_r(NULL, "\n", &saveptr);
    }
}

/* How the last identify_modem() released its probe fd, for the scan's
 * stuck-port detail. File-static for the same reason g_scan_slow is: one
 * bring-up thread per helper process runs the scan. */
static diag_probeclose_how_t g_probe_close_how = DIAG_PROBECLOSE_PLAIN;

/* Ports the last scan_modems() pass skipped because another process held their
 * claim at that instant (serial_open -> EWOULDBLOCK) -- in a concurrent
 * multi-source open, usually a sibling source's scan mid-probe. Counted so the
 * bring-up can tell "busy" from "absent" and rescan only for the former.
 * Reset with the slow/stuck detail at the top of every pass. */
static int g_scan_busy;

/* A lister's wait for the ports another process held during its pass.
 * The server runs the cellat and celldiag listers at once; each skips a
 * port the other is probing, so a modem with one AT port (the T99W175) would
 * be dropped by whichever lister came second. A lister's hold is
 * sub-second, so the held ports are re-tried until they are free or
 * this one shared deadline passes -- shared, because a port an open capture
 * holds is held for good and must cost a list the deadline once, not
 * once per port. 0 = off: only list_callback sets it; an open's scan already
 * rescans once. */
#define CELL_LIST_BUSY_WAIT_MS 1500
#define CELL_LIST_BUSY_STEP_MS 100
static int g_scan_list_wait;

/* The busy port the last scan identified through its holder's vouch,
 * and the holder's pid; g_scan_vouch_pid 0 = no vouch was used. Reset with the
 * rest of the per-pass detail, so a rescan reports only what it relied on. */
static pid_t g_scan_vouch_pid;
static char g_scan_vouch_port[256];

/* Set when the last identify_modem()'s open() hit its deadline: the
 * port was skipped, and the scan names it. */
static int g_probe_open_timed_out;

/* Ports whose AT+CGSN read was not an IMEI's shape twice, with what
 * they answered: "ttyUSB2(CGSN=Quectel)". Treated as "did not answer", so
 * they would otherwise pass without a word. Reset with the scan's per-pass
 * detail (scan_slow_reset) and reported with it (scan_report_ports). */
static char g_scan_badimei[256];

/* Every close after identify_modem() has written to the port goes through here.
 * A port that never reads what it is sent (an NMEA-only function) would
 * otherwise hold this thread in close() for the tty's 30 s closing_wait. The
 * bring-up runs off the open critical path, so that would not fail an open: it
 * would cost the source its first ~30 s of DIAG instead (see diag_probeclose.h). */
static void probe_release(int fd, const char *path) {
    g_probe_close_how = diag_probe_close(fd, path);
}

/* AT identify: probe a serial port for a modem and read its firmware + IMEI.
 * Non-AT ports (DIAG, NMEA) time out on the 150ms AT check and return 0.
 *
 * When want_imei is non-NULL, this is an IMEI-targeted scan (find_port_by_imei):
 * read the IMEI (AT+CGSN) first and, on a mismatch, return early without the
 * ~3s AT+CGMR firmware read. That halves the per-non-target-device cost and,
 * just as importantly under concurrent multi-source opens, shortens how
 * long each source holds each shared tty, which otherwise causes EBUSY storms
 * with many sources. want_imei==NULL keeps the list/enumerate behavior
 * (firmware required, IMEI best-effort). */
static int identify_modem(const char *path, char *fw_buf, size_t fw_sz,
                          char *imei_buf, size_t imei_sz,
                          const char *want_imei, int *imei_mismatch,
                          modemident_t *id) {
    if (imei_mismatch)
        *imei_mismatch = 0;
    modemident_clear(id);
    char resp[4096];

    g_probe_close_how = DIAG_PROBECLOSE_PLAIN;
    g_probe_open_timed_out = 0;
    int fd = serial_open(path, 115200);
    if (fd < 0) {
        int open_errno = errno;
        /* A held port may still answer, through its holder. The
         * claim carries no payload, so a paired cellat source that holds this
         * modem's only free AT port would make the modem unidentifiable for as
         * long as it ran (e.g. a T99W175, or an RM500Q with both AT ports held).
         * The holder verified the IMEI on this very port and published it; a
         * record that survives diag_identvouch's checks (same node instance,
         * writer alive) settles the port like an AT reply would -- a match is
         * this modem, a mismatch is confidently another one.
         *
         * Targeted scans only: a lister (want_imei == NULL) keeps reporting a
         * held port as held, so nothing it shows changes here. */
        if (open_errno == EWOULDBLOCK && want_imei != NULL) {
            pid_t vpid = 0;
            if (identvouch_lookup(path, id, &vpid)) {
                snprintf(imei_buf, imei_sz, "%s", id->imei);
                if (strcmp(id->imei, want_imei) != 0) {
                    if (imei_mismatch)
                        *imei_mismatch = 1;
                    modemident_clear(id);
                    imei_buf[0] = '\0';
                    return 0;
                }
                snprintf(fw_buf, fw_sz, "%s", id->firmware);
                g_scan_vouch_pid = vpid;
                snprintf(g_scan_vouch_port, sizeof(g_scan_vouch_port), "%s", path);
                return 1;
            }
        }
        /* Busy (a sibling holds the claim) is worth a rescan; an open
         * that timed out is not -- it is a tty mid-close, never the target. */
        if (open_errno == EWOULDBLOCK)
            g_scan_busy++;
        else if (open_errno == ETIMEDOUT)
            g_probe_open_timed_out = 1;
        return 0;
    }

    int n = at_command(fd, "AT", resp, sizeof(resp), 150);
    if (n < 0 || strstr(resp, "OK") == NULL) {
        probe_release(fd, path);
        return 0;
    }

    /* IMEI first so an IMEI-targeted scan can reject non-matches before the
     * costlier firmware read. */
    imei_buf[0] = '\0';
    n = at_info_command(fd, "AT+CGSN", resp, sizeof(resp), 3000);
    if (n > 0)
        at_first_value_line(resp, imei_buf, imei_sz);

    /* The mismatch below is confident only for a well-formed IMEI, so
     * a read that is not an IMEI's shape is re-asked once (the exchange
     * flushes input first, dropping a reply another prober left -- e.g. an
     * RM520N-GL's AT+CGMI answer "Quectel") and then treated as "did not
     * answer". Otherwise an IMEI-targeted scan would skip the device it was
     * looking for, and a --list would name the source after the stray reply. */
    if (imei_buf[0] && !modemident_imei_ok(imei_buf)) {
        char first[64];
        snprintf(first, sizeof(first), "%s", imei_buf);
        imei_buf[0] = '\0';
        n = at_info_command(fd, "AT+CGSN", resp, sizeof(resp), 3000);
        if (n > 0)
            at_first_value_line(resp, imei_buf, imei_sz);
        if (!modemident_imei_ok(imei_buf)) {
            fprintf(stderr, "celldiag: %s: AT+CGSN answered '%s', then '%s' "
                    "on retry -- not a %d-digit IMEI, so this port is treated "
                    "as not answering\n", path, first, imei_buf,
                    MODEMIDENT_IMEI_DIGITS);
            char label[48];
            snprintf(label, sizeof(label), "CGSN=%.24s", first);
            diag_probeclose_note_label(g_scan_badimei, sizeof(g_scan_badimei),
                                       path, label);
            imei_buf[0] = '\0';
        }
    }

    if (want_imei && (!imei_buf[0] || strcmp(imei_buf, want_imei) != 0)) {
        /* A confident mismatch: this port answered AT and returned a
         * well-formed IMEI that is not the one we want, so the whole USB
         * device is known not to be our modem. Distinguish it from "this port
         * did not answer" (imei_buf empty), where we have learned nothing --
         * the caller uses that difference to skip the device's remaining
         * ports. */
        if (imei_mismatch && imei_buf[0])
            *imei_mismatch = 1;
        probe_release(fd, path);
        return 0;   /* early-out: skip AT+CGMR on a non-target device */
    }

    struct timespec cgmr_t0, cgmr_t1;   /* see modemident_followup_ms() */
    clock_gettime(CLOCK_MONOTONIC, &cgmr_t0);
    n = at_info_command(fd, "AT+CGMR", resp, sizeof(resp), 3000);
    fw_buf[0] = '\0';
    if (n > 0)
        at_first_value_line(resp, fw_buf, fw_sz);

    /* The firmware string doubles as the model (rawlog %m, prov.model).
     * On an IMEI-targeted scan the IMEI already matched on this open port, so
     * the modem is here and responsive — an empty AT+CGMR is a transient read
     * (a busy/slow tty under concurrent multi-source opens), not "no
     * firmware". Retry once rather than discarding a matched modem and letting
     * the model silently fall back to the literal 'modem'. Scoped to want_imei
     * so the list/enumerate sweep is unchanged and only the one target modem
     * ever pays the extra round-trip. */
    if (!fw_buf[0] && want_imei) {
        clock_gettime(CLOCK_MONOTONIC, &cgmr_t0);   /* time the read that counts */
        n = at_info_command(fd, "AT+CGMR", resp, sizeof(resp), 3000);
        if (n > 0)
            at_first_value_line(resp, fw_buf, fw_sz);
    }

    if (!fw_buf[0]) {
        probe_release(fd, path);
        return 0;
    }

    /* The make and model, read while the port is ours. Only a port that
     * has already identified pays for them -- a non-target modem left above on
     * its IMEI mismatch -- so an IMEI-targeted scan adds two fast round-trips to
     * one modem, and a --list adds them per modem, which is exactly the answer
     * the Sources panel needs to show which modem each candidate is. The
     * firmware is fw_buf's value with any "+CGMR: " response code stripped
     * (fw_buf itself is left as it was: the profile selector and the rawlog
     * name already consume it). */
    if (id != NULL) {
        /* A firmware that arrived only by timing out marks a port that never
         * sends the final OK on info replies (the T99W175): read make/model
         * with a short deadline there instead of 3 s each. */
        clock_gettime(CLOCK_MONOTONIC, &cgmr_t1);
        long cgmr_ms = (long)(cgmr_t1.tv_sec - cgmr_t0.tv_sec) * 1000L +
                       (long)(cgmr_t1.tv_nsec - cgmr_t0.tv_nsec) / 1000000L;
        int follow_ms = (int)modemident_followup_ms(cgmr_ms, 1);

        snprintf(id->imei, sizeof(id->imei), "%s", imei_buf);
        modemident_value(fw_buf, id->firmware, sizeof(id->firmware));
        n = at_info_command(fd, "AT+CGMI", resp, sizeof(resp), follow_ms);
        if (n > 0)
            modemident_value(resp, id->make, sizeof(id->make));
        n = at_info_command(fd, "AT+CGMM", resp, sizeof(resp), follow_ms);
        if (n > 0)
            modemident_value(resp, id->model, sizeof(id->model));
    }

    probe_release(fd, path);
    return 1;
}

/* -----------------------------------------------------------------------
 * USB / sysfs port topology - ported from capture_cell_at.c
 * ----------------------------------------------------------------------- */

/* CELLDIAG_SCAN_PORTS: when set and non-empty, the IMEI scan's port
 * universe is exactly these -- a space-separated list of literal paths or globs
 * (space, not colon: by-id paths contain colons) -- instead of
 * /dev/ttyUSB* + /dev/ttyACM*. A path named twice is scanned once.
 *
 * It replaces rather than adds, unlike cellat's CELLAT_EXTRA_PORTS, because
 * both of its uses need the scan to touch nothing else:
 *   - an operator keeping the scan off a port it must not AT-probe (a
 *     non-target modem's NMEA tty) while still addressing by IMEI;
 *   - the offline harness, which drives the real scan -- its busy-port skip and
 *     the rescan -- against a PTY fake modem. Additive, a scan that skips
 *     the busy PTY would walk on into the host's real modems and write "AT" to
 *     every one of them from a unit test.
 * An operator naming one AT node wants atport=, which skips the scan. */
static int scan_ports_from_env(const char *list, char ports[][256],
                               int max_ports) {
    glob_t g;
    int count = 0;
    char *copy = strdup(list);
    if (!copy)
        return 0;
    char *saveptr = NULL, *tok;
    for (tok = strtok_r(copy, " ", &saveptr);
         tok && count < max_ports;
         tok = strtok_r(NULL, " ", &saveptr)) {
        if (glob(tok, 0, NULL, &g) != 0)
            continue;
        for (size_t i = 0; i < g.gl_pathc && count < max_ports; i++) {
            int dup = 0;
            for (int k = 0; k < count && !dup; k++)
                dup = strcmp(ports[k], g.gl_pathv[i]) == 0;
            if (dup)
                continue;
            strncpy(ports[count], g.gl_pathv[i], 255);
            ports[count][255] = '\0';
            count++;
        }
        globfree(&g);
    }
    free(copy);
    return count;
}

/* Which ports an IMEI scan walks.
 *
 * SCAN_ALL_PORTS is the ttyUSB/ttyACM set. SCAN_NONUSB_AT is the non-USB AT
 * nodes alone: the scan for a source whose diagport= is an MHI/wwan node, i.e.
 * a PCIe modem with no ttyUSB at all, which must not spend seconds AT-probing
 * every USB modem's ports to find it.
 *
 * The non-USB nodes are deliberately not in SCAN_ALL_PORTS, although cellat's
 * universe has them. The scan's sort puts a node with no USB id first, so
 * every USB celldiag source would AT-probe /dev/mhi_DUN before its own ports
 * -- contending with the paired cellat for the PCIe modem's one AT node --
 * and --list would offer celldiag-<PCIe IMEI>, which auto-detect cannot open
 * (it follows a USB AT port to its DIAG node, and bring-up fails "did not
 * resolve to a USB device"). A PCIe modem needs diagport=, and that branch is
 * where its AT node is scanned. */
typedef enum {
    SCAN_ALL_PORTS = 0,
    SCAN_NONUSB_AT = 1,
} scan_scope_t;

/* Append the non-USB AT nodes: /dev/wwan*at* (mainline) and /dev/mhi_DUN
 * (out-of-tree MHI). Filtered, never globbed raw: /dev/mhi_* also holds
 * mhi_SAHARA and mhi_BHI (EDL / firmware download) and /dev/wwan* holds
 * wwan0firehose0, and a scan writes "AT" into every port it admits. The shared
 * classifier is the only selector, as in cellat. */
static int add_nonusb_at_ports(char ports[][256], int count, int max_ports) {
    static const char *const patterns[] = { "/dev/wwan*", "/dev/mhi_*" };
    glob_t g;
    for (size_t s = 0; s < sizeof(patterns) / sizeof(patterns[0]); s++) {
        if (glob(patterns[s], 0, NULL, &g) != 0)
            continue;
        for (size_t i = 0; i < g.gl_pathc && count < max_ports; i++) {
            if (!diag_wwan_is_at(g.gl_pathv[i]) || strlen(g.gl_pathv[i]) > 255)
                continue;
            strcpy(ports[count], g.gl_pathv[i]);
            count++;
        }
        globfree(&g);
    }
    return count;
}

/* The USB serial ttys the last SCAN_ALL_PORTS enumeration did not admit,
 * as "ttyUSB0(ch341-uart 1a86:7523)": never opened, and named in the
 * scan detail so a modem the rule misses is diagnosable from the source's own
 * messages. Reset at the top of every enumeration. */
static char g_scan_refused[512];

/* Append the ttys `pattern` matches that sysfs says are suspected cell modems
 * A refused tty is never opened -- no open(), no termios, no "AT" --
 * because a GNSS receiver or a USB-UART bridge's owner pays for every byte and
 * every line setting a probe leaves behind. The decision is
 * diag_port_admit()'s, shared with cellat's scan so the two cannot disagree on
 * what a modem is. */
static int add_suspected_modem_ports(const char *pattern, char ports[][256],
                                     int count, int max_ports) {
    glob_t g;
    if (glob(pattern, 0, NULL, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc && count < max_ports; i++) {
            diag_portadmit_t v;
            if (strlen(g.gl_pathv[i]) > 255)
                continue;
            if (!diag_port_admit(DIAG_PORTADMIT_SYSFS, g.gl_pathv[i], &v)) {
                diag_portadmit_note(g_scan_refused, sizeof(g_scan_refused),
                                    g.gl_pathv[i], &v);
                diag_portadmit_log_once(stderr, "celldiag", g.gl_pathv[i], &v,
                                        "name it in CELLDIAG_SCAN_PORTS, or use "
                                        "atport=, to probe it");
                continue;
            }
            strcpy(ports[count], g.gl_pathv[i]);
            count++;
        }
    }
    globfree(&g);
    return count;
}

static int find_modem_ports(char ports[][256], int max_ports, scan_scope_t scope) {
    int count = 0;

    const char *only = getenv("CELLDIAG_SCAN_PORTS");
    if (only && *only) {
        count = scan_ports_from_env(only, ports, max_ports);
        /* The named universe, narrowed the same way as the real one: the
         * non-USB scope keeps only its AT nodes, and the USB scope keeps
         * everything that is not a wwan/MHI node. Without the second half, a
         * named mhi_DUN would be found by the USB pass itself and an offline
         * test could never reach the path a real PCIe modem takes -- the
         * non-USB fallback after a USB miss. */
        int kept = 0;
        for (int i = 0; i < count; i++) {
            int nonusb = diag_wwan_classify(ports[i], NULL) != DIAG_WWAN_NONE;
            if (scope == SCAN_NONUSB_AT ? !diag_wwan_is_at(ports[i]) : nonusb)
                continue;
            if (kept != i)
                memcpy(ports[kept], ports[i], 256);
            kept++;
        }
        return kept;
    }

    if (scope == SCAN_NONUSB_AT)
        return add_nonusb_at_ports(ports, 0, max_ports);

    /* Only suspected cell-modem ttys. Probing every /dev/ttyUSB* and
     * /dev/ttyACM* is not harmless: it can reset, for example, a GNSS
     * receiver's line speed. An
     * operator-named universe (CELLDIAG_SCAN_PORTS, above) is not filtered:
     * that is the escape hatch for a modem behind a USB-UART bridge. */
    g_scan_refused[0] = '\0';
    count = add_suspected_modem_ports("/dev/ttyUSB*", ports, count, max_ports);
    count = add_suspected_modem_ports("/dev/ttyACM*", ports, count, max_ports);

    return count;
}

/* Map a tty node to its parent USB device id ("2-1") via sysfs. 1 on success. */
static int get_usb_device_id(const char *port_path, char *usb_dev, size_t usb_dev_sz) {
    char sysfs_path[512];
    char resolved[512];
    const char *port_name;

    port_name = strrchr(port_path, '/');
    if (port_name)
        port_name++;
    else
        port_name = port_path;

    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/tty/%s/device", port_name);
    if (realpath(sysfs_path, resolved) == NULL)
        return 0;

    char *slash1 = strrchr(resolved, '/');
    if (!slash1) return 0;
    *slash1 = '\0';
    char *slash2 = strrchr(resolved, '/');
    if (!slash2) return 0;
    *slash2 = '\0';
    char *dev_name = strrchr(resolved, '/');
    if (!dev_name) return 0;
    dev_name++;

    strncpy(usb_dev, dev_name, usb_dev_sz - 1);
    usb_dev[usb_dev_sz - 1] = '\0';
    return 1;
}

/* USB interface number for a tty node ("2-1:1.4" -> 4). -1 on failure. */
static int get_usb_interface_num(const char *port_path) {
    char sysfs_path[512];
    char resolved[512];
    const char *port_name;

    port_name = strrchr(port_path, '/');
    if (port_name)
        port_name++;
    else
        port_name = port_path;

    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/tty/%s/device", port_name);
    if (realpath(sysfs_path, resolved) == NULL)
        return -1;

    char *slash = strrchr(resolved, '/');
    if (!slash) return -1;
    *slash = '\0';
    char *iface_dir = strrchr(resolved, '/');
    if (!iface_dir) return -1;
    iface_dir++;
    char *dot = strrchr(iface_dir, '.');
    if (!dot) return -1;
    /* Strict parse: the interface number is the decimal suffix after the last
     * '.' of the sysfs interface dir (e.g. "1-1:1.0" -> 0). atoi() would map a
     * malformed suffix to 0 - indistinguishable from a real if00, which the
     * profiles select by exact match (diag.port_detect interface:0). A
     * garbage suffix must be rejected (-1, excluded), not silently matched as
     * interface 0 nor treated as the lowest interface. */
    char *endp = NULL;
    long ifn = strtol(dot + 1, &endp, 10);
    if (endp == dot + 1 || *endp != '\0' || ifn < 0 || ifn > 255)
        return -1;
    return (int)ifn;
}

/* Read one hex-valued sysfs attribute of a tty's USB interface (e.g.
 * "bInterfaceClass" -> 0xff). Returns the value, or -1 if unreadable /
 * malformed. -1 (not 0) is the sentinel because 0x00 is a legitimate value for
 * every one of these bytes. */
static int read_usb_iface_hex_attr(const char *port_path, const char *attr) {
    char sysfs_path[512];
    char resolved[512];
    char attr_path[1024];
    char buf[32];
    const char *port_name;

    port_name = strrchr(port_path, '/');
    if (port_name)
        port_name++;
    else
        port_name = port_path;

    /* /sys/class/tty/ttyUSBn/device resolves to the port dir
     * (".../2-3.4.3:1.0/ttyUSB14"); the descriptor attributes live one level up,
     * in the USB interface dir ("2-3.4.3:1.0"). Same walk get_usb_interface_num
     * does. Reading them from the port dir silently finds nothing. */
    snprintf(sysfs_path, sizeof(sysfs_path), "/sys/class/tty/%s/device",
             port_name);
    if (realpath(sysfs_path, resolved) == NULL)
        return -1;
    char *slash = strrchr(resolved, '/');
    if (!slash)
        return -1;
    *slash = '\0';

    snprintf(attr_path, sizeof(attr_path), "%s/%s", resolved, attr);

    FILE *f = fopen(attr_path, "r");
    if (!f)
        return -1;
    if (!fgets(buf, sizeof(buf), f)) {
        fclose(f);
        return -1;
    }
    fclose(f);

    char *endp = NULL;
    long v = strtol(buf, &endp, 16);
    if (endp == buf || v < 0 || v > 255)
        return -1;
    /* Trailing junk beyond the newline means this is not the plain hex byte
     * the attribute is documented to be; reject rather than half-parse. */
    while (*endp == '\n' || *endp == '\r' || *endp == ' ')
        endp++;
    if (*endp != '\0')
        return -1;
    return (int)v;
}

/* USB interface descriptor triple (class/subclass/protocol) of a tty node.
 * Each out-param is set to -1 when unreadable. Used to classify DIAG by
 * descriptor rather than by the if00 convention. */
static void get_usb_interface_desc(const char *port_path,
                                   int *cls, int *sub, int *prot) {
    *cls  = read_usb_iface_hex_attr(port_path, "bInterfaceClass");
    *sub  = read_usb_iface_hex_attr(port_path, "bInterfaceSubClass");
    *prot = read_usb_iface_hex_attr(port_path, "bInterfaceProtocol");
}

/* Scan serial ports for AT-responding modems, one per physical USB device.
 * Sorted so higher (AT-likely) interfaces are tried first, minimizing timeouts
 * on DIAG/NMEA ports. Calls cb per modem; non-zero cb return stops the scan. */
typedef int (*modem_scan_cb)(const char *port, const char *fw,
                             const char *imei, const modemident_t *id,
                             void *ctx);

/* Per-port cost of the last scan_modems() sweep, for the at_scan phase
 * detail. Only ports costing >= SCAN_SLOW_MS are recorded -- the point is to
 * name which nodes make a scan expensive, not to log them all. File-static is
 * safe here: each capture source is its own helper process, and within it the
 * scan runs only from the single bring-up thread. */
#define SCAN_SLOW_MS 500
/* Defined further down with the bring-up phase timers. */
static long bringup_elapsed_ms(const struct timespec *start);
static char g_scan_slow[512];
/* Ports whose probe fd had unsent output at close, with how the wait
 * was avoided: "ttyUSB18(nowait)". Listed whatever they cost, because with
 * the wait avoided they cost ~150 ms and the slow list above would never name
 * them. */
static char g_scan_stuck[256];
/* Ports whose open() did not return within DIAG_PROBE_OPEN_DEADLINE_MS and were
 * skipped: "ttyUSB18(open-timeout)". Named for the same reason as the
 * stuck list: bounded, they would otherwise never be mentioned again. */
static char g_scan_openstuck[256];

static void scan_slow_reset(void) {
    g_scan_slow[0] = '\0';
    g_scan_stuck[0] = '\0';
    g_scan_openstuck[0] = '\0';
    g_scan_badimei[0] = '\0';
    g_scan_busy = 0;
    g_scan_vouch_pid = 0;
    g_scan_vouch_port[0] = '\0';
}

/* Report the last scan_modems() pass's per-port detail -- the slow ports
 * and the stuck ports -- under `what`. A function, not inline at the
 * at_scan lap, because a busy-port rescan must report the first pass before
 * its own pass resets the buffers: the first pass is the one that met the
 * contention. */
static void scan_report_ports(kis_capture_handler_t *caph, const char *who,
                              const char *what) {
    char buf[STATUS_MAX];
    /* Name the ports that made the scan expensive, if any. */
    if (g_scan_slow[0]) {
        snprintf(buf, sizeof(buf), "%s %s slow ports: %s", who, what,
                 g_scan_slow);
        cf_send_message(caph, buf, MSGFLAG_INFO);
    }
    /* A port that never took its probe: named even though it no
     * longer costs anything, so the avoided 30 s stays visible. */
    if (g_scan_stuck[0]) {
        snprintf(buf, sizeof(buf), "%s %s: port(s) never took the probe, "
                 "closed without waiting out closing_wait: %s", who, what,
                 g_scan_stuck);
        cf_send_message(caph, buf, MSGFLAG_INFO);
    }
    /* A port whose open() would have blocked out another prober's close:
     * skipped at the deadline instead of costing ~30 s. */
    if (g_scan_openstuck[0]) {
        snprintf(buf, sizeof(buf), "%s %s: port(s) still closing after another "
                 "probe, open() gave up at %d ms and skipped them: %s", who,
                 what, DIAG_PROBE_OPEN_DEADLINE_MS, g_scan_openstuck);
        cf_send_message(caph, buf, MSGFLAG_INFO);
    }
    /* A port that answered AT but not with an IMEI, twice: passed
     * over as silent, never as another modem, and named so it is findable. */
    if (g_scan_badimei[0]) {
        snprintf(buf, sizeof(buf), "%s %s: port(s) answered AT+CGSN with no "
                 "IMEI, twice; treated as not answering, not as another "
                 "modem: %s", who, what, g_scan_badimei);
        cf_send_message(caph, buf, MSGFLAG_INFO);
    }
    /* The ttys the scan did not open at all: not suspected cell modems by
     * their sysfs driver / vendor id, or a modem's known DIAG /
     * NMEA interface (labelled e.g. "if01 NMEA"). Named with their evidence
     * and the escape hatch, so a modem behind a USB-UART bridge -- or a port a
     * wrong table entry refused -- is findable. */
    if (g_scan_refused[0]) {
        snprintf(buf, sizeof(buf), "%s %s: not probed (not suspected cell "
                 "modems, or a modem's known non-AT port): %s (name one in "
                 "CELLDIAG_SCAN_PORTS to probe it)", who, what, g_scan_refused);
        cf_send_message(caph, buf, MSGFLAG_INFO);
    }
}

static void scan_slow_note(const char *port, long ms) {
    size_t off = strlen(g_scan_slow);
    if (off + 32 >= sizeof(g_scan_slow))
        return;
    const char *base = strrchr(port, '/');
    base = base ? base + 1 : port;
    snprintf(g_scan_slow + off, sizeof(g_scan_slow) - off, "%s%s:%ldms",
             off ? "," : "", base, ms);
}

static int scan_modems(modem_scan_cb cb, void *ctx, const char *want_imei,
                       scan_scope_t scope) {
    char all_ports[64][256];
    char usb_devs[64][64];
    int if_nums[64];
    int is_diag_node[64];
    int n_all = find_modem_ports(all_ports, 64, scope);
    int found = 0;

    scan_slow_reset();

    for (int i = 0; i < n_all; i++) {
        if (!get_usb_device_id(all_ports[i], usb_devs[i], sizeof(usb_devs[i])))
            usb_devs[i][0] = '\0';
        if_nums[i] = get_usb_interface_num(all_ports[i]);
        is_diag_node[i] = 0;
    }

    /* Mark each device's DIAG node so the AT probe can skip it.
     *
     * A DIAG port never answers AT, so probing it is pure cost -- but the cost
     * is not just the 150 ms timeout. This scan runs on every source open and
     * walks the whole ttyUSB space, so with N concurrent sources each one
     * AT-probes the other modems' DIAG ports, opening and writing to a node a
     * sibling source may be mid-LOG_CONFIG-handshake on. That handshake cannot
     * tell a disturbed exchange from a slow modem, so it waits out
     * DIAG_RESP_TIMEOUT_S: a handshake that takes 0.02 s solo can take 30-60 s
     * under a concurrent multi-source bring-up.
     *
     * Skip precisely the node the descriptor classifier would select (the
     * lowest DIAG-class interface on that device), not every DIAG-class
     * interface: on 2c7c:0700 if00/if01/if02 are all ff/ff/ff and if02 is what
     * actually answers AT+CGSN, so a blanket skip would make that modem
     * unidentifiable. */
    for (int i = 0; i < n_all; i++) {
        int cls, sub, prot;
        get_usb_interface_desc(all_ports[i], &cls, &sub, &prot);
        if (!diag_ifclass_is_diag(cls, sub, prot))
            continue;
        if (if_nums[i] < 0)
            continue;
        int lowest_on_dev = 1;
        for (int j = 0; j < n_all; j++) {
            if (j == i || !usb_devs[i][0] || strcmp(usb_devs[i], usb_devs[j]) != 0)
                continue;
            int jcls, jsub, jprot;
            get_usb_interface_desc(all_ports[j], &jcls, &jsub, &jprot);
            if (diag_ifclass_is_diag(jcls, jsub, jprot) &&
                if_nums[j] >= 0 && if_nums[j] < if_nums[i]) {
                lowest_on_dev = 0;
                break;
            }
        }
        is_diag_node[i] = lowest_on_dev;
    }

    for (int i = 0; i < n_all - 1; i++) {
        for (int j = i + 1; j < n_all; j++) {
            int swap = 0;
            int cmp = strcmp(usb_devs[i], usb_devs[j]);
            if (cmp > 0)
                swap = 1;
            else if (cmp == 0 && if_nums[i] < if_nums[j])
                swap = 1;
            if (swap) {
                char tmp_port[256], tmp_dev[64];
                int tmp_if;
                memcpy(tmp_port, all_ports[i], 256);
                memcpy(all_ports[i], all_ports[j], 256);
                memcpy(all_ports[j], tmp_port, 256);
                memcpy(tmp_dev, usb_devs[i], 64);
                memcpy(usb_devs[i], usb_devs[j], 64);
                memcpy(usb_devs[j], tmp_dev, 64);
                tmp_if = if_nums[i]; if_nums[i] = if_nums[j]; if_nums[j] = tmp_if;
                /* is_diag_node is indexed in lockstep with the three arrays
                 * above -- it must ride the same swap or the skip flags detach
                 * from their ports. */
                tmp_if = is_diag_node[i];
                is_diag_node[i] = is_diag_node[j];
                is_diag_node[j] = tmp_if;
            }
        }
    }

    char done_devs[64][64];
    int n_done = 0;
    int busy_idx[64];
    int n_busy = 0;

    for (int i = 0; i < n_all; i++) {
        if (usb_devs[i][0]) {
            int skip = 0;
            for (int j = 0; j < n_done; j++) {
                if (strcmp(done_devs[j], usb_devs[i]) == 0) { skip = 1; break; }
            }
            if (skip)
                continue;
        }

        /* Never AT-probe a device's DIAG node: it cannot answer, and doing so
         * disturbs a concurrent source's LOG_CONFIG handshake on that same
         * node (see the marking loop above). Every modem exposes at least one
         * non-DIAG function, so identification still has a port to use. */
        if (is_diag_node[i])
            continue;

        char fw_buf[256], imei_buf[64];
        modemident_t port_ident;
        struct timespec p0;
        clock_gettime(CLOCK_MONOTONIC, &p0);
        int mismatch = 0;
        int busy_before = g_scan_busy;
        int ident = identify_modem(all_ports[i], fw_buf, sizeof(fw_buf),
                                   imei_buf, sizeof(imei_buf), want_imei,
                                   &mismatch, &port_ident);
        long port_ms = bringup_elapsed_ms(&p0);
        if (port_ms >= SCAN_SLOW_MS)
            scan_slow_note(all_ports[i], port_ms);
        if (g_probe_close_how != DIAG_PROBECLOSE_PLAIN)
            diag_probeclose_note(g_scan_stuck, sizeof(g_scan_stuck),
                                 all_ports[i], g_probe_close_how);
        if (g_probe_open_timed_out)
            diag_probeclose_note_label(g_scan_openstuck,
                                       sizeof(g_scan_openstuck), all_ports[i],
                                       "open-timeout");
        if (!ident) {
            /* A confident IMEI mismatch settles the whole USB device: every
             * tty on it belongs to a modem we are not looking for, so probing
             * its remaining functions can only cost time (up to ~30 s per
             * port).
             *
             * Deliberately not done on a silent port: "did not answer" tells
             * us nothing about the device, and skipping on it would make a
             * modem whose first-tried function is mute undiscoverable. */
            if (mismatch && usb_devs[i][0] && n_done < 64) {
                strncpy(done_devs[n_done], usb_devs[i], 63);
                done_devs[n_done][63] = '\0';
                n_done++;
            }
            if (g_scan_busy > busy_before && n_busy < 64)
                busy_idx[n_busy++] = i;   /* lister retry, below */
            continue;
        }

        if (usb_devs[i][0] && n_done < 64) {
            strncpy(done_devs[n_done], usb_devs[i], 63);
            done_devs[n_done][63] = '\0';
            n_done++;
        }

        found++;
        if (cb && cb(all_ports[i], fw_buf, imei_buf, &port_ident, ctx))
            return found;
    }

    /* A lister re-tries the ports it found held (see
     * CELL_LIST_BUSY_WAIT_MS). A port whose device another port has since
     * identified is settled and dropped; one still held at the deadline is
     * skipped. */
    if (g_scan_list_wait && n_busy > 0) {
        struct timespec w0;
        clock_gettime(CLOCK_MONOTONIC, &w0);
        while (n_busy > 0 && bringup_elapsed_ms(&w0) < CELL_LIST_BUSY_WAIT_MS) {
            usleep(CELL_LIST_BUSY_STEP_MS * 1000);
            int kept = 0;
            for (int k = 0; k < n_busy; k++) {
                int i = busy_idx[k];
                int settled = 0;
                for (int j = 0; usb_devs[i][0] && j < n_done; j++)
                    if (strcmp(done_devs[j], usb_devs[i]) == 0) { settled = 1; break; }
                if (settled)
                    continue;
                char fw_buf[256], imei_buf[64];
                modemident_t port_ident;
                int busy_before = g_scan_busy;
                int ident = identify_modem(all_ports[i], fw_buf, sizeof(fw_buf),
                                           imei_buf, sizeof(imei_buf), want_imei,
                                           NULL, &port_ident);
                if (!ident) {
                    if (g_scan_busy > busy_before)
                        busy_idx[kept++] = i;
                    continue;
                }
                if (usb_devs[i][0] && n_done < 64) {
                    strncpy(done_devs[n_done], usb_devs[i], 63);
                    done_devs[n_done][63] = '\0';
                    n_done++;
                }
                found++;
                if (cb && cb(all_ports[i], fw_buf, imei_buf, &port_ident, ctx))
                    return found;
            }
            n_busy = kept;
        }
    }

    return found;
}

/* --- find-by-IMEI --- */

typedef struct {
    const char *target_imei;
    char *path_out;
    size_t path_sz;
    char *fw_out;
    size_t fw_sz;
    char *imei_out;
    size_t imei_sz;
    modemident_t *id_out;   /* the found modem's identity, or NULL */
} find_imei_ctx_t;

static int find_imei_cb(const char *port, const char *fw,
                        const char *imei, const modemident_t *id, void *ctx) {
    find_imei_ctx_t *c = (find_imei_ctx_t *)ctx;
    if (strcmp(imei, c->target_imei) != 0)
        return 0;
    if (c->id_out != NULL && id != NULL)
        *c->id_out = *id;

    strncpy(c->path_out, port, c->path_sz - 1);
    c->path_out[c->path_sz - 1] = '\0';
    if (c->fw_out) {
        strncpy(c->fw_out, fw, c->fw_sz - 1);
        c->fw_out[c->fw_sz - 1] = '\0';
    }
    if (c->imei_out) {
        strncpy(c->imei_out, imei, c->imei_sz - 1);
        c->imei_out[c->imei_sz - 1] = '\0';
    }
    return 1;
}

static int find_port_by_imei(const char *imei, char *path_out, size_t path_sz,
                             char *fw_out, size_t fw_sz,
                             char *imei_out, size_t imei_sz,
                             scan_scope_t scope, modemident_t *id_out) {
    find_imei_ctx_t ctx = {
        .target_imei = imei,
        .path_out = path_out, .path_sz = path_sz,
        .fw_out = fw_out, .fw_sz = fw_sz,
        .imei_out = imei_out, .imei_sz = imei_sz,
        .id_out = id_out,
    };
    path_out[0] = '\0';
    scan_modems(find_imei_cb, &ctx, imei, scope);
    return path_out[0] != '\0' ? 1 : 0;
}

/* Locate the DIAG interface on the same USB device as `sibling_port`.
 *
 * By default Qualcomm modems expose DIAG (QCDM) as the lowest USB interface
 * (if00), so we pick the tty on that USB device with the smallest interface
 * number. That if00-is-DIAG assumption does not hold for every modem, so an
 * optional per-model descriptor `pd` (resolved from the profile's
 * diag.port_detect) refines it:
 *   - pd->transport: "ttyUSB" (default) is handled here. "wwan_mhi" (and its
 *     "wwan"/"mhi" spellings) is auto-detected -- find_diag_port
 *     dispatches it to find_diag_port_wwan(), which classifies by node name
 *     because a PCIe modem has no USB descriptor to classify. "qmi_embedded" is
 *     not auto-detected -> actionable message, return 0.
 *   - pd->match == "interface" with pd->has_interface: select the ttyUSB whose
 *     USB bInterfaceNumber == pd->interface exactly (the robust path). Otherwise
 *     (match "lowest", or no descriptor) use the lowest-interface pick.
 * `pd` may be NULL, which is the default (ttyUSB/lowest).
 *
 * Returns 1 on success (out filled), 0 if the USB device or a matching tty
 * cannot be found. On failure, if `diag`/`diagsz` are provided, an actionable
 * diagnostic is composed there: which USB device the IMEI matched, which ttyUSB
 * interfaces were enumerated on it, and what to do about it. */
/* Locate the DIAG node on a non-USB (wwan / MHI) transport.
 *
 * Deliberately not anchored to an IMEI the way the ttyUSB path is. On USB, a
 * sibling AT port ties the search to one physical modem; on wwan/MHI there is no
 * such anchor in the node names, so this enumerates the whole node space and
 * refuses to choose when more than one modem's DIAG node is present -- see
 * diag_wwan_pick's -2. Guessing there would present as a working source bound to
 * the wrong modem, which is worse than an open error naming the fix.
 *
 * Returns 1 and fills `out` on success, 0 with a diagnostic otherwise. */
static int find_diag_port_wwan(char *out, size_t outsz, char *diag, size_t diagsz) {
    glob_t g;
    /* Both conventions in one enumeration: mainline wwan ports and out-of-tree
     * MHI channels. Their names are disjoint, so the classifier -- not the glob
     * -- decides what anything is. */
    static const char *kPatterns[] = { "/dev/wwan*", "/dev/mhi_*" };

    const char *nodes[DIAG_WWAN_MAX_NODES];
    char storage[DIAG_WWAN_MAX_NODES][128];
    int n = 0;

    /* A named universe (CELLDIAG_SCAN_PORTS) is the whole universe, for this
     * pick as for the AT scan: otherwise an offline test that names
     * PTY fakes as mhi_DUN / mhi_DIAG would have its DIAG node chosen from the
     * host's real /dev/mhi_* -- a real modem, opened from a unit test. */
    const char *only = getenv("CELLDIAG_SCAN_PORTS");
    if (only && *only) {
        char named[DIAG_WWAN_MAX_NODES][256];
        int m = scan_ports_from_env(only, named, DIAG_WWAN_MAX_NODES);
        for (int i = 0; i < m; i++) {
            if (diag_wwan_classify(named[i], NULL) == DIAG_WWAN_NONE)
                continue;
            snprintf(storage[n], sizeof(storage[n]), "%s", named[i]);
            nodes[n] = storage[n];
            n++;
        }
        goto pick;
    }

    for (size_t p = 0; p < sizeof(kPatterns) / sizeof(kPatterns[0]); p++) {
        if (glob(kPatterns[p], 0, NULL, &g) != 0)
            continue;
        for (size_t i = 0; i < g.gl_pathc && n < DIAG_WWAN_MAX_NODES; i++) {
            if (diag_wwan_classify(g.gl_pathv[i], NULL) == DIAG_WWAN_NONE)
                continue;   /* e.g. the wwan0 netdev, if it ever appears in /dev */
            snprintf(storage[n], sizeof(storage[n]), "%s", g.gl_pathv[i]);
            nodes[n] = storage[n];
            n++;
        }
        globfree(&g);
    }

pick:;
    int pick = diag_wwan_pick(nodes, n);
    if (pick < 0) {
        if (diag && diagsz)
            diag_wwan_format(pick, nodes, n, diag, diagsz);
        return 0;
    }

    snprintf(out, outsz, "%s", nodes[pick]);
    if (diag && diagsz)
        snprintf(diag, diagsz,
                 "DIAG node selected by wwan/MHI name: %s [%s] (of %d modem node(s))",
                 nodes[pick], diag_wwan_label(nodes[pick]), n);
    return 1;
}

static int find_diag_port(const char *sibling_port, char *out, size_t outsz,
                          const char *imei, char *diag, size_t diagsz,
                          const struct diag_port_detect *pd) {
    /* An AT sibling with no USB device (/dev/mhi_DUN, /dev/wwan0at0) is
     * a PCIe modem, so its DIAG node is found by node name -- there is no USB
     * device to follow. Decided before the profile's transport on purpose: one
     * firmware ships on both buses (the RM520N-GL can be wired as USB or PCIe),
     * so a firmware-keyed profile cannot know which this unit is,
     * and a ttyUSB descriptor would send it to get_usb_device_id() and a
     * "did not resolve to a USB device" failure. */
    if (sibling_port && diag_wwan_is_at(sibling_port))
        return find_diag_port_wwan(out, outsz, diag, diagsz);

    /* Transport dispatch. ttyUSB falls through to the USB-descriptor path below;
     * wwan/MHI is auto-detected by node name, because a PCIe modem has no
     * USB descriptor to classify. Anything else still fails loud with an
     * explanation rather than silently globbing ttyUSB and reporting a generic
     * "not found". */
    if (pd && pd->transport[0] && strcmp(pd->transport, "ttyUSB") != 0) {
        if (strcmp(pd->transport, "wwan_mhi") == 0 ||
                strcmp(pd->transport, "wwan") == 0 ||
                strcmp(pd->transport, "mhi") == 0)
            return find_diag_port_wwan(out, outsz, diag, diagsz);

        if (diag && diagsz)
            diag_portdiag_format_transport(imei, pd->transport, diag, diagsz);
        return 0;
    }

    char target_dev[64];
    if (!get_usb_device_id(sibling_port, target_dev, sizeof(target_dev))) {
        if (diag && diagsz)
            diag_portdiag_format(imei, sibling_port, NULL, NULL, 0, diag, diagsz);
        return 0;
    }

    /* Selection mode: exact bInterfaceNumber when the descriptor requests it,
     * else lowest-interface. */
    int want_if = -1;
    if (pd && pd->has_interface && strcmp(pd->match, "interface") == 0)
        want_if = pd->interface;

    glob_t g;
    int best_if = 1 << 30;
    char best[256] = "";
    /* Interface numbers seen on the matched USB device, for the failure
     * diagnostic. Bounded; a modem exposes a handful of ttyUSB functions. */
    int seen_ifs[32];
    int n_seen = 0;
    /* Descriptor-classified candidates on the matched device. Same
     * bound as seen_ifs - one entry per ttyUSB function on one modem. */
    struct diag_ifcand cands[32];
    int n_cands = 0;

    if (glob("/dev/ttyUSB*", 0, NULL, &g) == 0) {
        for (size_t i = 0; i < g.gl_pathc; i++) {
            char dev[64];
            if (!get_usb_device_id(g.gl_pathv[i], dev, sizeof(dev)))
                continue;
            if (strcmp(dev, target_dev) != 0)
                continue;
            int ifn = get_usb_interface_num(g.gl_pathv[i]);
            if (ifn >= 0 && n_seen < (int)(sizeof(seen_ifs) / sizeof(seen_ifs[0])))
                seen_ifs[n_seen++] = ifn;
            if (n_cands < (int)(sizeof(cands) / sizeof(cands[0]))) {
                struct diag_ifcand *c = &cands[n_cands++];
                memset(c, 0, sizeof(*c));
                snprintf(c->path, sizeof(c->path), "%s", g.gl_pathv[i]);
                c->if_num = ifn;
                get_usb_interface_desc(g.gl_pathv[i], &c->cls, &c->sub, &c->prot);
            }
            if (want_if >= 0) {
                /* Exact-match mode: take the tty on the requested interface. */
                if (ifn == want_if) {
                    strncpy(best, g.gl_pathv[i], sizeof(best) - 1);
                    best[sizeof(best) - 1] = '\0';
                }
            } else if (ifn >= 0 && ifn < best_if) {
                best_if = ifn;
                strncpy(best, g.gl_pathv[i], sizeof(best) - 1);
                best[sizeof(best) - 1] = '\0';
            }
        }
    }
    globfree(&g);

    /* Descriptor-based selection. Precedence:
     *   diagport=            (handled by the caller, never reaches here)
     *   profile match=interface  -- an explicit operator/profile pin wins
     *   USB descriptor class     -- this: deterministic, zero device I/O
     *   lowest interface number  -- the conventional if00, fallback
     *
     * It sits ahead of lowest-interface because a wrong pick is expensive: a
     * LOG_CONFIG handshake against a non-DIAG port is indistinguishable from a
     * slow modem and waits out DIAG_RESP_TIMEOUT_S, 20-60 s per mis-detected
     * port against 0.02 s for a correct one. The descriptor costs three sysfs
     * reads. Declining (-1) leaves `best` exactly as the lowest-interface
     * heuristic computed it, so an unrecognised composition degrades to that
     * rather than to a wrong answer. */
    if (want_if < 0) {
        int pick = diag_ifclass_pick(cands, n_cands);
        if (pick >= 0 && strcmp(cands[pick].path, best) != 0) {
            /* The descriptor disagrees with lowest-interface: trust it, and say
             * so -- lowest-interface would cost a 20-60 s timeout here. */
            if (diag && diagsz)
                snprintf(diag, diagsz,
                         "DIAG port selected by USB descriptor: %s [if%02d %s] "
                         "on %s (lowest-interface would have picked %s)",
                         cands[pick].path,
                         cands[pick].if_num >= 0 ? cands[pick].if_num : 0,
                         diag_ifclass_label(cands[pick].cls, cands[pick].sub,
                                            cands[pick].prot),
                         target_dev, best[0] ? best : "nothing");
            strncpy(best, cands[pick].path, sizeof(best) - 1);
            best[sizeof(best) - 1] = '\0';
        } else if (pick >= 0) {
            /* Agreement: the conventional if00 is the descriptor-classified
             * DIAG function. No message - this is the common, boring path. */
        } else if (best[0]) {
            /* No candidate carried a DIAG signature. Keep the lowest-interface pick
             * but warn: this is the shape of a composition the classifier has
             * not seen, and of the non-modem-serial-adapter case. */
            if (diag && diagsz)
                snprintf(diag, diagsz,
                         "no USB interface on %s carries a DIAG descriptor "
                         "(ff/ff/ff or ff/ff/30); falling back to the lowest "
                         "interface %s. If the LOG_CONFIG handshake times out, "
                         "this is probably the wrong port - pass diagport=.",
                         target_dev, best);
        }
    }

    if (!best[0]) {
        if (diag && diagsz) {
            /* In exact-interface mode the generic message's "expected DIAG on
             * the lowest interface (if00)" wording would misattribute the
             * failure - the operator pinned `want_if` via the profile. Name the
             * requested interface instead. */
            if (want_if >= 0)
                diag_portdiag_format_iface_missing(imei, sibling_port,
                        target_dev, want_if, seen_ifs, n_seen, diag, diagsz);
            else
                diag_portdiag_format(imei, sibling_port, target_dev,
                                     seen_ifs, n_seen, diag, diagsz);
        }
        return 0;
    }
    strncpy(out, best, outsz - 1);
    out[outsz - 1] = '\0';
    return 1;
}

/* -----------------------------------------------------------------------
 * Error reporting and decoder bring-up
 * ----------------------------------------------------------------------- */

/* Report a fatal post-open condition so the operator actually sees the reason.
 *
 * Do not "simplify" this back to a bare cf_send_error(). Under the v3
 * protocol cf_send_error() is silently discarded by the server. There is no
 * `case KIS_EXTERNAL_V3_CMD_ERROR` in either dispatcher --
 * kis_external_interface::dispatch_rx_packet_v3 falls through to
 * kis_datasource::dispatch_rx_packet_v3, which also has no case for it, so the
 * frame is dropped. From kis_datasource.cc:
 *
 *   // v3 drops explicit error/warning reports and rolls them into the return
 *   // codes of the packet headers itself.  The error message is sent as a
 *   // message prior to the packet being sent.
 *
 * "Sent as a message prior" is the prescribed idiom, and that is what the
 * cf_send_message() below is. It rides KIS_EXTERNAL_V3_CMD_MESSAGE, which the
 * server does handle.
 *
 * Errors raised from open_callback do not need this: they ride out on the open
 * report's return code. Without it, post-open failures (deferred bring-up,
 * replay/rawlog open, a decoder that cannot be armed) would surface only as a bare
 * "IPC connection closed".
 *
 * cf_send_error() is still called after it: it is the protocol-correct thing to
 * emit, it is what a v2 peer would consume, and it is what puts the source into
 * the error state that drives Kismet's re-open. It just cannot be relied on to
 * carry the human-readable reason. */
static void diag_report_error(kis_capture_handler_t *caph, const char *msg) {
    cf_send_message(caph, msg, MSGFLAG_ERROR);
    cf_send_error(caph, 0, msg);
}

static void f3_mark_norelay(local_diag_t *local, kis_capture_handler_t *caph) {
    local->f3_relay = 0;
    local->f3_norelay = 1;
    snprintf(local->f3_preset_buf, sizeof(local->f3_preset_buf), "%s+norelay",
             local->f3_preset ? local->f3_preset : "all");
    const char *armed = local->f3_preset ? local->f3_preset : "all";
    local->f3_preset = local->f3_preset_buf;

    char buf[STATUS_MAX];
    snprintf(buf, sizeof(buf),
             "%s f3=%s: ARMED BUT NOT RELAYED -- this source does not relay "
             "F3 prints to the message bus, so no diag_f3 record is sent. The prints are still captured: they "
             "are in the DIAG byte stream, so read them from a rawlog= tee or "
             "from the kismetdb's raw DIAG packets (rawpackets=on; "
             "kismetdb_to_hdlc extracts them) with an offline F3 decoder. The "
             "health readout says \"%s\" so this is not mistaken for a "
             "relayed stream.",
             local->name, armed, local->f3_preset_buf);
    /* MSGFLAG_ERROR, but not diag_report_error(): the operator asked for
     * something they are not getting, which has to be loud -- and the source is
     * otherwise healthy, so putting it into Kismet's error state (and driving a
     * re-open that would land here again) would be the wrong severity. */
    cf_send_message(caph, buf, MSGFLAG_ERROR);
}

/* gsmtap=: this process frames every eligible code it has a framer for. The
 * ones it has none for are declined and counted -- and named here, at ERROR,
 * because nothing else can send them. */
static void gsmtap_gate(local_diag_t *local, kis_capture_handler_t *caph) {
    if (!local->gsmtap_on)
        return;
    char buf[STATUS_MAX];
    char missing[96] = "";
    size_t mo = 0;
    for (size_t i = 0; i < DIAG_GSMTAP_ELIGIBLE_COUNT; i++) {
        uint16_t c = DIAG_GSMTAP_ELIGIBLE_CODES[i];
        if (!diag_native_has_gsmtap_framer(c) && mo < sizeof(missing))
            mo += (size_t)snprintf(missing + mo, sizeof(missing) - mo,
                                   "%s0x%04X", mo ? "/" : "", (unsigned)c);
    }
    snprintf(buf, sizeof(buf),
             "%s gsmtap (native): LTE RRC/NAS records -> udp://%s (Wireshark: "
             "-f \"udp port %s\")", local->name, local->gsmtap_dest,
             strrchr(local->gsmtap_dest, ':') + 1);
    cf_send_message(caph, buf, MSGFLAG_INFO);
    if (missing[0]) {
        snprintf(buf, sizeof(buf),
                 "%s gsmtap (native): %s NOT SENT -- this binary has no "
                 "native framer for them yet (LTE NAS). They are counted as "
                 "declined.", local->name, missing);
        cf_send_message(caph, buf, MSGFLAG_ERROR);
    }
}

/* The decoder's bring-up, at open: there is no process to start, but it still
 * says which decoder runs, so a harness that requires the report sees it
 * rather than silence. helper_alive means "the in-process decoder is alive",
 * judged from the reader's heartbeat (local_diag_t.live). F3 has no relay,
 * so F3 is marked armed-not-relayed here. */
static void decoder_bringup(kis_capture_handler_t *caph, local_diag_t *local) {
    if (local->f3_relay)
        f3_mark_norelay(local, caph);
    gsmtap_gate(local, caph);
    cf_send_message(caph, "decoder: native, in process", MSGFLAG_INFO);
}

/* Name the compression container an open fd starts with, or NULL if the bytes
 * are not a container this function knows.
 *
 * Why this exists: `replay=` is an open() + raw-HDLC deframe, and captures
 * are often stored compressed (`.dlf.zst` / `.hdlc.zst`). Handed a compressed
 * file, the deframer would walk compressed bytes: high-entropy data contains
 * 0x7E flags everywhere, so frames get synthesized out of compression noise
 * and the occasional one passes CRC16. The source would then report health
 * as "RX-NO-OBS | bytes=N | obs=0" -- the file read fine, and the radio
 * looks quiet ("no cells in range"), which is the misleading part.
 *
 * We refuse rather than decompress on purpose. Decompressing in C means linking
 * libzstd into the capture binary, which is a build-system decision; the
 * offline harness decompresses its fixtures before replaying them.
 *
 * A magic-byte reject, not a positive is-this-a-capture proof: the
 * failure being guarded is a compressed container, and every byte string this
 * rejects is one no raw-HDLC/DLF capture can begin with. Leaves the fd offset
 * at 0. */
static const char *replay_container_magic(int fd, const char **decompress_with) {
    static const struct { const char *name; const char *tool;
                          const unsigned char sig[6]; size_t len; } known[] = {
        { "zstd",  "zstd -d",  { 0x28, 0xB5, 0x2F, 0xFD },             4 },
        { "gzip",  "gunzip",   { 0x1F, 0x8B },                         2 },
        { "xz",    "unxz",     { 0xFD, '7',  'z',  'X', 'Z', 0x00 },   6 },
        { "bzip2", "bunzip2",  { 'B',  'Z',  'h' },                    3 },
    };
    unsigned char head[8];
    ssize_t n = pread(fd, head, sizeof(head), 0);
    if (n <= 0)
        return NULL;
    for (size_t i = 0; i < sizeof(known) / sizeof(known[0]); i++) {
        if ((size_t)n >= known[i].len &&
            memcmp(head, known[i].sig, known[i].len) == 0) {
            if (decompress_with != NULL)
                *decompress_with = known[i].tool;
            return known[i].name;
        }
    }
    return NULL;
}

/* Write the whole buffer, retrying short writes. Returns 0 on success, -1 on a
 * write error. */
static int write_all(int fd, const uint8_t *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;  /* EPIPE etc. */
        }
        off += (size_t)w;
    }
    return 0;
}

/* -----------------------------------------------------------------------
 * Native-decode tap
 * ----------------------------------------------------------------------- */

/* Per-record ceiling for the native decode. Generous vs real captures (the widest
 * observed cell_observation record yields well under this), and a record that
 * exceeds it still counts as native -- diag_native_decode reports how many it
 * wrote, and truncation here would understate native_obs, never overstate it. */
#define DIAG_NATIVE_TAP_MAX_OBS 64

/* A cached DIAG GNSS fix older than this (seconds) is not attached to a
 * cell_observation -- better an ungeotagged cell than one pinned to a stale
 * position after the vehicle has moved. */
#define DIAG_GPS_MAX_AGE_S 30

/* A JSON record from the DIAG reader thread, under rawpkt_emit's per-source
 * loss policy (see there). Live: a full ring drops the record, because
 * waiting would stop this thread reading the port, and the modem's bytes
 * then overrun and are lost to decoding, rawlog= and the raw stream alike.
 * Replay: a file can wait, so a full ring is retried for up to ~30 s.
 * Teardown: retried briefly. Never cf_handler_wait_ringbuffer(): it has no
 * timeout, and it can miss the wakeup.
 * Returns cf_send_json's 1 (queued), 0 (dropped) or -1 (error). */
#define EMIT_RETRY_NS          2000000L
#define EMIT_REPLAY_MAX_RETRIES 15000
#define EMIT_FINISH_MAX_RETRIES 1000
static int ring_send_json(kis_capture_handler_t *caph, local_diag_t *local,
                          struct cf_params_gps *gps, struct timeval tv,
                          const char *type, const char *json) {
    int budget = local->replay_path != NULL ? EMIT_REPLAY_MAX_RETRIES :
                 local->emit_finishing ? EMIT_FINISH_MAX_RETRIES : 0;
    int r = cf_send_json(caph, NULL, 0, NULL, gps, tv, (char *)type, (char *)json);
    for (int i = 0; r == 0 && i < budget; i++) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = EMIT_RETRY_NS };
        nanosleep(&ts, NULL);
        r = cf_send_json(caph, NULL, 0, NULL, gps, tv, (char *)type, (char *)json);
    }
    return r;
}

/* The first ring-full drop, once and loudly; the counts ride diag_stats.
 * A replay that drops has broken its contract (every byte reaches Kismet),
 * so it is an ERROR on the source, not a counter: a golden or an A/B taken
 * from it would silently miss rows. */
static void announce_ring_drops(kis_capture_handler_t *caph, local_diag_t *local);

static void report_ring_drop(kis_capture_handler_t *caph, local_diag_t *local,
                             const char *what) {
    char m[ERRBUF_MAX];
    if (local->replay_path != NULL) {
        snprintf(m, sizeof(m),
                 "%s REPLAY DROPPED a %s: Kismet's output ring stayed full "
                 "for the whole ~30 s retry. A replay must be lossless, so "
                 "this run is not a faithful conversion.",
                 local->name ? local->name : "celldiag", what);
        diag_report_error(caph, m);
        return;
    }
    if (!local->obs_drop_pending)
        local->obs_drop_what = what;   /* the kind that dropped first */
    local->obs_drop_pending = 1;
    announce_ring_drops(caph, local);
}

/* The live drop notice. Sent at the one moment the ring is full, so it can
 * itself be refused; it stays pending and is retried after the next send
 * that fits -- the first moment there is room. Marked only once queued. */
static void announce_ring_drops(kis_capture_handler_t *caph, local_diag_t *local) {
    char m[ERRBUF_MAX];
    const char *what = local->obs_drop_what ? local->obs_drop_what : "record";
    if (local->obs_drop_announced || !local->obs_drop_pending)
        return;
    snprintf(m, sizeof(m),
             "%s is DROPPING %ss: Kismet is not draining this source's output "
             "ring. They are dropped (and counted, obs_ring_dropped) so the "
             "DIAG port keeps being read; waiting would overrun the modem "
             "and lose its bytes from rawlog= and the raw stream too.",
             local->name ? local->name : "celldiag", what);
    if (cf_send_message(caph, m, MSGFLAG_ERROR) > 0)
        local->obs_drop_announced = 1;
}

/* The single emit seam: every cell_observation that reaches Kismet goes
 * through here, so the geo-stamp, the staleness gate, the health counter and
 * the ring-full policy are one behaviour, not one per call site.
 * Returns 0 on success, -1 if the send failed (the caller's contract). */
static int emit_observation(kis_capture_handler_t *caph, local_diag_t *local,
                            const char *line) {
    struct timeval tv;
    char errstr[ERRBUF_MAX];
    gettimeofday(&tv, NULL);

    /* Stamp the observation with the last DIAG GNSS fix if we have a fresh one
     * so Kismet geo-tags the resulting device. A stale or absent fix
     * -> NULL gps (ungeotagged). The native GNSS leg in native_tap_cb feeds
     * `last_gps`. */
    struct cf_params_gps gps;
    struct cf_params_gps *gpsp = NULL;
    if (local->last_gps.valid &&
            (tv.tv_sec - local->last_gps.ts) <= DIAG_GPS_MAX_AGE_S) {
        memset(&gps, 0, sizeof(gps));
        gps.lat = local->last_gps.lat;
        gps.lon = local->last_gps.lon;
        gps.alt = local->last_gps.alt;
        gps.fix = 3;   /* 3D; both decoders gate out no-fix records */
        gps.ts_sec = (uint64_t)local->last_gps.ts;
        gps.gps_type = (char *)"celldiag";
        gpsp = &gps;
    }

    int r = ring_send_json(caph, local, gpsp, tv, "CellModem", line);
    if (r > 0) {
        diag_stats_on_obs(&local->stats, tv.tv_sec);
        announce_ring_drops(caph, local);
    }
    if (r < 0) {
        snprintf(errstr, ERRBUF_MAX,
                 "%s failed to send DIAG JSON to Kismet", local->name);
        diag_report_error(caph, errstr);
        return -1;
    }
    if (r == 0) {
        diag_stats_on_obs_dropped(&local->stats);
        report_ring_drop(caph, local, "cell observation");
    }
    return 0;
}

/* What the tap callback needs to do its job.
 *
 * Counting needs only `local_diag_t *`, but emitting needs the capture
 * handler too, and a long-lived back-pointer inside
 * local_diag_t would be a lifetime question with no good answer (the handler
 * outlives the source, but nothing in this file says so). Both call sites --
 * feed_bytes and the end-of-stream flush -- already hold both pointers, so a
 * stack context costs nothing and cannot go stale. */
typedef struct {
    kis_capture_handler_t *caph;
    local_diag_t          *local;
} native_tap_ctx_t;

static void relay_census_line(kis_capture_handler_t *caph, local_diag_t *local,
                              const char *line);

/* 0x14D8 has no native leg on purpose (diag_native_decode.h: it can never
 * emit a fix), yet a census calling it unrecognized would escalate to ERROR on
 * every GNSS-masked source. So the census counts it DECODED when it has one of
 * the record's three fixed shapes (20 or 44 bytes, or 104 and up) with version
 * byte 1, and nothing more: there is nothing else to decode. */
static int native_census_accepts_0x14d8(const uint8_t *p, size_t n) {
    if (p == NULL || n < 20 || (n > 20 && n < 44) || (n > 44 && n < 104))
        return 0;
    return p[0] == 1;
}

/* Render and relay the census line. Called from the capture thread; the relay's sends never wait on
 * the ring, so the DIAG reader is never the thread that blocks. */
static void native_census_emit(kis_capture_handler_t *caph, local_diag_t *local,
                               double now) {
    char line[DIAG_INVENTORY_LINE_MAX];
    int n = diag_inventory_wire(local->native_inv, now, line, sizeof(line));
    /* Bounded by construction (see DIAG_INVENTORY_LINE_MAX), so this is a
     * contract break, and a census line is never relayed cut. */
    if (n < 0 || (size_t)n >= sizeof(line)) {
        if (!local->truncation_reported) {
            char wbuf[STATUS_MAX];
            local->truncation_reported = 1;
            snprintf(wbuf, sizeof(wbuf),
                     "%s native census did not render (%d bytes against %d); "
                     "census omitted. Suppressing further notices this run.",
                     local->name, n, DIAG_INVENTORY_LINE_MAX);
            cf_send_message(caph, wbuf, MSGFLAG_ERROR);
        }
        return;
    }
    relay_census_line(caph, local, line);
}

/* Count one record in the census: `decoded` is "a native surface claimed it", `emitted` how
 * many lines it yields. enrich_failed is always 0 here: a native leg contains
 * its own failures (diag_native_decode.cpp) and has no enrichment step that
 * can raise past it. */
static void native_census_tally(native_tap_ctx_t *ctx, const diag_log_record_t *rec,
                                int decoded, uint64_t emitted) {
    local_diag_t *local = ctx->local;
    if (local->native_inv == NULL)
        return;
    int ver = (rec->payload != NULL && rec->payload_len > 0) ? rec->payload[0] : -1;
    diag_inventory_record(local->native_inv, rec->log_code, ver, decoded,
                          emitted, 0);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double now = (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
    if (diag_inventory_cadence_due(&local->native_inv_cadence, now))
        native_census_emit(ctx->caph, local, now);
}

/* Frame one eligible record and send it -- GsmtapLive.offer, natively. No
 * framer for the code counts as declined (and as no_framer, reported beside
 * it); a send failure is counted, noticed once, and never waited on. */
static void native_gsmtap_offer(native_tap_ctx_t *ctx, const diag_log_record_t *rec) {
    local_diag_t *local = ctx->local;
    diag_gsmtap_sink_t *s = &local->gsmtap_native;
    uint8_t frame[16384];
    int n = diag_native_gsmtap_frame(rec->log_code, rec->payload,
                                     rec->payload_len, frame, sizeof(frame));
    if (n <= 0) {
        s->declined++;
        if (n < 0)
            s->no_framer++;
        return;
    }
    if (diag_gsmtap_sink_send(s, frame, (size_t)n) == 0 && !s->error_reported) {
        char ebuf[STATUS_MAX];
        s->error_reported = 1;
        snprintf(ebuf, sizeof(ebuf),
                 "%s gsmtap send to %s failed (%s); decoding continues, further "
                 "send errors are only counted", local->name, s->dest,
                 strerror(s->first_errno));
        cf_send_message(ctx->caph, ebuf, MSGFLAG_ERROR);
    }
}

/* Count one record no native leg reads, of a code whose layout is known: the
 * undecoded_native state. Same cadence check as native_census_tally. */
static void native_census_undecoded(native_tap_ctx_t *ctx,
                                    const diag_log_record_t *rec) {
    local_diag_t *local = ctx->local;
    if (local->native_inv == NULL)
        return;
    int ver = (rec->payload != NULL && rec->payload_len > 0) ? rec->payload[0] : -1;
    diag_inventory_record_undecoded(local->native_inv, rec->log_code, ver);
    struct timeval tv;
    gettimeofday(&tv, NULL);
    double now = (double)tv.tv_sec + (double)tv.tv_usec / 1e6;
    if (diag_inventory_cadence_due(&local->native_inv_cadence, now))
        native_census_emit(ctx->caph, local, now);
}

/* One LOG record recovered from the live stream by diag_logstream: routed to
 * its native leg, counted, and the observations it yields rendered and sent.
 * `fallback_records` counts the records no leg reads -- the native-coverage
 * gap, by record. */
static void native_tap_cb(const diag_log_record_t *rec, void *user) {
    native_tap_ctx_t *ctx = (native_tap_ctx_t *)user;
    local_diag_t *local = ctx->local;

    local->native_tap.records++;

    /* The live GSMTAP tap: every eligible code, the ones with no framer
     * counted as declined. Ahead of every other step: a record whose later
     * decode finds nothing is still a valid PDU. */
    if (local->gsmtap_native.fd >= 0 && diag_gsmtap_eligible(rec->log_code))
        native_gsmtap_offer(ctx, rec);

    /* GNSS first. It is a separate entry point, not a fifth branch of
     * diag_native_decode, because 0x1476 produces a position rather than a
     * cell_observation -- so a record is claimed by either surface, never both,
     * and the has_*_leg pair partitions the codes.
     *
     * Position matters: Kismet geo-tags every DIAG cell from it. */
    if (diag_native_has_gps_leg(rec->log_code)) {
        local->native_tap.native_records++;
        local->native_tap.gps_records++;

        diag_native_gps_fix_t fix;
        /* Judged against, then folded into, this source's freshness
         * reference. */
        int g = diag_native_decode_gps_fix(local->native_gnss_tracker,
                                           rec->log_code, rec->payload,
                                           rec->payload_len, &fix);
        /* g < 0 cannot happen here (has_gps_leg was true). Counting an
         * unexpected -1 as declined rather than asserting keeps a future
         * header/impl skew from killing a live capture over a counter. */
        if (g > 0 && fix.valid) {
            local->native_tap.gps_fixes++;

            /* And feed the geo-tag cache. `last_gps` is the cache every
             * outgoing cell_observation is stamped from.
             *
             * The native fix carries no timestamp (diag_native_gps_fix_t is
             * valid/lat/lon/alt), so arrival time is used for the staleness
             * gate. That is right for a live stream; on a replay it makes the
             * gate measure wall-clock rather than capture time.
             *
             * That is the CACHE's age. Whether the fix was already stale
             * when it arrived -- a receiver re-serving yesterday's position
             * arrives fresh forever -- is the freshness tracker's question
             * asked in GNSS time by the decode call above. */
            /* Rounded to 1e-6 degree and 0.1 m, the precision every
             * observation's GPS sub-block carries (~0.1 m), so a stamped
             * position never claims precision the fix does not have. */
            local->last_gps.lat = round(fix.lat_deg * 1e6) / 1e6;
            local->last_gps.lon = round(fix.lon_deg * 1e6) / 1e6;
            local->last_gps.alt = (float)(round(fix.alt_m * 10.0) / 10.0);
            local->last_gps.ts = time(NULL);
            local->last_gps.valid = 1;
            /* The gps_fix status line (diag_gpsfix.c), from the gate's
             * accepted values -- the unrounded ones -- not the cache's rounded
             * copy. */
            {
                char gbuf[STATUS_MAX];
                diag_gps_fix_status(gbuf, sizeof(gbuf), fix.lat_deg,
                                    fix.lon_deg, fix.alt_m, rec->log_code);
                cf_send_message(ctx->caph, gbuf, MSGFLAG_INFO);
                local->native_tap.gps_emitted++;
            }
        } else {
            local->native_tap.gps_declined++;
            /* Split by which gate refused. gps_declined stays the total;
             * the sub-counters keep the opposite findings apart -- a benign
             * no_position (engine on, no sky) vs a no_time seed position that
             * carries a plausible-but-wrong coordinate. */
            switch (fix.decline_reason) {
            case DIAG_NATIVE_GPS_DECLINE_NO_POSITION:
                local->native_tap.gps_declined_no_position++; break;
            case DIAG_NATIVE_GPS_DECLINE_PLACEHOLDER:
                local->native_tap.gps_declined_placeholder++; break;
            case DIAG_NATIVE_GPS_DECLINE_NO_TIME:
                local->native_tap.gps_declined_no_time++; break;
            case DIAG_NATIVE_GPS_DECLINE_STALE:
                local->native_tap.gps_declined_stale++; break;
            case DIAG_NATIVE_GPS_DECLINE_ALTITUDE:
                local->native_tap.gps_declined_altitude++; break;
            case DIAG_NATIVE_GPS_DECLINE_JUMP:
                local->native_tap.gps_declined_jump++; break;
            case DIAG_NATIVE_GPS_DECLINE_UNPARSEABLE:
                local->native_tap.gps_declined_unparseable++; break;
            case DIAG_NATIVE_GPS_DECLINE_NONE:
                /* !valid with reason NONE cannot happen (the decoder sets a
                 * reason whenever valid is false), but if a future skew makes it
                 * so, the total still counts it -- it just goes unattributed. */
                break;
            }
        }
        /* An unparseable record is DROPPED in the census, not decoded. The
         * gate verdicts (no position, placeholder, no time)
         * are a parsed record that yields no fix, and stay decoded. */
        native_census_tally(ctx, rec,
            (g >= 0 && !fix.valid &&
             fix.decline_reason == DIAG_NATIVE_GPS_DECLINE_UNPARSEABLE) ? 0 : 1,
            (g > 0 && fix.valid) ? 1 : 0);
        return;
    }

    /* Learn identity before decoding this record's observations. It is not
     * a stylistic choice: a 0xB0C0 SIB1 and a measurement of that same cell
     * can arrive in the same feed, and the measurement must carry the
     * identity. Learn-after would silently drop the identity from the first
     * observation of every cell. */
    /* The 0xB197 cell-config cache, learned at the same point for the
     * same reason. -1 for every other code, so this is one compare on the hot
     * path. */
    const int cfg = diag_native_cell_config_learn(local->native_sib1_map,
                                                  rec->log_code, rec->payload,
                                                  rec->payload_len);

    if (diag_native_is_identity_source(rec->log_code)) {
        local->native_tap.identity_records++;
        if (diag_native_sib1_learn(local->native_sib1_map, rec->log_code,
                                   rec->payload, rec->payload_len) > 0)
            local->native_tap.identity_learned++;
    }

    if (!diag_native_has_leg(rec->log_code)) {
        /* 0xB821 lands here, and that is correct, not an oversight: it seeds
         * the map above but produces no cell_observation of its own, and the
         * Exported-PDU framing it does feed
         * still runs elsewhere. Counting it as a native cell record would
         * overstate native coverage. identity_records is where its
         * contribution shows up. */
        local->native_tap.fallback_records++;
        /* For the census, a record the native path consumes without a cell
         * leg is still decoded: an identity source (0xB821), the 0xB197
         * config cache (cfg >= 0), or a well-formed 0x14D8 (a malformed one
         * is dropped). Of the rest, a code whose record layout is known is
         * undecoded_native -- the native-coverage to-do list -- and only a
         * code with no known layout is unrecognized. */
        if (cfg == DIAG_NATIVE_REFUSED)
            native_census_tally(ctx, rec, 0, 0);    /* a malformed 0xB197 */
        else if (cfg >= 0 || diag_native_is_identity_source(rec->log_code))
            native_census_tally(ctx, rec, 1, 0);
        else if (rec->log_code == 0x14D8)
            native_census_tally(ctx, rec,
                native_census_accepts_0x14d8(rec->payload, rec->payload_len), 0);
        else if (diag_inventory_code_known(rec->log_code))
            native_census_undecoded(ctx, rec);
        else
            native_census_tally(ctx, rec, 0, 0);
        return;
    }
    local->native_tap.native_records++;

    diag_native_obs_t obs[DIAG_NATIVE_TAP_MAX_OBS];
    uint64_t census_emitted = 0;
    /* refused: the leg declined the record as malformed (not "decoded, found
     * nothing"). The census then counts it dropped. */
    bool refused = false;
    int n = diag_native_decode_ex(rec->log_code, rec->payload, rec->payload_len,
                                  obs, DIAG_NATIVE_TAP_MAX_OBS, &refused);
    /* A 0xB0C0 MeasurementReport's neighbour rows, appended after the
     * record's own observations. They are joined against the measConfig state
     * diag_native_sib1_learn just updated, so they need the map;
     * diag_native_decode is per-record and has none. */
    if (n >= 0 && n < DIAG_NATIVE_TAP_MAX_OBS) {
        int m = diag_native_lte_meas_neighbours(local->native_sib1_map,
                    rec->log_code, rec->payload, rec->payload_len,
                    obs + n, (size_t)(DIAG_NATIVE_TAP_MAX_OBS - n));
        if (m > 0)
            n += m;
    }
    /* n < 0 cannot happen here (has_leg was true), but treating it as "found
     * nothing" rather than asserting keeps a future header/impl skew from
     * killing a live capture over a counter. */
    if (n > 0) {
        local->native_tap.native_obs += (uint64_t)n;
        for (int i = 0; i < n; i++) {
            if (diag_native_sib1_enrich(local->native_sib1_map, &obs[i]))
                local->native_tap.enriched++;
            /* Attaching mutates the map's alias guard, so it must see every
             * LTE row in emit order, rendered or not. */
            (void)diag_native_lte_cell_config(local->native_sib1_map, &obs[i]);
            /* Enrich before render, which is why the emit lives inside
             * this loop rather than in a second pass: an unenriched
             * observation renders as valid JSON, correct in every count, and
             * missing MCC/MNC/TAC/CID. */
            char jbuf[JSON_LINE_MAX];
            /* captured_at is a wall clock. log_tick is the record's own ts64 --
             * the field that makes two renderings of the same record
             * comparable, so it must come from `rec`, never from a clock. */
            struct timeval now;
            gettimeofday(&now, NULL);
            double captured_at = (double)now.tv_sec + (double)now.tv_usec / 1e6;
            int len = diag_native_obs_to_json(&obs[i],
                                              local->modem_imei ? local->modem_imei
                                                                : DIAG_IMEI_UNKNOWN,
                                              captured_at, rec->ts64,
                                              jbuf, sizeof(jbuf));
            if (len < 0) {
                /* A decode leg exists for this code but the serializer has no
                 * branch for it. Counted separately from `declined` (which
                 * means the leg legitimately found nothing): this is a
                 * decoded observation that never reaches Kismet, i.e. exactly
                 * the silent loss this count exists to expose. */
                local->native_tap.emit_declined++;
                continue;
            }
            if ((size_t)len >= sizeof(jbuf)) {
                /* The header's contract: >= out_len means truncated and the
                 * caller must not emit it. A truncated line is invalid JSON --
                 * dropping one observation beats feeding Kismet a parse error. */
                local->native_tap.emit_truncated++;
                continue;
            }
            census_emitted++;
            if (emit_observation(ctx->caph, local, jbuf) == 0)
                local->native_tap.emitted++;
        }
    } else {
        local->native_tap.declined++;
    }
    native_census_tally(ctx, rec, refused ? 0 : 1, census_emitted);
}

/* Populate the half of the stats contract diag_stats.c does not own:
 * the config-owned strings and the census. Kept in one place
 * because there are two emit sites (the cadence tick and the final one-shot at
 * spindown) and they must agree, rather than a field being correct at one
 * site and dead at another.
 *
 * Every group is gated on having actually been reported. Omission is a
 * deliberate signal, not a shortcut: apply_diag_stats_json() leaves a missing
 * key's tracker field untouched, so an unreported source keeps its default
 * instead of publishing a zero that reads as a healthy measurement ("tee on,
 * nothing written yet"; "every code recognized"). */
static int anchor_live(const local_diag_t *local);   /* defined with the anchors */

/* The counters the CRC census reads: the native decoder's own stream, which
 * checks every frame. NULL = nothing is counting
 * (a source that never reached its read loop), which callers must report as
 * "not measured", never as zero damage. */
static const diag_logstream_stats_t *crc_stats(const local_diag_t *local) {
    if (local->native_stream != NULL)
        return &local->native_stream->stats;
    return NULL;
}

/* CRC-bad frames within one check window that mark a stream as losing
 * bytes. A healthy capture shows at most the partial first and last frames
 * (nearly all clean captures carry <= 2 bad in total), so ten in one window
 * is damage, never the edges. Applied per window rather than per drive so it
 * fires while the operator can still act. */
#define CRC_DAMAGE_ALERT_FRAMES 10

/* Compare crc_bad against the previous check and, when this window crossed the
 * floor, say so -- an ERROR on the bus, and `crc_damage_alerts` in diag_stats,
 * which the server turns into the source's standing warning. */
static void crc_damage_check(kis_capture_handler_t *caph, local_diag_t *local,
                             time_t now) {
    const diag_logstream_stats_t *st = crc_stats(local);
    if (st == NULL)
        return;
    uint64_t delta = st->crc_bad - local->crc_watch.bad_at_check;
    long span = (long)(now - local->crc_watch.since);
    local->crc_watch.bad_at_check = st->crc_bad;
    local->crc_watch.since = now;
    if (delta < CRC_DAMAGE_ALERT_FRAMES)
        return;
    local->crc_watch.alerts++;
    char m[STATUS_MAX];
    snprintf(m, sizeof(m),
             "%s DIAG stream losing bytes: %llu CRC-bad frame(s) in the last "
             "%lds (%llu of %llu checked this session). Bytes the modem sent "
             "are not reaching the capture -- the usual cause: the decoder "
             "fell behind a DIAG burst and this read loop waited on it while "
             "the tty overflowed; the kernel logs nothing. The "
             "damaged frames are counted and dropped, never decoded",
             local->name ? local->name : "celldiag",
             (unsigned long long)delta, span < 0 ? 0 : span,
             (unsigned long long)st->crc_bad,
             (unsigned long long)(st->crc_ok + st->crc_bad));
    cf_send_message(caph, m, MSGFLAG_ERROR);
}

/* The census's last word, as a JSON row the server logs to the kismetdb
 * `data` table under this source (the RawDiagDrop route). The datasources row
 * cannot carry it: it is rewritten every 30 s and its shutdown rewrite does not
 * land, so the end of a drive -- where a stress burst can sit -- would
 * be missing. Call after the stream's final flush; sent once. */
static void crc_census_row(kis_capture_handler_t *caph, local_diag_t *local) {
    const diag_logstream_stats_t *st = crc_stats(local);
    if (st == NULL || local->crc_watch.row_sent)
        return;
    /* The raw stream's session id when there is one (rawpackets=on), so a
     * reader attaches the row to the stream it describes -- the same key the
     * RawDiagDrop / RawDiagAbort rows carry. Omitted, not zeroed, without it. */
    char sess[48] = "";
    if (local->rawpkt.s != NULL)
        snprintf(sess, sizeof(sess), "\"session_id\":%llu,",
                 (unsigned long long)local->rawpkt.s->session_id);
    char rec[384];
    snprintf(rec, sizeof(rec),
             "{\"schema\":\"diag-crc-census/1\",%s\"frames\":%llu,"
             "\"crc_checked\":%llu,\"crc_ok\":%llu,\"crc_bad\":%llu,"
             "\"short\":%llu,\"oversize\":%llu,\"damage_alerts\":%llu,"
             "\"counter\":\"%s\"}",
             sess,
             (unsigned long long)st->frames_seen,
             (unsigned long long)(st->crc_ok + st->crc_bad),
             (unsigned long long)st->crc_ok,
             (unsigned long long)st->crc_bad,
             (unsigned long long)st->skipped_short,
             (unsigned long long)st->oversize_dropped,
             (unsigned long long)local->crc_watch.alerts,
             local->native_stream != NULL ? "native" : "census");
    struct timeval now;
    gettimeofday(&now, NULL);
    if (cf_send_json(caph, NULL, 0, NULL, NULL, now, DIAG_CRC_CENSUS_TYPE, rec) > 0)
        local->crc_watch.row_sent = 1;
}

static void fill_stats_extra(const local_diag_t *local, diag_stats_extra_t *sx) {
    memset(sx, 0, sizeof(*sx));
    /* Which decoder produces what Kismet receives. helper_alive says whether
     * that decoder is alive: the reader's heartbeat (local_diag_t.live). */
    sx->decode_mode = "native-only";
    /* Always known: the source either armed F3 or it did not. */
    /* Report the resolved preset name, not a boolean re-rendered as one.
     * `f3_relay ? "all" : "off"` would report every severity floor as "all"
     * and the web-UI panel would show a stream the operator did not arm. */
    sx->f3_preset = local->f3_preset ? local->f3_preset :
                    (local->f3_relay ? "all" : "off");
    if (local->rawlog_path) {
        sx->rawlog_path  = local->rawlog_path;
        sx->rawlog_bytes = local->rawlog_bytes;
        sx->rawlog_valid = 1;
        /* Read the fd, not the path. The runtime-disable arm below
         * closes the sink and leaves rawlog_path set on purpose, so the path
         * answers "where did the bytes go?" and only the fd answers "is it
         * still writing?". Publishing the second question's answer is what
         * lets the web-UI control offer a restart after a stop instead of
         * rendering a permanently-on toggle. */
        sx->rawlog_active = (local->rawlog_fd >= 0);
    }
    if (local->inventory.valid) {
        sx->inventory_distinct_codes = local->inventory.distinct;
        sx->inventory_unrecognized   = local->inventory.unrecognized;
        sx->inventory_silent         = local->inventory.silent;
        sx->inventory_valid          = 1;
        sx->inventory_undecoded_native = local->inventory.undecoded_native;
        sx->inventory_undecoded_valid  = local->inventory.undecoded_valid;
    }
    /* The decoder's counters. Gated on the decoder being armed, not on it
     * having counted anything: an armed decoder that saw zero native records
     * is a real, reportable measurement ("the mask carries nothing these legs
     * handle"), whereas an unarmed one (a disabled source) has measured
     * nothing at all, and a published zero would read as the first. */
    if (local->native_stream != NULL) {
        sx->native_total_records     = local->native_tap.records;
        sx->native_records           = local->native_tap.native_records;
        sx->native_obs               = local->native_tap.native_obs;
        sx->native_declined          = local->native_tap.declined;
        sx->native_enriched          = local->native_tap.enriched;
        sx->native_gps_fixes         = local->native_tap.gps_fixes;
        sx->native_fallback_records  = local->native_tap.fallback_records;
        sx->native_valid             = 1;
    }
    /* The CRC census, whole or not at all, and only once something is
     * counting -- an unarmed census omits the group rather than publishing a
     * zero that reads as "no damage". */
    {
        const diag_logstream_stats_t *st = crc_stats(local);
        if (st != NULL) {
            sx->crc_valid         = 1;
            sx->crc_checked       = st->crc_ok + st->crc_bad;
            sx->crc_ok            = st->crc_ok;
            sx->crc_bad           = st->crc_bad;
            sx->crc_damage_alerts = local->crc_watch.alerts;
        }
    }
    /* The stream switches, read back. rawpackets= applies to a replay
     * too (it is how a replay's raw stream reaches the kismetdb); qsh= and the
     * ClockAnchor stream exist only on a live modem. A disabled source measured
     * nothing and reports none of them. */
    if (!local->disabled) {
        sx->rawpackets_valid = 1;
        sx->rawpackets_on = local->rawpkt.on;
        if (local->rawpkt.s != NULL) {
            sx->rawpackets_slices  = local->rawpkt.s->slices;
            sx->rawpackets_dropped = local->rawpkt.s->dropped_slices;
        }
    }
    if (!local->disabled && local->replay_path == NULL) {
        sx->qsh_valid     = 1;
        sx->qsh_requested = local->qsh_on;
        sx->qsh_armed     = local->qsh_armed;
    }
    if (anchor_live(local) || local->anchor.emitted > 0) {
        sx->anchor_valid      = 1;
        sx->anchor_count      = local->anchor.emitted;
        sx->anchor_ring_dropped = local->anchor_ring_dropped;
        sx->anchor_last_epoch = (long long) local->anchor.last_wall;
    }
}

/* Render the decoder's readout for the health cadence. Returns the length
 * written, or 0 when the decoder is not armed (caller emits nothing).
 *
 * Reports native coverage as a share of records -- an observation count would
 * flatter the native side, since the natively decoded codes are the multi-cell
 * ones. no-leg= is the records no leg reads. */
static int native_tap_format(const local_diag_t *local, char *out, size_t outsz) {
    if (local->native_stream == NULL)
        return 0;

    uint64_t recs = local->native_tap.records;
    unsigned pct = recs ? (unsigned)((local->native_tap.native_records * 100) / recs) : 0;

    int off = snprintf(out, outsz,
                    "%s nativedecode=only | records=%llu native=%llu (%u%%) "
                    "obs=%llu declined=%llu enriched=%llu | "
                    "sib1=%llu keys=%llu (%zu live) | "
                    "gnss=%llu fixes=%llu nofix=%llu "
                    "(nopos=%llu placeholder=%llu notime=%llu stale=%llu "
                    "altitude=%llu jump=%llu unparseable=%llu) unjudged=%llu | "
                    "no-leg=%llu | "
                    "frames=%llu crc_bad=%llu wrapped=%llu",
                    local->name ? local->name : "celldiag",
                    (unsigned long long)recs,
                    (unsigned long long)local->native_tap.native_records, pct,
                    (unsigned long long)local->native_tap.native_obs,
                    (unsigned long long)local->native_tap.declined,
                    /* `enriched` is reported next to obs on purpose: the
                     * two together are the only way to read the field-loss risk
                     * off this line. obs alone is identical whether enrichment
                     * runs or not, so an operator watching obs sees a healthy
                     * stream while every MCC/MNC/TAC/CID quietly vanishes. */
                    (unsigned long long)local->native_tap.enriched,
                    /* sib1= records seen, keys= new keys they added, (n live) =
                     * what the cache holds now. keys and live differ only if a
                     * future change stops being first-write-wins; printing both
                     * makes that visible rather than assumed. */
                    (unsigned long long)local->native_tap.identity_records,
                    (unsigned long long)local->native_tap.identity_learned,
                    diag_native_sib1_map_size(local->native_sib1_map),
                    /* Its own field group, in its own units -- see the counter
                     * struct. `nofix` separated from `fixes` because they are
                     * different findings: a GNSS record that decodes but has no
                     * usable position is not the same as a gnss= that stays 0,
                     * which is the mask not carrying GNSS at all.
                     *
                     * nofix is not "the modem has no sky view": on an EG25-G
                     * most declined records are a seed position with no time
                     * solution. See the counter's own declaration for what
                     * this number does and does not mean. */
                    (unsigned long long)local->native_tap.gps_records,
                    (unsigned long long)local->native_tap.gps_fixes,
                    (unsigned long long)local->native_tap.gps_declined,
                    (unsigned long long)local->native_tap.gps_declined_no_position,
                    (unsigned long long)local->native_tap.gps_declined_placeholder,
                    (unsigned long long)local->native_tap.gps_declined_no_time,
                    /* stale= is its own finding: the receiver HAS a time
                     * solution and a real position, from too long ago.
                     * unjudged= is the gate's warm-up hole -- the records
                     * accepted before any reference existed -- printed so a
                     * stale=0 can be read against how long the gate was blind. */
                    (unsigned long long)local->native_tap.gps_declined_stale,
                    /* altitude= / jump= are the plausibility arms: a fix
                     * the receiver reported at a place it
                     * cannot be. */
                    (unsigned long long)local->native_tap.gps_declined_altitude,
                    (unsigned long long)local->native_tap.gps_declined_jump,
                    (unsigned long long)local->native_tap.gps_declined_unparseable,
                    (unsigned long long)diag_native_gnss_tracker_unjudged(
                        local->native_gnss_tracker),
                    (unsigned long long)local->native_tap.fallback_records,
                    (unsigned long long)local->native_stream->stats.frames_seen,
                    (unsigned long long)local->native_stream->stats.crc_bad,
                    (unsigned long long)local->native_stream->stats.log_records_from_wrapper);

    if (off > 0 && (size_t)off < outsz)
        off += snprintf(out + off, outsz - (size_t)off,
                        " | emitted=%llu emit_declined=%llu emit_truncated=%llu "
                        "gps_emitted=%llu",
                        (unsigned long long)local->native_tap.emitted,
                        (unsigned long long)local->native_tap.emit_declined,
                        (unsigned long long)local->native_tap.emit_truncated,
                        (unsigned long long)local->native_tap.gps_emitted);

    return off;
}

/* -----------------------------------------------------------------------
 * Runtime option setter -- celldiag's opt-in to Kismet's generic
 * `POST /datasource/by-uuid/:uuid/set_channel` path
 * ----------------------------------------------------------------------- */

/* Why this rides the channel callbacks at all: `set_channel` is the only
 * generic runtime setter Kismet ships for a datasource. The HTTP endpoint
 * (datasourcetracker.cc), the server dispatch (kis_datasource.cc), the
 * CONFIGURE frame (capture_framework.c) and these two capture-side hooks
 * already exist; a source with set_tune_capable(false) makes the server
 * short-circuit before any of it runs. So every knob multiplexes through one
 * opaque string. That is Kismet's shape, not a design we chose.
 *
 * set_tune_capable(true) is a design call, not a mechanical flip -- see the
 * long note beside it in datasource_cell_diag.h. It is what the generic
 * datasource UI keys on to render channel affordances, and celldiag has no
 * channels. Owned there, deliberately, rather than left implicit here.
 *
 * One visible side effect worth stating: on success the framework stores the
 * knob string as the source's `channel` (capture_framework.c, `caph->channel =
 * strdup(channel)`), so the generic UI's channel column will read
 * `rawlog=/path.hdlc`. That is informative rather than wrong -- it is the last
 * runtime setting applied -- but it is not something this file can suppress.
 */

/* Translate: parse the knob into a heap struct the control callback applies.
 *
 * Never returns NULL for a bad input. A NULL would reach chancontrol_cb with no
 * way to say what was wrong, and the framework would report a bare failure --
 * effectively a silent no-op. The
 * error travels in the struct and is reported by the control callback, which is
 * the only one of the two that gets a `msg` buffer.
 *
 * The framework free()s this with plain free() when no chanfree_cb is
 * registered, which is correct here: one malloc, no inner pointers. */
static void *celldiag_chantranslate(kis_capture_handler_t *caph,
                                    const char *chanstr) {
    diag_optset_t *o = (diag_optset_t *) malloc(sizeof(diag_optset_t));
    (void) caph;
    if (o == NULL)
        return NULL;
    diag_optset_parse(chanstr, o);
    return o;
}

/* Apply. Writes `msg` on every path; the framework transmits it on the
 * CONFIGRESP when seqno != 0.
 *
 * The return code cannot say "refused", and -1 is not an option. The
 * framework's contract (capture_framework.h) gives three returns -- -1 fatal,
 * 0 "cannot tune this channel", 1+ success -- and CONFIGRESP is sent as
 * `cbret < 0 ? 0 : 1`. So the only return that reports failure on the wire is
 * also the one that tears the source down: capture_framework.c's lws receive
 * path sets `spindown` on any negative return. Reporting "you typed rawlog
 * wrong" through the status code would end a running wardrive over a typo,
 * and the source would shut down before the response flushed.
 *
 * So refusals return 0 and the reason travels in `msg` plus a MSGFLAG_ERROR
 * bus line. 0 over 1 because the framework skips `caph->channel = strdup(...)`
 * on non-positive returns, so a rejected knob does not become the source's
 * reported "channel". Consequence: a client that
 * reads only the CONFIGRESP success bit sees 1 for a refusal. The message is
 * the channel that carries the truth, which is why every test here asserts on
 * the text. -1 is reserved for conditions that really are fatal. */
static int celldiag_chancontrol(kis_capture_handler_t *caph, uint32_t seqno,
                                void *privchan, char *msg) {
    local_diag_t *local = (local_diag_t *) caph->userdata;
    diag_optset_t *o = (diag_optset_t *) privchan;
    char resolved[PATH_MAX];
    int fd;

    (void) seqno;

    if (o == NULL) {
        snprintf(msg, STATUS_MAX, "celldiag: out of memory parsing the setting");
        return -1;
    }

    /* BAD_SYNTAX / UNKNOWN_KEY / OPEN_TIME_ONLY / BAD_VALUE all land here with
     * a message the parse already composed. Reporting the parser's own words
     * keeps the three outcomes distinguishable at the operator, which is the
     * entire point of the classification. */
    if (o->status != DIAG_OPTSET_OK) {
        snprintf(msg, STATUS_MAX, "celldiag: %s", o->err);
        cf_send_message(caph, msg, MSGFLAG_ERROR);
        return 0;
    }

    if (o->key != DIAG_OPTSET_KEY_RAWLOG) {
        /* Unreachable while rawlog is the only runtime key -- and it is here so
         * that adding a key to OPTSET_KEYS with no apply path fails loudly
         * instead of returning success and doing nothing. */
        snprintf(msg, STATUS_MAX,
                 "celldiag: '%s' is runtime-settable but has no apply path in "
                 "this build -- this is a bug, please report it", o->key_str);
        cf_send_message(caph, msg, MSGFLAG_ERROR);
        return 0;
    }

    if (local->disabled) {
        snprintf(msg, STATUS_MAX,
                 "celldiag: source is enabled=false; nothing is being captured, "
                 "so there is no tee to change");
        cf_send_message(caph, msg, MSGFLAG_ERROR);
        return 0;
    }

    if (o->rawlog_disable) {
        uint64_t wrote;
        pthread_mutex_lock(&local->rawlog_lock);
        wrote = local->rawlog_bytes;
        if (local->rawlog_fd >= 0) {
            close(local->rawlog_fd);
            local->rawlog_fd = -1;
        }
        local->rawlog_stopped = 1;
        /* rawlog_path is deliberately left set. The stats object reports
         * `rawlog_path` + `rawlog_bytes` from it, and clearing it would make a
         * stopped tee indistinguishable from one that was never configured --
         * the operator would lose the answer to "where did the bytes I already
         * captured go?". The tee being closed is what rawlog_bytes ceasing to
         * advance reports. */
        pthread_mutex_unlock(&local->rawlog_lock);
        snprintf(msg, STATUS_MAX,
                 "celldiag: raw DIAG tee stopped after %llu byte(s) to %s",
                 (unsigned long long) wrote,
                 local->rawlog_path ? local->rawlog_path : "(no file)");
        cf_send_message(caph, msg, MSGFLAG_INFO);
        return 0;   /* applied -- and still not a channel: see below */
    }

    /* Resolve with the same function and the same %-token vocabulary the
     * open-time path uses, so a runtime path cannot expand differently from an
     * identical spec given at open. */
    if (diag_rawlog_resolve(o->value, local->modem_imei ? local->modem_imei :
                            DIAG_IMEI_UNKNOWN, local->modem_model, time(NULL),
                            resolved, sizeof(resolved)) != 0) {
        snprintf(msg, STATUS_MAX,
                 "celldiag: rawlog path from '%s' is too long to resolve",
                 o->value);
        cf_send_message(caph, msg, MSGFLAG_ERROR);
        return 0;
    }

    /* Opened before the old sink is closed. If the new path is unwritable, an
     * operator redirecting a live tee keeps the one they had rather than losing
     * capture to a typo -- the failure mode of a close-then-open. */
    fd = open(resolved, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        snprintf(msg, STATUS_MAX,
                 "celldiag: cannot open rawlog file %s: %s (the previous tee, "
                 "if any, is untouched)", resolved, strerror(errno));
        cf_send_message(caph, msg, MSGFLAG_ERROR);
        return 0;
    }

    pthread_mutex_lock(&local->rawlog_lock);
    if (local->rawlog_fd >= 0)
        close(local->rawlog_fd);
    local->rawlog_fd = fd;
    local->rawlog_stopped = 0;
    free(local->rawlog_path);
    local->rawlog_path = strdup(resolved);
    /* rawlog_bytes is not reset. It is a per-source lifetime total, and the
     * only assertion that can prove a runtime tee actually works is "the
     * counter moved" -- zeroing it here would make a working redirect and a
     * dead one look the same to the test and to the web UI alike. */
    pthread_mutex_unlock(&local->rawlog_lock);

    snprintf(msg, STATUS_MAX, "celldiag: raw DIAG tee now writing to %s", resolved);
    cf_send_message(caph, msg, MSGFLAG_INFO);
    /* 0, not 1 -- the convention cellat also follows. A return > 0 records
     * the string as the source's channel (`caph->channel = strdup(...)`), so
     * the server would show "rawlog=/x" as kismet.datasource.channel and
     * replay it after an error re-open -- quietly re-arming a tee the operator
     * may have stopped since, while forgetting any other setting. A runtime
     * setting is a one-time change to a running process; "channel" is reserved
     * for band/RAT locks. The cost is the one cellat pays: CONFIGRESP's
     * success bit is 1 for applied and refused alike, so the truth travels in
     * `msg`, the bus and the stats line. */
    return 0;
}

/* -----------------------------------------------------------------------
 * The raw DIAG stream as kismetdb packets
 *
 * The contract (DLT, slice header, why order lives in the header): see
 * diag_rawpkt.h. This block is delivery: each read's bytes are sliced and sent
 * as DLT 147 packets via cf_send_data, which the server logs into the kismetdb
 * `packets` table like any link frame (kis_databaselogfile log_packet keys on
 * the LINKFRAME alone, not on a PHY).
 * ----------------------------------------------------------------------- */

/* A replay retries a full ring every RAWPKT_REPLAY_RETRY_NS for at most
 * RAWPKT_REPLAY_MAX_RETRIES tries (~30 s) before counting the slice dropped,
 * so a server that has stopped reading cannot pin the capture thread forever.
 *
 * A sleep-retry and not cf_handler_wait_ringbuffer(): that waits on the
 * framework's flush condvar without holding its mutex, so a flush landing
 * between our failed send and the wait is missed and the thread sits until
 * some unrelated write (a PONG) broadcasts again. A bounded poll cannot lose a
 * wakeup. */
#define RAWPKT_REPLAY_RETRY_NS   2000000L
#define RAWPKT_REPLAY_MAX_RETRIES 15000
/* A live capture's teardown waits ~2 s at most for the residual and END. */
#define RAWPKT_FINISH_MAX_RETRIES 1000

typedef struct {
    kis_capture_handler_t *caph;
    local_diag_t *local;
    struct timeval tv;       /* host receipt time of the read being sliced */
    int finishing;           /* teardown: the port is no longer being read */
} rawpkt_ctx_t;

/* The loss policy differs by source on purpose -- do not unify it.
 *
 * Live: a full ring drops the slice. It is counted, and the hole is exact and
 * visible in the next slice's offset. Waiting instead would stop this thread
 * reading the DIAG port; the tty buffer then overflows and the bytes are lost
 * from rawlog= and from decoding as well. The in-db copy is a tee, and a tee
 * must never cost the primary product anything. (The decoded observations are
 * not at risk from the raw stream filling the ring: their path waits for room
 * rather than dropping.)
 *
 * Replay: a file can be paused, so a full ring waits and the in-db copy stays
 * lossless. That is what makes replaying an old .hdlc into a .kismet a
 * faithful conversion rather than a best-effort one.
 *
 * Finishing: at teardown nothing is reading the port any more, so the
 * live reason to drop is gone. The residual and the END slice wait too, briefly
 * on a live source -- END is what lets a reader tell a whole stream from one
 * that lost its tail, so losing it to a momentarily full ring is a waste. */
static int rawpkt_emit(void *vctx, const uint8_t *pkt, size_t len) {
    rawpkt_ctx_t *c = (rawpkt_ctx_t *)vctx;
    int budget = c->local->replay_path != NULL ? RAWPKT_REPLAY_MAX_RETRIES :
                 c->finishing ? RAWPKT_FINISH_MAX_RETRIES : 0;
    /* cf_send_data's buffer is non-const but only read: it copies into the ring. */
    int r = cf_send_data(c->caph, NULL, 0, NULL, NULL, c->tv, DIAG_RAWPKT_DLT,
                         (uint32_t)len, (uint32_t)len, (uint8_t *)pkt);
    for (int i = 0; r == 0 && i < budget; i++) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = RAWPKT_REPLAY_RETRY_NS };
        c->local->rawpkt.ring_waits++;
        nanosleep(&ts, NULL);
        r = cf_send_data(c->caph, NULL, 0, NULL, NULL, c->tv, DIAG_RAWPKT_DLT,
                         (uint32_t)len, (uint32_t)len, (uint8_t *)pkt);
    }
    return r > 0;
}

/* Say once that the stream is flowing, and once -- loudly -- that it has a
 * hole. Per-drop reporting would bury the bus under exactly the load that
 * causes drops; the end-of-stream summary carries the totals. */
static void rawpkt_report(kis_capture_handler_t *caph, local_diag_t *local) {
    diag_rawpkt_t *s = local->rawpkt.s;
    char m[STATUS_MAX];

    if (!local->rawpkt.announced && s->slices > 0) {
        local->rawpkt.announced = 1;
        snprintf(m, sizeof(m),
                 "%s raw DIAG stream -> Kismet packets: DLT 147 (LINKTYPE_USER0) "
                 "offset-stamped slices, session %llu, logged to the kismetdb "
                 "`packets` table (rawpackets=on)",
                 local->name ? local->name : "celldiag",
                 (unsigned long long)s->session_id);
        cf_send_message(caph, m, MSGFLAG_INFO);
    }
    /* Marked sent only once the send succeeds. This row and the notice below
     * go out at the one moment the ring is full: a slice did not fit, and a
     * few hundred bytes usually still do -- but not when the space left happens
     * to be smaller, and a one-shot attempt would then lose the only record of
     * a holed stream. So both are retried on every later read until they land.
     *
     * The RawDiagDrop row first, the notice only after it: the row is
     * the machine-readable witness a reader attributes to this source and
     * session (the `messages` table records no datasource). It matters most
     * when the drop is the stream's tail, which no offset gap can show. Sent
     * first, anyone who has seen the notice has the row too. */
    if (!local->rawpkt.drop_row_sent && s->dropped_slices > 0) {
        char rec[256];
        struct timeval now;
        gettimeofday(&now, NULL);
        if (diag_rawpkt_drop_json(s, rec, sizeof(rec)) == 0 &&
            cf_send_json(caph, NULL, 0, NULL, NULL, now,
                         DIAG_RAWPKT_DROP_TYPE, rec) > 0)
            local->rawpkt.drop_row_sent = 1;
    }
    if (local->rawpkt.drop_row_sent && !local->rawpkt.drop_reported) {
        snprintf(m, sizeof(m),
                 "%s raw DIAG slice DROPPED: Kismet's capture ring was full, so the "
                 "kismetdb copy of the stream now has a gap (first at stream offset "
                 "%llu; %llu slice(s) so far; recorded as a RawDiagDrop row, which "
                 "kismetdb_to_hdlc reports). rawlog= and decoding are unaffected; "
                 "further drops are counted, not reported",
                 local->name ? local->name : "celldiag",
                 (unsigned long long)s->first_drop_offset,
                 (unsigned long long)s->dropped_slices);
        if (cf_send_message(caph, m, MSGFLAG_ERROR) > 0)
            local->rawpkt.drop_reported = 1;
    }
}

static void rawpkt_feed(kis_capture_handler_t *caph, local_diag_t *local,
                        const struct timeval *tv, const uint8_t *buf, size_t len) {
    rawpkt_ctx_t ctx = { .caph = caph, .local = local, .tv = *tv };
    diag_rawpkt_feed(local->rawpkt.s, buf, len, rawpkt_emit, &ctx);
    rawpkt_report(caph, local);
}

/* End of stream (the paths that reach `done:` -- replay EOF, a dead port,
 * and a graceful close): send the partial frame left over, flagged
 * FRAGMENT, then the END slice, then the totals. A Kismet stop reaches
 * this point through the graceful close; only the plain close -- a
 * server or helper without it, or a close that ran out of grace -- still cancels
 * the capture thread first, so there the stream ends at the last whole slice
 * with no END, and its end is unconfirmed. */
static void rawpkt_finish(kis_capture_handler_t *caph, local_diag_t *local) {
    diag_rawpkt_t *s = local->rawpkt.s;
    char m[STATUS_MAX];
    rawpkt_ctx_t ctx = { .caph = caph, .local = local, .finishing = 1 };

    if (s == NULL)
        return;
    gettimeofday(&ctx.tv, NULL);
    diag_rawpkt_end(s, rawpkt_emit, &ctx);
    rawpkt_report(caph, local);
    snprintf(m, sizeof(m),
             "%s raw DIAG into the packets table (DLT 147): %llu slice(s), %llu B "
             "delivered; %llu slice(s) / %llu B dropped; %llu fragment(s); "
             "%llu ring-full wait(s); END at offset %llu %s",
             local->name ? local->name : "celldiag",
             (unsigned long long)s->slices, (unsigned long long)s->bytes,
             (unsigned long long)s->dropped_slices,
             (unsigned long long)s->dropped_bytes,
             (unsigned long long)s->fragments,
             (unsigned long long)local->rawpkt.ring_waits,
             (unsigned long long)s->offset,
             s->end_sent > 0 ? "delivered" : "DROPPED");
    cf_send_message(caph, m, (s->dropped_slices || s->end_sent < 0) ?
                                 MSGFLAG_ERROR : MSGFLAG_INFO);
    free(s);
    local->rawpkt.s = NULL;
}

/* The single DIAG-read -> decode seam. Tees `buf` to the rawlog sink (if
 * enabled) and the raw-packet stream, then decodes it. Teeing first means a
 * decode that fails mid-stream still leaves every byte we read on disk. A
 * rawlog write error is non-fatal to decoding: warn once, drop the sink, keep
 * decoding. */
static void feed_bytes(kis_capture_handler_t *caph, local_diag_t *local,
                      const uint8_t *buf, size_t len) {
    /* Every byte the decoder sees passed through here (live reads and the
     * handshake-buffered flush), so this is the one place to count bytes read
     * from the source for the health readout. */
    diag_stats_on_read(&local->stats, len, time(NULL));

    /* The raw packets' timestamp is the host receipt time of this read, so it
     * is taken before the rawlog write below, whose disk latency is not. */
    struct timeval rx_tv = { 0, 0 };
    if (local->rawpkt.s != NULL)
        gettimeofday(&rx_tv, NULL);

    /* Held across the write, not merely across the fd read: the runtime setter
     * may close this sink from the command thread, and a close between
     * the test and the write() would send capture bytes into whatever the
     * kernel handed that descriptor number to next. The write is bounded, so
     * so is the setter's wait. */
    pthread_mutex_lock(&local->rawlog_lock);
    if (local->rawlog_fd >= 0) {
        if (diag_rawlog_write(local->rawlog_fd, buf, len) != 0) {
            char e[ERRBUF_MAX];
            snprintf(e, ERRBUF_MAX,
                     "%s rawlog write failed (%s); stopping tee, decode continues",
                     local->name ? local->name : "celldiag", strerror(errno));
            close(local->rawlog_fd);
            local->rawlog_fd = -1;
            pthread_mutex_unlock(&local->rawlog_lock);
            /* Off-lock: cf_send_message takes the framework's own locks, and
             * nesting ours inside those in one place and not the other is how a
             * lock-order inversion gets introduced. The state change is already
             * committed above; this is only the report. */
            cf_send_message(caph, e, MSGFLAG_ERROR);
            pthread_mutex_lock(&local->rawlog_lock);
        } else {
            /* Counted only on a successful write, so the figure
             * the web UI shows is bytes on disk, not bytes offered to a sink
             * that has since gone away. */
            local->rawlog_bytes += (uint64_t)len;
        }
    }
    pthread_mutex_unlock(&local->rawlog_lock);

    /* The same bytes, into Kismet as DLT 147 packets. After the file
     * tee (which stays the authoritative copy -- it cannot drop) and before the
     * decode, for the tee's reason: a decode problem must not take these bytes
     * with it. Never fails the seam; a lost slice is a counted gap. */
    if (local->rawpkt.s != NULL)
        rawpkt_feed(caph, local, &rx_tv, buf, len);

    /* The decode. */
    if (local->native_stream != NULL) {
        native_tap_ctx_t ctx = { .caph = caph, .local = local };
        diag_logstream_feed(local->native_stream, buf, len, native_tap_cb, &ctx);
    }
}

/* -----------------------------------------------------------------------
 * Host<->modem-ts64 clock anchor (DIAG instance)
 *
 * Record format, midpoint pairing and sidecar: diag_clockanchor.h. This block
 * is the scheduling: when a DIAG_TS_F request goes out, how its reply is
 * recognised in the live stream, and where the paired record is delivered.
 * ----------------------------------------------------------------------- */

/* A reply normally lands in ~3.5 ms. Two seconds covers a reply queued
 * behind a boot-time log flood; past that the modem is treated as not having
 * answered, and after ANCHOR_MAX_TIMEOUTS in a row it is not asked again this
 * capture (a part without the command may drop it silently rather than send
 * BAD_CMD, and asking forever would be a request every 30 s into the void). */
#define ANCHOR_REPLY_TIMEOUT_NS 2000000000ULL
#define ANCHOR_END_TIMEOUT_NS   1000000000ULL
/* Graceful-close grace, advertised to the server: see main(). */
#define CELLDIAG_CLOSE_GRACE_MS 5000
#define ANCHOR_MAX_TIMEOUTS     3

static uint64_t anchor_mono_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* Is there a modem to ask? Not in replay (a file has no clock), not when
 * enabled=false opened nothing, and not after the modem refused. */
static int anchor_live(const local_diag_t *local) {
    return local->replay_path == NULL && !local->disabled &&
           local->diag_fd >= 0 && !local->anchor.off;
}

/* Write one DIAG_TS_F request and arm the reply scanner. The host clock is read
 * immediately before the write; the reply's read time closes the window. */
static void anchor_request(local_diag_t *local, const char *edge,
                           uint64_t timeout_ns) {
    uint8_t frame[8];
    size_t n = diag_clockanchor_build_request(frame, sizeof(frame));

    if (n == 0 || local->anchor.pending || !anchor_live(local))
        return;
    diag_tsf_scan_reset(&local->anchor.scan);
    gettimeofday(&local->anchor.send_tv, NULL);
    local->anchor.send_mono_ns = anchor_mono_ns();
    /* A 4-byte write refused by the DIAG fd means the port is going away; the
     * read side reports that loudly, so this counts it and stays quiet. */
    if (write_all(local->diag_fd, frame, n) != 0) {
        local->anchor.timed_out++;
        return;
    }
    local->anchor.pending = 1;
    local->anchor.edge = edge;
    local->anchor.deadline_mono_ns = local->anchor.send_mono_ns + timeout_ns;
}

/* Append a finished record to <rawlog>.clock_anchor.jsonl while the tee is
 * open. The sidecar follows the current rawlog path, so a runtime rawlog=
 * redirect moves it along with the .hdlc it describes. `try_lock` is
 * for main()'s END path, where a cancelled capture thread may have died holding
 * the lock (see anchor_end): by then no other thread touches these fields. */
static void anchor_sidecar_write(local_diag_t *local, const char *rec,
                                 int try_lock) {
    char path[DIAG_OPTSET_VALUE_MAX + 64];
    int locked;

    if (try_lock) {
        locked = (pthread_mutex_trylock(&local->rawlog_lock) == 0);
    } else {
        pthread_mutex_lock(&local->rawlog_lock);
        locked = 1;
    }
    if (local->rawlog_fd >= 0 && local->rawlog_path != NULL &&
        diag_clockanchor_sidecar_path(local->rawlog_path, path, sizeof(path)) == 0 &&
        diag_clockanchor_append(path, rec, strlen(rec)) != 0)
        local->anchor.sidecar_failed++;
    if (locked)
        pthread_mutex_unlock(&local->rawlog_lock);
}

/* Pair a reply with the host clock and deliver it. `caph` NULL means the END
 * path in main(): the Kismet pipe is closed by then, so the sidecar is the only
 * place the record can go. */
static void anchor_complete(kis_capture_handler_t *caph, local_diag_t *local,
                            uint64_t ts64, uint64_t recv_mono_ns) {
    struct timeval mid_tv;
    uint64_t mid_mono = 0;
    char host_utc[40];
    char rec[768];
    uint64_t rtt = recv_mono_ns > local->anchor.send_mono_ns ?
                   recv_mono_ns - local->anchor.send_mono_ns : 0;

    local->anchor.pending = 0;
    local->anchor.consecutive_timeouts = 0;
    diag_clockanchor_midpoint(&local->anchor.send_tv, local->anchor.send_mono_ns,
                              recv_mono_ns, &mid_tv, &mid_mono);
    diag_clockanchor_iso8601(host_utc, sizeof(host_utc), &mid_tv);
    if (diag_clockanchor_format_record(
            rec, sizeof(rec),
            local->source_uuid ? local->source_uuid :
                (local->name ? local->name : ""),
            local->anchor.seq, local->anchor.edge, host_utc, mid_mono, ts64,
            rtt) != 0)
        return;
    local->anchor.seq++;
    local->anchor.emitted++;
    local->anchor.last_wall = mid_tv.tv_sec;

    /* The sidecar first, then the relay. Relaying first lets a reader that
     * stops on the relayed row (a test harness, or a server closing the
     * source) close the pipe while this thread sits between the two calls;
     * the thread is then cancelled and the row reaches Kismet but never the
     * file, leaving a seq gap in the sidecar. Written first, any row a
     * consumer has seen is already on disk. */
    anchor_sidecar_write(local, rec, caph == NULL);

    if (caph != NULL) {
        /* Sent from the read loop, so under ring_send_json's policy: a
         * live source drops the row on a full ring rather than stop reading
         * the port. The sidecar above already has it, so the skew
         * measurement survives on disk; the drop is counted. */
        if (ring_send_json(caph, local, NULL, mid_tv, "ClockAnchor", rec) == 0) {
            local->anchor_ring_dropped++;
            report_ring_drop(caph, local, "ClockAnchor row");
        }
    }

    if (caph != NULL && local->anchor.emitted == 1) {
        char m[STATUS_MAX];
        snprintf(m, sizeof(m),
                 "%s clock anchor: modem ts64 paired with host UTC via DIAG_TS_F "
                 "(rtt %llu us); ClockAnchor rows %s",
                 local->name ? local->name : "celldiag",
                 (unsigned long long)(rtt / 1000ULL),
                 local->anchor.interval_ms ? "at start + every clock_anchor_sec"
                                           : "at start only (clock_anchor_sec=0)");
        cf_send_message(caph, m, MSGFLAG_INFO);
    }
}

/* Offer bytes just read from the DIAG port to the reply scanner. */
static void anchor_on_bytes(kis_capture_handler_t *caph, local_diag_t *local,
                            const uint8_t *buf, size_t len,
                            uint64_t recv_mono_ns) {
    uint64_t ts64 = 0;

    if (!local->anchor.pending)
        return;
    switch (diag_tsf_scan_feed(&local->anchor.scan, buf, len, &ts64)) {
        case DIAG_TSF_RESPONSE:
            anchor_complete(caph, local, ts64, recv_mono_ns);
            break;
        case DIAG_TSF_REJECTED:
            local->anchor.pending = 0;
            local->anchor.off = 1;
            if (caph != NULL) {
                char m[STATUS_MAX];
                snprintf(m, sizeof(m),
                         "%s modem rejected DIAG_TS_F (0x1D); no host<->modem "
                         "clock anchors this capture, so its frames are "
                         "wall-clockable only through a GNSS 0x1476 fix",
                         local->name ? local->name : "celldiag");
                cf_send_message(caph, m, MSGFLAG_ERROR);
            }
            break;
        case DIAG_TSF_NONE:
            break;
    }
}

/* Once per capture-loop pass: expire an unanswered request, then issue the
 * periodic one when it is due. */
static void anchor_tick(kis_capture_handler_t *caph, local_diag_t *local) {
    uint64_t now = anchor_mono_ns();

    if (local->anchor.pending && now >= local->anchor.deadline_mono_ns) {
        local->anchor.pending = 0;
        local->anchor.timed_out++;
        if (++local->anchor.consecutive_timeouts >= ANCHOR_MAX_TIMEOUTS) {
            char m[STATUS_MAX];
            local->anchor.off = 1;
            snprintf(m, sizeof(m),
                     "%s %u consecutive DIAG_TS_F requests went unanswered; "
                     "clock anchoring stopped for this capture. Without "
                     "it, frames are wall-clockable only through a GNSS 0x1476 fix",
                     local->name ? local->name : "celldiag",
                     local->anchor.consecutive_timeouts);
            cf_send_message(caph, m, MSGFLAG_ERROR);
        }
    }
    if (!local->anchor.pending && local->anchor.started &&
        local->anchor.interval_ms > 0 &&
        now / 1000000ULL - local->anchor.last_ms >= local->anchor.interval_ms) {
        local->anchor.last_ms = now / 1000000ULL;
        anchor_request(local, "periodic", ANCHOR_REPLY_TIMEOUT_NS);
    }
}

/* Synchronously read the DIAG port until the outstanding request is answered or
 * its deadline passes -- the END path only, where there is no capture loop left
 * to do it. Every byte read is still teed to rawlog=, so the .hdlc stays a
 * complete record of what the port produced; nothing is fed to the decoder,
 * which has already stopped. */
static void anchor_drain_sync(local_diag_t *local) {
    static uint8_t rbuf[65536];

    while (local->anchor.pending) {
        uint64_t now = anchor_mono_ns();
        if (now >= local->anchor.deadline_mono_ns) {
            local->anchor.pending = 0;
            local->anchor.timed_out++;
            return;
        }
        struct pollfd pf = { .fd = local->diag_fd, .events = POLLIN, .revents = 0 };
        int pr = poll(&pf, 1,
                      (int)((local->anchor.deadline_mono_ns - now) / 1000000ULL) + 1);
        if (pr < 0 && errno == EINTR)
            continue;
        if (pr <= 0)
            continue;              /* the deadline check above ends it */
        if (!(pf.revents & POLLIN)) {
            local->anchor.pending = 0;
            return;                /* HUP/ERR: the modem is gone */
        }
        ssize_t n = read(local->diag_fd, rbuf, sizeof(rbuf));
        uint64_t recv = anchor_mono_ns();
        if (n < 0 && (errno == EINTR || errno == EAGAIN))
            continue;
        if (n < 0) {
            local->anchor.pending = 0;
            return;
        }
        if (n == 0)
            continue;              /* VTIME idle tick */
        int locked = (pthread_mutex_trylock(&local->rawlog_lock) == 0);
        if (local->rawlog_fd >= 0 &&
            diag_rawlog_write(local->rawlog_fd, rbuf, (size_t)n) == 0)
            local->rawlog_bytes += (uint64_t)n;
        if (locked)
            pthread_mutex_unlock(&local->rawlog_lock);
        anchor_on_bytes(NULL, local, rbuf, (size_t)n, recv);
    }
}

/* The END anchor (the clock-anchor contract makes it mandatory at capture END).
 *
 * It cannot live in capture_thread's teardown, though that is where it reads
 * naturally -- and where cellat's END anchor sits. A plain (non-graceful)
 * close never reaches that code: Kismet closes the IPC pipe, the
 * framework's loop exits, main() calls cf_handler_shutdown(), and that
 * pthread_cancel()s the capture thread, which capture_framework.c runs with
 * PTHREAD_CANCEL_ASYNCHRONOUS. The thread dies wherever it is -- normally
 * parked in poll() -- and nothing after its read loop runs.
 *
 * So the END anchor runs here, in main(), after the cancel: the DIAG fd is
 * still open (the thread's own close never ran) and is now ours alone. It can
 * only be written to the sidecar -- the pipe it would have travelled to the
 * kismetdb is exactly what closed. The kismetdb therefore holds START +
 * periodic rows (>= 2 for any drive longer than one clock_anchor_sec=), and
 * the sidecar additionally holds the END pair.
 *
 * Ordering: wait for capture_exited (the cleanup handler's mark) before touching
 * the fd, so the cancelled reader is gone; let a request that was in flight at
 * cancel time land under its own edge, so its reply is not paired with the END
 * send; then ask once more. Bounded: at most ~0.5 s + 2 reply timeouts. */
static void anchor_end(local_diag_t *local) {
    if (!local->anchor.started || local->anchor.end_requested)
        return;
    for (int i = 0; i < 50 &&
             !__atomic_load_n(&local->capture_exited, __ATOMIC_ACQUIRE); i++)
        usleep(10000);
    if (!__atomic_load_n(&local->capture_exited, __ATOMIC_ACQUIRE) ||
        !anchor_live(local))
        return;
    anchor_drain_sync(local);
    anchor_request(local, "end", ANCHOR_END_TIMEOUT_NS);
    anchor_drain_sync(local);
}

/* The END anchor on a graceful close -- the path anchor_end's comment above
 * says a plain close cannot take. The server's CLOSEREQ leaves the
 * pipe open and waits for us to exit, so END is asked from inside the capture
 * loop: its reply is read, teed, sliced and scanned by the ordinary read path
 * and lands as an in-band ClockAnchor row as well as a sidecar line.
 *
 * One call per loop pass once the close is requested. Returns 1 while an
 * exchange is still in flight (keep reading), 0 when the loop may end. A
 * periodic request already in flight is let land under its own edge first, so
 * its reply is never paired with the END send. */
static int anchor_close_step(local_diag_t *local) {
    if (!local->anchor.started || !anchor_live(local))
        return 0;
    if (local->anchor.pending) {
        if (anchor_mono_ns() < local->anchor.deadline_mono_ns)
            return 1;
        local->anchor.pending = 0;
        local->anchor.timed_out++;
    }
    if (local->anchor.end_requested)
        return 0;
    local->anchor.end_requested = 1;
    anchor_request(local, "end", ANCHOR_END_TIMEOUT_NS);
    return local->anchor.pending;
}

/* -----------------------------------------------------------------------
 * Capture framework callbacks
 * ----------------------------------------------------------------------- */

/* The list_callback array's size; every writer bounds itself by it. */
#define LIST_MAX_INTERFACES 32

typedef struct {
    cf_params_list_interface_t **interfaces;
    int n_found;
} list_ctx_t;

static int list_modem_cb(const char *port, const char *fw,
                         const char *imei, const modemident_t *id, void *ctx) {
    (void)port;
    list_ctx_t *c = (list_ctx_t *)ctx;

    if (!imei[0])
        return 0;
    if (c->n_found >= LIST_MAX_INTERFACES)
        return 1;   /* full: stop the scan rather than write past the array */

    c->interfaces[c->n_found] = (cf_params_list_interface_t *)
        malloc(sizeof(cf_params_list_interface_t));
    memset(c->interfaces[c->n_found], 0, sizeof(cf_params_list_interface_t));

    char iface_name[512];
    snprintf(iface_name, sizeof(iface_name), "celldiag-%s", imei);
    c->interfaces[c->n_found]->interface = strdup(iface_name);

    /* The modem's own make/model/firmware, not the firmware alone --
     * this string is what the web UI's Sources panel shows for a source that
     * is not open yet, and the operator is choosing between modems. */
    char hw_desc[512];
    if (id != NULL)
        modemident_label(id, " DIAG", hw_desc, sizeof(hw_desc));
    else
        snprintf(hw_desc, sizeof(hw_desc), "%s IMEI:%s DIAG", fw, imei);
    c->interfaces[c->n_found]->hardware = strdup(hw_desc);

    c->n_found++;
    return 0;
}

/* The PCIe/MHI half of --list. The USB pass never sees these modems:
 * SCAN_ALL_PORTS keeps their AT nodes out so that USB sources do not
 * AT-probe /dev/mhi_DUN first. Without this pass the Data Sources panel would
 * offer "RM520N-GL -- AT commands" (cellat's universe has the node) and never
 * "RM520N-GL -- DIAG", and enabling DIAG on a PCIe modem would mean knowing
 * to hand-write atport=/diagport=.
 *
 * A row is offered only when the DIAG node resolves unambiguously by name,
 * which is exactly what the Enable click's bring-up will open (find_diag_port()
 * on a non-USB AT sibling); otherwise the list would offer a row that
 * auto-detect cannot open.
 *
 * A node held by another process is asked about through its holder's vouch:
 * the paired cellat source holds mhi_DUN for as long as it runs, so a
 * plain probe would hide the DIAG row exactly while the AT row is in use. A
 * holder that published nothing is a sibling lister mid-probe, which
 * lets go within an identify, so it is retried twice before the row is
 * dropped. */
static void list_nonusb_modems(list_ctx_t *c) {
    char ports[16][256];
    int n = find_modem_ports(ports, 16, SCAN_NONUSB_AT);
    if (n == 0)
        return;

    char diag[256], why[STATUS_MAX];
    if (!find_diag_port_wwan(diag, sizeof(diag), why, sizeof(why))) {
        fprintf(stderr, "celldiag: not listing the non-USB modem(s) at %s...: "
                "%s\n", ports[0], why);
        return;
    }

    for (int i = 0; i < n && c->n_found < LIST_MAX_INTERFACES; i++) {
        char fw[256] = "", imei[64] = "";
        modemident_t id;
        int ok = 0;
        for (int attempt = 0; attempt < 3 && !ok; attempt++) {
            g_scan_busy = 0;
            ok = identify_modem(ports[i], fw, sizeof(fw), imei, sizeof(imei),
                                NULL, NULL, &id);
            if (ok || g_scan_busy == 0)
                break;
            pid_t vpid = 0;
            if (identvouch_lookup(ports[i], &id, &vpid)) {
                snprintf(imei, sizeof(imei), "%s", id.imei);
                snprintf(fw, sizeof(fw), "%s", id.firmware);
                ok = 1;
                break;
            }
            usleep(250 * 1000);
        }
        if (!ok || !imei[0])
            continue;

        int dup = 0;
        char want[512];
        snprintf(want, sizeof(want), "celldiag-%s", imei);
        for (int j = 0; j < c->n_found && !dup; j++)
            dup = strcmp(c->interfaces[j]->interface, want) == 0;
        if (!dup)
            list_modem_cb(ports[i], fw, imei, &id, c);
    }
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno, char *msg,
                  cf_params_list_interface_t ***interfaces) {
    (void)caph; (void)seqno; (void)msg;
    *interfaces = (cf_params_list_interface_t **)
        malloc(sizeof(cf_params_list_interface_t *) * LIST_MAX_INTERFACES);

    list_ctx_t ctx = { .interfaces = *interfaces, .n_found = 0 };
    g_scan_list_wait = 1;          /* wait out a sibling lister */
    scan_modems(list_modem_cb, &ctx, NULL, SCAN_ALL_PORTS);   /* list: read fw+IMEI for every modem */
    g_scan_list_wait = 0;
    list_nonusb_modems(&ctx);                                 /* PCIe/MHI */

    return ctx.n_found;
}

/* Compose the datasource UUID for a celldiag source. An explicit uuid= flag in
 * the definition wins; otherwise a deterministic value is derived from the IMEI
 * and the source-type string. Computed identically here so both probe_callback
 * and open_callback register the same non-zero UUID -- Kismet's datasource
 * uniqueness check runs at probe/registration time, so a probe that leaves *uuid
 * as all-zeros makes every celldiag source collide on 00000000-... */
static void compose_diag_uuid(const char *imei, char *definition, char **uuid) {
    char *placeholder = NULL;
    int placeholder_len;
    char buf[STATUS_MAX];

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
        return;
    }

    snprintf(buf, sizeof(buf), "celldiag%s", imei);
    uint32_t hash = adler32_csum((unsigned char *)buf, strlen(buf));
    snprintf(buf, sizeof(buf), "%08X-0000-0000-0000-0000%08X",
             adler32_csum((unsigned char *)"kismet_cap_cell_diag",
                          strlen("kismet_cap_cell_diag")) & 0xFFFFFFFF,
             hash & 0xFFFFFFFF);
    *uuid = strdup(buf);
}

/* Validate a celldiag-<IMEI> definition without scanning ports (scanning can
 * exceed Kismet's 10s probe timeout). replay= definitions validate trivially. */
int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
                   char *msg, char **uuid,
                   cf_params_interface_t **ret_interface,
                   cf_params_spectrum_t **ret_spectrum) {
    (void)caph; (void)seqno;
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    if (strncmp(interface, "celldiag-", 9) != 0) {
        /* Say why -- but only for a definition that is plausibly ours.
         *
         * Kismet probes every definition against every capture binary, so a
         * blanket message here is what this binary would emit for `wlan0`
         * and for every sibling's source: declining a definition that belongs
         * to someone else is the normal case and must stay mute. What must
         * not stay mute is the near-miss -- `celldiag` (the source_type
         * string, the capture_interface value, and what this binary is named
         * after, so the obvious thing for an operator to type),
         * `celldiag_0`, `celldiag-`. Those are unambiguously aimed at us.
         *
         * NOTE: the server currently discards this message, a separate
         * defect: `datasource_tracker_source_probe::complete_probe` takes the
         * reason as `std::string in_reason __attribute__((unused))`, and when
         * every probe declines the completion callback never fires at all --
         * so the two branches below, which do write `msg`, are equally
         * silent. The text is here for when the server passes it on.
         */
        if (strncmp(interface, "celldiag", 8) == 0) {
            snprintf(msg, STATUS_MAX,
                     "'%s' is not a celldiag interface - expected "
                     "celldiag-<15-digit IMEI> (the IMEI selects WHICH modem; "
                     "a bare 'celldiag' cannot). Run "
                     "'kismet_cap_cell_diag --list' for the attached modems.",
                     interface);
        }
        free(interface);
        return 0;
    }

    const char *imei = interface + 9;
    if (strlen(imei) != 15) {
        snprintf(msg, STATUS_MAX,
                 "Invalid celldiag definition '%s' - expected celldiag-<15-digit IMEI>",
                 interface);
        free(interface);
        return 0;
    }
    for (int i = 0; i < 15; i++) {
        if (!isdigit(imei[i])) {
            snprintf(msg, STATUS_MAX, "Invalid IMEI in '%s' - must be 15 digits",
                     interface);
            free(interface);
            return 0;
        }
    }

    /* Register the same deterministic UUID the open path will use, so the
     * probe-time uniqueness check sees a unique id per source. */
    compose_diag_uuid(imei, definition, uuid);

    free(interface);
    return 1;
}

/* Per-phase bring-up timing. The aggregate `bring-up took N ms` figure
 * says a source was slow but not which step was slow, and the steps have wildly
 * different failure modes: an AT port scan, a port open, an SPC exchange, a
 * LOG_CONFIG handshake that waits out DIAG_RESP_TIMEOUT_S per exchange, an F3
 * arm, and the decoder arm. Attributing the time is the difference between
 * "bring-up is slow" and a fix. Rendered into one INFO line at the end of a
 * successful bring-up. */
#define DIAG_BRINGUP_PHASES 8
struct diag_bringup_phases {
    const char *name[DIAG_BRINGUP_PHASES];
    long        ms[DIAG_BRINGUP_PHASES];
    int         n;
    struct timespec mark;
};

static void bringup_phase_start(struct diag_bringup_phases *p) {
    p->n = 0;
    clock_gettime(CLOCK_MONOTONIC, &p->mark);
}

/* Milliseconds elapsed since `start` on the monotonic clock. */
static long bringup_elapsed_ms(const struct timespec *start) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (now.tv_sec - start->tv_sec) * 1000L +
           (now.tv_nsec - start->tv_nsec) / 1000000L;
}

/* The handler a deferred bring-up reports its progress to, NULL
 * otherwise. Set by the capture thread around its diag_bringup_run() call: an
 * inline bring-up (defer=false) runs inside open_callback, before the open is
 * answered, where a data frame has no source to land on. One bring-up thread
 * per helper process, so a file-static is safe (as g_scan_busy is). */
static kis_capture_handler_t *g_bringup_caph;

static void bringup_phase_format(const struct diag_bringup_phases *p,
                                 char *buf, size_t bufsz);

/* Send the phases completed so far (and, on failure, why) as a diag_stats
 * object -- the panel's "Bring-up" row. */
static void bringup_progress_send(kis_capture_handler_t *caph, const char *phases,
                                  long elapsed_ms, const char *error) {
    char jbuf[2048];
    if (caph == NULL ||
        diag_stats_format_bringup_json(phases, elapsed_ms, error, jbuf, sizeof(jbuf)) <= 0)
        return;
    struct timeval tv;
    gettimeofday(&tv, NULL);
    /* 0 == ring full: wait once and retry, as the ModemIdentity sender does. A
     * failure line lost to back-pressure is the exact silence this exists for. */
    if (cf_send_json(caph, NULL, 0, NULL, NULL, tv, "diag_stats", jbuf) == 0) {
        cf_handler_wait_ringbuffer(caph);
        cf_send_json(caph, NULL, 0, NULL, NULL, tv, "diag_stats", jbuf);
    }
}

/* Close the current phase under `name` and start the next. */
static void bringup_phase_lap(struct diag_bringup_phases *p, const char *name) {
    if (p->n >= DIAG_BRINGUP_PHASES)
        return;
    p->name[p->n] = name;
    p->ms[p->n] = bringup_elapsed_ms(&p->mark);
    p->n++;
    clock_gettime(CLOCK_MONOTONIC, &p->mark);
    if (g_bringup_caph != NULL) {
        char detail[256];
        long total = 0;
        for (int i = 0; i < p->n; i++)
            total += p->ms[i];
        bringup_phase_format(p, detail, sizeof(detail));
        bringup_progress_send(g_bringup_caph, detail, total, NULL);
    }
}

/* "at_scan=1204ms port_open=3ms mask=60021ms ..." into buf. */
static void bringup_phase_format(const struct diag_bringup_phases *p,
                                 char *buf, size_t bufsz) {
    size_t off = 0;
    if (!bufsz)
        return;
    buf[0] = '\0';
    for (int i = 0; i < p->n && off + 1 < bufsz; i++) {
        int w = snprintf(buf + off, bufsz - off, "%s%s=%ldms",
                         i ? " " : "", p->name[i], p->ms[i]);
        if (w < 0 || (size_t)w >= bufsz - off)
            break;
        off += (size_t)w;
    }
}

/* The IMEI scan's one rescan. Called only when a pass came back empty
 * and skipped at least one port because another process held its claim.
 *
 * A concurrent multi-source open scans the same ttys at the same time, and a
 * port a sibling is probing is skipped -- its claim is taken, and sharing it
 * would split the reply bytes. The target modem's own AT ports can all be
 * mid-probe at that instant; DIAG capture would still proceed on an explicit
 * diagport=, but the model would read 'unknown' in the rawlog name and
 * prov.model.
 *
 * So: report the first pass's detail before this pass overwrites it, pause
 * 250-775 ms -- jittered by pid so siblings that collided do not collide again
 * -- and scan once more. Once bounds the cost: the bring-up is off Kismet's
 * open deadline by default, and even inline (defer=false) it adds under
 * a second. Mirrors cellat's open_callback rescan, same pause. Returns
 * 1 when the rescan found the IMEI (at_port / fw / imei filled), else 0. */
static int diag_at_rescan(kis_capture_handler_t *caph, local_diag_t *local,
                          const char *imei_def,
                          char *at_port, size_t at_port_sz,
                          char *fw_buf, size_t fw_sz,
                          char *imei_buf, size_t imei_sz, int *rescanned,
                          scan_scope_t scope, modemident_t *id_out) {
    char buf[STATUS_MAX];
    const char *who = local->name ? local->name : "celldiag";
    int skipped = g_scan_busy;
    long pause_ms = 250 + (long)(getpid() % 8) * 75;

    scan_report_ports(caph, who, "AT identify");
    snprintf(buf, sizeof(buf), "%s AT identify: IMEI %s not found while %d "
             "port(s) were held by another process; rescanning once in %ld ms",
             who, imei_def, skipped, pause_ms);
    cf_send_message(caph, buf, MSGFLAG_INFO);

    usleep((useconds_t)pause_ms * 1000);
    *rescanned = 1;
    int found = find_port_by_imei(imei_def, at_port, at_port_sz, fw_buf, fw_sz,
                                  imei_buf, imei_sz, scope, id_out);

    snprintf(buf, sizeof(buf), "%s AT identify rescan: %s%s", who,
             found ? "found on " : "IMEI still not found",
             found ? at_port : "");
    cf_send_message(caph, buf, MSGFLAG_INFO);
    return found;
}

/* Let go of the DIAG port, taking back what this session armed on the modem:
 * the LOG mask, and with qsh=on the QSH-trace latch (which survives
 * reboots) and the 0x60 event stream it switched on. All
 * fire-and-forget -- nothing reads the port by now -- and each gated on its own
 * flag, so a passive tap or a replay sends nothing. Used by the stop teardown
 * and by every bring-up failure after the mask went out, because Kismet may
 * never get a working reopen and a failed open must not leave a flood behind.
 *
 * Without clearing the LOG mask, a modem keeps streaming after a clean
 * mask=full stop -- megabytes per 15 s to whoever opens the port next. */
static void diag_fd_release(local_diag_t *local) {
    if (local->diag_fd >= 0) {
        if (local->mask_armed)
            (void)diag_config_clear_log_mask(local->diag_fd);
        if (local->qsh_armed) {
            (void)diag_config_disarm_latched(local->diag_fd);
            (void)diag_config_disable_events(local->diag_fd);
        }
    }
    local->mask_armed = 0;
    local->qsh_armed = 0;
    serial_close_fd(&local->diag_fd);
}

/* Live-modem device bring-up: AT IMEI scan -> profile defaults -> DIAG
 * port resolve -> port open -> SPC unlock -> LOG_CONFIG mask -> F3 arm ->
 * rawlog resolve -> decoder arm. Everything here touches hardware and is
 * multi-second; it is the work kept off Kismet's open-command critical path.
 *
 * Reads its parameters from local->bringup (stashed by open_callback) and, on
 * success, fills in local->modem_model / modem_firmware / diag_path / name and
 * clears bringup.pending. On failure writes a human error into msg and returns
 * -1 with the DIAG port closed; the caller decides whether that fails the open
 * (defer=false) or raises a source error (deferred, the default).
 *
 * Runs exactly once per open, from a single thread -- either open_callback or
 * capture_thread, never both -- so no locking is needed around local->. */
static int diag_bringup_run(kis_capture_handler_t *caph, local_diag_t *local,
                            char *msg, size_t msg_sz) {
    char buf[STATUS_MAX];
    const char *imei_def = local->modem_imei;
    char *profiles_dir = local->bringup.profiles_dir;
    struct timespec t_start;
    clock_gettime(CLOCK_MONOTONIC, &t_start);
    struct diag_bringup_phases phases;
    bringup_phase_start(&phases);
    const char *diagport_override = local->bringup.diagport_override;
    int mask_full = local->bringup.mask_full;
    int mask_set  = local->bringup.mask_set;
    uint32_t f3_levels = local->bringup.f3_levels;
    const char *f3_preset = local->bringup.f3_preset ?
                            local->bringup.f3_preset : "off";
    int f3_set    = local->bringup.f3_set;
    int qsh_on    = local->bringup.qsh_on;   /* gated full-F3 tier */
    int spc_set   = local->bringup.spc_set;
    char spc_val[8];
    snprintf(spc_val, sizeof(spc_val), "%s", local->bringup.spc_val);

    local->bringup.profiles_dir = NULL;   /* ownership moves here */

    const char *atport_override = local->bringup.atport_override;
    char at_port[512] = "", fw_buf[256] = "", imei_buf[64] = "";
    modemident_t ident;  /* filled by whichever branch identifies */
    modemident_clear(&ident);
    int rescanned = 0;   /* the IMEI scan took its one busy-port rescan */
    if (atport_override[0]) {
        /* Explicit AT-identify node: the operator named the AT surface,
         * needed for an MHI/wwan modem the ttyUSB IMEI scan cannot see. Probe
         * exactly that port and verify the IMEI matches the source name, so a
         * mistyped node fails loud instead of binding the wrong modem. This
         * exercises serial_open()'s non-tty path for /dev/mhi_DUN. Use it for a
         * celldiag-only MHI capture, where mhi_DUN is free to be AT-probed. */
        int mismatch = 0;
        if (!identify_modem(atport_override, fw_buf, sizeof(fw_buf),
                            imei_buf, sizeof(imei_buf), imei_def, &mismatch,
                            &ident)) {
            snprintf(msg, msg_sz, mismatch ?
                     "atport=%s answered AT but reported a different IMEI than %s" :
                     "atport=%s did not AT-identify as IMEI %s",
                     atport_override, imei_def);
            goto fail;
        }
        snprintf(at_port, sizeof(at_port), "%s", atport_override);
    } else if (diagport_override[0] &&
               diag_wwan_classify(diagport_override, NULL) != DIAG_WWAN_NONE) {
        /* Explicit MHI/wwan DIAG node with no atport=. The modem is a
         * PCIe/inline part that exposes no /dev/ttyUSB*, so a full IMEI scan
         * would burn seconds AT-probing every sibling modem's ports before
         * reaching this one. So scan the non-USB AT nodes only: typically
         * /dev/mhi_DUN alone, a ~100 ms identify.
         *
         * In a fused cellat+celldiag capture the single AT node is held by the
         * cellat source. The contention is safe both ways:
         *   - cellat's ongoing open waits out a claim this probe holds;
         *   - a node cellat holds is refused EWOULDBLOCK here, never shared
         *     -- one busy-port rescan, then the fallback below.
         * The IMEI match picks the right modem when several expose such nodes. */
        if (find_port_by_imei(imei_def, at_port, sizeof(at_port),
                              fw_buf, sizeof(fw_buf), imei_buf, sizeof(imei_buf),
                              SCAN_NONUSB_AT, &ident) ||
            (g_scan_busy > 0 &&
             diag_at_rescan(caph, local, imei_def, at_port, sizeof(at_port),
                            fw_buf, sizeof(fw_buf), imei_buf, sizeof(imei_buf),
                            &rescanned, SCAN_NONUSB_AT, &ident))) {
            snprintf(buf, sizeof(buf),
                     "%s IMEI %s on explicit MHI/wwan diagport=%s: AT identity "
                     "from %s",
                     local->name ? local->name : "celldiag", imei_def,
                     diagport_override, at_port);
        } else {
            /* No answer: the node is held for a cellat session, absent, or
             * not named as an AT node (the scan admits only what the shared
             * classifier calls AT: mhi_DUN[<N>], wwan<N>at<M>).
             * DIAG node + IMEI are both known, so proceed without AT identity:
             * no firmware string (profile mask/f3/spc defaults skipped; an
             * explicit mask=/f3=/spc= still applies). */
            snprintf(imei_buf, sizeof(imei_buf), "%s", imei_def);
            snprintf(buf, sizeof(buf),
                     "%s IMEI %s on explicit MHI/wwan diagport=%s; no non-USB "
                     "AT node answered as this IMEI (held by a paired cellat "
                     "source, absent, or not named as an AT node), so proceeding "
                     "without AT identity (no firmware string; pass atport= for "
                     "verification)",
                     local->name ? local->name : "celldiag", imei_def,
                     diagport_override);
        }
        cf_send_message(caph, buf, MSGFLAG_INFO);
    } else if (!find_port_by_imei(imei_def, at_port, sizeof(at_port),
                           fw_buf, sizeof(fw_buf), imei_buf, sizeof(imei_buf),
                           SCAN_ALL_PORTS, &ident) &&
               !(g_scan_busy > 0 &&
                 diag_at_rescan(caph, local, imei_def, at_port, sizeof(at_port),
                                fw_buf, sizeof(fw_buf),
                                imei_buf, sizeof(imei_buf), &rescanned,
                                SCAN_ALL_PORTS, &ident))) {
        /* Scan failed -- after its one rescan, if a busy port earned one. An
         * explicit (ttyUSB) diagport still lets us bind on the source-name
         * IMEI; without one there is nothing to open. */
        if (diagport_override[0]) {
            snprintf(imei_buf, sizeof(imei_buf), "%s", imei_def);
            snprintf(buf, sizeof(buf),
                     "%s IMEI %s not on any scanned AT port; proceeding on "
                     "explicit diagport=%s without AT identity",
                     local->name ? local->name : "celldiag", imei_def,
                     diagport_override);
            cf_send_message(caph, buf, MSGFLAG_INFO);
        } else if (find_port_by_imei(imei_def, at_port, sizeof(at_port),
                                     fw_buf, sizeof(fw_buf),
                                     imei_buf, sizeof(imei_buf),
                                     SCAN_NONUSB_AT, &ident) ||
                   (g_scan_busy > 0 &&
                    diag_at_rescan(caph, local, imei_def, at_port,
                                   sizeof(at_port), fw_buf, sizeof(fw_buf),
                                   imei_buf, sizeof(imei_buf), &rescanned,
                                   SCAN_NONUSB_AT, &ident))) {
            /* Not on any USB port, but a non-USB AT node answered (or
             * its holder vouched) as this IMEI -- a PCIe/MHI modem addressed
             * by a bare celldiag-<imei>, which is exactly what the web UI's
             * Enable click sends. find_diag_port() resolves its DIAG node by
             * name. A fallback, never part of the USB pass: putting these
             * nodes in SCAN_ALL_PORTS would cost every USB source an AT probe
             * of mhi_DUN first, against the paired cellat (see scan_scope_t). */
            snprintf(buf, sizeof(buf),
                     "%s IMEI %s is not on any USB port; found on the non-USB AT "
                     "node %s (a PCIe/MHI modem), so its DIAG node is chosen by "
                     "name",
                     local->name ? local->name : "celldiag", imei_def, at_port);
            cf_send_message(caph, buf, MSGFLAG_INFO);
        } else {
            snprintf(msg, msg_sz, "Modem IMEI %s not found on any serial port "
                     "or non-USB (MHI/wwan) AT node", imei_def);
            goto fail;
        }
    }
    bringup_phase_lap(&phases, "at_scan");
    /* The per-port detail of the pass that decided. A rescan
     * reported its first pass itself, before overwriting it. */
    scan_report_ports(caph, local->name ? local->name : "celldiag",
                      rescanned ? "AT identify rescan" : "AT identify");
    free(local->modem_firmware);
    free(local->modem_model);
    local->modem_firmware = strdup(fw_buf);
    local->modem_model = strdup(fw_buf);

    /* What this open will report as the modem's identity. A found AT
     * port means the modem answered for itself; anything else (an MHI node
     * whose AT surface the paired cellat source holds, a ttyUSB scan that came
     * back empty on an explicit diagport=) proceeded on the IMEI the source was
     * addressed by, and the record says so rather than presenting it as read. */
    if (at_port[0] && ident.imei[0]) {
        /* Second-hand when the holder of at_port vouched for it -- the
         * record says so, and the bus says who, rather than presenting the
         * holder's reading as this source's own. */
        int vouched = g_scan_vouch_pid > 0 &&
                      strcmp(g_scan_vouch_port, at_port) == 0;
        local->ident = ident;
        snprintf(local->ident_method, sizeof(local->ident_method), "%s",
                 vouched ? MODEMIDENT_METHOD_VOUCHED : MODEMIDENT_METHOD_AT);
        snprintf(local->ident_at_port, sizeof(local->ident_at_port), "%s",
                 at_port);
        if (vouched) {
            /* A non-USB AT node has no USB device: its DIAG node is chosen by
             * name, and the line must not claim otherwise. */
            int by_name = diag_wwan_is_at(at_port) && !diagport_override[0];
            snprintf(buf, sizeof(buf),
                     "%s IMEI %s: %s is held by pid %ld (its paired source), "
                     "which read this modem over AT and vouched for it; the "
                     "DIAG port is %s",
                     local->name ? local->name : "celldiag", imei_def,
                     at_port, (long) g_scan_vouch_pid,
                     diagport_override[0] ? "the explicit diagport=" :
                     by_name ? "chosen by wwan/MHI node name" :
                     "resolved from that port's USB device");
            cf_send_message(caph, buf, MSGFLAG_INFO);
        }
    } else {
        modemident_clear(&local->ident);
        snprintf(local->ident.imei, sizeof(local->ident.imei), "%s", imei_def);
        snprintf(local->ident_method, sizeof(local->ident_method), "%s",
                 MODEMIDENT_METHOD_DEFINITION);
        local->ident_at_port[0] = '\0';
        local->ident_held = g_scan_busy > 0;
    }

    /* Backstop: never let the model be silently empty. If the bring-up
     * proceeded without an AT identity (an MHI diagport= with no atport=, or a
     * ttyUSB scan that could not read the firmware even after the retry above),
     * fw_buf is "" and the rawlog %m would expand to the ambiguous literal
     * 'modem' while prov.model went blank — losing which modem a raw DIAG tee
     * came from. Stamp an explicit 'unknown' sentinel and say so, so the
     * fallback is visible in the log and distinguishable from a modem that is
     * literally named 'modem'. INFO, not ERROR: proceeding without AT identity
     * is the intended path for a fused cellat+celldiag MHI capture (the AT node
     * is held by the cellat source), so escalating here would cry wolf. */
    if (!local->modem_model || !local->modem_model[0]) {
        free(local->modem_model);
        local->modem_model = strdup("unknown");
        snprintf(buf, sizeof(buf),
                 "%s IMEI %s: model/firmware unresolved (opened without AT "
                 "identity); rawlog %%m and prov.model will read 'unknown', "
                 "not a silent 'modem'",
                 local->name ? local->name : "celldiag", imei_def);
        cf_send_message(caph, buf, MSGFLAG_INFO);
    }

    /* Per-model DIAG port descriptor: resolved from the profile's
     * diag.port_detect so find_diag_port() can select by exact interface (or
     * report a non-ttyUSB transport) instead of assuming DIAG == if00.
     * have_pd stays 0 when no profiles dir / no matching profile / no
     * port_detect object, which is the lowest-interface default. Only
     * consulted for auto-detect (a diagport= override skips find_diag_port
     * entirely). */
    struct diag_port_detect pd_desc;
    int have_pd = 0;
    if (profiles_dir && *profiles_dir && !diagport_override[0])
        have_pd = diag_profile_port_detect(profiles_dir, fw_buf, &pd_desc);

    /* Per-modem defaults from the profile JSON: consulted only
     * when the operator did not set the option explicitly, so an explicit
     * mask=/f3= always wins. The firmware string (AT+CGMR) selects the
     * profile via its firmware_match glob. Silent no-op if no profiles dir
     * is configured or no profile matches. */
    if (profiles_dir && *profiles_dir) {
        char pv[DIAG_STATS_MASK_MAX];
        if (!mask_set &&
            diag_profile_lookup(profiles_dir, fw_buf, "mask_default",
                                pv, sizeof(pv))) {
            if (strcmp(pv, "wardrive") == 0) {
                mask_full = 0;
            } else if (strcmp(pv, "full") == 0 || strcmp(pv, "full-log") == 0) {
                mask_full = 1;
            } else {
                snprintf(buf, sizeof(buf),
                         "%s ignoring invalid profile mask_default '%s' "
                         "(expected wardrive|full); using built-in default",
                         local->name ? local->name : "celldiag", pv);
                cf_send_message(caph, buf, MSGFLAG_ERROR);
                goto mask_default_done;
            }
            snprintf(buf, sizeof(buf),
                     "%s mask=%s from profile default (firmware %s); "
                     "source option would override", local->name ? local->name
                     : "celldiag", mask_full ? "full" : "wardrive", fw_buf);
            cf_send_message(caph, buf, MSGFLAG_INFO);
        }
mask_default_done:
        if (!f3_set &&
            diag_profile_lookup(profiles_dir, fw_buf, "f3_default",
                                pv, sizeof(pv))) {
            /* Same table as the source-option parse -- one spelling
             * set, so a profile can never accept a value the option rejects. */
            if (!f3_preset_lookup(pv, &f3_levels, &f3_preset, NULL)) {
                snprintf(buf, sizeof(buf),
                         "%s ignoring invalid profile f3_default '%s' "
                         "(expected " F3_PRESET_NAMES "); using built-in default",
                         local->name ? local->name : "celldiag", pv);
                cf_send_message(caph, buf, MSGFLAG_ERROR);
                goto f3_default_done;
            }
            if (f3_levels) {
                snprintf(buf, sizeof(buf),
                         "%s f3=%s from profile default (firmware %s); "
                         "source option would override",
                         local->name ? local->name : "celldiag", f3_preset,
                         fw_buf);
                cf_send_message(caph, buf, MSGFLAG_INFO);
            }
        }
f3_default_done:
        /* spc default: a profile marks a known SPC-gated model (e.g.
         * EG25-G) with diag.spc so DIAG arms without the operator repeating
         * spc= on every source line. An explicit spc= still wins. Validated
         * here so a malformed profile value degrades to "no SPC" + a warning,
         * never a bad unlock attempt. */
        if (!spc_set &&
            diag_profile_lookup(profiles_dir, fw_buf, "spc", pv, sizeof(pv))) {
            uint8_t probe[6];
            if (diag_config_build_spc(probe, sizeof(probe), pv) != sizeof(probe)) {
                snprintf(buf, sizeof(buf),
                         "%s ignoring invalid profile diag.spc '%s' (expected "
                         "6 decimal digits); DIAG SPC unlock not sent",
                         local->modem_model ? local->modem_model : "celldiag", pv);
                cf_send_message(caph, buf, MSGFLAG_ERROR);
            } else {
                snprintf(spc_val, sizeof(spc_val), "%s", pv);
                snprintf(buf, sizeof(buf),
                         "%s spc=%s from profile default (firmware %s); will "
                         "unlock DIAG before arming the LOG mask", local->modem_model
                         ? local->modem_model : "celldiag", spc_val, fw_buf);
                cf_send_message(caph, buf, MSGFLAG_INFO);
            }
        }
    }

    /* Tell the helper to relay F3 (diag_f3 records) iff this source armed any
     * F3 preset. Resolved before the live/replay split, so a replayed
     * capture that contains MSG/EXT_MSG F3 is relayed too.
     *
     * Relay is all-or-nothing on purpose: the severity floor is enforced by the
     * modem, at arm time, by the mask below. There is no helper-side re-filter,
     * so f3=high/error on a replay source relays the file's F3 unfiltered --
     * the floor a capture was taken with is a property of the capture. */
    local->f3_relay  = (f3_levels != 0);
    local->f3_levels = f3_levels;
    local->f3_preset = f3_preset;

    char diag_port[512];
    if (diagport_override[0]) {
        snprintf(diag_port, sizeof(diag_port), "%s", diagport_override);
    } else {
        char portdiag[STATUS_MAX];
        portdiag[0] = '\0';
        if (!find_diag_port(at_port, diag_port, sizeof(diag_port),
                            imei_def, portdiag, sizeof(portdiag),
                            have_pd ? &pd_desc : NULL)) {
            /* Actionable failure: which USB device matched, which
             * ttyUSB interfaces were seen, and what to do. */
            snprintf(msg, msg_sz, "%s", portdiag[0] ? portdiag :
                     "Could not locate DIAG interface; pass diagport=/dev/ttyUSBx");
            goto fail;
        }
        /* find_diag_port also fills portdiag on success when the USB-descriptor
         * classifier overrode the lowest-interface convention, or when nothing
         * on the device carried a DIAG descriptor and it fell back.
         * Both are things an operator debugging a handshake timeout needs to
         * see, so relay them; silence means the boring agreeing case. */
        if (portdiag[0]) {
            snprintf(buf, sizeof(buf), "%s %s",
                     local->name ? local->name : "celldiag", portdiag);
            cf_send_message(caph, buf, MSGFLAG_INFO);
        }
    }
    bringup_phase_lap(&phases, "port_detect");

    /* Retry a transient port grab: during a rapid source relaunch a
     * dying sibling helper can still hold the DIAG port for a few hundred ms,
     * or the char node can blink during USB/MHI re-enumeration. A single-shot
     * open would fail the source open on that transient -- and on a
     * single-source server that failure can tear the whole server down via the
     * capture framework's "Remote side closed read pipe" path. 5 attempts x
     * 200 ms (~1 s max) absorbs the grab; a genuinely-wrong path (ENOENT)
     * still fails fast on the first attempt (see diag_open_errno_is_transient). */
    local->diag_fd = diag_capture_open_retry(diag_port, 5, 200);
    if (local->diag_fd < 0) {
        snprintf(msg, msg_sz, "Failed to open DIAG port %s: %s",
                 diag_port, strerror(errno));
        goto fail;
    }
    free(local->diag_path);
    local->diag_path = strdup(diag_port);
    bringup_phase_lap(&phases, "port_open");

    memset(&local->reader, 0, sizeof(local->reader));
    if (!local->no_mask) {
        /* SPC unlock before SET_MASK. Only sent when spc= or the
         * profile's diag.spc supplied a code, so the ungated LM960/RM500Q
         * path is byte-for-byte unchanged. On a gated modem (EG25-G) a
         * missing/wrong SPC is exactly why SET_MASK is silently refused, so a
         * rejection here fails the open loudly instead of surfacing later as
         * the misleading "LOG_CONFIG handshake failed (wrong port?)". */
        if (spc_val[0]) {
            if (diag_config_send_spc(local->diag_fd, &local->reader,
                                     spc_val) != 0) {
                snprintf(msg, msg_sz,
                         "DIAG SPC unlock (spc=%s) rejected on %s -- wrong SPC "
                         "for this unit, or the modem does not gate DIAG on SPC "
                         "(drop spc= for SDX24/SDX55-class parts)",
                         spc_val, diag_port);
                serial_close_fd(&local->diag_fd);
                goto fail;
            }
            snprintf(buf, sizeof(buf),
                     "%s DIAG SPC unlock accepted on %s -- arming LOG mask",
                     local->modem_model ? local->modem_model : "celldiag",
                     diag_port);
            cf_send_message(caph, buf, MSGFLAG_INFO);
        }
        bringup_phase_lap(&phases, "spc");
        /* Clear any latched QSH-trace / F3 flood before the LOG mask.
         * These modems keep emitting a previously-armed subsystem across reboots
         * until an explicit disarm is sent; the narrow LOG mask cannot reach
         * those subsystems (0x9001 / 0x7D vs the 0x73 it drives). Without this a
         * capture on a unit a prior tool/boot left armed inherits ~1,322 QSH/F3
         * frames per cell frame on SDX62. Fire-and-forget: a pre-QSH part just
         * answers BAD_CMD to the 0x9001 frame. An f3= preset (below, after the mask)
         * re-arms F3 for callers that want it. */
        (void)diag_config_disarm_latched(local->diag_fd);
        bringup_phase_lap(&phases, "disarm");
        int rc = mask_full
                 ? diag_config_apply_full_mask(local->diag_fd, &local->reader)
                 : diag_config_apply_narrow_mask(local->diag_fd, &local->reader,
                                                 DIAG_TARGET_CODES,
                                                 DIAG_TARGET_CODES_COUNT);
        if (rc != 0) {
            snprintf(msg, msg_sz,
                     "DIAG LOG_CONFIG handshake failed on %s "
                     "(wrong port, or SPC-gated?)", diag_port);
            serial_close_fd(&local->diag_fd);
            goto fail;
        }
        local->mask_armed = 1;
        if (mask_full) {
            /* One-line volume warning on the bus so an operator who selects
             * the flood preset sees why the stream is heavy. */
            snprintf(buf, sizeof(buf),
                     "%s mask=full: subscribed to EVERY advertised LOG code "
                     "on %s -- HIGH DIAG volume, use for diagnosis not "
                     "wardriving", local->name, diag_port);
            cf_send_message(caph, buf, MSGFLAG_INFO);
        }
    }
    bringup_phase_lap(&phases, "log_mask");
    /* Arm the F3 debug-message surface if requested. Orthogonal to the
     * LOG mask, so it runs even under nomask= (a passive LOG tap that still
     * wants F3). SET_ALL_RT_MASKS is the hardware-verified form; the preset only
     * varies the runtime-level mask it carries. */
    if (f3_levels) {
        const char *blurb = "";
        (void)f3_preset_lookup(f3_preset, NULL, NULL, &blurb);
        if (diag_config_enable_f3(local->diag_fd, &local->reader,
                                  f3_levels) != 0) {
            snprintf(msg, msg_sz,
                     "DIAG EXT_MSG_CONFIG (f3=%s) handshake failed on %s "
                     "(wrong port, or SPC-gated?)", f3_preset, diag_port);
            diag_fd_release(local);
            goto fail;
        }
        snprintf(buf, sizeof(buf),
                 "%s f3=%s: armed %s on %s (SET_ALL_RT_MASKS, level mask "
                 "0x%08X)", local->name, f3_preset, blurb, diag_port,
                 f3_levels);
        cf_send_message(caph, buf, MSGFLAG_INFO);
    }
    bringup_phase_lap(&phases, "f3_arm");
    /* qsh=on: arm the full F3 surface as a gated tier -- the QSH-trace
     * 0x9001 maskset (0x9D / 0x92) + 0x60 events + a diag_id binding request,
     * over the same fd the LOG/F3 handshakes just used (no second datasource,
     * no second open() of a flock-claimed port). All three are non-fatal by
     * policy: SDX20 answers status!=0 and MDM9607 answers
     * 0x13 BAD_CMD, both per-generation negatives rather than capture failures,
     * so the return is discarded and the capture continues. The startup
     * diag_config_disarm_latched (above) already cleared any inherited latch;
     * this arms it, and the stop path disarms it (gated on qsh_armed) so the
     * latch -- which survives reboots -- never rides into the next
     * capture on this modem. qsh_armed is set whenever the arm was attempted
     * (even on an unsupporting part) so the fire-and-forget stop disarm always
     * runs; a no-op disarm on a modem that ignored the arm is harmless. */
    if (qsh_on) {
        (void)diag_config_enable_qsh_trace(local->diag_fd, &local->reader);
        (void)diag_config_enable_events(local->diag_fd, &local->reader);
        int bind_rc = diag_config_request_diag_id_binding(
                local->diag_fd, &local->reader, local->diagid_wire,
                sizeof(local->diagid_wire), &local->diagid_wire_len);
        local->qsh_armed = 1;
        snprintf(buf, sizeof(buf),
                 "%s qsh=on: armed the FULL F3 surface on %s (QSH-trace 0x9001 "
                 "maskset 0x9D/0x92 + 0x60 events + diag_id binding: %s) -- "
                 "development tier, non-fatal, disarmed on stop", local->name,
                 diag_port,
                 bind_rc == 0 && local->diagid_wire_len > 0 ?
                     "table received, relayed into the stream" :
                 bind_rc == 0 ? "table received, too large to relay" :
                 bind_rc > 0 ? "no table (BAD_CMD or timeout)" : "request I/O error");
        cf_send_message(caph, buf, MSGFLAG_INFO);
    }
    bringup_phase_lap(&phases, "qsh_arm");
    /* Label the active preset for the health readout: the LOG
     * mask preset, "+f3" when F3 is armed, or "passive" when nomask= skips
     * the LOG handshake. A severity floor is spelled out ("+f3:error") because
     * a floored stream and a full one are indistinguishable from record volume
     * alone -- the readout has to say which one the operator is looking at. */
    {
        const char *base = local->no_mask ? "passive" :
                           (mask_full ? "full" : "wardrive");
        char f3_tag[24] = "";
        char qsh_tag[8] = "";
        char preset_label[DIAG_STATS_MASK_MAX];
        if (f3_levels == DIAG_F3_LEVELS_ALL)
            snprintf(f3_tag, sizeof(f3_tag), "+f3");
        else if (f3_levels)
            snprintf(f3_tag, sizeof(f3_tag), "+f3:%s", f3_preset);
        if (qsh_on)                       /* gated full-F3 tier */
            snprintf(qsh_tag, sizeof(qsh_tag), "+qsh");
        snprintf(preset_label, sizeof(preset_label), "%s%s%s", base, f3_tag,
                 qsh_tag);
        diag_stats_set_mask_preset(&local->stats, preset_label);
    }

    /* Now the model is known, so a rawlog= spec's %m can expand. */
    if (local->rawlog_spec) {
        char resolved[1024];
        if (diag_rawlog_resolve(local->rawlog_spec, imei_def, local->modem_model,
                                time(NULL), resolved, sizeof(resolved)) != 0) {
            snprintf(msg, msg_sz,
                     "rawlog path from '%s' is too long to resolve",
                     local->rawlog_spec);
            diag_fd_release(local);
            goto fail;
        }
        free(local->rawlog_path);
        local->rawlog_path = strdup(resolved);
    }

    decoder_bringup(caph, local);
    bringup_phase_lap(&phases, "decoder_start");
    bringup_phase_format(&phases, local->bringup.phase_detail,
                         sizeof(local->bringup.phase_detail));

    /* Replace the provisional identity now that the model is known. */
    {
        char hw_desc[512];
        snprintf(hw_desc, sizeof(hw_desc), "%s IMEI:%s DIAG",
                 local->modem_model, imei_def);
        free(local->name);
        local->name = strdup(hw_desc);
    }

    free(profiles_dir);
    local->bringup.pending = 0;
    local->bringup.elapsed_ms = bringup_elapsed_ms(&t_start);
    return 0;

fail:
    free(profiles_dir);
    /* The steps that did complete, for the failure report. */
    bringup_phase_format(&phases, local->bringup.phase_detail,
                         sizeof(local->bringup.phase_detail));
    local->bringup.pending = 0;
    local->bringup.elapsed_ms = bringup_elapsed_ms(&t_start);
    return -1;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
                  char *msg, uint32_t *dlt, char **uuid,
                  cf_params_interface_t **ret_interface,
                  cf_params_spectrum_t **ret_spectrum) {
    (void)seqno; (void)dlt;
    local_diag_t *local = (local_diag_t *)caph->userdata;
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    char buf[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }
    interface = strndup(placeholder, placeholder_len);

    if (strncmp(interface, "celldiag-", 9) != 0) {
        snprintf(msg, STATUS_MAX,
                 "Invalid celldiag definition '%s' - expected celldiag-<IMEI>",
                 interface);
        free(interface);
        return -1;
    }
    const char *imei = interface + 9;
    if (strlen(imei) != 15) {
        snprintf(msg, STATUS_MAX,
                 "Invalid celldiag definition '%s' - expected celldiag-<15-digit IMEI>",
                 interface);
        free(interface);
        return -1;
    }
    for (int i = 0; i < 15; i++) {
        if (!isdigit(imei[i])) {
            snprintf(msg, STATUS_MAX, "Invalid IMEI in '%s' - must be 15 digits",
                     interface);
            free(interface);
            return -1;
        }
    }
    char imei_def[16];
    strncpy(imei_def, imei, 15);
    imei_def[15] = '\0';
    free(interface);

    /* --- source options --- */
    /* helper= is refused, not ignored. It used to select an external
     * decoder; ignoring it would quietly switch an existing definition to the
     * built-in one, so a setup that named one decoder would measure another.
     * Kismet ignores unknown options, so this one has to be caught. */
    if (cf_find_flag(&placeholder, "helper", definition) > 0) {
        snprintf(msg, STATUS_MAX,
                 "celldiag: the helper= source option was removed: the decoder "
                 "is built into this binary. Remove helper= from '%s'.",
                 definition);
        return -1;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "replay", definition)) > 0)
        local->replay_path = strndup(placeholder, placeholder_len);

    /* rawlog= spec is captured now but resolved after the model is known
     * (below), so %m can expand. */
    if ((placeholder_len = cf_find_flag(&placeholder, "rawlog", definition)) > 0)
        local->rawlog_spec = strndup(placeholder, placeholder_len);

    char diagport_override[512] = "";
    if ((placeholder_len = cf_find_flag(&placeholder, "diagport", definition)) > 0) {
        char *p = strndup(placeholder, placeholder_len);
        strncpy(diagport_override, p, sizeof(diagport_override) - 1);
        free(p);
    }

    /* atport=<path> -- explicit AT-identify node. The IMEI->AT-port
     * scan globs /dev/ttyUSB* + /dev/ttyACM* only, so an MHI-only modem (PCIe
     * RM520N-GL: AT on /dev/mhi_DUN, DIAG on /dev/mhi_DIAG) is invisible to it
     * and the bring-up fails at at_scan even when diagport= is explicit. This
     * names the AT surface directly, mirroring cellat's atport=. Guard: refuse
     * a recognized wwan/MHI node that is not the AT surface (mhi_DIAG, mhi_QDSS,
     * mhi_SAHARA) -- probing it would write "ATI" into the DIAG/trace/EDL
     * channel. A ttyUSB/ttyACM classifies as DIAG_WWAN_NONE and is always
     * allowed (the normal scan already AT-probes those). */
    char atport_override[512] = "";
    if ((placeholder_len = cf_find_flag(&placeholder, "atport", definition)) > 0) {
        char *p = strndup(placeholder, placeholder_len);
        strncpy(atport_override, p, sizeof(atport_override) - 1);
        free(p);
        if (atport_override[0] &&
            diag_wwan_classify(atport_override, NULL) != DIAG_WWAN_NONE &&
            !diag_wwan_is_at(atport_override)) {
            snprintf(msg, STATUS_MAX,
                     "atport=%s is a recognized modem node but not its AT "
                     "surface (function: %s) -- refusing to write AT into it. "
                     "Pass the AT/DUN node instead (e.g. /dev/mhi_DUN).",
                     atport_override, diag_wwan_label(atport_override));
            return -1;
        }
    }

    local->gsmtap_on = 0;
    local->gsmtap_dest[0] = '\0';
    if ((placeholder_len = cf_find_flag(&placeholder, "gsmtap", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        char gerr[256];
        int g = diag_optset_gsmtap_dest(v, local->gsmtap_dest,
                                        sizeof(local->gsmtap_dest),
                                        gerr, sizeof(gerr));
        free(v);
        if (g < 0) {
            snprintf(msg, STATUS_MAX, "%s", gerr);
            return -1;
        }
        local->gsmtap_on = (g == 1);
    }

    local->no_mask = 0;
    if ((placeholder_len = cf_find_flag(&placeholder, "nomask", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (strcmp(v, "true") == 0 || strcmp(v, "1") == 0)
            local->no_mask = 1;
        free(v);
    }

    /* defer=<bool> -- run the live-modem bring-up off the open-command critical
     * path. Default true: the bring-up (AT IMEI scan + DIAG open + SPC +
     * LOG_CONFIG/F3 handshake) costs seconds and exceeds Kismet's
     * open-command deadline, so inline every first open would report "failed
     * to launch: Command did not complete" and depend on the 5 s auto-reopen
     * to recover -- which is not reliable once two sources race. defer=false
     * runs it inline (useful for bisecting a bring-up failure, since the
     * error then comes back as the open's own error string). */
    int defer = 1;
    if ((placeholder_len = cf_find_flag(&placeholder, "defer", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (strcmp(v, "false") == 0 || strcmp(v, "0") == 0 || strcmp(v, "no") == 0)
            defer = 0;
        else if (strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "yes") == 0)
            defer = 1;
        else {
            snprintf(msg, STATUS_MAX,
                     "Unknown defer value '%s' (expected true|false)", v);
            free(v);
            return -1;
        }
        free(v);
    }

    /* enabled=false leaves the source defined-but-idle: open_callback
     * registers it (so it shows in the source list) but does not probe the
     * modem, open the DIAG port, run the LOG_CONFIG/F3 handshake, or spawn the
     * helper. Runtime enable/disable/restart is mediated by the Kismet server,
     * which closes (reaps this process) and re-opens (respawns it) a source; a
     * fresh open with enabled=true then acquires the port + re-runs the
     * handshake from scratch. Default enabled. */
    local->disabled = 0;
    if ((placeholder_len = cf_find_flag(&placeholder, "enabled", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (strcmp(v, "false") == 0 || strcmp(v, "0") == 0 || strcmp(v, "no") == 0)
            local->disabled = 1;
        else if (strcmp(v, "true") == 0 || strcmp(v, "1") == 0 || strcmp(v, "yes") == 0)
            local->disabled = 0;
        else {
            /* The message lists all six spellings the compare above accepts,
             * so the decision and the report agree about the rule; an
             * operator told the rule wrongly cannot correct their own input.
             *
             * The compare is also case-sensitive, so `enabled=False` -- the
             * spelling a Python-side config generator emits -- hard-errors.
             * That is the right behaviour (fail loud, never guess), and the
             * message says so instead of leaving it to be discovered.
             *
             * cellat's cellat_bool_option_parse() generates its message from
             * the accepted-value lists so the two cannot drift; the helpers are
             * separate link units in separate directories, so sharing that TU
             * here is a build change rather than an include. Keep the two sets
             * in step by hand -- see cellat_options.h. */
            snprintf(msg, STATUS_MAX,
                     "Unknown enabled value '%s' -- expected true|1|yes or "
                     "false|0|no. The compare is case-sensitive on purpose (so "
                     "'%s' is rejected rather than guessed at); spell it "
                     "lowercase.", v, v);
            free(v);
            return -1;
        }
        free(v);
    }

    /* nativedecode= and census= name the decoder and the census producer.
     * There is one of each: the native decode legs, in this process, and the
     * census they feed (diag_inventory.c). `nativedecode=only` and
     * `census=native` say exactly that and are accepted, so an existing
     * definition that spells them keeps opening. Any other value is REFUSED,
     * not ignored: it asks for a decoder this binary does not have, and a
     * definition that silently measured something else would be worse than
     * one that does not open. */
    if ((placeholder_len = cf_find_flag(&placeholder, "nativedecode", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (strcmp(v, "only") != 0) {
            snprintf(msg, STATUS_MAX,
                     "nativedecode=%s is not supported: this source has one "
                     "decoder, the native one (nativedecode=only). Remove the "
                     "option, or set it to only.", v);
            free(v);
            return -1;
        }
        free(v);
    }
    if ((placeholder_len = cf_find_flag(&placeholder, "census", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (strcmp(v, "native") != 0) {
            snprintf(msg, STATUS_MAX,
                     "census=%s is not supported: the census is counted in this "
                     "process (census=native). Remove the option, or set it to "
                     "native.", v);
            free(v);
            return -1;
        }
        free(v);
    }

    /* mask=<preset> selects the LOG_CONFIG subscription:
     *   wardrive (default) -- curated WiGLE set (DIAG_TARGET_CODES), low volume.
     *   full               -- every advertised LOG code, HIGH volume.
     * nomask=true still wins (passive tap, no handshake at all). */
    int mask_full = 0;
    int mask_set = 0;   /* was mask= given explicitly? (gates the profile default) */
    if ((placeholder_len = cf_find_flag(&placeholder, "mask", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (strcmp(v, "wardrive") == 0) {
            mask_full = 0;
        } else if (strcmp(v, "full") == 0 || strcmp(v, "full-log") == 0) {
            mask_full = 1;
        } else {
            snprintf(msg, STATUS_MAX,
                     "Unknown mask preset '%s' (expected wardrive|full)", v);
            free(v);
            return -1;
        }
        mask_set = 1;
        free(v);
    }

    /* f3=<preset> arms the modem's F3 debug-message stream, orthogonal
     * to mask= (F3 rides DIAG_EXT_MSG_CONFIG_F, not LOG_CONFIG_F):
     *   off (default) -- no F3 arming; only the LOG mask above is applied.
     *   all           -- SET_ALL_RT_MASKS, every SSID at every severity. HIGH
     *                    volume; opt-in only. Composes with any mask= preset. */
    uint32_t f3_levels = 0;
    const char *f3_preset = "off";
    int f3_set = 0;   /* was f3= given explicitly? (gates the profile default) */
    if ((placeholder_len = cf_find_flag(&placeholder, "f3", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (!f3_preset_lookup(v, &f3_levels, &f3_preset, NULL)) {
            snprintf(msg, STATUS_MAX,
                     "Unknown f3 preset '%s' (expected " F3_PRESET_NAMES ")", v);
            free(v);
            return -1;
        }
        f3_set = 1;
        free(v);
    }

    /* qsh=on|off arms the full F3 surface as a gated tier over the same
     * DIAG fd -- the QSH-trace 0x9001 maskset (0x9D/0x92) + 0x60 events +
     * diag_id binding, not a second datasource (the port is flock-claimed and
     * most modems expose one DIAG interface). Off by default so a lean WiGLE
     * wardrive stays lean; only a development drive pays the QSH volume. QSH
     * emits no cell observations, so this never changes the phy_cell stream --
     * its value is in the rawlog= tee. Composes with f3=. */
    int qsh_on = 0;
    if ((placeholder_len = cf_find_flag(&placeholder, "qsh", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (strcmp(v, "on") == 0 || strcmp(v, "1") == 0 ||
            strcmp(v, "true") == 0) {
            qsh_on = 1;
        } else if (strcmp(v, "off") == 0 || strcmp(v, "0") == 0 ||
                   strcmp(v, "false") == 0) {
            qsh_on = 0;
        } else {
            snprintf(msg, STATUS_MAX,
                     "Unknown qsh value '%s' (expected on|off)", v);
            free(v);
            return -1;
        }
        free(v);
    }
    /* Seed on both paths from the parse, mirroring f3_relay -- arming itself is
     * live-only (needs the open fd), but the flag must be visible to the health
     * readout and the replay/disabled branches regardless. */
    local->qsh_on = qsh_on;

    /* rawpackets=on|off -- the raw DIAG stream into Kismet as DLT 147 packets
     * On by default: the .kismet is meant to be the drive's complete record,
     * and the raw stream is its most important part.
     * Independent of rawlog= (the external file tee), as cellat's RawAT is
     * of atlog=. Off exists for a host that cannot afford the volume -- the
     * kismetdb grows by what the rawlog= .hdlc would. An unknown value refuses
     * the open, like qsh=: a typo must not silently flip the in-db copy off. */
    local->rawpkt.on = 1;
    if ((placeholder_len = cf_find_flag(&placeholder, "rawpackets", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (strcmp(v, "on") == 0 || strcmp(v, "1") == 0 ||
            strcmp(v, "true") == 0) {
            local->rawpkt.on = 1;
        } else if (strcmp(v, "off") == 0 || strcmp(v, "0") == 0 ||
                   strcmp(v, "false") == 0) {
            local->rawpkt.on = 0;
        } else {
            snprintf(msg, STATUS_MAX,
                     "Unknown rawpackets value '%s' (expected on|off)", v);
            free(v);
            return -1;
        }
        free(v);
    }

    /* f3_relay must be seeded here, not only inside diag_bringup_run: the
     * whole local->bringup.* block below is live-path-only, so on a replay
     * source `f3=all` would parse cleanly and do nothing -- F3 never marked
     * armed, so the readout would not say what the operator asked for.
     *
     * Seeded here, from the parse, on both paths. The live bring-up may still
     * overwrite it with the profile-resolved value (an unset f3= can pick up a
     * per-modem f3_default keyed on the firmware string) -- which a replay
     * source has no way to look up, so the parsed value is final there. */
    local->f3_relay  = (f3_levels != 0);
    local->f3_levels = f3_levels;
    local->f3_preset = f3_preset;

    /* spc=<6 digits> sends a DIAG_SPC_F unlock before the LOG_CONFIG SET_MASK
     * EC2x/EG2x (MDM9607, e.g. EG25-G) gate SET_MASK behind the SPC;
     * SDX24/SDX55 don't. Absent by default (no SPC sent) -> unchanged behaviour
     * for the ungated modems; the profile's diag.spc default (below) supplies it
     * for a known-gated model without an explicit source option. */
    char spc_val[8] = "";
    int spc_set = 0;   /* was spc= given explicitly? (gates the profile default) */
    if ((placeholder_len = cf_find_flag(&placeholder, "spc", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        uint8_t probe[6];
        if (diag_config_build_spc(probe, sizeof(probe), v) != sizeof(probe)) {
            snprintf(msg, STATUS_MAX,
                     "Invalid spc='%s' (expected exactly 6 decimal digits, "
                     "e.g. spc=000000)", v);
            free(v);
            return -1;
        }
        strncpy(spc_val, v, sizeof(spc_val) - 1);
        spc_set = 1;
        free(v);
    }

    /* profiles=<dir> locates the capture_cell_at profile JSONs used for the
     * per-modem mask=/f3= defaults. Precedence: source option >
     * $CELLDIAG_PROFILES > compiled-in default. Empty => defaults not consulted. */
    char *profiles_dir = NULL;
    if ((placeholder_len = cf_find_flag(&placeholder, "profiles", definition)) > 0) {
        profiles_dir = strndup(placeholder, placeholder_len);
    } else {
        const char *env = getenv("CELLDIAG_PROFILES");
        profiles_dir = strdup(env && *env ? env : CELLDIAG_PROFILES_DEFAULT);
    }

    local->debug = 1;
    const char *debug_env = getenv("KISMET_CELLDIAG_DEBUG");
    if (debug_env && (strcmp(debug_env, "0") == 0 || strcmp(debug_env, "false") == 0))
        local->debug = 0;
    if ((placeholder_len = cf_find_flag(&placeholder, "debug", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        if (strcmp(v, "false") == 0 || strcmp(v, "0") == 0)
            local->debug = 0;
        else if (strcmp(v, "true") == 0 || strcmp(v, "1") == 0)
            local->debug = 1;
        free(v);
    }

    /* stats_interval=<sec> health-status cadence (0 disables). Default 30 so a
     * stalled modem surfaces without the operator opting in. */
    local->stats_interval = 30;
    if ((placeholder_len = cf_find_flag(&placeholder, "stats_interval", definition)) > 0) {
        char *v = strndup(placeholder, placeholder_len);
        long iv = strtol(v, NULL, 10);
        if (iv < 0)
            iv = 0;
        local->stats_interval = (time_t)iv;
        free(v);
    }
    diag_stats_init(&local->stats, time(NULL));

    /* clock_anchor_sec=<sec> -- periodic cadence of the host<->modem-ts64
     * ClockAnchor. Default 30 s, the value cellat's anchor
     * uses, so a fused drive's two transports anchor on the same beat. `0` turns
     * the periodic tick off; START and END still fire. A malformed value is
     * reported and the default kept -- a cadence that silently became 0 would
     * look like a working anchor that simply never ticked. */
    local->anchor.interval_ms = 30000;
    if ((placeholder_len = cf_find_flag(&placeholder, "clock_anchor_sec", definition)) > 0) {
        char *cav = strndup(placeholder, placeholder_len);
        if (cav != NULL) {
            char *endp = NULL;
            long secs = strtol(cav, &endp, 10);
            if (endp != cav && *endp == '\0' && secs >= 0) {
                local->anchor.interval_ms = (unsigned long)secs * 1000UL;
            } else {
                snprintf(buf, STATUS_MAX,
                         "%s ignoring invalid clock_anchor_sec='%s' (keeping %lus)",
                         local->name ? local->name : "celldiag", cav,
                         local->anchor.interval_ms / 1000);
                cf_send_message(caph, buf, MSGFLAG_ERROR);
            }
            free(cav);
        }
    }

    local->modem_imei = strdup(imei_def);

    /* --- resolve the DIAG source --- */
    if (local->disabled) {
        /* enabled=false: register the source but touch no hardware. We
         * do not even AT-probe for model/firmware - "does not open until
         * enabled" means no device I/O at all. The capture thread will idle. */
        local->diag_fd = -1;
        local->modem_model = strdup("DIAG disabled");
        local->modem_firmware = strdup("disabled");
        diag_stats_set_mask_preset(&local->stats, "disabled");
    } else if (local->replay_path) {
        /* Offline: no modem, no mask; the capture thread reads the file. */
        local->diag_fd = -1;
        local->modem_model = strdup("DIAG replay");
        local->modem_firmware = strdup(local->replay_path);
        diag_stats_set_mask_preset(&local->stats, "replay");
    } else {
        /* Live modem: nothing device-touching happens here. The AT IMEI
         * scan, DIAG port resolve+open, SPC unlock, LOG_CONFIG/F3 handshake and
         * decoder arm all move to diag_bringup_run(), run by capture_thread
         * (or inline below when defer=false). Provisional identity until the
         * bring-up learns the real model. */
        local->diag_fd = -1;
        local->modem_model = strdup("DIAG opening");
        local->modem_firmware = strdup("pending");
        diag_stats_set_mask_preset(&local->stats, "opening");

        snprintf(local->bringup.diagport_override,
                 sizeof(local->bringup.diagport_override), "%s",
                 diagport_override);
        snprintf(local->bringup.atport_override,
                 sizeof(local->bringup.atport_override), "%s",
                 atport_override);
        local->bringup.profiles_dir = profiles_dir;   /* ownership moves */
        profiles_dir = NULL;
        snprintf(local->bringup.spc_val, sizeof(local->bringup.spc_val), "%s",
                 spc_val);
        local->bringup.spc_set   = spc_set;
        local->bringup.mask_full = mask_full;
        local->bringup.mask_set  = mask_set;
        local->bringup.f3_levels = f3_levels;
        local->bringup.f3_preset = f3_preset;
        local->bringup.f3_set    = f3_set;
        local->bringup.qsh_on    = qsh_on;   /* gated full-F3 tier */
        local->bringup.pending   = 1;
        local->bringup.deferred  = defer;
    }

    free(profiles_dir);
    profiles_dir = NULL;

    /* --- interface info --- */
    char hw_desc[512];
    snprintf(hw_desc, sizeof(hw_desc), "%s IMEI:%s DIAG",
             local->modem_model, imei_def);
    local->name = strdup(hw_desc);

    /* --- run the bring-up inline when the operator opted out of deferral --- */
    if (local->bringup.pending && !defer) {
        if (diag_bringup_run(caph, local, msg, STATUS_MAX) != 0)
            return -1;
        /* diag_bringup_run replaced local->name with the real model. */
        snprintf(hw_desc, sizeof(hw_desc), "%s", local->name);
    }

    /* --- rawlog + helper for the non-live paths (the live path does both
     *     inside diag_bringup_run, where the model is known) --- */
    /* `!local->disabled` is load-bearing.
     *
     * The disabled branch above sets diag_fd = -1 and the "disabled" mask
     * preset, but it does not clear local->replay_path -- the option was
     * parsed, and parsing is not opening. Without the check an
     * `enabled=false,replay=<file>` source would fall into this block and
     * arm the decoder, while the status message below reports "no DIAG port
     * opened, no decoder started".
     *
     * Only replay is affected: a live disabled source has no replay_path and
     * never reaches here. But replay is exactly the configuration offline
     * tests use to verify the disabled path.
     *
     * Pinned by the celltools enabled=false replay tests. */
    if (!local->bringup.pending && local->replay_path && !local->disabled) {
        if (local->rawlog_spec) {
            char resolved[1024];
            if (diag_rawlog_resolve(local->rawlog_spec, imei_def,
                                    local->modem_model, time(NULL),
                                    resolved, sizeof(resolved)) != 0) {
                snprintf(msg, STATUS_MAX,
                         "rawlog path from '%s' is too long to resolve",
                         local->rawlog_spec);
                return -1;
            }
            local->rawlog_path = strdup(resolved);
        }
        decoder_bringup(caph, local);
    }

    (*ret_interface)->capif =
        strdup(local->diag_path ? local->diag_path :
               (local->replay_path ? local->replay_path : "diag"));
    (*ret_interface)->hardware = strdup(hw_desc);

    /* Same deterministic UUID the probe path registered. */
    compose_diag_uuid(imei_def, definition, uuid);
    /* The ClockAnchor source_name is this datasource's uuid, and capture_thread
     * only has `local` (cellat keeps the same copy). */
    free(local->source_uuid);
    local->source_uuid = (*uuid != NULL) ? strdup(*uuid) : NULL;

    if (local->disabled)
        snprintf(buf, STATUS_MAX, "Cell DIAG source %s registered but DISABLED "
                 "(enabled=false) - no DIAG port opened, no decoder started; "
                 "re-enable to start capture", local->name);
    else if (local->bringup.pending)
        /* The open command is answered now, well inside Kismet's
         * deadline; the modem bring-up runs next in the capture thread and
         * reports its own success/failure on the message bus. */
        snprintf(buf, STATUS_MAX, "Cell DIAG source celldiag-%s accepted; "
                 "opening modem in the background (deferred bring-up)", imei_def);
    else
        snprintf(buf, STATUS_MAX, "Cell DIAG source %s opened (%s%s)",
                 local->name,
                 local->replay_path ? "replay " : "live ",
                 local->replay_path ? local->replay_path :
                    (local->no_mask ? "passive/no-mask" : local->diag_path));
    cf_send_message(caph, buf, MSGFLAG_INFO);

    return 1;
}

/* A cached DIAG GNSS fix older than this (seconds) is not attached to a
 * cell_observation -- better an ungeotagged cell than one pinned to a stale
 * position after the vehicle has moved. */
#define DIAG_GPS_MAX_AGE_S 30

/* Extract an unquoted JSON number for `key` from a flat one-line object into
 * *out. Returns 1 on success, 0 if the key is absent or unparseable. Minimal
 * (no nested-object descent): the census line's top-level `*_total` keys are
 * unique, so a quoted-key+colon match is unambiguous. */
static int json_extract_number(const char *json, const char *key, double *out) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\":", key);
    const char *p = strstr(json, pat);
    if (!p)
        return 0;
    p += strlen(pat);
    while (*p == ' ' || *p == '\t')
        p++;
    char *endp = NULL;
    double v = strtod(p, &endp);
    if (endp == p)
        return 0;
    *out = v;
    return 1;
}

/* Room for the census table's own control line.
 *
 * Sized from the producer's own bound, not from a round number: the census caps
 * the table at 24 rows, and the worst-case row (u64 maxima in all five counters,
 * all three flags) is 120 bytes -> 2,880. 4096 clears that with headroom and is
 * still a stack buffer.
 *
 * Deliberately not STATUS_MAX (1024). That is the size that forced this onto
 * its own line in the first place; reusing it here would reintroduce the
 * truncation one layer down, where the symptom is a table that silently ends
 * mid-row rather than a budget overrun anyone measures. */
#define DIAG_CENSUS_TABLE_MAX 4096

/* Is every byte of the census table within the alphabet the producer declares?
 *
 * The table is a delimited string rather than JSON precisely because that
 * alphabet needs no escaping -- so this is the assertion that the premise holds,
 * and the reason the relay can build its object with a bare snprintf. Hex digits
 * and decimal digits (0-9 A-F a-f), the structural bytes `x/v,;`, the `-`
 * no-flags placeholder, and the flag letters `s`/`u`/`e`, plus `n`
 * (undecoded_native, native census only; `e` is already covered by the hex
 * range, spelled out anyway so the vocabulary is readable here).
 *
 * Written as an allow-list. A deny-list of `"` and `\` would pass any future
 * byte nobody thought of. */
static int census_table_alphabet_ok(const char *s) {
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        if ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f') ||
            (*p >= 'A' && *p <= 'F'))
            continue;
        if (*p == 'x' || *p == '/' || *p == 'v' || *p == ',' || *p == ';' ||
            *p == '-' || *p == 's' || *p == 'u' || *p == 'n')
            continue;
        return 0;
    }
    return 1;
}

/* Relay one diag_inventory census line (diag_inventory.c's rendering). Never
 * forwarded raw (the line can outgrow a frame): its `status` goes to the
 * message bus, its counts into the diag_stats cache, its `table` onto the
 * diag_census control line. */
static void relay_census_line(kis_capture_handler_t *caph, local_diag_t *local,
                              const char *line) {
    /* The three flag counts, read once and used by both blocks below (the
     * escalation and the stats cache). The `*_total` integers, never the
     * arrays' lengths: the arrays are bounded on the wire
     * (DIAG_INVENTORY_WIRE_LIST_MAX), so their length is not the count.
     *
     * The alarm count is `silent_actionable_total`, not `silent_total`. They
     * differ by the codes that cannot emit on any capture -- currently just
     * 0x14D8, whose lat/lon/alt read 0.0, so it parses 100% and emits 0% on
     * every healthy source. Escalating on `silent_total` would escalate
     * always, i.e. no signal at all. The census keeps printing the full
     * `silent[...]` list; this changes only what escalates. */
    uint64_t unrec_n = 0, silent_n = 0, enrich_n = 0;
    int got_u, got_s, got_e;
    {
        double d;
        if ((got_u = json_extract_number(line, "unrecognized_total", &d)))
            unrec_n = d > 0 ? (uint64_t)d : 0;
        if ((got_s = json_extract_number(line, "silent_actionable_total", &d)))
            silent_n = d > 0 ? (uint64_t)d : 0;
        if ((got_e = json_extract_number(line, "enrich_failed_total", &d)))
            enrich_n = d > 0 ? (uint64_t)d : 0;
    }

    char st[STATUS_MAX];
    if (diag_profile_json_string(line, "status", st, sizeof(st))) {
        /* Escalate the census line from INFO to ERROR when any finding is
         * non-zero, so it stands out instead of scrolling past among routine
         * INFO lines:
         *   unrecognized  -- the early warning that a firmware emits something
         *                    no known layout covers (usually new firmware);
         *   silent        -- an emit-contract code that parsed and produced
         *                    nothing: on a live source indistinguishable from
         *                    "no cells in range", the failure this census
         *                    exists to make visible. Gated to the contract
         *                    codes; ungated it would fire on nearly every key
         *                    of a wardriving capture, i.e. permanently;
         *   enrich_failed -- a record a leg understood and then lost in its own
         *                    mapping layer, counted rather than fatal. */
        int flagged = (got_u && unrec_n > 0) || (got_s && silent_n > 0) ||
                      (got_e && enrich_n > 0);
        cf_send_message(caph, st, flagged ? MSGFLAG_ERROR : MSGFLAG_INFO);
    }
    /* Cache the census counters for the structured stats
     * object. The message-bus line above is for a human tailing the
     * log; these three are what the datasource sets into
     * inventory_{distinct_codes,unrecognized,silent}, which is the
     * only path by which a web UI can ever show them.
     *
     * `valid` flips on the first census and never back. Until then
     * the keys are omitted entirely rather than sent as zeros --
     * "0 unrecognized" and "no census yet" are opposite readings. */
    {
        double dcount = 0;
        int got_d = json_extract_number(line, "distinct", &dcount);
        /* All three or nothing: a partial census would publish a
         * distinct-code count next to a stale unrecognized count,
         * which reads as authoritative and is not. */
        if (got_d && got_u && got_s) {
            local->inventory.distinct =
                dcount > 0 ? (uint64_t)dcount : 0;
            local->inventory.unrecognized = unrec_n;
            local->inventory.silent = silent_n;
            local->inventory.valid = 1;
            /* The third state. Read when present and never escalated: it is a
             * coverage to-do list, not a finding about the stream. */
            double un = 0;
            if (json_extract_number(line, "undecoded_native_total", &un)) {
                local->inventory.undecoded_native = un > 0 ? (uint64_t)un : 0;
                local->inventory.undecoded_valid = 1;
            }
        }
    }
    /* Relay the census table on its own control line.
     *
     * It cannot ride diag_stats: 24 rows of a realistic census
     * render to ~620 bytes against DIAG_STATS_EXTRA_MAX = 768,
     * worst case 2,880. Adding it would blow the budget and trip
     * diag_stats' drop_path retry -- which degrades by silently
     * dropping rawlog_path: valid JSON, all counters present, one
     * registered field permanently dead, and it would look correct.
     * diag_stats.h already warns that "the retry is a last-resort
     * degradation, not a sizing strategy".
     *
     * Extracted with the existing diag_profile_json_string(), the
     * same way status / mask_preset / rawlog_path already travel --
     * no JSON parser enters this binary for the web UI's benefit. */
    {
        char tbl[DIAG_CENSUS_TABLE_MAX];
        if (diag_profile_json_string(line, "table",
                                     tbl, sizeof(tbl))) {
            /* The producer's contract is that every character is a
             * hex digit, a decimal digit, or from `x/v,;-` plus the
             * flag alphabet -- which is why this needs no escaping.
             * Checked rather than trusted: an out-of-alphabet byte
             * means the producer contract broke, and emitting it
             * raw would put a quote or backslash into the object
             * and fail the consumer's parse, taking the whole line
             * with it. Omitting the table and saying so out loud
             * keeps the failure attributable -- a silently dropped
             * table is the census's own blindness one layer up. */
            if (census_table_alphabet_ok(tbl)) {
                char cbuf[DIAG_CENSUS_TABLE_MAX + 32];
                struct timeval ctv;
                /* "type" is carried in the body as well as in the
                 * mpack routing field, matching diag_stats. The
                 * mpack type is what the datasource dispatches on;
                 * the body copy is what makes the line
                 * self-describing to anything holding the JSON
                 * alone -- a tee'd log, a human. A control line indistinguishable from an
                 * observation by its own content is how one ends up
                 * silently counted as one. */
                int n = snprintf(cbuf, sizeof(cbuf),
                                 "{\"type\":\"diag_census\","
                                 "\"table\":\"%s\"}", tbl);
                if (n > 0 && (size_t)n < sizeof(cbuf)) {
                    gettimeofday(&ctv, NULL);
                    cf_send_json(caph, NULL, 0, NULL, NULL, ctv,
                                 "diag_census", cbuf);
                }
            } else {
                cf_send_message(caph,
                    "celldiag: census table contains characters "
                    "outside its declared alphabet -- table "
                    "omitted, counters unaffected",
                    MSGFLAG_ERROR);
            }
        }
    }
}

/* -----------------------------------------------------------------------
 * Decoder liveness
 *
 * The contract is at local_diag_t.live. This block holds the watchdog: its
 * cadence, its judgment and what it tells the server. The heartbeat itself is
 * stamped at the top of the read loop in capture_thread_run.
 * ----------------------------------------------------------------------- */

/* The watchdog judges every LIVE_TICK_NS and sleeps in LIVE_SLICE_NS pieces,
 * so a stop is seen within one slice. A stall is reported within bound + one
 * tick of the reader's last pass. Slices, not a condition variable: a
 * monotonic timed wait has no portable spelling (Darwin has no
 * pthread_condattr_setclock), and a wall-clock one sleeps through a clock step. */
#define LIVE_TICK_NS   500000000ULL
#define LIVE_SLICE_NS  100000000L
#define LIVE_BOUND_NS  ((uint64_t)DIAG_STATS_DECODER_STALL_SEC * 1000000000ULL)

/* One judgment of the reader's heartbeat, and what the server is told about
 * it. Runs on the watchdog thread, and once on the capture thread at arm time,
 * before the watchdog exists -- never on both at once. */
static void live_tick(kis_capture_handler_t *caph, local_diag_t *local) {
    /* A source being stopped is not a stalled one. A graceful close spends its
     * grace on the END exchange; a shutdown cancels the reader outright. */
    if (caph->shutdown || cf_handler_close_requested(caph) ||
            __atomic_load_n(&local->capture_exited, __ATOMIC_ACQUIRE))
        return;

    /* The heartbeat is read before the clock, so a reader that beats in
     * between is judged fresh (diag_stats_heartbeat_stale: hb after now). */
    uint64_t hb  = __atomic_load_n(&local->live.hb_ns, __ATOMIC_ACQUIRE);
    uint64_t now = anchor_mono_ns();
    int stale    = diag_stats_heartbeat_stale(hb, now, LIVE_BOUND_NS);
    int stalled  = local->live.stalled;

    if (stale && !stalled) {
        stalled = 1;
        local->live.stall_hb_ns = hb;
        local->live.last_line_ns = 0;      /* the first line goes out now */
    } else if (!stale && stalled) {
        stalled = 0;
        char m[STATUS_MAX];
        snprintf(m, sizeof(m),
                 "%s nativedecode=only: the decoder is alive again -- the DIAG "
                 "reader advanced after %llu s without progress",
                 local->name ? local->name : "celldiag",
                 (unsigned long long)((hb - local->live.stall_hb_ns) /
                                      1000000000ULL));
        cf_send_message(caph, m, MSGFLAG_INFO);
    }
    local->live.stalled = stalled;

    /* The panel's field, on each change of state. A send the ring will not
     * take is not marked as reported, so it is retried next tick: an alarm
     * lost to a full ring would leave the panel reading the last state it
     * heard. */
    int alive = !stalled;
    if (alive != local->live.reported) {
        char js[128];
        if (diag_stats_format_liveness_json(alive, "native-only",
                                            js, sizeof(js)) > 0) {
            struct timeval tv;
            gettimeofday(&tv, NULL);
            if (cf_send_json(caph, NULL, 0, NULL, NULL, tv, "diag_stats", js) > 0)
                local->live.reported = alive;
        }
    }

    /* The verdict line, at once and then on the stats cadence while the stall
     * lasts. The reader prints the regular line and is the thread that is
     * stuck, so without this the cadence would simply go quiet. A monitor
     * keyed on the verdict word would read that silence as nothing at all. */
    if (stalled) {
        uint64_t every = local->stats_interval > 0
                             ? (uint64_t)local->stats_interval * 1000000000ULL : 0;
        if (local->live.last_line_ns == 0 ||
                (every > 0 && now - local->live.last_line_ns >= every)) {
            char m[STATUS_MAX];
            if (diag_stats_format_decoder_stalled((now - hb) / 1000000ULL,
                                                  LIVE_BOUND_NS / 1000000ULL,
                                                  m, sizeof(m)) > 0 &&
                    cf_send_message(caph, m, MSGFLAG_ERROR) > 0)
                local->live.last_line_ns = now;
        }
    }
}

static void *live_thread(void *arg) {
    local_diag_t *local = (local_diag_t *)arg;
    uint64_t next = anchor_mono_ns() + LIVE_TICK_NS;
    while (!__atomic_load_n(&local->live.stop, __ATOMIC_ACQUIRE)) {
        struct timespec ts = { .tv_sec = 0, .tv_nsec = LIVE_SLICE_NS };
        nanosleep(&ts, NULL);
        if (__atomic_load_n(&local->live.stop, __ATOMIC_ACQUIRE))
            break;
        uint64_t now = anchor_mono_ns();
        if (now < next)
            continue;
        next = now + LIVE_TICK_NS;
        live_tick(local->live.caph, local);
    }
    return NULL;
}

/* Arm the heartbeat and start the watchdog. The first judgment runs here,
 * synchronously, so even a replay that finishes before the watchdog's first
 * tick has told the server its decoder was alive -- judged from the heartbeat
 * just stamped, by the same code that later reports a stall. Returns -1 when
 * the watchdog cannot be started: the source could then never report a stall,
 * and a liveness it cannot withdraw is the hard-coded 1 this replaces. */
static int live_start(kis_capture_handler_t *caph, local_diag_t *local) {
    local->live.caph = caph;
    local->live.reported = -1;
    local->live.stalled = 0;
    local->live.stall_hb_ns = 0;
    local->live.last_line_ns = 0;
    __atomic_store_n(&local->live.stop, 0, __ATOMIC_RELEASE);
    __atomic_store_n(&local->live.hb_ns, anchor_mono_ns(), __ATOMIC_RELEASE);
    local->live.armed = 1;
    live_tick(caph, local);
    /* The reader's own lines: it prints only while it runs (local_diag_t.live). */
    diag_stats_set_helper_alive(&local->stats, !local->live.stalled);

    int old, rc;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old);
    pthread_mutex_lock(&local->live.lock);
    rc = pthread_create(&local->live.tid, NULL, live_thread, local);
    local->live.started = (rc == 0);
    pthread_mutex_unlock(&local->live.lock);
    pthread_setcancelstate(old, NULL);
    if (rc != 0) {
        local->live.armed = 0;
        errno = rc;            /* pthread_create returns it; errno is untouched */
        return -1;
    }
    return 0;
}

/* Stop and join the watchdog. Idempotent, and safe from either of the two
 * threads that call it (the capture thread's teardown, main() after the loop):
 * one of them joins, the other returns. Cancellation is held off around the
 * lock, because the capture thread is cancelled asynchronously at shutdown,
 * and a cancel inside the lock would leave main() waiting on it forever. */
static void live_stop(local_diag_t *local) {
    int old, started;
    pthread_t tid;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old);
    pthread_mutex_lock(&local->live.lock);
    started = local->live.started;
    tid = local->live.tid;
    local->live.started = 0;
    pthread_mutex_unlock(&local->live.lock);
    if (started) {
        __atomic_store_n(&local->live.stop, 1, __ATOMIC_RELEASE);
        pthread_join(tid, NULL);
    }
    pthread_setcancelstate(old, NULL);
}

/* The structured stats line for an enabled=false source.
 *
 * Why this exists: the server's celldiag fields are set from the `diag_stats`
 * JSON line alone, not the human `stats:` text line. With only the text line a
 * disabled source reports nothing: helper_alive sits at its default 0 and
 * mask_preset at "", and the panel renders the source -- which Kismet shows
 * as running, because it opened successfully -- as a red "Decoder DEAD
 * -- observations have stopped". An intentionally idle source would read as
 * a failure.
 *
 * It carries exactly two facts, both true: no decoder was started
 * (helper_alive 0) and the preset is the "disabled" sentinel the open path
 * already sets. No counter is sent -- nothing was measured, and a row of zeros
 * would read as "running and seeing nothing", the same misreading from the
 * other side. The panel keys on mask_preset == "disabled". */
static void send_disabled_stats(kis_capture_handler_t *caph) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    int r = cf_send_json(caph, NULL, 0, NULL, NULL, tv, "diag_stats",
                         "{\"type\":\"diag_stats\",\"helper_alive\":0,"
                         "\"mask_preset\":\"disabled\"}");
    if (r == 0)
        cf_handler_wait_ringbuffer(caph);
}

/* One ModemIdentity record per open -- the modem the bring-up just
 * identified, sent to the server, which installs its label as this source's
 * hardware (replacing the placeholder "DIAG opening") and logs it as a
 * kismetdb data row. Nothing for
 * a replay or a disabled source: neither read a modem. */
static void send_modem_identity(kis_capture_handler_t *caph, local_diag_t *local) {
    char label[512], rec[1024];

    if (!local->ident_method[0])
        return;
    modemident_label(&local->ident, " DIAG", label, sizeof(label));
    if (modemident_json(&local->ident, "celldiag", local->ident_method,
                        local->ident_at_port, label, rec, sizeof(rec)) != 0)
        return;

    struct timeval tv;
    gettimeofday(&tv, NULL);
    /* 0 == ring buffer full: wait for room and offer it once more, as the
     * ClockAnchor sender does. It is one row per open; losing it to a moment of
     * back-pressure would leave the container unable to name this modem. */
    if (cf_send_json(caph, NULL, 0, NULL, NULL, tv, MODEMIDENT_TYPE, rec) == 0) {
        cf_handler_wait_ringbuffer(caph);
        (void)cf_send_json(caph, NULL, 0, NULL, NULL, tv, MODEMIDENT_TYPE, rec);
    }
}

static void capture_thread_run(kis_capture_handler_t *caph) {
    local_diag_t *local = (local_diag_t *)caph->userdata;
    char errstr[ERRBUF_MAX];

    /* enabled=false: idle until the server closes/reaps us. Nothing was
     * opened (no port, no helper, no rawlog), so there is nothing to read or
     * tear down - just tick the health cadence so an operator sees the source
     * is intentionally disabled, and spin down cleanly on shutdown. */
    if (local->disabled) {
        /* At once, not one stats_interval (30 s) from now: the panel must not
         * spend the first half-minute calling a disabled source dead. */
        send_disabled_stats(caph);
        while (!caph->shutdown && !cf_handler_close_requested(caph)) {
            time_t snow = time(NULL);
            if (diag_stats_due(&local->stats, local->stats_interval, snow)) {
                char sbuf[STATUS_MAX];
                diag_stats_format(&local->stats, snow, local->stats_interval,
                                  sbuf, sizeof(sbuf));
                cf_send_message(caph, sbuf, MSGFLAG_INFO);
                send_disabled_stats(caph);
                diag_stats_mark_status(&local->stats, snow);
            }
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 250000000 };
            nanosleep(&ts, NULL);
        }
        cf_handler_spindown(caph);
        return;
    }

    /* Deferred live-modem bring-up. open_callback answered Kismet's
     * open command immediately; the multi-second device work happens here, off
     * that critical path. A failure is reported as a per-source error, which
     * gets the same recovery Kismet already applies (5 s re-open) -- but the
     * open itself does not race the deadline, so the ERROR line means a real
     * bring-up failure. */
    int src_fd;
    int replay_fd = -1;

    if (local->bringup.pending) {
        char berr[STATUS_MAX];
        berr[0] = '\0';
        g_bringup_caph = caph;   /* progress lines per phase */
        int brc = diag_bringup_run(caph, local, berr, sizeof(berr));
        g_bringup_caph = NULL;
        if (brc != 0) {
            snprintf(errstr, ERRBUF_MAX,
                     "celldiag-%s bring-up failed after %ld ms: %s",
                     local->modem_imei ? local->modem_imei : "?",
                     local->bringup.elapsed_ms,
                     berr[0] ? berr : "unknown error");
            /* The reason as fields, before the helper exits -- the
             * message below reaches the bus, but the source's own error would
             * otherwise read "IPC connection closed". */
            bringup_progress_send(caph, local->bringup.phase_detail,
                                  local->bringup.elapsed_ms,
                                  berr[0] ? berr : "unknown error");
            /* ...and the spindown stats line below must agree with it: it
             * re-sends mask_preset, which still read "opening". */
            diag_stats_set_mask_preset(&local->stats, "failed");
            diag_report_error(caph, errstr);
            /* Fall through to `done:` -- not a bare return. cf_handler_spindown
             * is what lets the framework deliver the error above; skipping it
             * makes the failure surface as a bare "IPC connection closed" and
             * the real reason is lost. */
            goto done;
        }
        /* The elapsed figure is the work kept out of Kismet's open-command
         * deadline. Printing it makes the bring-up cost measurable instead of
         * inferred. */
        snprintf(errstr, ERRBUF_MAX,
                 "Cell DIAG source %s opened (live %s) -- bring-up took %ld ms "
                 "off the open critical path [%s]",
                 local->name,
                 local->no_mask ? "passive/no-mask" : local->diag_path,
                 local->bringup.elapsed_ms,
                 local->bringup.phase_detail[0] ? local->bringup.phase_detail
                                                : "no phase detail");
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        /* ...and the finished figure as fields. */
        bringup_progress_send(caph, local->bringup.phase_detail,
                              local->bringup.elapsed_ms, NULL);
    }

    /* After the bring-up, deferred (just above) or inline (open_callback,
     * defer=false): either way the identity is resolved by now. */
    send_modem_identity(caph, local);

    src_fd = local->diag_fd;
    if (local->replay_path) {
        replay_fd = open(local->replay_path, O_RDONLY);
        if (replay_fd < 0) {
            snprintf(errstr, ERRBUF_MAX, "%s cannot open replay file %s: %s",
                     local->name, local->replay_path, strerror(errno));
            diag_report_error(caph, errstr);
            goto done;
        }
        /* Refuse a compressed container loudly. Without this the
         * deframer walks the compressed bytes and reports RX-NO-OBS on a real
         * capture -- see replay_container_magic() for why refusing beats
         * linking libzstd here. */
        const char *container = NULL, *decompress_with = NULL;
        if ((container = replay_container_magic(replay_fd,
                                                &decompress_with)) != NULL) {
            snprintf(errstr, ERRBUF_MAX,
                     "%s replay file %s is a %s-compressed container, not a raw "
                     "DIAG capture. celldiag deframes raw HDLC and would decode "
                     "the COMPRESSED bytes as records -- yielding 0 "
                     "observations and a RX-NO-OBS health line on a capture "
                     "that has cells in it. Decompress it first (%s) and point "
                     "replay= at the result.",
                     local->name, local->replay_path, container,
                     decompress_with);
            diag_report_error(caph, errstr);
            close(replay_fd);
            replay_fd = -1;
            goto done;
        }
        src_fd = replay_fd;
    }

    /* Open the raw-DIAG tee sink (rawlog=). Failing to create the file the
     * operator explicitly asked for is a hard error - better than silently
     * decoding without the capture they wanted.
     *
     * The runtime setter can act before this point: the source answers its
     * open before the device work that precedes this. A stop it applied is
     * honoured here, and a sink a runtime rawlog=<path> opened is the tee, so
     * this open is skipped. Both are read under rawlog_lock, and read again
     * after the open, which a knob can also overtake. */
    pthread_mutex_lock(&local->rawlog_lock);
    int tee_stopped = local->rawlog_stopped;
    int tee_redirected = local->rawlog_fd >= 0;
    char tee_path[1024];
    snprintf(tee_path, sizeof(tee_path), "%s",
             local->rawlog_path ? local->rawlog_path : "");
    pthread_mutex_unlock(&local->rawlog_lock);
    if (tee_path[0] && tee_stopped) {
        snprintf(errstr, ERRBUF_MAX,
                 "%s rawlog=off was applied before the capture began; the raw "
                 "DIAG tee to %s is not opened", local->name, tee_path);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
    } else if (tee_path[0]) {
        /* Never O_TRUNC. Every reopen of this source is a new
         * helper, so a fixed rawlog= path would be truncated by each one,
         * leaving only the last session's tee beside a kismetdb holding all
         * of them. A non-empty file is an earlier session's tee, and this
         * session gets its own stamped sibling -- one tee per kismetdb DIAG
         * stream, so the two can be compared. The companion and clock-anchor
         * sidecars key off
         * rawlog_path, so they follow the diverted name. */
        char session_path[1024];
        int diverted = 0;
        int overtaken = 0;
        if (!tee_redirected) {
            int tee_fd = diag_rawlog_open_session(tee_path, time(NULL),
                                                  session_path,
                                                  sizeof(session_path),
                                                  &diverted);
            if (tee_fd < 0) {
                snprintf(errstr, ERRBUF_MAX, "%s cannot open rawlog file %s: %s",
                         local->name, tee_path, strerror(errno));
                diag_report_error(caph, errstr);
                if (replay_fd >= 0)
                    close(replay_fd);
                goto done;
            }
            pthread_mutex_lock(&local->rawlog_lock);
            if (local->rawlog_stopped || local->rawlog_fd >= 0) {
                /* A runtime rawlog= landed during the open, and it wins. */
                close(tee_fd);
                overtaken = 1;
                diverted = 0;
            } else {
                local->rawlog_fd = tee_fd;
                if (diverted) {
                    char *prev = local->rawlog_path;
                    local->rawlog_path = strdup(session_path);
                    snprintf(errstr, ERRBUF_MAX,
                             "%s rawlog file %s already holds an earlier "
                             "session's tee; this session tees to %s so "
                             "neither is overwritten",
                             local->name, prev, session_path);
                    free(prev);
                }
            }
            pthread_mutex_unlock(&local->rawlog_lock);
        }
        if (diverted)
            cf_send_message(caph, errstr, MSGFLAG_INFO);
        pthread_mutex_lock(&local->rawlog_lock);
        int tee_open = !local->rawlog_stopped && local->rawlog_fd >= 0;
        snprintf(tee_path, sizeof(tee_path), "%s",
                 local->rawlog_path ? local->rawlog_path : "");
        pthread_mutex_unlock(&local->rawlog_lock);
        if (tee_open) {
            snprintf(errstr, ERRBUF_MAX, "%s teeing raw DIAG stream to %s%s",
                     local->name, tee_path,
                     (tee_redirected || overtaken) ?
                         " (the runtime rawlog= that preceded the capture)" : "");
            cf_send_message(caph, errstr, MSGFLAG_INFO);
        } else {
            snprintf(errstr, ERRBUF_MAX,
                     "%s rawlog=off was applied while the tee was opening; "
                     "the raw DIAG tee to %s is not running",
                     local->name, tee_path);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
        }

        if (!tee_open)
            goto tee_done;   /* no tee, so no provenance to write beside it */

        /* Companion capture-config provenance sidecar:
         * <rawlog>.capture_meta.json next to the .hdlc, recording the host
         * clock at open + the arm-time config only celldiag knows. Not a
         * vendor-attribution source; this is open-time provenance. The
         * ts64<->UTC anchors arrive all capture long and go to their own
         * <rawlog>.clock_anchor.jsonl (see anchor_complete).
         *
         * Non-fatal: a failed sidecar must never kill the capture the operator
         * asked for. Warn and continue -- the .hdlc is the deliverable. */
        char capmeta_path[1024];
        /* 1536: make + product_model ride beside the 256-byte
         * firmware; a record that does not fit is not written at all. */
        char capmeta_rec[1536];
        if (diag_capmeta_sidecar_path(local->rawlog_path, capmeta_path,
                                      sizeof(capmeta_path)) == 0 &&
            diag_capmeta_format(
                capmeta_rec, sizeof(capmeta_rec), time(NULL),
                local->modem_imei, local->modem_model, local->modem_firmware,
                local->ident.make, local->ident.model,
                strcmp(local->ident_method, MODEMIDENT_METHOD_AT) == 0 ?
                    DIAG_CAPMETA_IDENTITY_AT :
                strcmp(local->ident_method, MODEMIDENT_METHOD_VOUCHED) == 0 ?
                    DIAG_CAPMETA_IDENTITY_VOUCHED :
                local->ident_held ? DIAG_CAPMETA_IDENTITY_HELD :
                                    DIAG_CAPMETA_IDENTITY_NONE,
                local->stats.mask_preset, local->f3_preset, local->diag_path,
                diag_capmeta_basename(local->rawlog_path)) == 0 &&
            diag_capmeta_write(capmeta_path, capmeta_rec,
                               strlen(capmeta_rec)) == 0) {
            snprintf(errstr, ERRBUF_MAX, "%s wrote capture_meta sidecar %s",
                     local->name, capmeta_path);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
        } else {
            snprintf(errstr, ERRBUF_MAX,
                     "%s could not write the capture_meta sidecar for %s "
                     "(provenance only; capture continues)",
                     local->name, local->rawlog_path);
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
        }
    }
tee_done:

    diag_stats_set_port_open(&local->stats, 1);

    /* The raw-packet slicer. Started here -- before the handshake
     * flush below -- so offset 0 is the first byte feed_bytes sees, the same
     * first byte a rawlog= tee opened just above writes. The session id is the
     * host clock now: it tells two streams of one datasource apart (Kismet
     * re-spawns a failed source, and each spawn starts again at offset 0).
     * Not fatal if the allocation fails: capture and rawlog= go on without it. */
    if (local->rawpkt.on) {
        local->rawpkt.s = (diag_rawpkt_t *)malloc(sizeof(diag_rawpkt_t));
        if (local->rawpkt.s == NULL) {
            snprintf(errstr, ERRBUF_MAX,
                     "%s could not allocate the raw-packet slicer; the kismetdb "
                     "will carry no raw DIAG stream this capture (rawlog= and "
                     "decoding are unaffected)", local->name);
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
        } else {
            struct timespec rt;
            clock_gettime(CLOCK_REALTIME, &rt);
            uint64_t session = (uint64_t)rt.tv_sec * 1000000000ULL +
                               (uint64_t)rt.tv_nsec;
            /* CELLDIAG_RAWPKT_SESSION_ID: a test hook, like
             * CELLDIAG_SCAN_PORTS. A test that forges a CRC32 collision between
             * a slice and some other packet must know the slice's bytes, and the
             * session id is in its header. Never set it for a real capture: two
             * streams sharing an id could not be told apart by a reader. */
            const char *sid = getenv("CELLDIAG_RAWPKT_SESSION_ID");
            if (sid != NULL && *sid) {
                char *end = NULL;
                unsigned long long v = strtoull(sid, &end, 10);
                if (end != NULL && *end == '\0')
                    session = (uint64_t)v;
            }
            diag_rawpkt_init(local->rawpkt.s, session);
        }
    }

    /* Arm the native decoder. Allocated here rather than at parse time so the
     * enabled=false path stays allocation-free along with fd- and sink-free: a
     * defined-but-idle source returns before this point and never touches it.
     * It is the only decoder, so a failed allocation fails the source. */
    {
        local->native_stream = (diag_logstream_t *)malloc(sizeof(diag_logstream_t));
        if (local->native_stream == NULL) {
            snprintf(errstr, ERRBUF_MAX,
                     "%s could not allocate the native decoder", local->name);
            diag_report_error(caph, errstr);
            goto done;
        }
        {
            diag_logstream_init(local->native_stream);
            /* Same not-fatal rule as the stream above: a NULL map means
             * diag_native_sib1_learn/_enrich no-op and the tap decodes
             * unenriched, which is strictly better than refusing to capture. */
            local->native_sib1_map = diag_native_sib1_map_new();
            if (local->native_sib1_map == NULL) {
                snprintf(errstr, ERRBUF_MAX,
                         "%s could not allocate the SIB1 identity cache; the "
                         "decoder will report enriched=0 regardless of what "
                         "the stream carries", local->name);
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
            }
            /* The GNSS freshness reference, on the same not-fatal
             * rule: a NULL tracker leaves the staleness gate OFF and the tap
             * decoding per record -- which re-opens the 13.68 h re-served-fix
             * hole, so it is reported, not silent. */
            local->native_gnss_tracker = diag_native_gnss_tracker_new(
                diag_native_gnss_default_max_fix_age_ms());
            if (local->native_gnss_tracker == NULL) {
                snprintf(errstr, ERRBUF_MAX,
                         "%s could not allocate the GNSS freshness tracker; the "
                         "native GNSS gate will NOT refuse stale (re-served) "
                         "fixes this run", local->name);
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
            }
            /* The census, armed with the decoder that feeds it, on the stats
             * interval when set, else 30 s. A failed allocation is loud rather
             * than fatal, as above -- but it is a lost census, not a degraded
             * one: nothing else counts. */
            {
                local->native_inv = diag_inventory_new(0, 0);
                if (local->native_inv == NULL) {
                    snprintf(errstr, ERRBUF_MAX,
                             "%s could not allocate the census; this session "
                             "publishes NO diag_inventory census", local->name);
                    cf_send_message(caph, errstr, MSGFLAG_ERROR);
                } else {
                    struct timeval itv;
                    /* The census this process takes has the third state:
                     * a known-layout code no native leg reads is
                     * undecoded_native, not unrecognized. */
                    diag_inventory_set_native_coverage(local->native_inv, 1);
                    gettimeofday(&itv, NULL);
                    diag_inventory_cadence_arm(&local->native_inv_cadence,
                        local->stats_interval > 0 ? (double)local->stats_interval
                                                  : 30.0,
                        (double)itv.tv_sec + (double)itv.tv_usec / 1e6);
                }
            }
            /* The GSMTAP sink, when gsmtap= asked for one. A socket that will
             * not open is loud: nothing else sends these frames. */
            local->gsmtap_native.fd = -1;
            if (local->gsmtap_on &&
                    diag_gsmtap_sink_open(&local->gsmtap_native,
                                          local->gsmtap_dest) != 0) {
                snprintf(errstr, ERRBUF_MAX,
                         "%s gsmtap (native): cannot open a UDP socket to %s "
                         "(%s); NO GSMTAP frames this session",
                         local->name, local->gsmtap_dest, strerror(errno));
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
            }
            char nbuf[STATUS_MAX];
            uint16_t codes[16];
            uint16_t gcodes[16];
            size_t ncodes = diag_native_codes(codes, 16);
            /* Listed as its own group, not appended to the cell list:
             * the two sets route to different entry points, and an operator
             * reading "5 native legs" would reasonably expect
             * diag_native_has_leg() to answer true for all five. */
            size_t ngcodes = diag_native_gps_codes(gcodes, 16);
            int off = snprintf(nbuf, sizeof(nbuf),
                               "%s nativedecode=only armed; %zu cell leg(s):",
                               local->name, ncodes);
            for (size_t i = 0; i < ncodes && off > 0 && (size_t)off < sizeof(nbuf); i++)
                off += snprintf(nbuf + off, sizeof(nbuf) - (size_t)off,
                                " 0x%04X", codes[i]);
            if (off > 0 && (size_t)off < sizeof(nbuf))
                off += snprintf(nbuf + off, sizeof(nbuf) - (size_t)off,
                                "; %zu GNSS leg(s):", ngcodes);
            for (size_t i = 0; i < ngcodes && off > 0 && (size_t)off < sizeof(nbuf); i++)
                off += snprintf(nbuf + off, sizeof(nbuf) - (size_t)off,
                                " 0x%04X", gcodes[i]);
            cf_send_message(caph, nbuf, MSGFLAG_INFO);
        }
    }

    /* The CRC census window starts with the first byte fed below. */
    local->crc_watch.since = time(NULL);

    /* The decoder is armed (the tap above), so its liveness starts being
     * judged here -- before the first feed_bytes below, which can stall the
     * same way the read loop can. */
    if (live_start(caph, local) != 0) {
        snprintf(errstr, ERRBUF_MAX,
                 "%s could not start the decoder watchdog (%s); it is what "
                 "reports a stalled decoder, and a source that cannot report "
                 "one must not claim a live one",
                 local->name, strerror(errno));
        diag_report_error(caph, errstr);
        if (replay_fd >= 0)
            close(replay_fd);
        goto done;
    }

    /* The DIAGID-table reply the qsh=on bring-up consumed. It was read
     * before the bytes still buffered below, so it goes first. In the stream,
     * an offline HDLC walk finds it in both the rawlog tee and the kismetdb
     * raw packets -- without it a drive's diag_id_binding would be empty. */
    if (!local->replay_path && local->diagid_wire_len > 0) {
        size_t n = local->diagid_wire_len;
        local->diagid_wire_len = 0;
        feed_bytes(caph, local, local->diagid_wire, n);
    }

    /* Flush bytes the LOG_CONFIG handshake already buffered into the shared
     * reader before draining the live port (live path only). */
    if (!local->replay_path && local->reader.pos < local->reader.len) {
        size_t rem = local->reader.len - local->reader.pos;
        feed_bytes(caph, local, local->reader.buf + local->reader.pos, rem);
    }

    /* START clock anchor. Issued after the handshake flush so
     * no byte the scanner looks at predates the request, and seeds the periodic
     * timer so the first periodic tick is a full interval later. The reply is
     * picked out of the stream by the read loop below. */
    if (anchor_live(local)) {
        local->anchor.started = 1;
        anchor_request(local, "start", ANCHOR_REPLY_TIMEOUT_NS);
        local->anchor.last_ms = anchor_mono_ns() / 1000000ULL;
    }

    int closing = 0;
    while (!caph->shutdown) {
        /* The decoder's heartbeat. Every pass stamps it,
         * idle poll timeouts included, so a quiet port is not a stalled
         * decoder; only a pass that never comes back is (local_diag_t.live). */
        if (local->live.armed)
            __atomic_store_n(&local->live.hb_ns, anchor_mono_ns(),
                             __ATOMIC_RELEASE);

        /* Graceful close: stop reading once the END exchange is done,
         * then fall through to `done:` -- final stats, the END raw slice, the
         * QSH disarm -- all with the pipe still open. */
        if (cf_handler_close_requested(caph)) {
            closing = 1;
            if (!anchor_close_step(local))
                break;
        }

        /* Health status cadence. Checked at the top of every iteration
         * - including idle (0-byte) ticks - so a stalled source is reported
         * within one interval, using the interval itself as the stall window. */
        time_t snow = time(NULL);
        if (diag_stats_due(&local->stats, local->stats_interval, snow)) {
            char sbuf[STATUS_MAX];
            diag_stats_format(&local->stats, snow, local->stats_interval,
                              sbuf, sizeof(sbuf));
            cf_send_message(caph, sbuf, MSGFLAG_INFO);
            /* Structured companion: the machine-parseable counters the
             * kis_datasource_cell_diag consumer sets into its tracker fields.
             * Routed as its own mpack type ("diag_stats", not "CellModem"), so
             * the datasource intercepts it and phy_cell never builds a device
             * from it. Emitted before mark_status so obs_per_sec reflects this
             * interval's throughput, matching the human line above. */
            char jbuf[2048];   /* > STATUS_MAX (see DIAG_STATS_EXTRA_MAX) */
            /* Config- and census-owned fields are layered in by the site
             * that owns them -- diag_stats.c is pure libc and knows nothing
             * of the f3 option, the rawlog sink, or the helper's census. */
            crc_damage_check(caph, local, snow);   /* before the JSON */
            diag_stats_extra_t sx;
            fill_stats_extra(local, &sx);
            if (diag_stats_format_json_ex(&local->stats, &sx, snow,
                                          jbuf, sizeof(jbuf)) > 0) {
                struct timeval jtv;
                gettimeofday(&jtv, NULL);
                cf_send_json(caph, NULL, 0, NULL, NULL, jtv, "diag_stats", jbuf);
            }
            /* The decoder's readout, on the same cadence as the health line so
             * the two are read together: "N observations flowed, and the
             * native legs covered M% of the records that produced them". Its
             * own line rather than a field on diag_stats, so the datasource's
             * stats-field contract does not churn with it. */
            char ntbuf[STATUS_MAX];
            if (native_tap_format(local, ntbuf, sizeof(ntbuf)) > 0)
                cf_send_message(caph, ntbuf, MSGFLAG_INFO);
            diag_stats_mark_status(&local->stats, snow);
        }

        /* Clock anchor: expire an unanswered request, issue the
         * periodic one when due. Every pass -- idle ones included -- so the
         * cadence holds on a quiet port. */
        if (!closing)
            anchor_tick(caph, local);

        uint8_t rbuf[65536];
        struct pollfd fds[1];
        fds[0].fd = src_fd;            fds[0].events = POLLIN;
        fds[0].revents = 0;

        int pr = poll(fds, 1, 250);
        if (pr < 0) {
            if (errno == EINTR)
                continue;
            break;
        }

        if (fds[0].revents & POLLIN) {
            ssize_t n = read(src_fd, rbuf, sizeof(rbuf));
            /* Stamped here, before feed_bytes: the decode and emit inside it
             * take time that is not part of the modem's round trip. */
            uint64_t recv_mono_ns = anchor_mono_ns();
            if (n < 0) {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                diag_stats_on_read_error(&local->stats);
                break;
            }
            if (n == 0) {
                /* Replay: EOF, finish (the residual frame is flushed at
                 * `done:`). Live: a 0-byte read is a VTIME idle tick, keep
                 * going. */
                if (local->replay_path)
                    break;
                continue;
            }
            feed_bytes(caph, local, rbuf, (size_t)n);
            anchor_on_bytes(caph, local, rbuf, (size_t)n, recv_mono_ns);
        } else if (fds[0].revents & (POLLHUP | POLLERR)) {
            break;
        }
    }

    if (replay_fd >= 0)
        close(replay_fd);
    goto done;

done:
    /* The reader has left its loop, so the watchdog's judgment ends here.
     * Joined before the final stats below, so no liveness object can land
     * after the "decoder stopped" one. */
    live_stop(local);
    local->live.armed = 0;
    local->emit_finishing = 1;     /* the port is no longer read */
    /* The native census's final snapshot, so a finished replay or a stopped
     * source leaves a complete census even when no interval elapsed. Ahead of
     * the final diag_stats below, so inventory_* carry the final counts. The
     * residual frame is
     * flushed first, or the last record of a replay would miss the census;
     * the flush in the native block further down is then a no-op. */
    if (local->native_inv != NULL && local->native_stream != NULL) {
        native_tap_ctx_t ictx = { .caph = caph, .local = local };
        struct timeval itv;
        diag_logstream_flush(local->native_stream, native_tap_cb, &ictx);
        gettimeofday(&itv, NULL);
        native_census_emit(caph, local,
                           (double)itv.tv_sec + (double)itv.tv_usec / 1e6);
    }
    diag_stats_set_port_open(&local->stats, 0);
    diag_stats_set_helper_alive(&local->stats, 0);
    /* One-shot final health line so a finished replay / stopped source leaves a
     * totals summary on the bus even if stats_interval never fired. */
    {
        time_t fnow = time(NULL);
        char sbuf[STATUS_MAX];
        diag_stats_format(&local->stats, fnow,
                          local->stats_interval > 0 ? local->stats_interval : 30,
                          sbuf, sizeof(sbuf));
        cf_send_message(caph, sbuf, MSGFLAG_INFO);

        /* The structured companion is needed here as well as the human line
         * above. It matters most for the census: its last (and on a short
         * run, its only) snapshot is taken just above, after the last cadence
         * tick. Without a final structured emit the datasource's inventory_*
         * fields never see a census at all, so they read 0 -- "every code
         * recognized" -- while the status line reports unrecognized keys.
         *
         * Also the correct final state generally: port_open/helper_alive were
         * just cleared above, so this is the tick that tells the server the
         * source stopped rather than leaving stale live-looking counters. */
        /* The last CRC window too -- a burst after the final cadence tick,
         * or a whole replay with stats_interval=0, is otherwise never judged. */
        crc_damage_check(caph, local, fnow);
        diag_stats_extra_t fsx;
        char fjbuf[2048];
        fill_stats_extra(local, &fsx);
        if (diag_stats_format_json_ex(&local->stats, &fsx, fnow,
                                      fjbuf, sizeof(fjbuf)) > 0) {
            struct timeval ftv;
            gettimeofday(&ftv, NULL);
            cf_send_json(caph, NULL, 0, NULL, NULL, ftv, "diag_stats", fjbuf);
        }
    }
    /* Final native-decode totals. Flush first: the last frame of a finished
     * replay has no chunk after it, so its record only exists if the residual
     * is processed at end-of-stream -- without the flush every run would come
     * up one record short. */
    if (local->native_stream != NULL) {
        char ntbuf[STATUS_MAX];
        native_tap_ctx_t fctx = { .caph = caph, .local = local };
        diag_logstream_flush(local->native_stream, native_tap_cb, &fctx);
        crc_census_row(caph, local);   /* after the flush, before the free */
        if (native_tap_format(local, ntbuf, sizeof(ntbuf)) > 0)
            cf_send_message(caph, ntbuf, MSGFLAG_INFO);
        free(local->native_stream);
        local->native_stream = NULL;
        /* Freed after native_tap_format, which reads the map's live size for the
         * final readout. Freeing with the stream above would print 0 keys on the
         * one line an offline replay run is actually read from. */
        diag_native_sib1_map_free(local->native_sib1_map);
        local->native_sib1_map = NULL;
        /* After native_tap_format for the same reason: it prints unjudged=. */
        diag_native_gnss_tracker_free(local->native_gnss_tracker);
        local->native_gnss_tracker = NULL;
        diag_inventory_free(local->native_inv);
        local->native_inv = NULL;
        /* GsmtapLive.report(): the tap's three counts, once, at the end. */
        if (local->gsmtap_native.fd >= 0) {
            char gbuf[STATUS_MAX];
            int go = snprintf(gbuf, sizeof(gbuf), "%s ", local->name);
            if (go > 0 && (size_t)go < sizeof(gbuf))
                diag_gsmtap_sink_report(&local->gsmtap_native, gbuf + go,
                                        sizeof(gbuf) - (size_t)go);
            cf_send_message(caph, gbuf, MSGFLAG_INFO);
            diag_gsmtap_sink_close(&local->gsmtap_native);
        }
    }
    /* Before spindown, while the pipe can still carry the residual slice and
     * the totals line. */
    rawpkt_finish(caph, local);
    if (local->rawlog_fd >= 0) {
        close(local->rawlog_fd);
        local->rawlog_fd = -1;
    }
    /* Disarm the QSH-trace latch if this capture armed it. The latch
     * survives reboots, so leaving it set floods the next capture on
     * this modem with QSH/event frames (~1,322 per cell frame on SDX62, see the
     * startup disarm rationale). The helper has been reaped and the read loop
     * has ended, so the fd is idle: fire-and-forget over the still-open fd
     * (diag_config_disarm_latched sends the QSH-trace + F3 disarms with no ack
     * read), before serial_close_fd below. Gated on qsh_armed so a lean
     * wardrive / f3-only run sends nothing extra at stop. This is the "finally"
     * half of the try/finally the arm site opened.
     *
     * The arm also turned on the 0x60 event stream, which disarm_latched does
     * not touch, so it is turned off here too; otherwise 0x60 events keep
     * streaming after a qsh=on stop (REST or Ctrl-C) even though 0x9D stops. */
    diag_fd_release(local);   /* + the LOG mask this capture armed */
    cf_handler_spindown(caph);
}

/* Cleanup handler: runs when capture_thread_run returns and when the thread is
 * cancelled. An atomic store is all it does -- async-signal-safe, which
 * matters because the cancel is asynchronous. main()'s END anchor waits on it
 * before reading the DIAG fd itself. */
static void capture_thread_mark_exited(void *arg) {
    __atomic_store_n(&((local_diag_t *)arg)->capture_exited, 1, __ATOMIC_RELEASE);
}

void capture_thread(kis_capture_handler_t *caph) {
    pthread_cleanup_push(capture_thread_mark_exited, caph->userdata);
    capture_thread_run(caph);
    pthread_cleanup_pop(1);
}

/* -----------------------------------------------------------------------
 * main
 * ----------------------------------------------------------------------- */

int main(int argc, char *argv[]) {
    /* Tag this binary's reported version with the decode path it was built for
     * ("native" = the native C++ legs).  Set before anything parses argv,
     * because --version is answered during that parse and would otherwise
     * report an untagged string. */
    cf_version_extra = CELLDIAG_NATIVE_MODE;

    local_diag_t local = {
        .diag_path = NULL,
        .replay_path = NULL,
        .rawlog_spec = NULL,
        .rawlog_path = NULL,
        .modem_imei = NULL,
        .modem_firmware = NULL,
        .modem_model = NULL,
        .name = NULL,
        .diag_fd = -1,
        .rawlog_fd = -1,
        .no_mask = 0,
        .disabled = 0,
        .debug = 0,
        .gsmtap_native = { .fd = -1 },
        /* Static initialiser rather than a pthread_mutex_init() call: `local`
         * is a stack object in main() with a whole-program lifetime, and an
         * initialiser cannot be forgotten on a path that returns early. */
        .rawlog_lock = PTHREAD_MUTEX_INITIALIZER,
        .anchor = { .interval_ms = 30000 },   /* set for real in open_callback */
        .source_uuid = NULL,
        .capture_exited = 0,
        .live = { .lock = PTHREAD_MUTEX_INITIALIZER, .reported = -1 },
    };

    /* A dead helper must not kill us with SIGPIPE mid-write; we detect the
     * broken pipe via write()'s EPIPE return instead. */
    signal(SIGPIPE, SIG_IGN);

    kis_capture_handler_t *caph = cf_handler_init("celldiag");
    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    cf_handler_set_userdata(caph, &local);
    cf_handler_set_open_cb(caph, open_callback);
    cf_handler_set_probe_cb(caph, probe_callback);
    cf_handler_set_listdevices_cb(caph, list_callback);
    cf_handler_set_capture_cb(caph, capture_thread);
    /* The runtime option setter. Both are required: without the
     * translate hook the framework strdup()s the raw string and hands us a
     * char*, and without the control hook capture_framework.c answers "source
     * does not support channel configuration" before either is reached. */
    cf_handler_set_chantranslate_cb(caph, celldiag_chantranslate);
    cf_handler_set_chancontrol_cb(caph, celldiag_chancontrol);
    /* Stop on the server's CLOSEREQ with the pipe still open, so the END
     * anchor, the END raw slice and the QSH disarm all run and reach the
     * kismetdb. The grace covers a periodic DIAG_TS_F in flight (2 s) + END
     * (1 s) + the helper reap (~1 s). */
    cf_handler_set_close_grace(caph, CELLDIAG_CLOSE_GRACE_MS);

    int r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    cf_handler_remote_capture(caph);
    cf_jail_filesystem(caph);
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);

    /* The capture thread's teardown normally stopped the watchdog already.
     * When the loop ended first (the server went away), stop it here, before
     * the shutdown cancels the reader: a reader cancelled under a watchdog
     * still running would be judged a stall on its way out. */
    live_stop(&local);

    cf_handler_shutdown(caph);

    /* END clock anchor -- here, not in capture_thread; see anchor_end(). */
    anchor_end(&local);

    if (local.diag_fd >= 0)
        close(local.diag_fd);
    free(local.diag_path);
    free(local.replay_path);
    free(local.rawlog_spec);
    free(local.rawlog_path);
    free(local.modem_imei);
    free(local.modem_firmware);
    free(local.modem_model);
    free(local.name);
    free(local.source_uuid);

    return 0;
}
