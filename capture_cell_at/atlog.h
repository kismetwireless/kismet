/* atlog.h - raw AT command/response transcript tee for the cellat source.
 *
 * `atlog=<spec>` tees every AT command+response exchange to disk as JSONL, one
 * record per exchange, host-timestamped, WHILE cellat is also decoding the
 * response into Kismet observations. It sits at the single AT-exchange seam
 * (at_command_t in capture_cell_at.c), so the file holds exactly the exchanges
 * the decoder saw.
 *
 * PRIMARY PURPOSE — a self-contained raw AT capture. atlog is fully DIAG-
 * INDEPENDENT: an AT-only drive (no celldiag source anywhere) can arm atlog=
 * and get the complete, host-timestamped record of every command sent and
 * response received, so that when a drive misbehaves you can go back and see
 * exactly what the modem was asked and what it answered. Nothing below the
 * libc layer, and nothing in the capture path, requires a concurrent DIAG
 * capture to exist. (This module is the AT-side analogue of celldiag's
 * `rawlog=`, but the two are independent capture products — either can run
 * alone.)
 *
 * WHY JSONL and not the existing text `transcript=`. `transcript=` is a
 * human-readable debug log ([ISO8601] TX:/RX: lines, wall-clock only). This is
 * a corpus DATA PRODUCT — one machine-ingestable record per exchange:
 *
 *   {"ts_mono_ns": <u64>, "ts_utc": "<ISO8601 us>", "cmd": "...",
 *    "response": "...", "duration_ms": <float>, "err": null|"...",
 *    "tx_done_ns": <u64>|null, "first_rx_ns": <u64>|null,
 *    "rx_done_ns": <u64>|null}
 *
 * ts_mono_ns (host CLOCK_MONOTONIC ns) orders exchanges monotonically within
 * the AT capture itself (an NTP step mid-drive cannot reorder them); ts_utc is
 * the wall-clock secondary.
 *
 * ts_mono_ns is the instant BEFORE the command is sent, and duration_ms runs
 * from there to the end of the whole exchange, so on their own they cannot say
 * where the time went or when the answer arrived. The last three keys
 * split the exchange, on the same clock as ts_mono_ns:
 *
 *   tx_done_ns  - ts_mono_ns   host TX cost (flush + write)
 *   first_rx_ns - tx_done_ns   modem think-time (to the first response line)
 *   rx_done_ns  - first_rx_ns  response transfer (plus host per-byte read cost)
 *
 * and rx_done_ns is when the answer was complete, the instant to geotag a
 * reported cell at, rather than ts_mono_ns, when it was asked for (at 80 mph
 * that is ~3.6 cm per ms of exchange). null means the exchange never got there:
 * rx_done_ns is null for an exchange that ended on a timeout or EOF rather than
 * OK/ERROR/+CME ERROR. What each instant measures exactly is documented on
 * at_timing_t in at_serial.inc.
 *
 * New keys go at the END, never between existing ones. A reader that indexes
 * by name is unaffected either way, but kismetdb_to_atlog reproduces this line
 * byte for byte and consumers compare records that way.
 *
 * SECONDARY (BONUS) — DIAG correlation. The schema is aligned field-for-field
 * with an offline DIAG/AT-poll correlator, so IF a DIAG capture was running
 * concurrently, that same ts_mono_ns lets the correlator align AT exchanges
 * to DIAG frames (which carry no host clock) with no shim.
 * This is an optional consumer of an already-complete AT product, never a
 * requirement of it.
 *
 * The file is written UNCOMPRESSED live; compress it (e.g. to .zst) after the
 * capture, never inline.
 *
 * The path templating, JSON escaping, and record formatting are libc-only (no
 * Kismet, no serial, no DIAG) so they are unit-tested standalone in test_atlog.c
 * (`make check` in this directory), the same factoring as diag_rawlog.
 */
#ifndef ATLOG_H
#define ATLOG_H

#include <stddef.h>
#include <stdint.h>
#include <time.h>

/* Resolve an atlog= spec into a concrete file path. Mirrors
 * diag_rawlog_resolve token-for-token:
 *   %i -> IMEI, %m -> model (sanitized to [A-Za-z0-9._-]), %t -> UTC
 *   "YYYYmmddTHHMMSSZ", %% -> literal '%'.
 * If the expanded spec names an existing directory, or ends in '/', a filename
 * "cellat-<imei>-<ts>.jsonl" is synthesized inside it so concurrent per-modem
 * sources never collide. IMEI and model are path-sanitized (a garbled/hostile
 * IMEI carrying '/' or a wholly-dot ".."/"." component cannot inject a
 * separator or climb the tree).
 * Writes a NUL-terminated result to `out`. Returns 0 on success, -1 if the
 * result would not fit in `outsz` (out left untouched on overflow). */
int atlog_resolve(const char *spec, const char *imei, const char *model,
                  time_t now, char *out, size_t outsz);

/* JSON-escape src[0..len) into out (bounded by outsz, always NUL-terminated on
 * success). Escapes '"' and '\\' as short escapes, the C0 control set as
 * \b \f \n \r \t or \u00XX, and passes everything else (incl. '/', UTF-8 high
 * bytes) through unchanged. Returns the number of bytes written (excluding the
 * NUL), or -1 on overflow (out then holds a truncated-but-terminated prefix).
 * A NULL src is treated as empty. */
int atlog_json_escape(const char *src, size_t len, char *out, size_t outsz);

/* Format ONE JSONL record (including the trailing '\n') into out, bounded by
 * outsz. Field order and names match the DIAG/AT-poll correlator's schema.
 *   ts_mono_ns : host CLOCK_MONOTONIC nanoseconds
 *   ts_utc     : caller-formatted ISO8601 string (emitted as-is, JSON-escaped)
 *   cmd        : the AT command line sent (JSON-escaped)
 *   response   : the full raw response (JSON-escaped)
 *   duration_ms: exchange wall time, emitted with 2 decimals
 *   err        : NULL -> JSON null; else a JSON-escaped string
 *   tx_done_ns, first_rx_ns, rx_done_ns : host CLOCK_MONOTONIC ns, or 0 for
 *                "never reached" -> JSON null
 * Returns 0 on success, -1 on overflow (out untouched-or-truncated; caller
 * treats the record as dropped and counts it). */
int atlog_format_record(char *out, size_t outsz,
                        uint64_t ts_mono_ns, const char *ts_utc,
                        const char *cmd, const char *response,
                        double duration_ms, const char *err,
                        uint64_t tx_done_ns, uint64_t first_rx_ns,
                        uint64_t rx_done_ns);

/* Write the whole buffer to fd, retrying short writes. Returns 0 on success,
 * -1 on error (errno set) - e.g. a full disk or a vanished path. */
int atlog_write(int fd, const char *buf, size_t len);

#endif /* ATLOG_H */
