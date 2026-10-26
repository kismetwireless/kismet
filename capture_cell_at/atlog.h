/* atlog.h - the RawAT record: every AT command+response exchange cellat makes,
 * as one JSON line, host-timestamped, sent to Kismet as a RawAT data row
 * (kismetdb_to_atlog writes them back out as a .jsonl file). It is built at the
 * single AT-exchange seam (at_command_t in capture_cell_at.c), so the rows hold
 * exactly the exchanges the decoder saw.
 *
 *   {"ts_mono_ns": <u64>, "ts_utc": "<ISO8601 us>", "cmd": "...",
 *    "response": "...", "duration_ms": <float>, "err": null|"...",
 *    "tx_done_ns": <u64>|null, "first_rx_ns": <u64>|null,
 *    "rx_done_ns": <u64>|null}
 *
 * ts_mono_ns (host CLOCK_MONOTONIC ns) orders exchanges within the capture (an
 * NTP step mid-drive cannot reorder them); ts_utc is the wall-clock secondary.
 * ts_mono_ns is the instant BEFORE the command is sent and duration_ms runs to
 * the end of the exchange; the last three keys split it, on the same clock:
 *
 *   tx_done_ns  - ts_mono_ns   host TX cost (flush + write)
 *   first_rx_ns - tx_done_ns   modem think-time (to the first response line)
 *   rx_done_ns  - first_rx_ns  response transfer (plus host per-byte read cost)
 *
 * null means the exchange never got there: rx_done_ns is null for an exchange
 * that ended on a timeout or EOF rather than OK/ERROR/+CME ERROR. What each
 * instant measures is documented on at_timing_t in at_serial.inc.
 *
 * New keys go at the END, never between existing ones: kismetdb_to_atlog
 * reproduces this line byte for byte and consumers compare records that way.
 *
 * libc-only, so test_atlog.c (`--enable-cell-selftest`) runs it standalone.
 */
#ifndef ATLOG_H
#define ATLOG_H

#include <stddef.h>
#include <stdint.h>

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

#endif /* ATLOG_H */
