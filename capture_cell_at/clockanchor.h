/* clockanchor.h - host<->modem-RTC clock-anchor record for the cellat source
 * (the clock-anchor/1 contract).
 *
 * The cellat source periodically issues AT+CCLK? and emits a "ClockAnchor" row
 * into the kismetdb `data` table (via cf_send_json) that pairs the HOST clock
 * (authoritative wall-clock + monotonic) with the MODEM RTC reading, at capture
 * START, END and every `clock_anchor_sec=` seconds in between. From >=2 such
 * rows (start + end) a post-processor computes the host<->modem offset and drift
 * for an AT-only drive with NO other transport present (no DIAG ts64, no GNSS
 * 0x1476): skew must be recoverable from a single transport.
 *
 * DIVISION OF LABOUR -- why the AT+CCLK? exchange and the ClockAnchor row are
 * two separate products:
 *   - The raw AT+CCLK? exchange rides the normal at_command_t() seam, so it is
 *     already teed into the atlog= file AND the RawAT kismetdb row,
 *     host-timestamped. That raw exchange is the primary record.
 *   - This ClockAnchor row is the STRUCTURED metadata layer: it lifts the parsed
 *     modem reading next to the host clock in one uniform schema shared with the
 *     DIAG transport, so downstream skew analysis needs no per-transport
 *     special-casing.
 *
 * WHY source_clock_value IS THE RAW CCLK STRING (not a normalised UTC).
 * AT+CCLK? returns `+CCLK: "yy/MM/dd,hh:mm:ss(+/-)zz"` where zz is a signed
 * quarter-hour TZ. 3GPP TS 27.007 says the hh:mm:ss field is LOCAL time and zz
 * the offset to GMT -- but observed firmware disagrees: a network-synced Quectel
 * RM520N-GL returns the time field already in UTC while STILL tagging a nonzero
 * zz (for example `"26/09/21,22:02:23-24"` read at host UTC 22:02:2x, i.e.
 * NOT local-minus-6h). So "normalise to UTC" cannot be done correctly in this
 * layer from the string alone -- the interpretation is firmware-dependent. The
 * honest anchor is therefore (host_utc, raw modem string): the post-processor
 * resolves the interpretation with firmware knowledge, and the host pairing is
 * what actually bounds the skew regardless. We store the raw string verbatim and
 * add no lossy guess. (Precision observed across EG25-G / LM960A18 / RM520N-GL:
 * whole SECONDS on every firmware.)
 *
 * Like atlog.c and cellat_options.c, this is a libc-only translation unit (no
 * Kismet, no serial) so cclk_extract() and the record formatter are unit-tested
 * standalone in test_clockanchor.c (`make check` in this directory).
 */
#ifndef CLOCKANCHOR_H
#define CLOCKANCHOR_H

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

/* Extract the quoted datetime payload from an AT+CCLK? response into `out`
 * (NUL-terminated on success). Given a response containing
 *   +CCLK: "26/09/21,22:02:23-24"
 * writes `26/09/21,22:02:23-24` (the bytes BETWEEN the quotes, outer quotes
 * stripped). Tolerant of the leading CRLF, "+CCLK:" with or without a space, and
 * trailing "OK". Returns 0 on success, -1 if no `+CCLK:` + quoted value is
 * present or the value does not fit in `outsz`. A NULL/empty response is -1.
 *
 * The value is emitted verbatim as the ClockAnchor `source_clock_value`; see the
 * file header for why it is NOT normalised here. */
int cclk_extract(const char *resp, char *out, size_t outsz);

/* Format ONE ClockAnchor JSON record (including the trailing '\n') into `out`,
 * bounded by `outsz`. Field order/names match the clock-anchor/1 contract:
 *
 *   {"schema": "clock-anchor/1", "transport": "<t>", "source_name": "<s>",
 *    "seq": <u64>, "edge": "<e>", "host_utc": "<iso>", "host_mono_ns": <u64>,
 *    "source_clock_kind": "<k>", "source_clock_value": "<v>"}
 *
 * The schema tag is constant ("clock-anchor/1"). Every free-form string
 * (transport, source_name, edge, host_utc, source_clock_kind,
 * source_clock_value) is JSON-escaped. A NULL string field is emitted as an
 * empty string, never JSON null (a ClockAnchor with a missing field is a bug,
 * and "" surfaces it more usefully than null). Returns 0 on success, -1 on
 * overflow (caller treats the record as dropped). */
int clockanchor_format_record(char *out, size_t outsz,
                              const char *transport, const char *source_name,
                              uint64_t seq, const char *edge,
                              const char *host_utc, uint64_t host_mono_ns,
                              const char *source_clock_kind,
                              const char *source_clock_value);

/* The same record with `host_rtt_ns` appended as a 10th field -- the
 * shape the DIAG anchor carries, so the two transports stay
 * uniform. host_utc / host_mono_ns are then the MIDPOINT of the window in which
 * the modem read its clock, and host_rtt_ns that window's width: the anchor is
 * wrong by at most host_rtt_ns / 2. Same return contract. */
int clockanchor_format_record_rtt(char *out, size_t outsz,
                                  const char *transport, const char *source_name,
                                  uint64_t seq, const char *edge,
                                  const char *host_utc, uint64_t host_mono_ns,
                                  const char *source_clock_kind,
                                  const char *source_clock_value,
                                  uint64_t host_rtt_ns);

/* The midpoint of a clock-read window [mono_lo, mono_hi] on the host's
 * MONOTONIC clock, and the wall clock at that midpoint. For AT+CCLK?
 * the window is the exchange's [tx_done_ns, first_rx_ns]: the modem
 * read its RTC after the command left the host and before the first byte of
 * its answer. (tv_ref, mono_ref) is ONE wall/monotonic pair taken together
 * before the exchange; the wall clock at the midpoint is tv_ref plus the
 * MONOTONIC distance to it, so a wall-clock step inside the exchange cannot skew
 * it (the diag_clockanchor_midpoint rule). A window with mono_hi < mono_lo is
 * zero-width at mono_lo; a midpoint before mono_ref keeps tv_ref. */
void clockanchor_bracket(const struct timeval *tv_ref, uint64_t mono_ref,
                         uint64_t mono_lo, uint64_t mono_hi,
                         struct timeval *tv_mid, uint64_t *mono_mid,
                         uint64_t *rtt_ns);

#endif /* CLOCKANCHOR_H */
