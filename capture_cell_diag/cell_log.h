/* cell_log.h - the CellLog kismetdb rows both cell capture helpers write.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The provenance and debug detail the helpers used to write to side files
 * (celldiag's capture_meta sidecar, cellat's AT transcript) is sent instead as
 * `CellLog` JSON records, which kismetdb keeps as rows in `data`.
 * kismetdb_to_celllog reads them back.
 *
 * Record contract, schema "cell-log/1" (a string value that is NULL or empty
 * is OMITTED):
 *
 *   schema      "cell-log/1"
 *   src         "cellat" | "celldiag"
 *   kind        "session"  once per capture: what was opened and how
 *               "log"      one debug event; sent only with debug=true
 *   ts_utc      ISO 8601 UTC, microseconds
 *   ts_mono_ns  host CLOCK_MONOTONIC, the axis RawAT and ClockAnchor use
 *
 *   session:    the caller's key/value pairs, all strings
 *   log:        dir   "TX" | "RX" | "RX-LATE" | "RX-DROP" | "note"
 *               text  the event; binary frames are lowercase hex
 *               text_len  the full length, present only when text was cut
 *
 * libc only, so test_cell_log runs with no modem and no framework.
 */

#ifndef CELL_LOG_H
#define CELL_LOG_H

#include <stddef.h>
#include <stdint.h>
#include <sys/time.h>

#define CELL_LOG_TYPE    "CellLog"
#define CELL_LOG_SCHEMA  "cell-log/1"

/* One record must fit one server frame; see CELLAT_ROW_JSON_MAX. */
#define CELL_LOG_ROW_MAX 12288

typedef struct {
    const char *key;
    const char *value;
} cell_log_kv_t;

/* Format a session record into out. Returns 0, or -1 on overflow / bad args
 * (out is then ""). */
int cell_log_session_json(char *out, size_t outsz, const char *src,
                          const struct timeval *tv, uint64_t mono_ns,
                          const cell_log_kv_t *kv, size_t nkv);

/* Format a log record into out. text[0..textlen) is cut to fit outsz rather
 * than failing; text_len then records the full length. Returns 0, or -1 when
 * not even the fixed fields fit. */
int cell_log_entry_json(char *out, size_t outsz, const char *src,
                        const struct timeval *tv, uint64_t mono_ns,
                        const char *dir, const char *text, size_t textlen);

/* Lowercase hex of buf[0..len) into out, NUL-terminated, stopping at a whole
 * byte when out is full. Returns the number of input bytes rendered. */
size_t cell_log_hex(const uint8_t *buf, size_t len, char *out, size_t outsz);

#endif /* CELL_LOG_H */
