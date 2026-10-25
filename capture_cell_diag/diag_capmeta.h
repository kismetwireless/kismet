/* diag_capmeta.h - capture-config provenance sidecar for celldiag rawlog.
 *
 * When `rawlog=` opens a raw-HDLC tee (diag_rawlog.h), celldiag also writes a
 * companion JSON sidecar next to the `.hdlc` recording the CAPTURE CONFIGURATION
 * that only the datasource authoritatively knows at open time:
 *
 *   {"schema": "celldiag-capmeta/1",
 *    "host_utc_start": "2026-09-20T17:00:00Z",   <- time(NULL) at rawlog open
 *    "imei": "...", "model": "...", "firmware": "...",
 *    "make": "Quectel", "product_model": "RM500Q-AE", "identity": "at",
 *    "mask_preset": "wardrive", "f3_preset": "all+norelay",
 *    "diag_node": "/dev/mhi_DIAG", "rawlog": "celldiag-<imei>-<ts>.hdlc"}
 *
 * SCOPE: this is PROVENANCE, not modem ATTRIBUTION. Vendor/model attribution
 * of a drive is supplied by the operator in a separate `capture_meta_<ts>.json`.
 * celldiag has no vendor string and its "model" is the firmware id it probed,
 * so it does NOT claim to be an attribution source. The sidecar name
 * `<rawlog>.capture_meta.json` deliberately does NOT match a
 * `capture_meta_*.json` glob (no `capture_meta_` prefix), so the two never
 * collide. What this file uniquely carries is the arm-time config (mask/f3
 * preset), the exact host clock at rawlog open, the verified IMEI/firmware, and
 * the DIAG node. The host-UTC <-> modem-ts64 clock anchors are NOT appended
 * here: they arrive throughout the capture, so they live in their own
 * append-only <rawlog>.clock_anchor.jsonl (diag_clockanchor.h).
 *
 * NOTE: `model` is celldiag's %m -- the FIRMWARE id the bring-up read, a build
 * string, NOT a product model. `make` / `product_model` are the modem's
 * own AT+CGMI / AT+CGMM answers, the same two values the ModemIdentity record
 * carries (diag_modemident.h), so a tee's companion names a Telit or Sierra
 * unit whose build string ("32.01.110") names no product on its own. "" when
 * the bring-up did not read them.
 *
 * `identity` says whether model/firmware were READ: "at" (the modem
 * answered over AT), "vouched" (read over AT by the process holding the
 * AT port -- the paired cellat -- and validated here), "unresolved-held-by-sibling" (the only AT node was held by
 * another process -- on a PCIe modem, the paired cellat source, which holds it
 * for the whole capture -- so take the identity from the kismetdb ModemIdentity
 * rows), or "unresolved" (no AT node answered; also a replay). Additive, so the
 * schema stays /1: a reader that predates the key still reads the rest.
 *
 * Written UNCOMPRESSED, once, at open; any later compression of the .hdlc
 * leaves the tiny JSON as-is.
 *
 * The path derivation, JSON escaping and record formatting are libc-only (no
 * Kismet dependency) so they are unit-tested standalone in test_diag_capmeta.c
 * (`make -f standalone.mk check` in this directory), exactly as diag_rawlog is.
 */
#ifndef DIAG_CAPMETA_H
#define DIAG_CAPMETA_H

#include <stddef.h>
#include <time.h>

/* Derive the sidecar path from a resolved rawlog path by appending the fixed
 * suffix ".capture_meta.json" -- so `.../celldiag-<imei>-<ts>.hdlc` yields
 * `.../celldiag-<imei>-<ts>.hdlc.capture_meta.json`, an unambiguous 1:1 mapping
 * that stays next to the .hdlc regardless of how many captures share the dir.
 * Writes a NUL-terminated result to `out`. Returns 0 on success, -1 if the
 * result would not fit in `outsz` (out left untouched on overflow) or on a NULL
 * argument. */
int diag_capmeta_sidecar_path(const char *rawlog_path, char *out, size_t outsz);

/* JSON-escape src[0..len) into out (bounded by outsz, always NUL-terminated on
 * success). Escapes '"' and '\\' as short escapes, the C0 control set as
 * \b \f \n \r \t or \u00XX, and passes everything else (incl. '/', UTF-8 high
 * bytes) through unchanged. Returns bytes written (excluding the NUL), or -1 on
 * overflow. A NULL src is treated as empty. Exposed for the selftest. */
int diag_capmeta_json_escape(const char *src, size_t len, char *out, size_t outsz);

/* Format the whole capture_meta JSON object (with a trailing '\n') into out,
 * bounded by outsz. `host_utc` is rendered as ISO-8601 "YYYY-MM-DDTHH:MM:SSZ"
 * from gmtime_r. Every string is JSON-escaped; a NULL string field is emitted as
 * an empty JSON string "" (the consumer treats "" as absent). Field order and
 * names are fixed (see the header block). Returns 0 on success, -1 on overflow
 * (out untouched-or-truncated; caller treats the sidecar as not written) or on a
 * NULL out. */
int diag_capmeta_format(char *out, size_t outsz,
                        time_t host_utc,
                        const char *imei, const char *model,
                        const char *firmware, const char *make,
                        const char *product_model, const char *identity,
                        const char *mask_preset,
                        const char *f3_preset, const char *diag_node,
                        const char *rawlog_basename);

/* The `identity` spellings. */
#define DIAG_CAPMETA_IDENTITY_AT        "at"
#define DIAG_CAPMETA_IDENTITY_HELD      "unresolved-held-by-sibling"
#define DIAG_CAPMETA_IDENTITY_NONE      "unresolved"
/* Read over AT by the process holding the port, validated here. */
#define DIAG_CAPMETA_IDENTITY_VOUCHED   "vouched"

/* Basename of a path: the segment after the last '/', or the whole string if
 * there is none. Returns a pointer INTO `path` (no copy); NULL maps to "". */
const char *diag_capmeta_basename(const char *path);

/* One-shot write: open `path` O_WRONLY|O_CREAT|O_TRUNC 0644, write the whole
 * buffer (retrying short writes), close. Returns 0 on success, -1 on error
 * (errno set). Unlike the rawlog tee this is not a kept-open fd -- the sidecar
 * is a single small object written once at open time. */
int diag_capmeta_write(const char *path, const char *buf, size_t len);

#endif /* DIAG_CAPMETA_H */
