/* diag_profile.h - per-model DIAG defaults from the capture_cell_at profile JSONs.
 *
 * The celldiag source options (mask=, f3=, ...) can each take a per-modem
 * DEFAULT from that modem's profile, so an operator does not have to repeat the
 * same knob on every source line for a known model. The profiles already exist
 * as capture_cell_at/profiles/<model>.json; each carries a "firmware_match"
 * glob (e.g. "RM520N*") tested against the modem's AT+CGMR firmware string, and
 * a "diag" object. This module resolves:
 *
 *     firmware string  --(firmware_match glob)-->  profile  -->  diag.<key>
 *
 * so mask= falls back to diag.mask_default and f3= to diag.f3_default (the
 * source option still overrides the profile default; the profile default
 * overrides the compiled-in default). The diag.port_detect descriptor uses the
 * same selection path.
 *
 * Deliberately libc-only (no Kismet link, no JSON library) so it unit-tests
 * standalone in test_diag_profile.c (`make check`). The JSON reader is a narrow
 * string-value extractor scoped to the flat "diag" object of a controlled,
 * repo-authored config file - NOT a general JSON parser. It handles the subset
 * these profiles use (object nesting, string values, // no comments) and treats
 * anything it does not understand as "key absent" (return 0), so a malformed or
 * unexpected profile degrades to the compiled-in default rather than misparsing.
 */
#ifndef DIAG_PROFILE_H
#define DIAG_PROFILE_H

#include <stddef.h>

/* Extract a string value `diag.<key>` from the profile whose top-level
 * "firmware_match" glob matches `firmware`, searching every *.json in
 * `profiles_dir`.
 *
 * Returns 1 and writes a NUL-terminated value to `out` on a hit; returns 0 if
 * `profiles_dir` is NULL/empty, no profile's firmware_match matches, the matched
 * profile has no "diag" object, the key is absent, or its value is not a string
 * (e.g. null). `out` is left untouched on a 0 return. A value too long for
 * `outsz` is treated as absent (return 0) rather than truncated.
 */
int diag_profile_lookup(const char *profiles_dir, const char *firmware,
                        const char *key, char *out, size_t outsz);

/* Per-model DIAG port-detection descriptor, resolved from the matched
 * profile's `diag.port_detect` object. It formalizes the implicit
 * "DIAG = lowest USB interface (if00)" assumption into a machine-read descriptor
 * so the other cases (DIAG on a non-if00 interface, or on MHI/wwan with no
 * ttyUSB at all) can be described per model instead of hard-coded. Absent fields
 * keep the caller's back-compatible defaults (transport=ttyUSB, match=lowest). */
struct diag_port_detect {
    char transport[32];          /* "ttyUSB" | "wwan_mhi" | "qmi_embedded"; "" if absent */
    char match[32];              /* "lowest" | "interface"; "" if absent */
    int  interface;              /* USB bInterfaceNumber of the DIAG fn; valid iff has_interface */
    int  has_interface;          /* 1 if "interface" was present as a JSON number */
    char driver_path_glob[256];  /* wwan_mhi node hint (e.g. "/dev/wwan*qcdm*"); "" if absent */
};

/* Resolve `diag.port_detect` from the profile whose top-level "firmware_match"
 * glob matches `firmware`. Returns 1 and fills *out (each field independently;
 * a missing field is left "" / has_interface=0) if a `port_detect` OBJECT was
 * found in the matched profile's "diag" object; returns 0 (and zeroes *out) if
 * `profiles_dir` is NULL/empty, no profile matches, there is no "diag" object,
 * or it has no "port_detect" object. A 0 return means "use the caller's
 * defaults" (transport=ttyUSB, match=lowest) - the zero-regression path. */
int diag_profile_port_detect(const char *profiles_dir, const char *firmware,
                             struct diag_port_detect *out);

/* --- lower-level helpers, exposed for unit testing --- */

/* Extract an integer value `"key": <number>` from the JSON text `json`, matching
 * only when "key" is used as an object key (followed by ':' then a base-10
 * integer, optionally signed). Returns 1 and writes *out on success; 0 if the
 * key is absent, its value is not an integer (string / object / float / bool /
 * null), or it does not parse. Exposed for unit testing. */
int diag_profile_json_int(const char *json, const char *key, int *out);

/* Find `"key": "value"` in the JSON text `json` and copy value to out.
 * Only matches when "key" is used as an object key (followed by ':' then a
 * string). Returns 1 on success, 0 if not found / not a string / too long. */
int diag_profile_json_string(const char *json, const char *key,
                             char *out, size_t outsz);

/* Return a pointer to the brace-balanced body of object `"key": { ... }` in
 * `json` (pointing at the opening '{'), and its length via *len (including the
 * braces). Returns NULL if the key is absent or its value is not an object.
 * String contents are respected during brace matching. */
const char *diag_profile_json_object(const char *json, const char *key,
                                     size_t *len);

/* fnmatch-style glob match of `pattern` against `str`, supporting '*' and '?'.
 * Returns 1 on match, 0 otherwise. (Thin wrapper over fnmatch; exposed so the
 * test can assert the matching semantics profiles rely on.) */
int diag_profile_glob_match(const char *pattern, const char *str);

#endif /* DIAG_PROFILE_H */
