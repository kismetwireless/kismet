/* diag_gpsfix.h - the gps_fix status line.
 *
 * Every accepted fix is relayed to the message bus as
 *
 *   celldiag GPS fix <lat %.6f>,<lon %.6f> alt=<alt %.0f>m src=0x<code %04X>
 *
 * (capture_cell_diag.c, native_tap_cb). The format rounds the EXACT binary
 * value, half to even, so a half-way altitude renders 12.5 -> "12" and
 * 13.5 -> "14", and negative zero renders "-0.000000" / "alt=-0m".
 * test_diag_gpsfix pins those cases.
 *
 * Pure libc.
 */
#ifndef DIAG_GPSFIX_H
#define DIAG_GPSFIX_H

#include <stddef.h>
#include <stdint.h>

/* snprintf contract: returns the full length; >= out_len means truncated. */
int diag_gps_fix_status(char *out, size_t out_len, double lat_deg,
                        double lon_deg, double alt_m, uint16_t log_code);

#endif
