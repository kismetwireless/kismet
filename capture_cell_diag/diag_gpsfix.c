/* diag_gpsfix.c - the gps_fix status line; see diag_gpsfix.h. */

#include "diag_gpsfix.h"

#include <stdio.h>

int diag_gps_fix_status(char *out, size_t out_len, double lat_deg,
                        double lon_deg, double alt_m, uint16_t log_code) {
    return snprintf(out, out_len, "celldiag GPS fix %.6f,%.6f alt=%.0fm src=0x%04X",
                    lat_deg, lon_deg, alt_m, (unsigned)log_code);
}
