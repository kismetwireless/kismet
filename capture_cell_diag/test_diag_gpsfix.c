/* test_diag_gpsfix.c - the gps_fix status line against pinned goldens.
 *
 *   ./test_diag_gpsfix            pinned goldens, with the rounding edge cases:
 *                                 half-way altitudes, negative zero, a tie that
 *                                 is not one in binary.
 *   ./test_diag_gpsfix --format   one "<lat> <lon> <alt> <code>" per stdin line
 *                                 (round-trip doubles), one status line out per
 *                                 line: a driver for a differential test against
 *                                 another renderer.
 */

#include "diag_gpsfix.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int failures = 0;

static void golden(double lat, double lon, double alt, const char *want) {
    char b[160];
    diag_gps_fix_status(b, sizeof(b), lat, lon, alt, 0x1476);
    if (strcmp(b, want) != 0) {
        fprintf(stderr, "FAIL (%.17g, %.17g, %.17g)\n  got:  %s\n  want: %s\n",
                lat, lon, alt, b, want);
        failures++;
    }
}

static int format_driver(void) {
    char line[256];
    while (fgets(line, sizeof(line), stdin) != NULL) {
        double lat, lon, alt;
        unsigned code;
        if (sscanf(line, "%lf %lf %lf %u", &lat, &lon, &alt, &code) != 4)
            continue;
        char b[160];
        diag_gps_fix_status(b, sizeof(b), lat, lon, alt, (uint16_t)code);
        puts(b);
    }
    return 0;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--format") == 0)
        return format_driver();

    /* f"celldiag GPS fix {lat:.6f},{lon:.6f} alt={alt:.0f}m src=0x{0x1476:04X}" */
    golden(12.345678, -98.765432, 1407.0,
           "celldiag GPS fix 12.345678,-98.765432 alt=1407m src=0x1476");
    /* Half-way altitudes round half to even, in both. */
    golden(0.5, 1.5, 12.5, "celldiag GPS fix 0.500000,1.500000 alt=12m src=0x1476");
    golden(1.0, 2.0, 13.5, "celldiag GPS fix 1.000000,2.000000 alt=14m src=0x1476");
    /* Negative zero keeps its sign, in both. */
    golden(-0.0, -0.0, -0.0, "celldiag GPS fix -0.000000,-0.000000 alt=-0m src=0x1476");
    /* -0.5 rounds to -0; 5e-07 is just under its tie in binary. */
    golden(-0.4, 0.0000005, -0.5, "celldiag GPS fix -0.400000,0.000000 alt=-0m src=0x1476");
    /* A carry through every digit. */
    golden(89.9999995, -179.9999995, 2.5,
           "celldiag GPS fix 90.000000,-180.000000 alt=2m src=0x1476");

    if (failures) {
        fprintf(stderr, "test_diag_gpsfix: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_diag_gpsfix: all tests passed\n");
    return 0;
}
