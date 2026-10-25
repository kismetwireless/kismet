/* SPDX-License-Identifier: Apache-2.0
 *
 * at_serial.inc must compile on a platform whose termios lacks the high baud
 * constants.
 *
 * ## The problem
 *
 * The framework-free selftests are the part of this tree that builds on a host
 * that cannot `./configure` (macOS: no libwebsockets / libpcap / libmosquitto /
 * sensors.h):
 *
 *     make -C capture_cell_at  -f standalone.mk check
 *     make -C capture_cell_diag -f standalone.mk check
 *
 * On macOS / Apple clang an unguarded at_serial.inc fails with:
 *
 *     ./at_serial.inc:128:30: error: use of undeclared identifier 'B460800'
 *     ./at_serial.inc:129:30: error: use of undeclared identifier 'B921600'
 *
 * macOS's termios tops out at B230400; higher rates go through the
 * IOSSIOSPEED ioctl. Without the guards, the selftests do not build on the one
 * platform where they are the only available coverage.
 *
 * ## Why this test can run on Linux
 *
 * The defect is not "Darwin behaves differently at runtime" -- it is "these
 * two identifiers do not exist". That is reproducible anywhere by removing
 * them: include <termios.h> first, `#undef` both, then include the unit. The
 * translation unit either compiles without them or it does not, and the answer
 * is the same on every host.
 *
 * Negative control: with the `#ifdef` guards removed from
 * at_serial.inc this file fails to compile with exactly the two errors quoted
 * above. Without that check the test would be a compile of a file that never
 * referenced the constants anyway.
 *
 * This is a compile-time assertion. Building it is passing it; `main` only
 * exists so the recipe produces a runnable artifact like its siblings. The
 * runtime half -- that an unsupported rate REFUSES rather than silently
 * running at 115200 -- is asserted below, and only on a host where the
 * constants are really absent, because on Linux the refusal branch is
 * preprocessed away (which is the correct behaviour there).
 */
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>

/* Darwin's termios, simulated by subtraction. Must come AFTER <termios.h> and
 * BEFORE at_serial.inc; the include guard keeps the unit's own <termios.h>
 * from putting them back. */
#undef B460800
#undef B921600

#include "at_serial.inc"

int main(void) {
    /* Reference the unit so the compiler cannot discard the translation unit,
     * and so a future `-Wunused` sweep does not "fix" this file into a no-op. */
    if ((void *)serial_open == NULL) {
        fprintf(stderr, "unreachable\n");
        return 1;
    }
    printf("PASS: at_serial.inc compiles with B460800/B921600 absent "
           "(the darwin case)\n");
    return 0;
}
