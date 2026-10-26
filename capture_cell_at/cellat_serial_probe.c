/* cellat_serial_probe.c - standalone AT-over-serial probe (no Kismet).
 *
 * Opens a modem AT port and runs one or more AT commands, printing the
 * responses. Shares serial_open / at_command with the Kismet capture_cell_at
 * binary via at_serial.inc, so a successful probe hardware-validates that exact
 * path -- in particular the non-tty transport (an MHI char device like
 * /dev/mhi_DUN on a PCIe RM520N-GL, or a /dev/wwan* inline-driver port), where
 * tcgetattr() fails and the open must not treat that as fatal. The AT-side analogue of the
 * DIAG side's celldiag_probe.
 *
 *   cellat_serial_probe /dev/mhi_DUN 'AT+CGSN' 'ATI'
 *   cellat_serial_probe /dev/ttyUSB7           # defaults to ATI
 */
#include <stdio.h>

#include "at_serial.inc"

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <at-port> [AT-cmd ...]   (default cmd: ATI)\n",
                argv[0]);
        return 2;
    }

    const char *port = argv[1];
    int fd = serial_open(port, 115200);
    if (fd < 0) {
        fprintf(stderr, "cellat_serial_probe: serial_open(%s) failed: %s\n", port,
                strerror(errno));
        return 1;
    }
    fprintf(stderr, "cellat_serial_probe: opened %s (%s)\n", port,
            isatty(fd) ? "tty" : "non-tty");

    int rc = 0;
    int ncmd = argc - 2;
    int iters = ncmd > 0 ? ncmd : 1;
    for (int i = 0; i < iters; i++) {
        const char *cmd = ncmd > 0 ? argv[2 + i] : "ATI";
        char resp[4096];
        int n = at_command(fd, cmd, resp, sizeof(resp), 3000);
        if (n < 0) {
            fprintf(stderr, "  %s -> ERROR (at_command returned -1)\n", cmd);
            rc = 1;
        } else {
            printf("=== %s (%d bytes) ===\n%s\n", cmd, n, resp);
        }
    }

    serial_close(&fd);
    return rc;
}
