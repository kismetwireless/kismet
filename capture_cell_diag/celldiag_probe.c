/* celldiag_probe.c - standalone DIAG capture probe (no Kismet dependency).
 *
 * Opens a modem DIAG port, applies the M1 narrow log-mask, and pumps the raw
 * HDLC byte stream the modem emits straight to stdout -- the exact byte stream
 * the Kismet capture_cell_diag binary pipes to the diaggrok bridge helper.
 * Pipe it into the helper to see live cell observations:
 *
 *   celldiag_probe /dev/ttyUSB0 | \
 *       .venv/bin/python tools/kismet_diag_decode.py --imei <IMEI>
 *
 * Wire format: a raw HDLC byte stream, NOT length-prefixed frames. The helper's
 * diaggrok.hdlc.iter_log_records_stream() owns HDLC framing, CRC, and the
 * QShrink4 / QSR envelopes (0x98 / 0x99 / 0x92) that SDX55/62/72 basebands wrap
 * LOG_F records in -- so the probe must not pre-deframe or opcode-strip. (An
 * SDX20 like the LM960 uses bare 0x10 and would tolerate pre-deframing; the
 * envelope basebands do not, hence the raw passthrough.)
 *
 * This shares diag_capture / diag_config / diag_hdlc with the Kismet binary,
 * so a successful probe hardware-validates that whole path. The optional
 * [max_bytes] arg caps the passthrough for bounded test runs (0 == until idle).
 */
#include "diag_capture.h"
#include "diag_config.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PASSTHROUGH_IDLE_LIMIT 12   /* ~12 * VTIME(5s) = 60s of silence */

int main(int argc, char **argv) {
    const char *port;
    long max_bytes = 0;               /* 0 == run until idle timeout */
    long emitted = 0;
    int no_mask = 0;                  /* --no-mask: passive tap, skip LOG_CONFIG */
    diag_reader_t reader;
    int fd, i;

    if (argc < 2) {
        fprintf(stderr, "usage: %s <diag-port> [max_bytes] [--no-mask]\n", argv[0]);
        return 2;
    }
    port = argv[1];
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--no-mask") == 0)
            no_mask = 1;
        else
            max_bytes = strtol(argv[i], NULL, 10);
    }

    fd = diag_capture_open(port);
    if (fd < 0) {
        fprintf(stderr, "celldiag_probe: cannot open %s\n", port);
        return 1;
    }

    /* One reader threads through the handshake and the capture loop so no
     * buffered bytes are lost at the boundary. */
    memset(&reader, 0, sizeof(reader));

    if (no_mask) {
        fprintf(stderr, "celldiag_probe: passive mode (no LOG_CONFIG); "
                        "capturing whatever the port already emits...\n");
    } else if (diag_config_apply_narrow_mask(fd, &reader, DIAG_TARGET_CODES,
                                             DIAG_TARGET_CODES_COUNT) != 0) {
        fprintf(stderr, "celldiag_probe: LOG_CONFIG handshake failed on %s "
                        "(wrong port, or SPC-gated?)\n", port);
        close(fd);
        return 1;
    } else {
        fprintf(stderr, "celldiag_probe: mask applied, streaming LOG_F frames...\n");
    }

    /* Raw passthrough: the bridge (diaggrok) handles HDLC framing and the
     * QShrink4 / QSR envelopes (0x98 / 0x99 / 0x92) that SDX55/62/72 basebands
     * wrap LOG_F records in, so the probe just pumps the modem's bytes. First
     * flush any bytes the handshake reader already buffered, then stream. */
    if (reader.pos < reader.len) {
        size_t rem = reader.len - reader.pos;
        fwrite(reader.buf + reader.pos, 1, rem, stdout);
        emitted += (long)rem;
    }

    {
        int idle = 0;
        for (;;) {
            uint8_t buf[65536];
            ssize_t n = read(fd, buf, sizeof(buf));
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                break;
            }
            if (n == 0) {                       /* VTIME timeout: quiet port */
                if (++idle >= PASSTHROUGH_IDLE_LIMIT)
                    break;
                continue;
            }
            idle = 0;
            if (fwrite(buf, 1, (size_t)n, stdout) != (size_t)n)
                break;
            fflush(stdout);
            emitted += n;
            if (max_bytes && emitted >= max_bytes)   /* optional byte cap */
                break;
        }
    }

    fprintf(stderr, "celldiag_probe: %ld bytes passed through\n", emitted);
    close(fd);
    return 0;
}
