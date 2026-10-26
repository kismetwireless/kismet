/* celldiag_probe.c - standalone DIAG capture probe (no Kismet dependency).
 *
 * Opens a modem DIAG port, applies the M1 narrow log-mask, and pumps the raw
 * HDLC byte stream the modem emits straight to stdout -- the same byte stream
 * the Kismet capture_cell_diag binary decodes. Capture it to a file and replay
 * it through the helper to see the cell observations:
 *
 *   celldiag_probe /dev/ttyUSB0 > cap.hdlc
 *   ./celldiag_replay_ndjson ./kismet_cap_cell_diag \
 *       celldiag-000000000000000:replay=<absolute path of cap.hdlc>
 *
 * Wire format: a raw HDLC byte stream, NOT length-prefixed frames. The decoder's
 * extractor (diag_logstream.c) owns HDLC framing, CRC, and the QShrink4 / QSR
 * envelopes (0x98 / 0x99 / 0x92) that SDX55/62/72 basebands wrap LOG_F records
 * in -- so the probe must not pre-deframe or opcode-strip. (An
 * SDX20 like the LM960 uses bare 0x10 and would tolerate pre-deframing; the
 * envelope basebands do not, hence the raw passthrough.)
 *
 * This shares diag_capture / diag_config / diag_hdlc with the Kismet binary,
 * so a successful probe hardware-validates that whole path. The optional
 * [max_bytes] arg caps the passthrough for bounded test runs (0 == until idle).
 *
 * SPC-gated modems. EC2x/EG2x-class parts (MDM9607, e.g. the EG25-G)
 * gate DIAG_LOG_CONFIG_F SET_MASK behind a DIAG_SPC_F unlock, so without one
 * the handshake fails and the probe could not validate those modems at all
 * while kismet_cap_cell_diag could. The unlock is resolved the SAME way the
 * helper resolves it -- from the matched capture_cell_at profile's `diag.spc`
 * via diag_profile_lookup() -- so the SPC lives in exactly ONE place for both
 * tools and cannot drift. The helper reads the firmware string off the AT port
 * itself; the probe is deliberately Kismet-free (no serial_open/at_command), so
 * the operator supplies it with --firmware. --spc is the explicit override, and
 * matches the helper's spc= source option rather than introducing a new knob.
 */
#include "diag_capture.h"
#include "diag_config.h"
#include "diag_profile.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Same fallback as capture_cell_diag.c: empty means "no profile dir known",
 * which degrades to "no SPC" rather than guessing a path. */
#ifndef CELLDIAG_PROFILES_DEFAULT
#define CELLDIAG_PROFILES_DEFAULT ""
#endif

#define PASSTHROUGH_IDLE_LIMIT 12   /* ~12 * VTIME(5s) = 60s of silence */

int main(int argc, char **argv) {
    const char *port;
    long max_bytes = 0;               /* 0 == run until idle timeout */
    long emitted = 0;
    int no_mask = 0;                  /* --no-mask: passive tap, skip LOG_CONFIG */
    char spc_val[8] = "";             /* resolved SPC; "" == send no unlock */
    int spc_set = 0;                  /* --spc given explicitly (gates profile) */
    const char *firmware = NULL;      /* --firmware: profile match key */
    const char *profiles_dir = NULL;  /* --profiles, else $CELLDIAG_PROFILES */
    diag_reader_t reader;
    int fd, i;

    if (argc < 2) {
        fprintf(stderr,
                "usage: %s <diag-port> [max_bytes] [--no-mask]\n"
                "           [--spc <6 digits>] [--firmware <at+cgmr string>]\n"
                "           [--profiles <dir>]\n"
                "\n"
                "  --spc       DIAG_SPC_F unlock sent before LOG_CONFIG. Needed on\n"
                "              SPC-gated modems (EC2x/EG2x, e.g. EG25-G); factory\n"
                "              default is 000000. Overrides the profile default.\n"
                "  --firmware  AT+CGMR string (e.g. EG25GGBR07A08M2G). Matched against\n"
                "              each profile's firmware_match glob to pick up that\n"
                "              model's diag.spc -- the same lookup the Kismet helper\n"
                "              does, so there is one SPC source of truth.\n"
                "  --profiles  dir of capture_cell_at profile JSONs; defaults to\n"
                "              $CELLDIAG_PROFILES.\n",
                argv[0]);
        return 2;
    }
    port = argv[1];
    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--no-mask") == 0) {
            no_mask = 1;
        } else if (strcmp(argv[i], "--spc") == 0 && i + 1 < argc) {
            snprintf(spc_val, sizeof(spc_val), "%s", argv[++i]);
            spc_set = 1;
        } else if (strcmp(argv[i], "--firmware") == 0 && i + 1 < argc) {
            firmware = argv[++i];
        } else if (strcmp(argv[i], "--profiles") == 0 && i + 1 < argc) {
            profiles_dir = argv[++i];
        } else if (strncmp(argv[i], "--", 2) == 0) {
            fprintf(stderr, "celldiag_probe: unknown or incomplete option '%s'\n",
                    argv[i]);
            return 2;
        } else {
            max_bytes = strtol(argv[i], NULL, 10);
        }
    }

    if (!profiles_dir) {
        const char *env = getenv("CELLDIAG_PROFILES");
        profiles_dir = (env && *env) ? env : CELLDIAG_PROFILES_DEFAULT;
    }

    /* SPC resolution, mirroring capture_cell_diag.c's precedence exactly:
     * explicit --spc > the matched profile's diag.spc > none. Validated with
     * the same diag_config_build_spc() the send path uses, so a malformed
     * value degrades to "no SPC" plus a warning instead of a confusing
     * mid-handshake failure. */
    if (!spc_set && firmware && *firmware && profiles_dir && *profiles_dir) {
        char pv[8];
        if (diag_profile_lookup(profiles_dir, firmware, "spc", pv, sizeof(pv))) {
            uint8_t probe_body[6];
            if (diag_config_build_spc(probe_body, sizeof(probe_body), pv)
                    != sizeof(probe_body)) {
                fprintf(stderr, "celldiag_probe: ignoring invalid profile "
                                "diag.spc '%s' (expected 6 decimal digits); "
                                "no SPC unlock will be sent\n", pv);
            } else {
                snprintf(spc_val, sizeof(spc_val), "%s", pv);
                fprintf(stderr, "celldiag_probe: spc=%s from profile default "
                                "(firmware %s)\n", spc_val, firmware);
            }
        }
    }
    if (spc_set) {
        uint8_t probe_body[6];
        if (diag_config_build_spc(probe_body, sizeof(probe_body), spc_val)
                != sizeof(probe_body)) {
            fprintf(stderr, "celldiag_probe: --spc '%s' is not 6 decimal "
                            "digits\n", spc_val);
            return 2;
        }
    }

    fd = diag_capture_open(port);
    if (fd < 0) {
        fprintf(stderr, "celldiag_probe: cannot open %s\n", port);
        return 1;
    }

    /* One reader threads through the handshake and the capture loop so no
     * buffered bytes are lost at the boundary. */
    memset(&reader, 0, sizeof(reader));

    /* SPC unlock BEFORE SET_MASK. Only sent when a code was
     * supplied, so the ungated LM960 / RM500Q / RM520N path is byte-for-byte
     * unchanged. Report the outcome explicitly -- a silent no-op here must not
     * be mistakable for success. */
    if (!no_mask && spc_val[0]) {
        if (diag_config_send_spc(fd, &reader, spc_val) != 0) {
            fprintf(stderr, "celldiag_probe: DIAG SPC unlock (spc=%s) rejected "
                            "on %s -- wrong SPC for this unit, or the modem does "
                            "not gate DIAG on SPC (drop --spc for SDX24/SDX55-"
                            "class parts)\n", spc_val, port);
            close(fd);
            return 1;
        }
        fprintf(stderr, "celldiag_probe: DIAG SPC unlock accepted on %s -- "
                        "arming LOG mask\n", port);
    }

    /* Clear any LATCHED QSH-trace / F3 flood BEFORE the LOG mask: a
     * prior tool/boot may have left 0x9D / 0x99 armed on a subsystem the narrow
     * LOG mask cannot reach, and it survives reboots. Skipped under --no-mask,
     * where the whole point is to observe whatever the port already emits. */
    if (!no_mask) {
        (void)diag_config_disarm_latched(fd);
        fprintf(stderr, "celldiag_probe: sent latched-state disarm "
                        "(QSH-trace + F3) on %s\n", port);
    }

    if (no_mask) {
        fprintf(stderr, "celldiag_probe: passive mode (no LOG_CONFIG); "
                        "capturing whatever the port already emits...\n");
    } else if (diag_config_apply_narrow_mask(fd, &reader, DIAG_TARGET_CODES,
                                             DIAG_TARGET_CODES_COUNT) != 0) {
        fprintf(stderr, "celldiag_probe: LOG_CONFIG handshake failed on %s "
                        "(wrong port, or SPC-gated?)%s\n", port,
                spc_val[0] ? " -- an SPC unlock WAS accepted, so this is not "
                             "the SPC gate"
                           : " -- if this is an EC2x/EG2x-class part, retry "
                             "with --firmware <AT+CGMR string> (or --spc "
                             "000000)");
        close(fd);
        return 1;
    } else {
        fprintf(stderr, "celldiag_probe: mask applied, streaming LOG_F frames...\n");
    }

    /* Raw passthrough: the decoder's extractor handles HDLC framing and the
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
