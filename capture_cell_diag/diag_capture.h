/* diag_capture.h - reusable DIAG capture core.
 *
 * Opens a modem DIAG serial port raw and yields deframed DIAG LOG_F frames.
 * Shared by the standalone celldiag_probe (offline/dev) and the Kismet
 * capture_cell_diag binary, so the port/framing logic is written and hardware-
 * validated once.
 */
#ifndef DIAG_CAPTURE_H
#define DIAG_CAPTURE_H

#include <stddef.h>
#include <stdint.h>

/* Buffered byte reader state; zero-initialize before first use. The buffer
 * doubles as the per-syscall read size: it must be large (64 KiB, matching
 * libqmi/DiagClient) so each read() drains the kernel tty buffer in one go. A
 * heavy DIAG log/F3 flood otherwise overflows the tty ring between small reads
 * and silently drops frames -- including the rare command responses. */
typedef struct {
    uint8_t buf[65536];
    size_t  pos;
    size_t  len;
} diag_reader_t;

/* Open the DIAG serial port raw (8N1, no flow control, per-read timeout).
 * Returns an fd >= 0, or -1 on error (errno set). */
int diag_capture_open(const char *port);

/* Read the next CRC-valid deframed DIAG frame of ANY opcode into out (opcode
 * byte first, trailing CRC stripped), length in *len. Skips partial frames
 * (a live port is almost always joined mid-frame) and CRC-failed frames, and
 * tolerates brief idle gaps. Returns 0 on a valid frame, -1 on read error/EOF
 * or after too many consecutive idle periods. Used by the LOG_CONFIG handshake
 * to fish command responses out of a live frame flood.
 *
 * NOTE: this returns whole HDLC frames of ANY opcode. It deliberately does not
 * unwrap the QShrink4 / QSR envelopes (0x98 / 0x99 / 0x92) that SDX55/62/72
 * basebands pack LOG_F records into -- in Phase 1 the raw byte stream is handed
 * to the diaggrok bridge, which owns envelope handling. A Phase 2 pure-C
 * decoder will need to port that envelope logic here. */
int diag_read_frame(int fd, diag_reader_t *r,
                    uint8_t *out, size_t outcap, size_t *len);

#endif /* DIAG_CAPTURE_H */
