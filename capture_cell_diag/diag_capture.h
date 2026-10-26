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

/* Take an exclusive advisory claim on an already-open port fd.
 *
 * Two processes reading one port do not each get a copy of the bytes: the
 * kernel hands every byte to exactly one reader, so the stream is SPLIT
 * between them. cellat scans EVERY port on the host hunting for AT responders
 * and a DIAG port is one of the ports it probes, so celldiag and cellat race
 * by construction whenever both run on the same modem.
 *
 * flock() is advisory: it only excludes other flock() users, which is why both
 * binaries take it (cellat's is in capture_cell_at/at_serial.inc). The
 * lock is per open-file-description and the kernel drops it when the last fd
 * referring to that description closes, INCLUDING on crash, so no stale lock
 * can strand a port.
 *
 * Returns 0 if the claim was taken, -1 if another descriptor already holds the
 * port. Does not close fd -- the caller owns it either way. */
int diag_port_claim(int fd);

/* Open the DIAG serial port raw (8N1, no flow control, per-read timeout).
 * Takes diag_port_claim() before configuring the port, so a port another
 * process holds fails here rather than being read concurrently.
 * Returns an fd >= 0, or -1 on error (errno set). */
int diag_capture_open(const char *port);

/* Open the DIAG port, retrying up to `attempts` times with `delay_ms` between
 * tries when the failure is a transient port grab (a dying sibling helper still
 * holding it during a rapid relaunch, or a brief re-enumeration).
 * A permanent failure (bad path) returns -1 on the first attempt. Returns the
 * open fd, or -1 after exhausting the retries. */
int diag_capture_open_retry(const char *port, int attempts, int delay_ms);

/* Read the next CRC-valid deframed DIAG frame of ANY opcode into out (opcode
 * byte first, trailing CRC stripped), length in *len. Skips partial frames
 * (a live port is almost always joined mid-frame) and CRC-failed frames, and
 * tolerates brief idle gaps. Returns 0 on a valid frame, -1 on read error/EOF
 * or after too many consecutive idle periods. Used by the LOG_CONFIG handshake
 * to fish command responses out of a live frame flood.
 *
 * NOTE: this returns whole HDLC frames of ANY opcode. It deliberately does not
 * unwrap the QShrink4 / QSR envelopes (0x98 / 0x99 / 0x92) that SDX55/62/72
 * basebands pack LOG_F records into. The raw byte stream goes to
 * diag_logstream.{h,c}, which owns envelope handling. */
int diag_read_frame(int fd, diag_reader_t *r,
                    uint8_t *out, size_t outcap, size_t *len);

#endif /* DIAG_CAPTURE_H */
