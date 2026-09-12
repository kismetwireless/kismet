/* diag_hdlc.h - HDLC framing for the Qualcomm DIAG transport.
 *
 * DIAG serial framing is PPP-style HDLC: each frame is the payload plus a
 * trailing 2-byte CRC-16/X-25 (little-endian), byte-stuffed so that the frame
 * delimiter 0x7E never appears inside, then terminated by a literal 0x7E.
 *
 * Escape rule: 0x7D is the escape byte; the following byte is XORed with 0x20.
 * So on the wire 0x7E -> 0x7D 0x5E and 0x7D -> 0x7D 0x5D.
 *
 * The CRC matches diaggrok's crc16_ccitt (reflected poly 0x8408, init 0xFFFF,
 * xorout 0xFFFF); test vector crc("123456789") == 0x906E. Keeping the two in
 * lockstep is what lets the Phase 1 diaggrok bridge validate this deframer.
 */
#ifndef DIAG_HDLC_H
#define DIAG_HDLC_H

#include <stddef.h>
#include <stdint.h>

/* CRC-16/X-25 over data[0..len). Exposed for the LOG_CONFIG builder + tests. */
uint16_t diag_hdlc_crc16(const uint8_t *data, size_t len);

/* Remove HDLC escape sequences from in[0..inlen) into out (capacity outcap).
 * Returns the unescaped length, or 0 if it would overflow outcap. */
size_t diag_hdlc_unescape(const uint8_t *in, size_t inlen,
                          uint8_t *out, size_t outcap);

/* Given an unescaped frame body that still carries its trailing 2-byte
 * little-endian CRC, verify the CRC. On success, strip it (*len -= 2) and
 * return 1. On mismatch or a too-short frame, leave *len untouched, return 0. */
int diag_hdlc_check_crc(const uint8_t *frame, size_t *len);

/* Build a complete escaped, CRC'd, 0x7E-terminated DIAG frame for a command:
 * out = escape(cmd || body || crc16_le(cmd || body)) || 0x7E.
 * Returns the total wire length, or 0 if it would overflow outcap. */
size_t diag_hdlc_build(uint8_t cmd, const uint8_t *body, size_t bodylen,
                       uint8_t *out, size_t outcap);

#endif /* DIAG_HDLC_H */
