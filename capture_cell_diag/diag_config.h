/* diag_config.h - DIAG LOG_CONFIG narrow-mask handshake.
 *
 * To make a modem emit specific DIAG log codes we run the DIAG_LOG_CONFIG_F
 * (0x73) handshake: RETRIEVE_RANGES to learn how many codes each of the 16 log
 * types advertises, then one SET_MASK per touched type with a bitmask that
 * subscribes to EXACTLY the codes we want (not qcsuper's "all logs", which
 * floods the stream). A DIAG log code is (equipment_id << 12) | item: the top
 * 4 bits pick the log type (index into bitsizes), the low 12 bits are the item
 * within it. Within a type's mask, item i is bit (i % 8) of byte (i / 8),
 * LSB-first.
 *
 * The mask math is kept identical to diaggulp.py's _narrow_mask_bytes so the
 * Phase 1 diaggrok bridge and this binary drive the modem the same way.
 */
#ifndef DIAG_CONFIG_H
#define DIAG_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#include "diag_capture.h"   /* diag_reader_t, diag_read_frame */

#define DIAG_LOG_TYPES        16
/* item is 12-bit, so bitsize <= 4096 codes -> at most 512 mask bytes. */
#define DIAG_MAX_MASK_BYTES   512

/* Target codes: 0xB193 LTE ML1 serving (signal) + 0xB0C0 LTE RRC OTA (SIB1 ->
 * identity). M3 extends this with NR ML1 and LTE neighbor codes. */
extern const uint16_t DIAG_TARGET_CODES[];
extern const size_t DIAG_TARGET_CODES_COUNT;

typedef struct {
    uint32_t bitsizes[DIAG_LOG_TYPES];               /* from RETRIEVE_RANGES */
    uint8_t  mask[DIAG_LOG_TYPES][DIAG_MAX_MASK_BYTES];
    size_t   mask_len[DIAG_LOG_TYPES];               /* 0 == type not touched */
} diag_log_mask_t;

/* Build per-type subscription masks for `codes` from an already-populated
 * m->bitsizes. Zeroes m->mask/m->mask_len first. Returns 0 on success, or -1
 * if any code's equipment id or item is outside the modem's advertised range
 * (nothing is applied in that case). */
int diag_config_narrow_mask(const uint16_t *codes, size_t ncodes,
                            diag_log_mask_t *m);

/* Live handshake over an open DIAG fd (blocking). `r` is the shared frame
 * reader (also used by the capture loop) so buffered bytes carry across the
 * handshake->capture boundary and a flooded port is tolerated. Returns 0 on
 * success, -1 on I/O error / timeout / modem-reported failure. */
int diag_config_retrieve_ranges(int fd, diag_reader_t *r,
                                uint32_t bitsizes[DIAG_LOG_TYPES]);
int diag_config_apply_narrow_mask(int fd, diag_reader_t *r,
                                  const uint16_t *codes, size_t ncodes);

#endif /* DIAG_CONFIG_H */
