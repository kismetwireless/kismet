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
 * The mask math is pinned by the in-file selftest (-DDIAG_CONFIG_SELFTEST).
 */
#ifndef DIAG_CONFIG_H
#define DIAG_CONFIG_H

#include <stddef.h>
#include <stdint.h>

#include "diag_capture.h"   /* diag_reader_t, diag_read_frame */

#define DIAG_LOG_TYPES        16
/* item is 12-bit, so bitsize <= 4096 codes -> at most 512 mask bytes. */
#define DIAG_MAX_MASK_BYTES   512

/* Upper bound on a narrow subscription's code list (the filtered supported
 * subset in diag_config_apply_narrow_mask). The default target set is a
 * handful of codes; 64 is generous headroom for the stack buffer. */
#define DIAG_MAX_TARGET_CODES 64

/* Target codes: 0xB193 LTE ML1 serving (signal) + 0xB0C0 LTE RRC OTA (SIB1 ->
 * identity), plus NR ML1 and LTE neighbor codes. */
extern const uint16_t DIAG_TARGET_CODES[];
extern const size_t DIAG_TARGET_CODES_COUNT;

typedef struct {
    uint32_t bitsizes[DIAG_LOG_TYPES];               /* from RETRIEVE_RANGES */
    uint8_t  mask[DIAG_LOG_TYPES][DIAG_MAX_MASK_BYTES];
    size_t   mask_len[DIAG_LOG_TYPES];               /* 0 == type not touched */
} diag_log_mask_t;

/* Build per-type subscription masks for `codes` from an already-populated
 * m->bitsizes. Zeroes m->mask/m->mask_len first. EXCLUSIVE: every advertised
 * type with no target code gets an all-zero mask (mask_len > 0), so applying
 * it clears a stale mask a previous DIAG client left there. Returns 0 on success, or -1
 * if any code's equipment id or item is outside the modem's advertised range
 * (nothing is applied in that case). */
int diag_config_narrow_mask(const uint16_t *codes, size_t ncodes,
                            diag_log_mask_t *m);

/* Copy the subset of `codes` that the modem actually advertises (per an
 * already-populated `bitsizes` from diag_config_retrieve_ranges) into `out`,
 * up to `outcap` entries; returns the count kept. A code is kept iff its log
 * type advertises a non-zero range AND its item is within that range. This lets
 * a mixed LTE+NR target set (DIAG_TARGET_CODES) subscribe to just the supported
 * subset on a modem that doesn't advertise every code -- e.g. an LTE-only
 * MDM9607 (EG25-G) whose type 0xB advertises 513 codes rejects the NR codes
 * 0xB821 (item 2081) / 0xB97F (item 2431). Without this filter,
 * diag_config_narrow_mask's strict out-of-range rejection fails the WHOLE
 * handshake on such a modem. Pure/testable. */
size_t diag_config_filter_supported(const uint16_t *codes, size_t ncodes,
                                    const uint32_t bitsizes[DIAG_LOG_TYPES],
                                    uint16_t *out, size_t outcap);

/* Build an all-codes ("full log") subscription mask: every code the modem
 * advertised, in every log type. m->bitsizes must already be populated (via
 * diag_config_retrieve_ranges). Zeroes m->mask/m->mask_len first, then for each
 * type with a non-zero bitsize sets every in-range bit (byte length mirrors the
 * narrow path: ceil(bitsize/8)), clearing any bits past the advertised range in
 * the final byte. A type whose advertised bitsize somehow exceeds the 12-bit
 * item ceiling (4096 codes / 512 bytes) is clamped to the representable range so
 * the buffer cannot overflow. Returns 0 (cannot fail -- it derives the mask from
 * the advertised ranges, so nothing is ever out of range). Backs the `full`
 * preset; it floods the DIAG stream, so keep it behind an explicit
 * operator opt-in. */
int diag_config_full_mask(diag_log_mask_t *m);

/* Live handshake over an open DIAG fd (blocking). `r` is the shared frame
 * reader (also used by the capture loop) so buffered bytes carry across the
 * handshake->capture boundary and a flooded port is tolerated. Returns 0 on
 * success, -1 on I/O error / timeout / modem-reported failure. */
int diag_config_retrieve_ranges(int fd, diag_reader_t *r,
                                uint32_t bitsizes[DIAG_LOG_TYPES]);
int diag_config_apply_narrow_mask(int fd, diag_reader_t *r,
                                  const uint16_t *codes, size_t ncodes);

/* Live "full log" handshake: retrieve ranges, build the all-codes mask
 * (diag_config_full_mask), and SET_MASK every advertised type. Same return
 * contract as diag_config_apply_narrow_mask. HIGH volume -- caller gates it. */
int diag_config_apply_full_mask(int fd, diag_reader_t *r);

/* ---- F3 runtime-level masks ----
 *
 * The u32 in the SET_ALL_RT_MASKS body is ANDed against each *emitting site's*
 * `ss_mask` (the per-site mask the firmware compiles in, and the same value the
 * qdb hash rows carry in their `ss_mask` column). A site emits iff the AND is
 * nonzero. The low 5 bits are a severity ladder; bits >= 5 are per-SSID custom
 * meanings, not higher severities. Across qdbs from several vendors and chipset
 * families, the share of sites whose format string contains an error word rises
 * monotonically with the ladder bit.
 *
 * The masks below are subtractive on purpose. A *selective* floor ("send
 * ERROR|FATAL", i.e. 0x00000018) looks like the obvious reading of "severity
 * floor" but acts as a mute button: about two thirds of F3 records come from
 * sites carrying only custom bits, so 0x00000018 keeps roughly 1% of the stream
 * and drops the ML1 / tuner / GNSS prints that F3 is wanted for. Clearing low
 * ladder bits from all-ones silences ladder-only sites and leaves every
 * custom-bit site armed.
 *
 * Typical retention (SIM8202G-M2 drive capture):
 *   ALL          0xFFFFFFFF  100.0%
 *   HIGH_AND_UP  0xFFFFFFFC   94.2%   drop LOW+MED-only sites
 *   ERROR_AND_UP 0xFFFFFFF8   68.4%   drop LOW+MED+HIGH-only sites
 * The names say what a *ladder-only* site must reach to survive; a site with any
 * custom bit survives all three. */
#define DIAG_F3_LEVELS_ALL           0xFFFFFFFFu
#define DIAG_F3_LEVELS_HIGH_AND_UP   0xFFFFFFFCu
#define DIAG_F3_LEVELS_ERROR_AND_UP  0xFFFFFFF8u

/* Build the DIAG_EXT_MSG_CONFIG_F / SET_ALL_RT_MASKS (sub_cmd 5) request body
 * -- the bytes *after* the 0x7D command code. "<BxxI": sub_cmd(5) + 2 reserved
 * pad + u32 runtime-level mask. Pure and testable; with DIAG_F3_LEVELS_ALL it
 * is the hardware-verified all-F3 arming payload. Writes 7
 * bytes; returns the length written, or 0 if cap < 7 or `levels` is 0 (an
 * all-zero mask arms nothing while reporting as armed -- the caller's "off"
 * state is "do not send this handshake", never "send an empty one"). */
size_t diag_config_build_f3(uint8_t *out, size_t cap, uint32_t levels);

/* diag_config_build_f3(out, cap, DIAG_F3_LEVELS_ALL). */
size_t diag_config_build_all_f3(uint8_t *out, size_t cap);

/* Arm the modem's ENTIRE F3 debug-message surface: DIAG_EXT_MSG_CONFIG_F (0x7D)
 * / SET_ALL_RT_MASKS with every runtime level on. This is the celldiag `f3=all`
 * preset, orthogonal to the LOG mask: F3 free-text ext-msgs (0x79 plaintext /
 * 0x99 QSR4-terse) ride a different DIAG subsystem than LOG_F codes, so this
 * composes with any mask= preset. High volume (a chatty modem emits hundreds of
 * thousands of 0x99 frames in 30s), so it is off by default and opt-in only.
 * The bounded per-SSID SET_RT_MASK (sub_cmd 4) is not hardware-verified here;
 * SET_ALL_RT_MASKS is the hardware-verified form. Returns 0 on the
 * modem's ack, -1 on I/O error / timeout (a wrong layout fails visibly rather
 * than arming nothing).
 *
 * `levels` is one of the DIAG_F3_LEVELS_* masks above -- read the note there
 * before inventing another one. diag_config_enable_all_f3() is the ALL case. */
int diag_config_enable_f3(int fd, diag_reader_t *r, uint32_t levels);
int diag_config_enable_all_f3(int fd, diag_reader_t *r);

/* ---- Latched-state disarm ----
 *
 * These modems remember their last DIAG state per subsystem and keep emitting
 * that log type until it is explicitly disabled, and that state survives
 * reboots: a power-cycle does not reset it, only an explicit disarm does. So a
 * prior tool's (or a prior boot's) QSH-trace arm (0x9D) and F3 ext-msg arm
 * (0x99 QSR4 / 0x79) ride into this capture as inherited flood. On an SDX62
 * (RM520N-GL) in NR5G-SA idle camp that can be over a thousand QSH/F3 frames
 * for every DIAG_LOG_F frame, leaving the cell data a tiny fraction of the
 * stream.
 *
 * The narrow LOG mask cannot reach them: 0x9D rides 0x9001 and 0x99/0x79 ride
 * 0x7D EXT_MSG_CONFIG_F, two config subsystems the LOG_CONFIG_F (0x73) mask
 * never touches. Sending the disarms BEFORE the LOG mask makes every capture
 * start from a known per-subsystem state instead of whatever the last user
 * latched. (An operator who wants F3 re-arms it with the f3= preset, which runs
 * after the LOG mask; QSH stays cleared unless the qsh= tier arms it.)
 *
 * Both disarms are the empty/zero form of an arm the modem accepts on the same
 * subsystem.
 */

/* Build the QSH-trace disarm body -- the 19 bytes AFTER the 0x4B
 * DIAG_SUBSYS_CMD_F opcode. With the opcode prepended by send_cmd this is the
 * exact 20-byte inner
 *   4b 44 01 90 03 00 00 00 01 00 00 00 01 00 00 00 00 00 00 00
 * (subsys 0x44, cmd 0x9001, arg_count 3, word_a 1, word_b 1, count 0 -- an
 * empty maskset = the matching disarm for the QSH-trace arm). Writes 19 bytes;
 * returns the length, or 0 if cap < 19. Pure/testable. */
size_t diag_config_build_qsh_trace_disarm(uint8_t *out, size_t cap);

/* Build the F3 disarm body -- the 7 bytes AFTER the 0x7D DIAG_EXT_MSG_CONFIG_F
 * opcode: SET_ALL_RT_MASKS (sub_cmd 5) + 2 pad + u32le level 0 ->
 *   05 00 00 00 00 00 00
 * (SET_ALL_RT_MASKS at level 0). This
 * is the level-0 form diag_config_build_f3() deliberately REFUSES to emit (an
 * all-zero ARM reports as armed while emitting nothing); a DISARM legitimately
 * wants exactly it. Writes 7 bytes; returns the length, or 0 if cap < 7.
 * Pure/testable. */
size_t diag_config_build_f3_disarm(uint8_t *out, size_t cap);

/* Fire both disarms over an open DIAG fd, before the LOG mask. Fire-and-forget
 * like apply_mask_struct's SET_MASK: the disarm takes effect regardless, and a
 * pre-QSH part that answers 0x13 BAD_CMD to the 0x9001 frame (e.g. the SDX20
 * LM960, which returns status 2 and emits no 0x9D, or the MDM9607 EG25-G) is a
 * per-generation negative, not a capture failure. Any BAD_CMD/echo the disarms provoke is left in the shared reader buffer
 * and skipped by the next read_response (retrieve_ranges). Returns 0 once both
 * frames are on the wire, -1 on write error. */
int diag_config_disarm_latched(int fd);

/* ---- Full F3 surface arming: QSH-trace 0x9D/0x92 + 0x60 events ----
 *
 * celldiag's f3= preset arms only the 0x7D EXT_MSG plane (0x79 plaintext /
 * 0x99 QSR4-terse). The QSH-trace plane (0x9D DIAG_QSH_TRACE_PAYLOAD_F / 0x92)
 * rides a different config subsystem -- 0x4B DIAG_SUBSYS_CMD_F / subsys 0x44 /
 * cmd 0x9001 -- and 0x60 events ride 0x60, neither of which the f3= mask ever
 * touches, so the full set of F3 log types needs these armed as well. The
 * builders below are the ARM counterparts of the disarm builders above: the
 * QSH-trace arm (the golden 40-SSID maskset) and the event-report enable.
 *
 * Gate these behind an explicit qsh= tier, not f3=all. QSH is debug trace (it
 * emits no cell observations) and its volume is enormous: over a thousand
 * QSH/F3 frames per DIAG_LOG_F frame on an SDX62 in NR5G-SA idle. A lean WiGLE
 * wardrive should not pay that; only a debug capture opts in.
 *
 * WARNING: the QSH-trace arm latches per subsystem and survives reboots, so a
 * capture that arms it must disarm on stop (diag_config_build_qsh_trace_disarm),
 * scoped to when it was armed. Otherwise the flood rides into the next capture,
 * whatever tool runs it.
 */

/* (ssid, level) pairs in the golden QSH-trace maskset (a CFW-3212 diag.cfg,
 * frame 73). */
#define DIAG_QSH_TRACE_GOLDEN_PAIRS  40
/* Golden ARM body length AFTER the 0x4B opcode: subsys(1) + cmd(2) + 4 u32
 * header words (16) + 40 * [u16 ssid + u16 level] (160) = 179 bytes. */
#define DIAG_QSH_TRACE_ARM_LEN       179
/* diag_id binding-table REQUEST body length AFTER the 0x4B opcode:
 * subsys(1) + u16le cmd(2) + u8 version(1) = 4 bytes. */
#define DIAG_DIAGID_REQ_LEN          4
/* Room for the DIAGID-table reply as it crossed the wire: a <=512-byte frame,
 * every byte escaped, plus its CRC and the 0x7E. */
#define DIAG_DIAGID_WIRE_MAX         (2 * (512 + 2) + 1)

/* Build the QSH-trace ARM body -- the bytes AFTER the 0x4B DIAG_SUBSYS_CMD_F
 * opcode. Mirrors build_qsh_trace_maskset_set(GOLDEN_QSH_TRACE_PAIRS)
 * byte-for-byte: subsys 0x44 + u16le(0x9001) + u32le(arg_count = 3 + 40)
 * + u32le(word_a = 1) + u32le(word_b = 1) + u32le(count = 40) + 40 x
 * [u16le(ssid) + u16le(level)] from the golden CFW-3212 /data/diag.cfg frame 73
 * (the exact maskset diag_mdlog replays to turn on 0x9D). This is the non-empty
 * counterpart of diag_config_build_qsh_trace_disarm (count 0). The golden pairs
 * are in strictly ascending ssid order -- the modem rejects any other order
 * with status 1. Writes DIAG_QSH_TRACE_ARM_LEN bytes; returns the
 * length, or 0 if cap < DIAG_QSH_TRACE_ARM_LEN. Pure/testable. */
size_t diag_config_build_qsh_trace_arm(uint8_t *out, size_t cap);

/* Build the DIAG event-report ENABLE body -- the 1 byte AFTER the 0x60
 * DIAG_EVENT_REPORT_F opcode: u8(1). Mirrors build_event_report_enable(True)
 * (u8(0x60) + u8(1)); send_cmd prepends the 0x60. The all-events surface needs
 * no accompanying 0x82 mask. Writes 1 byte; returns 1, or 0 if cap < 1. */
size_t diag_config_build_event_report_enable(uint8_t *out, size_t cap);

/* Build the DIAG event-report DISABLE body: u8(0) after the 0x60 opcode, the
 * counterpart of diag_config_build_event_report_enable. Mirrors
 * build_event_report_enable(False) (u8(0x60) + u8(0)). Writes 1 byte; returns
 * 1, or 0 if cap < 1. */
size_t diag_config_build_event_report_disable(uint8_t *out, size_t cap);

/* Build the QSHRINK4 diag_id binding-table REQUEST body -- the 4 bytes AFTER
 * the 0x4B opcode: subsys 0x12 (DIAG_SERV) + u16le(0x0222) + u8(version = 1).
 * The 5-byte form is required: the bare 4-byte
 * request WITHOUT the version byte is silently DROPPED on SDX55/62. The
 * reply names the protection domains behind the capture's diag_id channels so a
 * later 0x9D/0x99 frame can be resolved to the right qdb. Writes
 * DIAG_DIAGID_REQ_LEN bytes; returns the length, or 0 if cap is too small. */
size_t diag_config_build_diag_id_binding_request(uint8_t *out, size_t cap);

/* Arm the QSH-trace plane (0x9D/0x92) over an open DIAG fd: send the golden
 * maskset 0x9001 SET, read the 0x4B echo, inspect the u32 status word. NON-FATAL
 * by policy: a pre-QSH part is a
 * per-generation negative, not a capture failure (SDX20/LM960 returns status 2
 * and emits no 0x9D; MDM9607/EG25-G answers 0x13 BAD_CMD, which read_response
 * takes as the answer at once rather than waiting out its 20 s deadline).
 * Returns 0 on the modem's status-0
 * ack (0x9D should now flow), 1 when the frame went out but no status-0 echo
 * came back (non-zero status / BAD_CMD / timeout -- armed-or-unsupported, the
 * caller continues), or -1 on a write/transport I/O error. */
int diag_config_enable_qsh_trace(int fd, diag_reader_t *r);

/* Enable the 0x60 event-report stream over an open DIAG fd. NON-FATAL by
 * policy: a part that BAD_CMDs it just continues.
 * Returns 0 on the 0x60 echo, 1 on no echo (BAD_CMD/timeout), -1 on I/O error. */
int diag_config_enable_events(int fd, diag_reader_t *r);

/* Turn the 0x60 event-report stream back OFF over an open DIAG fd -- the stop
 * half of diag_config_enable_events. Fire-and-forget like
 * diag_config_disarm_latched: no ack is read (the stop path's fd has no reader
 * left), and a part that BAD_CMDs it has no stream to stop anyway. Returns 0
 * once the frame is written, -1 on a build or I/O error. */
int diag_config_disable_events(int fd);

/* Build the LOG_CONFIG DISABLE body: "<3xI" with operation 0, the 7 bytes after
 * the 0x73 opcode. One frame clears the mask of every log type. */
size_t diag_config_build_log_disable(uint8_t *out, size_t cap);

/* Clear the LOG mask over an open DIAG fd -- the stop half of
 * diag_config_apply_{narrow,full}_mask. Without it a capture leaves the
 * modem streaming its mask, at the full-mask rate after mask=full, for whatever
 * DIAG client opens the port next. Fire-and-forget like
 * diag_config_disable_events. Returns 0 once written, -1 on a build or I/O error. */
int diag_config_clear_log_mask(int fd);

/* Is `frame` (unescaped, CRC stripped) the DIAGID-table reply: 0x4B, subsys
 * 0x12, cmd u16le 0x0222? The table body is not validated -- an offline reader
 * of the stream does that; this only picks the frame out. */
int diag_config_is_diag_id_binding_reply(const uint8_t *frame, size_t len);

/* Request the diag_id binding table over an open DIAG fd. Best-effort like the
 * other arms: a bad_cmd/timeout is a recorded negative, never fatal.
 * Returns 0 on the table reply, 1 on no reply (bad_cmd/timeout), -1 on I/O
 * error. Any OTHER 0x4B frame read while waiting (a late QSH-trace echo) is
 * skipped, not taken for the table.
 *
 * On 0, the reply is written to `wire` exactly as it crossed the wire --
 * re-escaped, CRC'd and 0x7E-terminated, which is canonical, so the bytes are
 * the modem's own -- and its length to *wire_len (0 if wirecap is too small).
 * The caller relays it into the capture stream: the handshake reader
 * consumes the reply, so without the relay no tee, raw packet or .scan.json
 * ever saw it. `wire` may be NULL. */
int diag_config_request_diag_id_binding(int fd, diag_reader_t *r,
                                        uint8_t *wire, size_t wirecap,
                                        size_t *wire_len);

/* ---- SPC unlock (DIAG_SPC_F 0x41) ---- */

/* Build the DIAG_SPC_F request body -- the 6 bytes *after* the 0x41 opcode.
 * `spc` must be EXACTLY 6 ASCII decimal digits (the Service Programming Code;
 * factory default "000000"). Writes those 6 bytes to `out` and returns 6 on
 * success, or 0 if `spc` is not exactly 6 digits or cap < 6. Pure/testable;
 * mirrors qfenix diag_send_spc's `memset(&cmd[1], 0x30, 6)` for the default. */
size_t diag_config_build_spc(uint8_t *out, size_t cap, const char *spc);

/* Send a DIAG_SPC_F (0x41) Service Programming Code unlock over an open DIAG fd.
 * Some modem families -- notably EC2x/EG2x (MDM9607, e.g. the EG25-G) -- GATE
 * the DIAG_LOG_CONFIG_F SET_MASK behind an SPC unlock: without it every SET_MASK
 * is rejected and the modem emits no subscribed LOG codes, even though raw DIAG
 * flows. SDX24 (LM960) / SDX55 (RM500Q) do not gate it. Reads the
 * 0x41 echo out of any interleaved boot flood (like the other handshakes) and
 * treats status byte resp[1] == 1 as success (qfenix convention). Returns 0 on
 * the modem's success ack, -1 on I/O error, timeout, or a non-success status
 * (incl. a wrong SPC, which never echoes 0x41 and so trips the deadline). */
int diag_config_send_spc(int fd, diag_reader_t *r, const char *spc);

#endif /* DIAG_CONFIG_H */
