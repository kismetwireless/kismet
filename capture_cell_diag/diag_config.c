/* clock_gettime(CLOCK_MONOTONIC) needs a POSIX feature-test macro under strict
 * -std=c11; the Kismet build uses -std=gnu11 where it is visible by default. */
#define _DEFAULT_SOURCE
/* diag_config.c - DIAG LOG_CONFIG narrow-mask handshake.
 *
 * See diag_config.h. The pure mask math (diag_config_narrow_mask) is pinned by
 * the selftest.
 * The live handshake functions need real hardware to exercise.
 *
 * Self-test build (diag_capture.c is needed for diag_read_frame, used by the
 * live read_response helper linked into the same TU):
 *   cc -DDIAG_CONFIG_SELFTEST -Wall -Wextra -Werror \
 *      diag_config.c diag_hdlc.c diag_capture.c -o /tmp/diag_config_selftest
 */
#include "diag_config.h"
#include "diag_hdlc.h"

#include <errno.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* DIAG_LOG_CONFIG_F handshake constants. */
#define DIAG_LOG_CONFIG_F        0x73
#define LOG_CFG_DISABLE          0   /* clear every log type's mask */
#define LOG_CFG_RETRIEVE_RANGES  1
#define LOG_CFG_SET_MASK         3
#define LOG_CFG_SUCCESS          0

/* DIAG_LOG_CONFIG_F frame layout (deframed, opcode byte kept at [0]):
 *   [0]      cmd echo (0x73)
 *   [1..3]   3 pad bytes (they follow the opcode)
 *   [4..7]   operation (u32 LE)
 *   [8..11]  status (u32 LE)
 *   [12..]   16 bitsizes (u32 LE each), for RETRIEVE_RANGES
 * Requests have the same [3 pad][op u32][args...] shape after the opcode. */
#define LOG_CFG_OP_OFFSET        4
#define LOG_CFG_STATUS_OFFSET    8
#define LOG_CFG_BITSIZES_OFFSET  12

/* Target log codes. The eight cell codes are equipment id 0xB (item = code &
 * 0xFFF), so they subscribe within one type-0xB SET_MASK; the two GNSS codes
 * are type-1 (0x1476 >> 12 == 1), so the mask now spans two log types and
 * apply_mask_struct emits a SET_MASK for type-1 as well as type-0xB. On an
 * LTE-only / GNSS-off modem that advertises no type-1 range, filter_supported
 * drops the GNSS codes and the cell subset still arms.
 *   0xB193 LTE ML1 serving cell measurement (signal).
 *   0xB0C0 LTE RRC OTA, carries SIB1 -> full cell identity (MCC/MNC/TAC/CellID).
 *   0xB192 LTE ML1 idle-mode neighbor cells (PCI/EARFCN; energy, not dBm).
 *   0xB195 LTE ML1 connected-mode neighbor cells (PCI/EARFCN/RSRP).
 *   0xB17F LTE ML1 per-cell measurement (per-cell EARFCN/PCI + rsrp/rsrq/RSSI;
 *          fixed 40B). The DIAG source's per-cell RSSI, forwarded onto serving
 *          + neighbour observations. item 0x17F = 383 -> byte 47 bit 7, well
 *          inside the type-0xB range the higher cell codes already require.
 *   0xB197 LTE ML1 serving cell information: per-cell CONFIGURATION (DL
 *          bandwidth in RB, Tx antenna ports, as decoded by SCAT), cached per
 *          (pci, earfcn) and attached as bandwidth / bandwidth_rb / tx_antennas
 *          to every LTE observation of that cell. Low-rate. item 0x197 = 407
 *          -> byte 50 bit 7, the byte 0xB192/0xB193/0xB195 already populate.
 *          Its EARFCN is 16-bit truncated; the cache is keyed
 *          accordingly.
 *   0xB821 NR5G RRC OTA, carries NR SIB1 -> NR cell identity (item 0x821 is a
 *          much higher bit than the LTE codes, so the modem's type-0xB range
 *          must advertise past 2081 for it to subscribe).
 *   0xB97F NR5G ML1 measurement DB: per component-carrier serving +
 *          neighbour cells with per-cell SS-RSRP/RSRQ (checked against
 *          AT+QSCAN). The NR analog of the LTE 0xB193/0xB195 signal
 *          codes -- item 0x97F = 2431 is the highest bit in the set, so the type-0xB
 *          range must advertise past 2431 for it to subscribe.
 * (0xB825 is intentionally omitted: it is
 * LOG_NR5G_RRC_CONFIGURATION_INFO, nci-only, not a mappable measurement.)
 *
 * GNSS (type-1), so a DIAG-only wardrive has location and cell devices can be
 * geo-tagged from the DIAG source:
 *   0x1476 GNSS Position Report (lat/lon/alt + GPS UTC). The position source;
 *          item 0x476 = 1142 -> byte 142 bit 6. Layout confirmed against F3
 *          prints.
 *   0x14D8 GNSS ME Position Fix -- NOT a position source. Item 0x4D8 = 1240
 *          -> byte 155 bit 0 (the highest item in the set; a modem's type-1
 *          range must advertise past 1240 for it to subscribe).
 *
 *          It is not a backup GPS source either. Its lat/lon/alt bytes
 *          [+20..+43] are not populated by any known firmware, so they read
 *          0.0, which fails the 1 < |lat| < 90 validity gate: a 0x14D8 record
 *          can never yield a fix; the 0x1476 records are the entire GNSS
 *          position yield.
 *
 *          It stays in the mask as a GNSS engine-liveness signal: records
 *          arriving from it while 0x1476 produces no fix distinguish "the GNSS
 *          engine is running and has no sky view" from "GNSS is off / not
 *          subscribed". Those two states are otherwise indistinguishable at
 *          this layer, since both present as zero positions. The per-code
 *          census reports it as `decoded=N emitted=0 silent=true`, which is
 *          the liveness reading. Volume is ~1% of the stream.
 *
 *          The `0x14d8 kept for liveness, not position` selftest below pins
 *          this, so anyone removing "the dead GNSS code" reads this first. */
const uint16_t DIAG_TARGET_CODES[] = {
    0xB193, 0xB0C0, 0xB192, 0xB195, 0xB17F, 0xB197, 0xB821, 0xB97F,
    0x1476, 0x14D8 };
const size_t DIAG_TARGET_CODES_COUNT =
    sizeof(DIAG_TARGET_CODES) / sizeof(DIAG_TARGET_CODES[0]);

static uint32_t rd_u32le(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

int diag_config_narrow_mask(const uint16_t *codes, size_t ncodes,
                            diag_log_mask_t *m) {
    size_t i;

    for (i = 0; i < DIAG_LOG_TYPES; i++) {
        memset(m->mask[i], 0, DIAG_MAX_MASK_BYTES);
        m->mask_len[i] = 0;
    }

    for (i = 0; i < ncodes; i++) {
        uint16_t code = codes[i];
        unsigned log_type = (unsigned)(code >> 12);
        unsigned item = (unsigned)(code & 0x0FFF);
        uint32_t bitsize;
        size_t need;

        if (log_type >= DIAG_LOG_TYPES)
            return -1;
        bitsize = m->bitsizes[log_type];
        if (bitsize == 0 || item >= bitsize)
            return -1;

        need = (bitsize + 7) / 8;
        if (need > DIAG_MAX_MASK_BYTES)
            return -1;
        m->mask_len[log_type] = need;
        m->mask[log_type][item / 8] |= (uint8_t)(1u << (item % 8));
    }

    /* Exclusivity: every log type the modem advertises
     * that carries NO target code gets an explicit ALL-ZERO mask, so
     * apply_mask_struct() clears it instead of skipping it. SET_MASK is per
     * log type and the modem keeps a type's mask across DIAG port closes, so
     * skipping a type leaves whatever the PREVIOUS client armed there. On an
     * EG25-G a stale full mask on types 4/5/7 stays near-silent while the
     * modem idles on LTE, then floods off-mask 2G/3G codes (e.g. 0x508F) once
     * an AT+CFUN=4->1 forces a multi-RAT search. That looks like "the modem
     * drops the mask on CFUN"; it does not, and with the types cleared the
     * same cycle carries no off-mask codes.
     *
     * Types advertising 0 codes stay untouched (nothing to clear). A bogus
     * range past 4096 items is clamped exactly as diag_config_full_mask does,
     * keeping the SET_MASK bitsize field consistent with the bytes sent. */
    for (i = 0; i < DIAG_LOG_TYPES; i++) {
        uint32_t bitsize = m->bitsizes[i];

        if (bitsize == 0 || m->mask_len[i] != 0)
            continue;
        if (bitsize > (uint32_t)DIAG_MAX_MASK_BYTES * 8)
            bitsize = (uint32_t)DIAG_MAX_MASK_BYTES * 8;
        m->bitsizes[i] = bitsize;
        m->mask_len[i] = (bitsize + 7) / 8;   /* bytes already zeroed above */
    }
    return 0;
}

size_t diag_config_filter_supported(const uint16_t *codes, size_t ncodes,
                                    const uint32_t bitsizes[DIAG_LOG_TYPES],
                                    uint16_t *out, size_t outcap) {
    size_t i, k = 0;

    for (i = 0; i < ncodes && k < outcap; i++) {
        unsigned log_type = (unsigned)(codes[i] >> 12);
        unsigned item = (unsigned)(codes[i] & 0x0FFF);

        if (log_type >= DIAG_LOG_TYPES)
            continue;
        if (bitsizes[log_type] == 0 || item >= bitsizes[log_type])
            continue;
        out[k++] = codes[i];
    }
    return k;
}

int diag_config_full_mask(diag_log_mask_t *m) {
    size_t lt;

    for (lt = 0; lt < DIAG_LOG_TYPES; lt++) {
        uint32_t bitsize = m->bitsizes[lt];
        size_t need;

        memset(m->mask[lt], 0, DIAG_MAX_MASK_BYTES);
        m->mask_len[lt] = 0;
        if (bitsize == 0)
            continue;
        /* item is 12-bit; a well-behaved modem never advertises past 4096, but
         * clamp defensively so a bogus range can't overrun the 512-byte mask. */
        if (bitsize > (uint32_t)DIAG_MAX_MASK_BYTES * 8)
            bitsize = (uint32_t)DIAG_MAX_MASK_BYTES * 8;

        need = (bitsize + 7) / 8;
        memset(m->mask[lt], 0xFF, need);
        /* Clear bits past the advertised range in the final byte so we don't
         * subscribe codes the modem never declared. */
        if (bitsize % 8)
            m->mask[lt][need - 1] = (uint8_t)((1u << (bitsize % 8)) - 1);
        m->mask_len[lt] = need;
        /* Keep the SET_MASK bitsize field consistent with any clamp above. */
        m->bitsizes[lt] = bitsize;
    }
    return 0;
}

/* ---- live handshake ---- */

/* Read frames (via the shared robust reader) until one whose DIAG opcode
 * (byte 0) matches expect_cmd, skipping interleaved frames until a wall-clock
 * deadline -- a live port floods F3 (0x99) and LOG_F frames around the command
 * response, so many thousands of frames can precede it. Bounded by time, not a
 * frame count. Returns 0 on match, -1
 * on read error or timeout.
 *
 * The deadline must clear a *boot-time F3 flood*: a modem that powers up with
 * extended-message (0x99 QSR4 / 0x79) logging already enabled streams
 * ~10k+ frames before it services the LOG_CONFIG retrieve. On a Telit LM960
 * (SDX20) whose firmware boots with F3 on, the 0x73 echo can arrive ~6 s deep
 * into the flood, so a 5 s deadline fails the handshake spuriously. 20 s gives
 * comfortable margin without risking a hang (a genuinely dead port still trips
 * the 60 s idle-timeout in diag_read_frame). */
#define DIAG_RESP_TIMEOUT_S 20.0
static double monotonic_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

/* DIAG error responses: <code> <echo of the offending request...>. */
#define DIAG_BAD_CMD_F  0x13
#define DIAG_BAD_PARM_F 0x14
#define DIAG_BAD_LEN_F  0x15

/* Is this frame the modem REJECTING the request (expect_cmd, req)? The
 * echo must name this request's opcode AND repeat its first body bytes --
 * for a 0x4B request those are the subsys id and command word, which is what
 * tells the QSH arm (0x44/0x9001) from the diag_id binding (0x12/0x0222). A
 * rejection of any OTHER request (a fire-and-forget disarm's, left in the
 * reader buffer) is not this request's answer and is skipped like any frame. */
static int is_rejection_of(const uint8_t *f, size_t n, uint8_t expect_cmd,
                           const uint8_t *req, size_t reqlen) {
    size_t need = reqlen < 3 ? reqlen : 3;
    if (n < 2 + need)
        return 0;
    if (f[0] != DIAG_BAD_CMD_F && f[0] != DIAG_BAD_PARM_F && f[0] != DIAG_BAD_LEN_F)
        return 0;
    return f[1] == expect_cmd && (need == 0 || memcmp(f + 2, req, need) == 0);
}

/* Returns 0 on the request's echo, 1 when the modem REJECTED it (0x13/0x14/0x15
 * echoing it: an answer, so returned at once rather than waiting out the
 * deadline on every unsupported command), -1 on a read error or timeout.
 * `req`/`reqlen` are the body sent after the opcode.
 *
 * `echo_len`: how many leading body bytes the reply must repeat after the
 * opcode to count as THIS request's answer; 0 = the opcode alone. Every
 * LOG_CONFIG operation answers 0x73, so a stale ack of another operation (the
 * previous client's fire-and-forget LOG_CFG_DISABLE, which an MHI node keeps
 * queued across close) would otherwise pass as the RETRIEVE_RANGES reply and
 * fail the open. A LOG_CONFIG reply echoes its "<3xI" header, so matching
 * those 7 bytes skips it like any other frame. */
static int read_response(int fd, diag_reader_t *r, uint8_t expect_cmd,
                         const uint8_t *req, size_t reqlen, size_t echo_len,
                         uint8_t *out, size_t outcap, size_t *out_len) {
    double deadline = monotonic_s() + DIAG_RESP_TIMEOUT_S;
    if (echo_len > reqlen)
        echo_len = reqlen;
    for (;;) {
        if (diag_read_frame(fd, r, out, outcap, out_len) != 0)
            return -1;
        if (*out_len >= 1 + echo_len && out[0] == expect_cmd &&
            (echo_len == 0 || memcmp(out + 1, req, echo_len) == 0))
            return 0;
        if (is_rejection_of(out, *out_len, expect_cmd, req, reqlen))
            return 1;
        if (monotonic_s() > deadline)
            return -1;
    }
}

static int send_cmd(int fd, uint8_t cmd, const uint8_t *body, size_t bodylen) {
    uint8_t wire[2048];
    size_t wlen = diag_hdlc_build(cmd, body, bodylen, wire, sizeof(wire));
    size_t off = 0;

    if (wlen == 0)
        return -1;
    while (off < wlen) {
        ssize_t n = write(fd, wire + off, wlen - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)n;
    }
    tcdrain(fd);   /* block until the whole frame is on the wire before reading */
    return 0;
}

int diag_config_retrieve_ranges(int fd, diag_reader_t *r,
                                uint32_t bitsizes[DIAG_LOG_TYPES]) {
    uint8_t body[7];
    uint8_t resp[512];
    size_t rlen = 0;
    size_t i;

    /* "<3xI": 3 pad bytes + u32 operation. */
    memset(body, 0, sizeof(body));
    body[3] = LOG_CFG_RETRIEVE_RANGES;

    if (send_cmd(fd, DIAG_LOG_CONFIG_F, body, sizeof(body)) != 0)
        return -1;
    if (read_response(fd, r, DIAG_LOG_CONFIG_F, body, sizeof(body), sizeof(body),
                      resp, sizeof(resp), &rlen) != 0)
        return -1;
    if (rlen < LOG_CFG_BITSIZES_OFFSET + DIAG_LOG_TYPES * 4)
        return -1;
    if (rd_u32le(resp + LOG_CFG_OP_OFFSET) != LOG_CFG_RETRIEVE_RANGES)
        return -1;
    if (rd_u32le(resp + LOG_CFG_STATUS_OFFSET) != LOG_CFG_SUCCESS)
        return -1;

    for (i = 0; i < DIAG_LOG_TYPES; i++)
        bitsizes[i] = rd_u32le(resp + LOG_CFG_BITSIZES_OFFSET + i * 4);
    return 0;
}

/* Emit one SET_MASK per touched log type from an already-built mask struct.
 * Shared by the narrow and full apply paths so both drive the modem over the
 * exact same wire framing -- the preset only changes which bits `m` carries,
 * never how they are sent. Returns 0 on success, -1 on write error. */
static int apply_mask_struct(int fd, const diag_log_mask_t *m) {
    size_t lt;

    for (lt = 0; lt < DIAG_LOG_TYPES; lt++) {
        uint8_t body[15 + DIAG_MAX_MASK_BYTES];
        size_t blen;

        if (m->mask_len[lt] == 0)
            continue;

        /* "<3xIII" + mask: 3 pad, then u32 SET_MASK, u32 log_type, u32 bitsize,
         * then the mask bytes. Header is 15 bytes (3 + 3*4). */
        memset(body, 0, 15);
        body[3] = LOG_CFG_SET_MASK;                             /* op   @ [3..6]  */
        body[7] = (uint8_t)(lt & 0xFF);                         /* type @ [7..10] */
        body[11] = (uint8_t)(m->bitsizes[lt] & 0xFF);           /* bits @ [11..14]*/
        body[12] = (uint8_t)((m->bitsizes[lt] >> 8) & 0xFF);
        body[13] = (uint8_t)((m->bitsizes[lt] >> 16) & 0xFF);
        body[14] = (uint8_t)((m->bitsizes[lt] >> 24) & 0xFF);
        memcpy(body + 15, m->mask[lt], m->mask_len[lt]);
        blen = 15 + m->mask_len[lt];

        /* Fire-and-forget: the SET_MASK ack and the log records it enables flow
         * straight into the raw stream, and the decoder ignores non-log
         * frames -- so we do not block fishing the ack out of a live log flood.
         * The command takes effect regardless (verified on RM520N-GL SDX62). */
        if (send_cmd(fd, DIAG_LOG_CONFIG_F, body, blen) != 0)
            return -1;
    }
    return 0;
}

int diag_config_apply_narrow_mask(int fd, diag_reader_t *r,
                                  const uint16_t *codes, size_t ncodes) {
    diag_log_mask_t m;
    uint16_t supported[DIAG_MAX_TARGET_CODES];
    size_t nsup;

    if (diag_config_retrieve_ranges(fd, r, m.bitsizes) != 0)
        return -1;
    /* Filter to codes this modem advertises before building the mask, so a
     * mixed LTE+NR target set arms on an LTE-only modem (subscribing to the
     * supported subset) instead of failing the whole handshake on the first
     * out-of-range code. narrow_mask stays strict on the survivors. */
    nsup = diag_config_filter_supported(codes, ncodes, m.bitsizes,
                                        supported, DIAG_MAX_TARGET_CODES);
    if (nsup == 0)
        return -1;   /* modem advertises none of the requested codes */
    if (diag_config_narrow_mask(supported, nsup, &m) != 0)
        return -1;
    return apply_mask_struct(fd, &m);
}

int diag_config_apply_full_mask(int fd, diag_reader_t *r) {
    diag_log_mask_t m;

    if (diag_config_retrieve_ranges(fd, r, m.bitsizes) != 0)
        return -1;
    if (diag_config_full_mask(&m) != 0)
        return -1;
    return apply_mask_struct(fd, &m);
}

/* ---- F3 ext-message arming (DIAG_EXT_MSG_CONFIG_F, distinct from LOG_F) ---- */

/* F3 free-text debug messages ride DIAG_EXT_MSG_CONFIG_F, NOT the LOG_CONFIG_F
 * (0x73) subsystem above -- see diag_config.h. */
#define DIAG_EXT_MSG_CONFIG_F      0x7D
#define EXT_MSG_SET_ALL_RT_MASKS   5

size_t diag_config_build_f3(uint8_t *out, size_t cap, uint32_t levels) {
    /* "<BxxI": sub_cmd + 2 reserved pad bytes + u32 runtime-level mask. */
    if (cap < 7)
        return 0;
    /* A zero mask is "arm nothing", which is not a thing this path should ever
     * send: the caller's OFF state is "do not send the handshake at all". An
     * all-zero mask on the wire would arm the modem to emit nothing while the
     * source reports F3 as armed -- silence that reads as a quiet modem. */
    if (levels == 0)
        return 0;
    memset(out, 0, 7);
    out[0] = EXT_MSG_SET_ALL_RT_MASKS;
    out[3] = (uint8_t)(levels & 0xFF);
    out[4] = (uint8_t)((levels >> 8) & 0xFF);
    out[5] = (uint8_t)((levels >> 16) & 0xFF);
    out[6] = (uint8_t)((levels >> 24) & 0xFF);
    return 7;
}

size_t diag_config_build_all_f3(uint8_t *out, size_t cap) {
    return diag_config_build_f3(out, cap, DIAG_F3_LEVELS_ALL);
}

int diag_config_enable_f3(int fd, diag_reader_t *r, uint32_t levels) {
    uint8_t body[7];
    uint8_t resp[256];
    size_t rlen = 0;

    if (diag_config_build_f3(body, sizeof(body), levels) != sizeof(body))
        return -1;
    if (send_cmd(fd, DIAG_EXT_MSG_CONFIG_F, body, sizeof(body)) != 0)
        return -1;
    /* Wait for the 0x7D echo. Unlike the fire-and-forget SET_MASK path, we read
     * the ack so a wrong layout / DIAG_BAD_CMD_F rejection surfaces as a failure
     * (read_response tolerates any interleaved flood until the echo or the
     * deadline, then returns -1). */
    if (read_response(fd, r, DIAG_EXT_MSG_CONFIG_F, body, sizeof(body), 0, resp, sizeof(resp), &rlen) != 0)
        return -1;
    return 0;
}

int diag_config_enable_all_f3(int fd, diag_reader_t *r) {
    return diag_config_enable_f3(fd, r, DIAG_F3_LEVELS_ALL);
}

/* ---- SPC unlock (DIAG_SPC_F, gates SET_MASK on EC2x/EG2x) ---- */

#define DIAG_SPC_F   0x41
#define SPC_LEN      6

size_t diag_config_build_spc(uint8_t *out, size_t cap, const char *spc) {
    size_t i;

    if (spc == NULL || cap < SPC_LEN)
        return 0;
    for (i = 0; i < SPC_LEN; i++) {
        /* A short string trips here at its '\0' (< '0'), so this also enforces
         * "at least 6 chars" without a separate length read. */
        if (spc[i] < '0' || spc[i] > '9')
            return 0;
    }
    if (spc[SPC_LEN] != '\0')   /* longer than 6 digits -> reject */
        return 0;
    memcpy(out, spc, SPC_LEN);
    return SPC_LEN;
}

int diag_config_send_spc(int fd, diag_reader_t *r, const char *spc) {
    uint8_t body[SPC_LEN];
    uint8_t resp[64];
    size_t rlen = 0;

    if (diag_config_build_spc(body, sizeof(body), spc) != SPC_LEN)
        return -1;
    if (send_cmd(fd, DIAG_SPC_F, body, sizeof(body)) != 0)
        return -1;
    /* Fish the 0x41 echo out of any boot-time flood. A rejected SPC replies with
     * a DIAG error opcode (0x18 BAD_SPC_MODE_F etc.), not 0x41, so read_response
     * skips it and trips the deadline -> -1, which is the failure we want. */
    if (read_response(fd, r, DIAG_SPC_F, body, sizeof(body), 0, resp, sizeof(resp), &rlen) != 0)
        return -1;
    if (rlen < 2 || resp[1] != 1)   /* status byte: 1 == unlocked (qfenix) */
        return -1;
    return 0;
}

/* ---- Latched-state disarm: QSH-trace 0x9001 empty maskset + F3 0x7D level 0 ---- */

#define DIAG_SUBSYS_CMD_F        0x4B    /* subsystem-dispatch envelope opcode   */
#define DIAG_SUBSYS_LTE          0x44    /* subsys_id the QSH-trace maskset rides */
#define QSH_TRACE_MASKSET_SET    0x9001  /* subsys cmd: QSH-trace maskset SET     */
#define QSH_TRACE_SET_MIN_ARGS   3       /* arg_count base; +1 per (ssid,level)   */

size_t diag_config_build_qsh_trace_disarm(uint8_t *out, size_t cap) {
    /* Body AFTER the 0x4B opcode. Mirrors build_qsh_trace_maskset_set(())
     * byte-for-byte: subsys_id + u16le(cmd) + u32le(arg_count) + u32le(word_a)
     * + u32le(word_b) + u32le(count), with count == 0 so no (ssid,level) pairs
     * follow. arg_count is QSH_TRACE_SET_MIN_ARGS + count == 3; word_a/word_b
     * are 1 in the sole golden cfg. An empty maskset is the matching disarm. */
    if (cap < 19)
        return 0;
    memset(out, 0, 19);
    out[0]  = DIAG_SUBSYS_LTE;                                 /* subsys_id      */
    out[1]  = (uint8_t)(QSH_TRACE_MASKSET_SET & 0xFF);         /* cmd lo  (0x01) */
    out[2]  = (uint8_t)((QSH_TRACE_MASKSET_SET >> 8) & 0xFF);  /* cmd hi  (0x90) */
    out[3]  = QSH_TRACE_SET_MIN_ARGS;                          /* arg_count = 3  */
    out[7]  = 1;                                               /* word_a = 1     */
    out[11] = 1;                                               /* word_b = 1     */
    /* out[15..18] = count = 0 (already zeroed) -> empty maskset = disarm.       */
    return 19;
}

size_t diag_config_build_f3_disarm(uint8_t *out, size_t cap) {
    /* Body AFTER the 0x7D opcode: SET_ALL_RT_MASKS (5) + 2 pad + u32le(0).
     * The level-0 form diag_config_build_f3() refuses (it treats an all-zero
     * arm as a report-armed/emit-nothing bug); a DISARM legitimately wants it,
     * mirroring build_ext_msg_config_set_all_rt_masks_request(0). */
    if (cap < 7)
        return 0;
    memset(out, 0, 7);
    out[0] = EXT_MSG_SET_ALL_RT_MASKS;   /* 5; out[1..6] stay 0 -> pad + level 0 */
    return 7;
}

int diag_config_disarm_latched(int fd) {
    uint8_t f3[7];
    uint8_t qsh[19];

    /* F3 then QSH -- independent subsystems, so order is immaterial, but fixed
     * for a reproducible wire trace. Both fire-and-forget (no ack read): the
     * disarm takes effect regardless, and a pre-QSH part's BAD_CMD is skipped
     * by the next read_response. */
    if (diag_config_build_f3_disarm(f3, sizeof(f3)) != sizeof(f3))
        return -1;
    if (send_cmd(fd, DIAG_EXT_MSG_CONFIG_F, f3, sizeof(f3)) != 0)
        return -1;
    if (diag_config_build_qsh_trace_disarm(qsh, sizeof(qsh)) != sizeof(qsh))
        return -1;
    if (send_cmd(fd, DIAG_SUBSYS_CMD_F, qsh, sizeof(qsh)) != 0)
        return -1;
    return 0;
}

/* ---- Full F3 surface arming: QSH-trace 0x9D/0x92 + 0x60 events ---- */

#define DIAG_EVENT_REPORT_F      0x60    /* event-report on/off opcode           */
#define DIAG_SERV_SUBSYS         0x12    /* DIAG_SERV subsys the diag_id table rides */
#define DIAGID_TABLE_CMD         0x0222  /* DIAGNOSTIC_SERVICES_DIAGID_TABLE cmd  */
#define DIAGID_TABLE_VERSION     0x01    /* the 5-byte form; bare 4-byte is dropped */

/* The exact 40-SSID (ssid, level) maskset from the golden CFW-3212
 * /data/diag.cfg frame 73, verbatim. In
 * strictly ascending ssid order (the modem rejects any other order with
 * status 1). A QSH-trace `level` is NOT a monotonic severity -- some SSIDs carry a
 * per-subsystem bitmask (e.g. 0x4C -> 0x087F) -- so no range check applies. */
static const uint16_t QSH_TRACE_GOLDEN[DIAG_QSH_TRACE_GOLDEN_PAIRS][2] = {
    {0x06, 0x0F}, {0x09, 0x3E}, {0x0B, 0x03}, {0x0D, 0x03}, {0x12, 0x01},
    {0x2A, 0x03}, {0x2D, 0x03}, {0x2F, 0x07}, {0x34, 0x0F}, {0x35, 0x1F},
    {0x36, 0x03}, {0x3D, 0x03}, {0x40, 0x03}, {0x49, 0x0B}, {0x4C, 0x087F},
    {0x4E, 0x02}, {0x50, 0x03}, {0x53, 0x3F}, {0x54, 0x0F}, {0x55, 0x0F},
    {0x56, 0x03}, {0x57, 0x03}, {0x58, 0x01}, {0x59, 0x0F}, {0x5E, 0x01},
    {0x60, 0x07}, {0x61, 0x03}, {0x62, 0x0F}, {0x63, 0x03}, {0x64, 0x3F},
    {0x65, 0x03}, {0x68, 0x03}, {0x69, 0x0F}, {0x6B, 0x03}, {0x6C, 0x03},
    {0x6D, 0x03}, {0x6E, 0x03}, {0x6F, 0x01}, {0x70, 0x01}, {0x71, 0x03},
};

size_t diag_config_build_qsh_trace_arm(uint8_t *out, size_t cap) {
    /* Body AFTER the 0x4B opcode -- the non-empty counterpart of
     * diag_config_build_qsh_trace_disarm. Header identical to the disarm
     * (subsys + cmd + arg_count + word_a + word_b + count), but count == 40 and
     * arg_count == 3 + 40, followed by the 40 (u16le ssid, u16le level) pairs. */
    size_t i, pos;
    const uint32_t count = DIAG_QSH_TRACE_GOLDEN_PAIRS;
    const uint32_t arg_count = QSH_TRACE_SET_MIN_ARGS + count;   /* 3 + 40 = 43 */

    if (cap < DIAG_QSH_TRACE_ARM_LEN)
        return 0;
    memset(out, 0, DIAG_QSH_TRACE_ARM_LEN);
    out[0]  = DIAG_SUBSYS_LTE;                                 /* subsys_id 0x44 */
    out[1]  = (uint8_t)(QSH_TRACE_MASKSET_SET & 0xFF);         /* cmd lo  (0x01) */
    out[2]  = (uint8_t)((QSH_TRACE_MASKSET_SET >> 8) & 0xFF);  /* cmd hi  (0x90) */
    out[3]  = (uint8_t)arg_count;                              /* arg_count = 43 */
    out[7]  = 1;                                               /* word_a = 1     */
    out[11] = 1;                                               /* word_b = 1     */
    out[15] = (uint8_t)count;                                  /* count = 40     */
    /* 40 (ssid, level) pairs, each two u16le, starting after the 16-byte header
     * (subsys+cmd = 3 bytes, then 4 u32 words = bytes 3..18, so pairs at 19). */
    pos = 19;
    for (i = 0; i < DIAG_QSH_TRACE_GOLDEN_PAIRS; i++) {
        out[pos++] = (uint8_t)(QSH_TRACE_GOLDEN[i][0] & 0xFF);        /* ssid lo */
        out[pos++] = (uint8_t)((QSH_TRACE_GOLDEN[i][0] >> 8) & 0xFF); /* ssid hi */
        out[pos++] = (uint8_t)(QSH_TRACE_GOLDEN[i][1] & 0xFF);        /* lvl  lo */
        out[pos++] = (uint8_t)((QSH_TRACE_GOLDEN[i][1] >> 8) & 0xFF); /* lvl  hi */
    }
    return DIAG_QSH_TRACE_ARM_LEN;   /* pos == 19 + 160 == 179 */
}

size_t diag_config_build_event_report_enable(uint8_t *out, size_t cap) {
    /* Body AFTER the 0x60 opcode: u8(1). send_cmd prepends the 0x60. */
    if (cap < 1)
        return 0;
    out[0] = 1;
    return 1;
}

size_t diag_config_build_event_report_disable(uint8_t *out, size_t cap) {
    /* Body AFTER the 0x60 opcode: u8(0). send_cmd prepends the 0x60. */
    if (cap < 1)
        return 0;
    out[0] = 0;
    return 1;
}

size_t diag_config_build_diag_id_binding_request(uint8_t *out, size_t cap) {
    /* Body AFTER the 0x4B opcode: subsys 0x12 + u16le(0x0222) + u8(version). */
    if (cap < DIAG_DIAGID_REQ_LEN)
        return 0;
    out[0] = DIAG_SERV_SUBSYS;                             /* subsys 0x12       */
    out[1] = (uint8_t)(DIAGID_TABLE_CMD & 0xFF);           /* cmd lo  (0x22)    */
    out[2] = (uint8_t)((DIAGID_TABLE_CMD >> 8) & 0xFF);    /* cmd hi  (0x02)    */
    out[3] = DIAGID_TABLE_VERSION;                         /* table version = 1 */
    return DIAG_DIAGID_REQ_LEN;
}

int diag_config_enable_qsh_trace(int fd, diag_reader_t *r) {
    uint8_t body[DIAG_QSH_TRACE_ARM_LEN];
    uint8_t resp[256];
    size_t rlen = 0;
    uint32_t status;

    if (diag_config_build_qsh_trace_arm(body, sizeof(body)) != sizeof(body))
        return -1;
    if (send_cmd(fd, DIAG_SUBSYS_CMD_F, body, sizeof(body)) != 0)
        return -1;   /* write/transport I/O error */
    /* NON-FATAL by policy: a part that doesn't implement QSH trace answers
     * BAD_CMD (read_response returns 1 at once) or, on the SDX20,
     * echoes with a non-zero status -> we report 1 (armed-or-unsupported), not
     * -1. Only a silent part still costs the deadline. The caller continues
     * either way. */
    if (read_response(fd, r, DIAG_SUBSYS_CMD_F, body, sizeof(body), 0, resp, sizeof(resp), &rlen) != 0)
        return 1;
    /* resp: 0x4B, subsys(0x44), cmd(0x01 0x90), u32le status. */
    if (rlen < 8)
        return 1;
    status = (uint32_t)resp[4] | ((uint32_t)resp[5] << 8)
           | ((uint32_t)resp[6] << 16) | ((uint32_t)resp[7] << 24);
    return status == 0 ? 0 : 1;
}

int diag_config_enable_events(int fd, diag_reader_t *r) {
    uint8_t body[1];
    uint8_t resp[64];
    size_t rlen = 0;

    if (diag_config_build_event_report_enable(body, sizeof(body)) != sizeof(body))
        return -1;
    if (send_cmd(fd, DIAG_EVENT_REPORT_F, body, sizeof(body)) != 0)
        return -1;
    if (read_response(fd, r, DIAG_EVENT_REPORT_F, body, sizeof(body), 0, resp, sizeof(resp), &rlen) != 0)
        return 1;   /* BAD_CMD/timeout -- non-fatal, additive stream */
    return 0;
}

int diag_config_disable_events(int fd) {
    uint8_t body[1];

    if (diag_config_build_event_report_disable(body, sizeof(body)) != sizeof(body))
        return -1;
    return send_cmd(fd, DIAG_EVENT_REPORT_F, body, sizeof(body)) != 0 ? -1 : 0;
}

size_t diag_config_build_log_disable(uint8_t *out, size_t cap) {
    /* "<3xI": 3 pad bytes + u32le operation, the retrieve_ranges framing. */
    if (cap < 7)
        return 0;
    memset(out, 0, 7);
    out[3] = LOG_CFG_DISABLE;
    return 7;
}

int diag_config_clear_log_mask(int fd) {
    uint8_t body[7];

    if (diag_config_build_log_disable(body, sizeof(body)) != sizeof(body))
        return -1;
    return send_cmd(fd, DIAG_LOG_CONFIG_F, body, sizeof(body)) != 0 ? -1 : 0;
}

int diag_config_is_diag_id_binding_reply(const uint8_t *frame, size_t len) {
    return len >= 4 && frame[0] == DIAG_SUBSYS_CMD_F
        && frame[1] == DIAG_SERV_SUBSYS
        && frame[2] == (uint8_t)(DIAGID_TABLE_CMD & 0xFF)
        && frame[3] == (uint8_t)((DIAGID_TABLE_CMD >> 8) & 0xFF);
}

int diag_config_request_diag_id_binding(int fd, diag_reader_t *r,
                                        uint8_t *wire, size_t wirecap,
                                        size_t *wire_len) {
    uint8_t body[DIAG_DIAGID_REQ_LEN];
    uint8_t resp[512];
    size_t rlen = 0;
    double deadline;

    if (wire_len != NULL)
        *wire_len = 0;
    if (diag_config_build_diag_id_binding_request(body, sizeof(body))
            != sizeof(body))
        return -1;
    if (send_cmd(fd, DIAG_SUBSYS_CMD_F, body, sizeof(body)) != 0)
        return -1;
    /* Best-effort: SDX20/MDM9607 answer 0x13 BAD_CMD (never echoes 0x4B for this
     * cmd), SDX55/62 return the table. A missing reply is a recorded negative.
     * read_response returns the first 0x4B of ANY subsys, so keep reading until
     * it is this one. */
    deadline = monotonic_s() + DIAG_RESP_TIMEOUT_S;
    for (;;) {
        if (read_response(fd, r, DIAG_SUBSYS_CMD_F, body, sizeof(body), 0, resp, sizeof(resp), &rlen) != 0)
            return 1;
        if (diag_config_is_diag_id_binding_reply(resp, rlen))
            break;
        if (monotonic_s() > deadline)
            return 1;
    }
    if (wire != NULL && wire_len != NULL)
        *wire_len = diag_hdlc_build(resp[0], resp + 1, rlen - 1, wire, wirecap);
    return 0;
}

#ifdef DIAG_CONFIG_SELFTEST
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/wait.h>

static int fail;

static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        fail = 1;
    }
}

/* A forked fake modem on `fd`: writes `a`, then `b` (either may be NULL), then
 * streams log frames every 50 ms for 30 s, as a live DIAG port does. The
 * stream is what lets a request that is never matched reach read_response's
 * 20 s deadline instead of diag_read_frame's 60 s idle timeout. */
static pid_t fake_modem(int fd, const uint8_t *a, size_t al,
                        const uint8_t *b, size_t bl) {
    pid_t pid = fork();
    if (pid != 0)
        return pid;
    static const uint8_t logbody[] = { 0x00, 0x10, 0x00, 0xC0, 0xB0 };
    uint8_t filler[32];
    size_t fl = diag_hdlc_build(0x10, logbody, sizeof(logbody), filler, sizeof(filler));
    if ((a && write(fd, a, al) != (ssize_t)al) || (b && write(fd, b, bl) != (ssize_t)bl))
        _exit(1);
    for (int i = 0; i < 600; i++) {
        if (write(fd, filler, fl) != (ssize_t)fl)
            _exit(0);
        usleep(50000);
    }
    _exit(0);
}

static void stop_fake_modem(pid_t pid) {
    if (pid > 0) {
        kill(pid, SIGKILL);
        waitpid(pid, NULL, 0);
    }
}

int main(void) {
    diag_log_mask_t m;
    size_t i;

    memset(&m, 0, sizeof(m));

    /* Worked example:
     * bitsizes[0xB]=1024, codes {0xB193, 0xB0C0} ->
     * type 0xB, len 128, byte24=0x01 (0xB0C0), byte50=0x08 (0xB193). */
    m.bitsizes[0xB] = 1024;
    {
        const uint16_t codes[] = { 0xB193, 0xB0C0 };
        check(diag_config_narrow_mask(codes, 2, &m) == 0, "narrow_mask ok");
        check(m.mask_len[0xB] == 128, "type 0xB mask len == 128");
        check(m.mask[0xB][24] == 0x01, "byte 24 == 0x01 (0xB0C0)");
        check(m.mask[0xB][50] == 0x08, "byte 50 == 0x08 (0xB193)");
        for (i = 0; i < DIAG_MAX_MASK_BYTES; i++)
            if (i != 24 && i != 50)
                check(m.mask[0xB][i] == 0, "no stray bits set");
        for (i = 0; i < DIAG_LOG_TYPES; i++)
            if (i != 0xB)
                check(m.mask_len[i] == 0,
                      "unadvertised types (bitsize 0) stay untouched");
    }

    /* Exclusivity: an ADVERTISED type with no target code is sent an
     * explicit all-zero mask, so a previous client's mask on it is cleared.
     * Skipping it causes the EG25-G 2G/3G flood after a CFUN cycle. */
    {
        const uint16_t codes[] = { 0xB193 };
        memset(&m, 0, sizeof(m));
        m.bitsizes[0xB] = 1024;
        m.bitsizes[0x4] = 2320;   /* EG25-G WCDMA range, measured */
        m.bitsizes[0x5] = 1056;   /* EG25-G GSM range, measured */
        m.bitsizes[0x7] = 1279;   /* not a multiple of 8 -> 160 bytes */
        check(diag_config_narrow_mask(codes, 1, &m) == 0, "exclusive: ok");
        check(m.mask_len[0x4] == 290, "exclusive: type 4 cleared (290 bytes)");
        check(m.mask_len[0x5] == 132, "exclusive: type 5 cleared (132 bytes)");
        check(m.mask_len[0x7] == 160, "exclusive: type 7 cleared (160 bytes)");
        for (i = 0; i < DIAG_MAX_MASK_BYTES; i++)
            check(m.mask[0x4][i] == 0 && m.mask[0x5][i] == 0 &&
                      m.mask[0x7][i] == 0,
                  "exclusive: cleared types carry no set bit");
        check(m.mask_len[0x1] == 0, "exclusive: unadvertised type 1 untouched");
        check(m.mask_len[0xB] == 128 && m.mask[0xB][50] == 0x08,
              "exclusive: the target type is still armed");
    }

    /* A bogus >4096-item range on a cleared type is clamped like full_mask,
     * so the zero mask fits the 512-byte buffer and bitsize matches it. */
    {
        const uint16_t codes[] = { 0xB193 };
        memset(&m, 0, sizeof(m));
        m.bitsizes[0xB] = 1024;
        m.bitsizes[0xD] = 9000;
        check(diag_config_narrow_mask(codes, 1, &m) == 0, "clamp: ok");
        check(m.mask_len[0xD] == DIAG_MAX_MASK_BYTES && m.bitsizes[0xD] == 4096,
              "clamp: oversized cleared type clamped to 512 bytes / 4096 bits");
    }

    /* Out-of-range item is rejected without applying anything. */
    {
        const uint16_t bad[] = { 0xBFFF }; /* item 0xFFF >= bitsize 1024 */
        memset(&m, 0, sizeof(m));
        m.bitsizes[0xB] = 1024;
        check(diag_config_narrow_mask(bad, 1, &m) == -1, "out-of-range rejected");
    }

    /* Equipment id with no advertised codes is rejected. */
    {
        const uint16_t bad[] = { 0xC000 }; /* type 0xC, bitsize 0 */
        memset(&m, 0, sizeof(m));
        m.bitsizes[0xB] = 1024;
        check(diag_config_narrow_mask(bad, 1, &m) == -1, "empty type rejected");
    }

    check(DIAG_TARGET_CODES_COUNT == 10 && DIAG_TARGET_CODES[0] == 0xB193 &&
              DIAG_TARGET_CODES[1] == 0xB0C0 && DIAG_TARGET_CODES[2] == 0xB192 &&
              DIAG_TARGET_CODES[3] == 0xB195 && DIAG_TARGET_CODES[4] == 0xB17F &&
              DIAG_TARGET_CODES[5] == 0xB197 &&
              DIAG_TARGET_CODES[6] == 0xB821 && DIAG_TARGET_CODES[7] == 0xB97F &&
              DIAG_TARGET_CODES[8] == 0x1476 && DIAG_TARGET_CODES[9] == 0x14D8,
          "target codes == {8 cell type-0xB} + {0x1476,0x14D8 GNSS type-1}");

    /* 0x14D8 stays in the mask, but not as a backup GPS source (parse_0x14d8
     * hardcodes lat/lon/alt to 0.0, so it never yields a fix). It is kept as a
     * GNSS engine-liveness signal: its records distinguish "engine running, no
     * sky view" from "GNSS off", two states that otherwise both present as
     * zero positions.
     *
     * This check exists because the natural cleanup is to delete the code. An
     * assertion that only counts codes would pass whichever GNSS code was
     * dropped, so the identity is asserted alongside the ordering that puts
     * 0x14D8 last, and the message names the reason. */
    check(DIAG_TARGET_CODES[9] == 0x14D8 && DIAG_TARGET_CODES[8] == 0x1476,
          "0x14d8 kept for liveness, not position; 0x1476 is the only "
          "position source");

    /* Full target set mask math. The cell codes are type-0xB, incl. the high-
     * item NR codes 0xB821 (item 0x821 = 2081 -> byte 260, bit 1) and 0xB97F
     * (item 0x97F = 2431 -> byte 303, bit 7); needs a type-0xB range past 2431.
     * The GNSS codes are type-1, so the same call now populates a second log
     * type -- exercising the multi-type narrow-mask path.
     *   type 0xB:
     *     0xB0C0 item 192 -> byte 24 bit 0 (0x01)
     *     0xB17F item 383 -> byte 47 bit 7 (0x80)
     *     0xB192 item 402 -> byte 50 bit 2 (0x04)
     *     0xB193 item 403 -> byte 50 bit 3 (0x08)
     *     0xB195 item 405 -> byte 50 bit 5 (0x20)
 *     0xB197 item 407 -> byte 50 bit 7 (0x80)   => byte 50 == 0xAC
     *     0xB821 item 2081 -> byte 260 bit 1 (0x02)
     *     0xB97F item 2431 -> byte 303 bit 7 (0x80)
     *   type 0x1:
     *     0x1476 item 1142 -> byte 142 bit 6 (0x40)
     *     0x14D8 item 1240 -> byte 155 bit 0 (0x01) */
    {
        memset(&m, 0, sizeof(m));
        m.bitsizes[0xB] = 4096;
        m.bitsizes[0x1] = 4096;   /* modem must advertise a type-1 GNSS range */
        check(diag_config_narrow_mask(DIAG_TARGET_CODES, DIAG_TARGET_CODES_COUNT,
                                      &m) == 0, "full target set narrow_mask ok");
        check(m.mask_len[0xB] == 512, "type 0xB mask len == 512 (bitsize 4096)");
        check(m.mask[0xB][24] == 0x01, "byte 24 == 0x01 (0xB0C0)");
        check(m.mask[0xB][47] == 0x80, "byte 47 == 0x80 (0xB17F)");
        check(m.mask[0xB][50] == 0xAC,
              "byte 50 == 0xAC (0xB192|0xB193|0xB195|0xB197)");
        check(m.mask[0xB][260] == 0x02, "byte 260 == 0x02 (0xB821)");
        check(m.mask[0xB][303] == 0x80, "byte 303 == 0x80 (0xB97F)");
        for (i = 0; i < DIAG_MAX_MASK_BYTES; i++)
            if (i != 24 && i != 47 && i != 50 && i != 260 && i != 303)
                check(m.mask[0xB][i] == 0, "no stray bits set (type 0xB)");
        /* type-1 GNSS leg */
        check(m.mask_len[0x1] == 512, "type 0x1 mask len == 512 (bitsize 4096)");
        check(m.mask[0x1][142] == 0x40, "byte 142 == 0x40 (0x1476)");
        check(m.mask[0x1][155] == 0x01, "byte 155 == 0x01 (0x14D8)");
        for (i = 0; i < DIAG_MAX_MASK_BYTES; i++)
            if (i != 142 && i != 155)
                check(m.mask[0x1][i] == 0, "no stray bits set (type 0x1)");
    }

    /* full_mask (the `full` preset): every advertised bit set, byte length
     * mirrors narrow (ceil(bitsize/8)), trailing bits past the range cleared,
     * and only types with a non-zero advertised bitsize are touched. */
    {
        memset(&m, 0, sizeof(m));
        m.bitsizes[0xB] = 1024;   /* whole bytes: 128 */
        m.bitsizes[0x1] = 20;     /* partial last byte: ceil(20/8)=3, 20%8=4 */
        m.bitsizes[0x5] = 0;      /* untouched: modem advertised nothing here */
        check(diag_config_full_mask(&m) == 0, "full_mask ok");
        check(m.mask_len[0xB] == 128, "full type 0xB len == 128");
        check(m.mask[0xB][0] == 0xFF && m.mask[0xB][127] == 0xFF,
              "full type 0xB endpoints all-ones");
        check(m.mask_len[0x1] == 3, "full type 0x1 len == 3");
        check(m.mask[0x1][0] == 0xFF && m.mask[0x1][1] == 0xFF,
              "full type 0x1 first two bytes all-ones");
        check(m.mask[0x1][2] == 0x0F, "full type 0x1 last byte == 0x0F (20 bits)");
        for (i = 0; i < DIAG_LOG_TYPES; i++)
            if (i != 0xB && i != 0x1)
                check(m.mask_len[i] == 0, "full: zero-bitsize types stay untouched");
    }

    /* full_mask clamp guard: a bogus over-4096 bitsize is capped at the 512-byte
     * ceiling instead of overrunning the mask buffer. */
    {
        memset(&m, 0, sizeof(m));
        m.bitsizes[0xB] = 9000;   /* > 4096 codes -- impossible for a 12-bit item */
        check(diag_config_full_mask(&m) == 0, "full_mask clamp ok");
        check(m.mask_len[0xB] == DIAG_MAX_MASK_BYTES,
              "full clamp: mask_len == 512");
        check(m.bitsizes[0xB] == (uint32_t)DIAG_MAX_MASK_BYTES * 8,
              "full clamp: bitsize field clamped to 4096");
        check(m.mask[0xB][DIAG_MAX_MASK_BYTES - 1] == 0xFF,
              "full clamp: last byte all-ones (4096 %% 8 == 0)");
    }

    /* all-F3 arming payload: DIAG_EXT_MSG_CONFIG_F / SET_ALL_RT_MASKS.
     * sub_cmd 5, 2 pad bytes, u32le 0xFFFFFFFF. */
    {
        uint8_t b[7];
        size_t n = diag_config_build_all_f3(b, sizeof(b));
        check(n == 7, "all_f3 body length == 7");
        check(b[0] == 5, "all_f3 sub_cmd == SET_ALL_RT_MASKS (5)");
        check(b[1] == 0 && b[2] == 0, "all_f3 reserved pad bytes zero");
        check(b[3] == 0xFF && b[4] == 0xFF && b[5] == 0xFF && b[6] == 0xFF,
              "all_f3 level mask == 0xFFFFFFFF (every severity on)");
        check(diag_config_build_all_f3(b, 6) == 0, "all_f3 rejects cap < 7");
    }

    /* Subtractive severity floors. The named masks are the two non-ALL rows
     * of the retention table in diag_config.h; the point of pinning the
     * literal bytes is that a floor is ONE u32 and a wrong one silences the
     * log while every test that checks "is F3 armed" stays green.
     *
     * The custom-bit check below matters most: 0x00000018 is "ERROR|FATAL",
     * the selective reading of severity floor, and it keeps only about 1% of
     * a real F3 stream. It must never be one of the presets. */
    {
        uint8_t b[7];
        check(diag_config_build_f3(b, sizeof(b), DIAG_F3_LEVELS_HIGH_AND_UP) == 7,
              "build_f3 HIGH_AND_UP length == 7");
        check(b[0] == 5 && b[1] == 0 && b[2] == 0,
              "build_f3 HIGH_AND_UP header == sub_cmd 5 + zero pad");
        check(b[3] == 0xFC && b[4] == 0xFF && b[5] == 0xFF && b[6] == 0xFF,
              "build_f3 HIGH_AND_UP mask == 0xFFFFFFFC little-endian");

        check(diag_config_build_f3(b, sizeof(b), DIAG_F3_LEVELS_ERROR_AND_UP) == 7,
              "build_f3 ERROR_AND_UP length == 7");
        check(b[3] == 0xF8 && b[4] == 0xFF && b[5] == 0xFF && b[6] == 0xFF,
              "build_f3 ERROR_AND_UP mask == 0xFFFFFFF8 little-endian");

        /* Subtractive, not selective: every preset keeps the custom bits. */
        check((DIAG_F3_LEVELS_HIGH_AND_UP & ~0x1Fu) == 0xFFFFFFE0u &&
              (DIAG_F3_LEVELS_ERROR_AND_UP & ~0x1Fu) == 0xFFFFFFE0u,
              "every f3 floor retains ALL per-SSID custom bits (>= bit 5)");
        /* ...and each drops exactly the ladder bits its name says it drops. */
        check((DIAG_F3_LEVELS_ALL & 0x1Fu) == 0x1Fu,
              "ALL keeps every ladder bit");
        check((DIAG_F3_LEVELS_HIGH_AND_UP & 0x1Fu) == 0x1Cu,
              "HIGH_AND_UP drops LOW+MED ladder bits only");
        check((DIAG_F3_LEVELS_ERROR_AND_UP & 0x1Fu) == 0x18u,
              "ERROR_AND_UP drops LOW+MED+HIGH ladder bits only");

        check(diag_config_build_f3(b, sizeof(b), 0) == 0,
              "build_f3 rejects an all-zero mask (arms nothing, reports armed)");
        check(diag_config_build_f3(b, 6, DIAG_F3_LEVELS_ERROR_AND_UP) == 0,
              "build_f3 rejects cap < 7");
    }

    /* Latched-state disarms. Byte-parity is the whole point: each is the
     * empty/zero form of an arm, and a wrong byte would leave the
     * QSH/F3 flood latched while every "did we send a disarm?" test stayed
     * green -- the same failure the F3-floor block guards. */
    {
        /* QSH-trace disarm body (19 bytes after the 0x4B opcode): the empty
         * maskset's 20-byte inner minus its leading 0x4B, which send_cmd
         * prepends. */
        static const uint8_t want_qsh[19] = {
            0x44, 0x01, 0x90,             /* subsys_id, cmd 0x9001 (le)          */
            0x03, 0x00, 0x00, 0x00,       /* arg_count = 3                       */
            0x01, 0x00, 0x00, 0x00,       /* word_a = 1                          */
            0x01, 0x00, 0x00, 0x00,       /* word_b = 1                          */
            0x00, 0x00, 0x00, 0x00 };     /* count = 0 -> empty maskset (disarm) */
        uint8_t b[19];
        size_t n = diag_config_build_qsh_trace_disarm(b, sizeof(b));
        check(n == 19, "qsh_trace_disarm body length == 19");
        check(memcmp(b, want_qsh, 19) == 0,
              "qsh_trace_disarm == build_qsh_trace_maskset_set(()) inner[1:]");
        check(diag_config_build_qsh_trace_disarm(b, 18) == 0,
              "qsh_trace_disarm rejects cap < 19");

        /* F3 disarm body (7 bytes after the 0x7D opcode) == SET_ALL_RT_MASKS
         * level 0. Identical shape to build_all_f3 but with a zero level -- the
         * exact frame build_f3 refuses (see the build_f3 level-0 reject above). */
        {
            static const uint8_t want_f3[7] = {
                0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
            uint8_t f[7];
            size_t fn = diag_config_build_f3_disarm(f, sizeof(f));
            check(fn == 7, "f3_disarm body length == 7");
            check(memcmp(f, want_f3, 7) == 0,
                  "f3_disarm == SET_ALL_RT_MASKS (5) + pad + level 0");
            check(diag_config_build_f3_disarm(f, 6) == 0,
                  "f3_disarm rejects cap < 7");
            /* The disarm is exactly the level-0 arm build_f3 rejects: same
             * bytes, opposite policy. Pin that they agree on everything but the
             * refusal, so a future edit to one cannot silently diverge. */
            check(diag_config_build_f3(f, sizeof(f), 0) == 0 &&
                      diag_config_build_f3_disarm(f, sizeof(f)) == 7,
                  "build_f3 refuses level 0; f3_disarm supplies it");
        }
    }

    /* Full F3 surface ARM builders. Byte-parity is the whole point --
     * these must reproduce the hardware-verified arms exactly, or the
     * modem arms a different (or no) maskset while every "did we arm QSH?" test
     * stays green. The QSH literal below is the golden maskset's 180-byte
     * inner minus its leading 0x4B, which send_cmd prepends. */
    {
        static const uint8_t want_qsh_arm[DIAG_QSH_TRACE_ARM_LEN] = {
            0x44, 0x01, 0x90,             /* subsys 0x44, cmd 0x9001 (le)         */
            0x2B, 0x00, 0x00, 0x00,       /* arg_count = 43 (3 + 40)              */
            0x01, 0x00, 0x00, 0x00,       /* word_a = 1                           */
            0x01, 0x00, 0x00, 0x00,       /* word_b = 1                           */
            0x28, 0x00, 0x00, 0x00,       /* count = 40                           */
            /* 40 (u16le ssid, u16le level) pairs, golden CFW-3212 diag.cfg:      */
            0x06, 0x00, 0x0F, 0x00, 0x09, 0x00, 0x3E, 0x00,
            0x0B, 0x00, 0x03, 0x00, 0x0D, 0x00, 0x03, 0x00,
            0x12, 0x00, 0x01, 0x00, 0x2A, 0x00, 0x03, 0x00,
            0x2D, 0x00, 0x03, 0x00, 0x2F, 0x00, 0x07, 0x00,
            0x34, 0x00, 0x0F, 0x00, 0x35, 0x00, 0x1F, 0x00,
            0x36, 0x00, 0x03, 0x00, 0x3D, 0x00, 0x03, 0x00,
            0x40, 0x00, 0x03, 0x00, 0x49, 0x00, 0x0B, 0x00,
            0x4C, 0x00, 0x7F, 0x08,       /* ssid 0x4C, level 0x087F (bitmask)    */
            0x4E, 0x00, 0x02, 0x00, 0x50, 0x00, 0x03, 0x00,
            0x53, 0x00, 0x3F, 0x00, 0x54, 0x00, 0x0F, 0x00,
            0x55, 0x00, 0x0F, 0x00, 0x56, 0x00, 0x03, 0x00,
            0x57, 0x00, 0x03, 0x00, 0x58, 0x00, 0x01, 0x00,
            0x59, 0x00, 0x0F, 0x00, 0x5E, 0x00, 0x01, 0x00,
            0x60, 0x00, 0x07, 0x00, 0x61, 0x00, 0x03, 0x00,
            0x62, 0x00, 0x0F, 0x00, 0x63, 0x00, 0x03, 0x00,
            0x64, 0x00, 0x3F, 0x00, 0x65, 0x00, 0x03, 0x00,
            0x68, 0x00, 0x03, 0x00, 0x69, 0x00, 0x0F, 0x00,
            0x6B, 0x00, 0x03, 0x00, 0x6C, 0x00, 0x03, 0x00,
            0x6D, 0x00, 0x03, 0x00, 0x6E, 0x00, 0x03, 0x00,
            0x6F, 0x00, 0x01, 0x00, 0x70, 0x00, 0x01, 0x00,
            0x71, 0x00, 0x03, 0x00 };
        uint8_t b[DIAG_QSH_TRACE_ARM_LEN];
        size_t n = diag_config_build_qsh_trace_arm(b, sizeof(b));
        check(n == DIAG_QSH_TRACE_ARM_LEN,
              "qsh_trace_arm body length == 179");
        check(memcmp(b, want_qsh_arm, DIAG_QSH_TRACE_ARM_LEN) == 0,
              "qsh_trace_arm == build_qsh_trace_maskset_set(GOLDEN)[1:]");
        check(diag_config_build_qsh_trace_arm(b, DIAG_QSH_TRACE_ARM_LEN - 1) == 0,
              "qsh_trace_arm rejects cap < 179");
        /* The arm and disarm share the 0x4B/subsys/cmd header and differ ONLY
         * in count (40 vs 0) + the trailing pairs -- pin that, so a header edit
         * to one cannot silently diverge from the other. */
        {
            uint8_t d[19];
            check(diag_config_build_qsh_trace_disarm(d, sizeof(d)) == 19 &&
                      memcmp(b, d, 3) == 0 && b[15] == 0x28 && d[15] == 0x00,
                  "arm/disarm share header; count 40 vs 0 is the only header diff");
        }

        /* Event-report enable body: u8(1) after the 0x60 opcode. */
        {
            uint8_t e[1];
            check(diag_config_build_event_report_enable(e, sizeof(e)) == 1 &&
                      e[0] == 0x01,
                  "event_report_enable == u8(1)");
            check(diag_config_build_event_report_enable(e, 0) == 0,
                  "event_report_enable rejects cap < 1");
            /* ...and its stop-path counterpart: u8(0), the only byte
             * that differs. */
            check(diag_config_build_event_report_disable(e, sizeof(e)) == 1 &&
                      e[0] == 0x00,
                  "event_report_disable == u8(0)");
            check(diag_config_build_event_report_disable(e, 0) == 0,
                  "event_report_disable rejects cap < 1");
        }

        /* diag_id binding request body: 12 22 02 01 after the 0x4B opcode
         * (subsys 0x12, cmd 0x0222 le, version 1) -- the 5-byte form. */
        {
            static const uint8_t want_dib[DIAG_DIAGID_REQ_LEN] = {
                0x12, 0x22, 0x02, 0x01 };
            uint8_t q[DIAG_DIAGID_REQ_LEN];
            check(diag_config_build_diag_id_binding_request(q, sizeof(q))
                      == DIAG_DIAGID_REQ_LEN &&
                      memcmp(q, want_dib, DIAG_DIAGID_REQ_LEN) == 0,
                  "diag_id_binding_request == subsys 0x12 + 0x0222 + version 1");
            check(diag_config_build_diag_id_binding_request(q, 3) == 0,
                  "diag_id_binding_request rejects cap < 4");
        }
    }

    /* SPC unlock body: DIAG_SPC_F 6-byte ASCII code. Default "000000"
     * mirrors qfenix diag_send_spc (memset 0x30 x 6). Reject non-6-digit input. */
    {
        uint8_t s[SPC_LEN];
        check(diag_config_build_spc(s, sizeof(s), "000000") == SPC_LEN,
              "build_spc default length == 6");
        for (i = 0; i < SPC_LEN; i++)
            check(s[i] == 0x30, "build_spc default byte == '0' (0x30)");
        check(diag_config_build_spc(s, sizeof(s), "123456") == SPC_LEN &&
                  s[0] == '1' && s[5] == '6', "build_spc arbitrary digits");
        check(diag_config_build_spc(s, sizeof(s), "12345") == 0,
              "build_spc rejects short (5-digit)");
        check(diag_config_build_spc(s, sizeof(s), "1234567") == 0,
              "build_spc rejects long (7-digit)");
        check(diag_config_build_spc(s, sizeof(s), "12a456") == 0,
              "build_spc rejects non-digit");
        check(diag_config_build_spc(s, sizeof(s), NULL) == 0,
              "build_spc rejects NULL");
        check(diag_config_build_spc(s, 5, "000000") == 0,
              "build_spc rejects cap < 6");
    }

    /* Empty subscription (ncodes == 0): valid, sets no bit. An operator mask=
     * list that resolves to no codes must not error or set stray bits. Under
     * exclusivity the advertised type is CLEARED (a zero mask), not
     * skipped; an unadvertised type stays untouched. (apply_narrow_mask never
     * gets here with 0 codes -- it returns -1 on an empty supported set.) */
    {
        memset(&m, 0, sizeof(m));
        m.bitsizes[0xB] = 1024;
        check(diag_config_narrow_mask(NULL, 0, &m) == 0, "empty code list ok");
        check(m.mask_len[0xB] == 128, "empty list: advertised type cleared");
        for (i = 0; i < DIAG_MAX_MASK_BYTES; i++)
            check(m.mask[0xB][i] == 0, "empty list: no bit set");
        for (i = 0; i < DIAG_LOG_TYPES; i++)
            if (i != 0xB)
                check(m.mask_len[i] == 0, "empty list: unadvertised untouched");
    }

    /* Duplicate codes are idempotent: OR-ing the same bit twice yields the same
     * mask as listing it once (a profile may repeat a code). */
    {
        const uint16_t once[] = { 0xB193 };
        const uint16_t twice[] = { 0xB193, 0xB193 };
        diag_log_mask_t m2;
        memset(&m, 0, sizeof(m));
        memset(&m2, 0, sizeof(m2));
        m.bitsizes[0xB] = 1024;
        m2.bitsizes[0xB] = 1024;
        check(diag_config_narrow_mask(once, 1, &m) == 0, "single-code mask ok");
        check(diag_config_narrow_mask(twice, 2, &m2) == 0, "dup-code mask ok");
        check(m.mask_len[0xB] == m2.mask_len[0xB],
              "dup vs single: same mask_len");
        check(memcmp(m.mask[0xB], m2.mask[0xB], DIAG_MAX_MASK_BYTES) == 0,
              "dup vs single: identical mask bytes (idempotent OR)");
    }

    /* filter_supported: keep only codes the modem advertises. Models the
     * live EG25-G (LTE-only MDM9607) where type 0xB advertises 513 codes and no
     * type-1 range: the LTE codes survive; the NR codes 0xB821 (item 2081) /
     * 0xB97F (item 2431) drop, and so do the type-1 GNSS codes. */
    {
        uint32_t bits[DIAG_LOG_TYPES];
        uint16_t out[DIAG_MAX_TARGET_CODES];
        size_t k;
        memset(bits, 0, sizeof(bits));
        bits[0xB] = 513;  /* LTE-only advertised range, GNSS engine unadvertised */
        k = diag_config_filter_supported(DIAG_TARGET_CODES,
                                         DIAG_TARGET_CODES_COUNT, bits,
                                         out, DIAG_MAX_TARGET_CODES);
        check(k == 6, "filter keeps 6 LTE codes, drops 2 NR + 2 GNSS");
        check(out[0] == 0xB193 && out[1] == 0xB0C0 && out[2] == 0xB192 &&
                  out[3] == 0xB195 && out[4] == 0xB17F && out[5] == 0xB197,
              "filter kept the LTE codes in order");
        /* Fully-capable modem: NR range past 2431 AND a type-1 GNSS range past
         * 1240 -> all 10 survive (the 8 cell codes + both GNSS codes). */
        memset(bits, 0, sizeof(bits));
        bits[0xB] = 2559;  /* LM960 SDX24 advertised range */
        bits[0x1] = 1280;  /* type-1 range past item 0x4D8 = 1240 */
        k = diag_config_filter_supported(DIAG_TARGET_CODES,
                                         DIAG_TARGET_CODES_COUNT, bits,
                                         out, DIAG_MAX_TARGET_CODES);
        check(k == DIAG_TARGET_CODES_COUNT,
              "fully-capable modem keeps all 10 (8 cell + 2 GNSS)");
        check(out[8] == 0x1476 && out[9] == 0x14D8,
              "filter kept the GNSS codes after the cell codes");
        /* A type advertising nothing drops all its codes; outcap is honored. */
        memset(bits, 0, sizeof(bits));  /* every type bitsize 0 */
        k = diag_config_filter_supported(DIAG_TARGET_CODES,
                                         DIAG_TARGET_CODES_COUNT, bits,
                                         out, DIAG_MAX_TARGET_CODES);
        check(k == 0, "no advertised ranges -> nothing kept");
        {
            const uint16_t many[] = {0xB0C0, 0xB193, 0xB192};
            uint16_t small[1];
            memset(bits, 0, sizeof(bits));
            bits[0xB] = 1024;
            k = diag_config_filter_supported(many, 3, bits, small, 1);
            check(k == 1 && small[0] == 0xB0C0, "outcap clamps kept count");
        }
    }

    /* The DIAGID-table reply is picked out by subsys + cmd, a QSH-trace
     * echo read first is skipped, and the reply comes back as its wire bytes. */
    {
        static const uint8_t table[] = {
            0x4B, 0x12, 0x22, 0x02, 0x01, 0x02,
            0x01, 0x05, 'A', 'P', 'P', 'S', 0x00,
            0x02, 0x12, 'm', 'd', 'm', '/', 'm', 'o', 'd', 'e', 'm', '/',
            'r', 'o', 'o', 't', '_', 'p', 'd', 0x00 };
        static const uint8_t qsh_echo[] = { 0x4B, 0x44, 0x01, 0x90, 0, 0, 0, 0 };
        uint8_t want[DIAG_DIAGID_WIRE_MAX], got[DIAG_DIAGID_WIRE_MAX];
        uint8_t other[64], req[64];
        size_t wlen, glen = 99, olen;
        diag_reader_t *rd = calloc(1, sizeof(*rd));
        int sv[2];

        check(diag_config_is_diag_id_binding_reply(table, sizeof(table)),
              "is_diag_id_binding_reply: the SDX55 table");
        check(!diag_config_is_diag_id_binding_reply(qsh_echo, sizeof(qsh_echo)),
              "is_diag_id_binding_reply: a QSH-trace echo is not the table");
        check(!diag_config_is_diag_id_binding_reply(table, 3),
              "is_diag_id_binding_reply: too short");
        {
            /* The same cmd word on another subsys is another command's reply:
             * the subsys byte must be checked, not only the cmd. */
            static const uint8_t other_subsys[] = { 0x4B, 0x13, 0x22, 0x02, 0x01 };
            check(!diag_config_is_diag_id_binding_reply(other_subsys, sizeof(other_subsys)),
                  "is_diag_id_binding_reply: cmd 0x0222 on subsys 0x13 is not the table");
        }

        wlen = diag_hdlc_build(table[0], table + 1, sizeof(table) - 1, want, sizeof(want));
        olen = diag_hdlc_build(qsh_echo[0], qsh_echo + 1, sizeof(qsh_echo) - 1,
                               other, sizeof(other));
        check(rd != NULL && wlen > 0 && olen > 0 &&
              socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "binding: fixture");
        if (rd != NULL && wlen > 0 && olen > 0) {
            /* The modem's side is queued up front: the echo, then the table. */
            check(write(sv[1], other, olen) == (ssize_t)olen &&
                  write(sv[1], want, wlen) == (ssize_t)wlen, "binding: queue replies");
            check(diag_config_request_diag_id_binding(sv[0], rd, got, sizeof(got),
                                                      &glen) == 0,
                  "binding: the table reply returns 0");
            check(glen == wlen && memcmp(got, want, wlen) == 0,
                  "binding: the relayed bytes are the reply's wire bytes");
            /* The request that went out is the 5-byte form. */
            {
                ssize_t n = read(sv[1], req, sizeof(req));
                uint8_t q[8];
                size_t ql = diag_config_build_diag_id_binding_request(q, sizeof(q));
                uint8_t qw[32];
                size_t qwl = diag_hdlc_build(DIAG_SUBSYS_CMD_F, q, ql, qw, sizeof(qw));
                check(n == (ssize_t)qwl && memcmp(req, qw, qwl) == 0,
                      "binding: the request frame on the wire");
            }
            /* No room to relay: still a received table (0), nothing relayed. */
            check(write(sv[1], want, wlen) == (ssize_t)wlen, "binding: queue again");
            glen = 99;
            check(diag_config_request_diag_id_binding(sv[0], rd, got, 4, &glen) == 0
                  && glen == 0, "binding: a too-small buffer relays nothing");
            close(sv[0]);
            close(sv[1]);
        }
        free(rd);
    }

    /* A REJECTED request is an answer, not a timeout.
     * A part that does not implement a command answers 0x13 BAD_CMD (or 0x14 /
     * 0x15) followed by an echo of the request. Waiting only for the request's
     * own opcode would cost the full 20 s deadline per rejection (LM960:
     * binding; EG25-G: arm + binding) while the modem streams on, on every
     * reopen. The fake modem below answers, then keeps streaming log frames
     * the way a live one does, so a reader that ignores rejections stalls. */
    {
        uint8_t arm[DIAG_QSH_TRACE_ARM_LEN], bind[DIAG_DIAGID_REQ_LEN], ev[1];
        size_t arml = diag_config_build_qsh_trace_arm(arm, sizeof(arm));
        size_t bindl = diag_config_build_diag_id_binding_request(bind, sizeof(bind));
        size_t evl = diag_config_build_event_report_enable(ev, sizeof(ev));
        static const uint8_t table[] = { 0x4B, 0x12, 0x22, 0x02, 0x01, 0x00 };
        uint8_t wbuf[2][2 * (2 + DIAG_QSH_TRACE_ARM_LEN) + 8];
        size_t wlen[2];
        struct { const char *what; uint8_t code; int which; int want; } cases[] = {
            { "qsh arm BAD_CMD",  0x13, 0, 1 },
            { "qsh arm BAD_PARM", 0x14, 0, 1 },
            { "binding BAD_CMD",  0x13, 1, 1 },
            { "events BAD_CMD",   0x13, 2, 1 },
        };

        check(arml == sizeof(arm) && bindl == sizeof(bind) && evl == sizeof(ev),
              "rejection: request builders");
        for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
            const uint8_t *req = cases[c].which == 0 ? arm : cases[c].which == 1 ? bind : ev;
            size_t reql = cases[c].which == 0 ? arml : cases[c].which == 1 ? bindl : evl;
            uint8_t reqop = cases[c].which == 2 ? DIAG_EVENT_REPORT_F : DIAG_SUBSYS_CMD_F;
            uint8_t echo[1 + DIAG_QSH_TRACE_ARM_LEN];
            echo[0] = reqop;
            memcpy(echo + 1, req, reql);
            wlen[0] = diag_hdlc_build(cases[c].code, echo, 1 + reql, wbuf[0], sizeof(wbuf[0]));

            int sv[2];
            diag_reader_t *rd = calloc(1, sizeof(*rd));
            if (rd == NULL || socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
                check(0, "rejection: fixture");
                free(rd);
                continue;
            }
            pid_t modem = fake_modem(sv[1], wbuf[0], wlen[0], NULL, 0);
            double t0 = monotonic_s();
            int rc = cases[c].which == 0 ? diag_config_enable_qsh_trace(sv[0], rd)
                   : cases[c].which == 1 ? diag_config_request_diag_id_binding(sv[0], rd, NULL, 0, NULL)
                   : diag_config_enable_events(sv[0], rd);
            double took = monotonic_s() - t0;
            stop_fake_modem(modem);
            char what[160];
            snprintf(what, sizeof(what), "rejection: %s returns %d (got %d)",
                     cases[c].what, cases[c].want, rc);
            check(rc == cases[c].want, what);
            snprintf(what, sizeof(what), "rejection: %s is answered at once, not at "
                     "the deadline (took %.1f s)", cases[c].what, took);
            check(took < 2.0, what);
            close(sv[0]);
            close(sv[1]);
            free(rd);
        }

        /* ...but only a rejection of THIS request. The binding waits on "any
         * 0x4B"; another 0x4B request's BAD_CMD (the QSH arm's, same opcode,
         * other subsys) must not end it before the table arrives. */
        {
            uint8_t echo[1 + DIAG_QSH_TRACE_ARM_LEN];
            echo[0] = DIAG_SUBSYS_CMD_F;
            memcpy(echo + 1, arm, arml);
            wlen[0] = diag_hdlc_build(0x13, echo, 1 + arml, wbuf[0], sizeof(wbuf[0]));
            wlen[1] = diag_hdlc_build(table[0], table + 1, sizeof(table) - 1,
                                      wbuf[1], sizeof(wbuf[1]));
            int sv[2];
            diag_reader_t *rd = calloc(1, sizeof(*rd));
            if (rd != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
                pid_t modem = fake_modem(sv[1], wbuf[0], wlen[0], wbuf[1], wlen[1]);
                check(diag_config_request_diag_id_binding(sv[0], rd, NULL, 0, NULL) == 0,
                      "rejection: another request's BAD_CMD does not end the binding wait");
                stop_fake_modem(modem);
                close(sv[0]);
                close(sv[1]);
            } else {
                check(0, "rejection: fixture (other request)");
            }
            free(rd);
        }
        /* The LOG_CONFIG handshake reads past the disarms' stale BAD_CMDs to its
         * 0x73 echo (diag_config_disarm_latched's contract): a rejection echoing
         * ANOTHER opcode is not this request's answer. */
        {
            uint8_t disarm[16], echo[20];
            size_t dl = diag_config_build_f3_disarm(disarm, sizeof(disarm));
            echo[0] = DIAG_EXT_MSG_CONFIG_F;
            memcpy(echo + 1, disarm, dl);
            wlen[0] = diag_hdlc_build(0x13, echo, 1 + dl, wbuf[0], sizeof(wbuf[0]));
            /* ...and one whose echoed body is byte-for-byte this request's
             * (3 pad + RETRIEVE_RANGES) under another opcode: only the opcode
             * says it is not ours. */
            {
                uint8_t same[8] = { DIAG_EXT_MSG_CONFIG_F, 0, 0, 0, LOG_CFG_RETRIEVE_RANGES, 0, 0, 0 };
                wlen[0] += diag_hdlc_build(0x13, same, sizeof(same), wbuf[0] + wlen[0],
                                           sizeof(wbuf[0]) - wlen[0]);
            }
            uint8_t r73[LOG_CFG_BITSIZES_OFFSET + 4 * DIAG_LOG_TYPES];
            memset(r73, 0, sizeof(r73));
            r73[0] = DIAG_LOG_CONFIG_F;
            r73[4] = LOG_CFG_RETRIEVE_RANGES;
            wlen[1] = diag_hdlc_build(r73[0], r73 + 1, sizeof(r73) - 1, wbuf[1], sizeof(wbuf[1]));
            int sv[2];
            uint32_t bits[DIAG_LOG_TYPES];
            diag_reader_t *rd = calloc(1, sizeof(*rd));
            if (rd != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
                pid_t modem = fake_modem(sv[1], wbuf[0], wlen[0], wbuf[1], wlen[1]);
                check(diag_config_retrieve_ranges(sv[0], rd, bits) == 0,
                      "rejection: a stale disarm BAD_CMD does not fail retrieve_ranges");
                stop_fake_modem(modem);
                close(sv[0]);
                close(sv[1]);
            } else {
                check(0, "rejection: fixture (retrieve_ranges)");
            }
            free(rd);
        }
    }

    /* A stale LOG_CONFIG reply to ANOTHER operation is not this request's
     * answer. The previous client's teardown sends LOG_CFG_DISABLE
     * fire-and-forget and closes; on an MHI node (/dev/mhi_DIAG, PCIe
     * RM520N-GL) its ack (`73 000000 00000000 00000000`) stays queued across
     * the close, and the next open's RETRIEVE_RANGES read would take it (same
     * 0x73 opcode), see op 0, and fail the bring-up. A USB tty flushes input
     * on open, so this is MHI-specific. A client killed mid-arm leaves a
     * SET_MASK ack (op 3) queued the same way. */
    {
        static const uint8_t stale_ops[] = { LOG_CFG_DISABLE, LOG_CFG_SET_MASK };
        for (size_t s = 0; s < sizeof(stale_ops); s++) {
            uint8_t wbuf[2][2 * (LOG_CFG_BITSIZES_OFFSET + 4 * DIAG_LOG_TYPES) + 8];
            size_t wlen[2];
            uint8_t stale[12];
            memset(stale, 0, sizeof(stale));
            stale[0] = DIAG_LOG_CONFIG_F;
            stale[LOG_CFG_OP_OFFSET] = stale_ops[s];
            wlen[0] = diag_hdlc_build(stale[0], stale + 1, sizeof(stale) - 1,
                                      wbuf[0], sizeof(wbuf[0]));
            uint8_t r73[LOG_CFG_BITSIZES_OFFSET + 4 * DIAG_LOG_TYPES];
            memset(r73, 0, sizeof(r73));
            r73[0] = DIAG_LOG_CONFIG_F;
            r73[LOG_CFG_OP_OFFSET] = LOG_CFG_RETRIEVE_RANGES;
            r73[LOG_CFG_BITSIZES_OFFSET + 4 * 0xB] = 0x00;   /* type 0xB: 1024 */
            r73[LOG_CFG_BITSIZES_OFFSET + 4 * 0xB + 1] = 0x04;
            wlen[1] = diag_hdlc_build(r73[0], r73 + 1, sizeof(r73) - 1,
                                      wbuf[1], sizeof(wbuf[1]));
            int sv[2];
            uint32_t bits[DIAG_LOG_TYPES];
            char what[160];
            diag_reader_t *rd = calloc(1, sizeof(*rd));
            if (rd != NULL && socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0) {
                pid_t modem = fake_modem(sv[1], wbuf[0], wlen[0], wbuf[1], wlen[1]);
                int rc = diag_config_retrieve_ranges(sv[0], rd, bits);
                stop_fake_modem(modem);
                snprintf(what, sizeof(what), "stale 0x73: a queued op-%u ack does "
                         "not fail retrieve_ranges", stale_ops[s]);
                check(rc == 0, what);
                snprintf(what, sizeof(what), "stale 0x73: op-%u skipped, the real "
                         "ranges are read (type 0xB = 1024)", stale_ops[s]);
                check(rc == 0 && bits[0xB] == 1024, what);
                close(sv[0]);
                close(sv[1]);
            } else {
                check(0, "stale 0x73: fixture");
            }
            free(rd);
        }
    }

    if (fail) {
        fprintf(stderr, "diag_config selftest FAILED\n");
        return 1;
    }
    printf("diag_config selftest OK\n");
    return 0;
}
#endif /* DIAG_CONFIG_SELFTEST */
