/* clock_gettime(CLOCK_MONOTONIC) needs a POSIX feature-test macro under strict
 * -std=c11; the Kismet build uses -std=gnu11 where it is visible by default. */
#define _DEFAULT_SOURCE
/* diag_config.c - DIAG LOG_CONFIG narrow-mask handshake.
 *
 * See diag_config.h. The pure mask math (diag_config_narrow_mask) mirrors
 * diaggulp.py's _narrow_mask_bytes byte-for-byte and is covered by the selftest.
 * The live handshake functions are exercised at the M1.9 hardware smoke test.
 *
 * Self-test build:
 *   cc -DDIAG_CONFIG_SELFTEST -Wall -Wextra -Werror diag_config.c diag_hdlc.c \
 *      -o /tmp/diag_config_selftest
 */
#include "diag_config.h"
#include "diag_hdlc.h"

#include <errno.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>

/* DIAG_LOG_CONFIG_F handshake constants (see diaggulp.py). */
#define DIAG_LOG_CONFIG_F        0x73
#define LOG_CFG_RETRIEVE_RANGES  1
#define LOG_CFG_SET_MASK         3
#define LOG_CFG_SUCCESS          0

/* DIAG_LOG_CONFIG_F frame layout (deframed, opcode byte kept at [0]):
 *   [0]      cmd echo (0x73)
 *   [1..3]   3 pad bytes (the "<3x" in diaggulp's struct, applied to the
 *            opcode-stripped payload -- so they follow the opcode)
 *   [4..7]   operation (u32 LE)
 *   [8..11]  status (u32 LE)
 *   [12..]   16 bitsizes (u32 LE each), for RETRIEVE_RANGES
 * Requests have the same [3 pad][op u32][args...] shape after the opcode. */
#define LOG_CFG_OP_OFFSET        4
#define LOG_CFG_STATUS_OFFSET    8
#define LOG_CFG_BITSIZES_OFFSET  12

/* Target log codes, all equipment id 0xB (item = code & 0xFFF), so they all
 * subscribe within the same type-0xB SET_MASK:
 *   0xB193 LTE ML1 serving cell measurement (signal).
 *   0xB0C0 LTE RRC OTA, carries SIB1 -> full cell identity (MCC/MNC/TAC/CellID).
 *   0xB192 LTE ML1 idle-mode neighbor cells (PCI/EARFCN; energy-not-dBm #2173).
 *   0xB195 LTE ML1 connected-mode neighbor cells (PCI/EARFCN/RSRP).
 *   0xB821 NR5G RRC OTA, carries NR SIB1 -> NR cell identity (item 0x821 is a
 *          much higher bit than the LTE codes, so the modem's type-0xB range
 *          must advertise past 2081 for it to subscribe).
 *   0xB97F NR5G ML1 measurement DB (M3.5): per component-carrier serving +
 *          neighbour cells with per-cell SS-RSRP/RSRQ (ground-truthed vs
 *          AT+QSCAN; #434). The NR analog of the LTE 0xB193/0xB195 signal
 *          codes, and net-new vs dlf_to_wigle (which maps no NR measurement) --
 *          item 0x97F = 2431 is the highest bit in the set, so the type-0xB
 *          range must advertise past 2431 for it to subscribe.
 * (The plan's "NR5G ML1 0xB825" is intentionally omitted: 0xB825 is
 * LOG_NR5G_RRC_CONFIGURATION_INFO, nci-only, not a mappable measurement, and
 * not in the dlf_to_wigle WiGLE-parity set the bridge helper mirrors.) */
const uint16_t DIAG_TARGET_CODES[] = {
    0xB193, 0xB0C0, 0xB192, 0xB195, 0xB821, 0xB97F };
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
    return 0;
}

/* ---- live handshake ---- */

/* Read frames (via the shared robust reader) until one whose DIAG opcode
 * (byte 0) matches expect_cmd, skipping interleaved frames until a wall-clock
 * deadline -- a live port floods F3 (0x99) and LOG_F frames around the command
 * response, so many thousands of frames can precede it. Bounded by time (like
 * diaggulp's DiagClient._send_recv), not a frame count. Returns 0 on match, -1
 * on read error or timeout. */
#define DIAG_RESP_TIMEOUT_S 5.0
static double monotonic_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;
}

static int read_response(int fd, diag_reader_t *r, uint8_t expect_cmd,
                         uint8_t *out, size_t outcap, size_t *out_len) {
    double deadline = monotonic_s() + DIAG_RESP_TIMEOUT_S;
    for (;;) {
        if (diag_read_frame(fd, r, out, outcap, out_len) != 0)
            return -1;
        if (*out_len >= 1 && out[0] == expect_cmd)
            return 0;
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
    if (read_response(fd, r, DIAG_LOG_CONFIG_F, resp, sizeof(resp), &rlen) != 0)
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

int diag_config_apply_narrow_mask(int fd, diag_reader_t *r,
                                  const uint16_t *codes, size_t ncodes) {
    diag_log_mask_t m;
    size_t lt;

    if (diag_config_retrieve_ranges(fd, r, m.bitsizes) != 0)
        return -1;
    if (diag_config_narrow_mask(codes, ncodes, &m) != 0)
        return -1;

    for (lt = 0; lt < DIAG_LOG_TYPES; lt++) {
        uint8_t body[15 + DIAG_MAX_MASK_BYTES];
        size_t blen;

        if (m.mask_len[lt] == 0)
            continue;

        /* "<3xIII" + mask: 3 pad, then u32 SET_MASK, u32 log_type, u32 bitsize,
         * then the mask bytes. Header is 15 bytes (3 + 3*4). */
        memset(body, 0, 15);
        body[3] = LOG_CFG_SET_MASK;                             /* op   @ [3..6]  */
        body[7] = (uint8_t)(lt & 0xFF);                         /* type @ [7..10] */
        body[11] = (uint8_t)(m.bitsizes[lt] & 0xFF);            /* bits @ [11..14]*/
        body[12] = (uint8_t)((m.bitsizes[lt] >> 8) & 0xFF);
        body[13] = (uint8_t)((m.bitsizes[lt] >> 16) & 0xFF);
        body[14] = (uint8_t)((m.bitsizes[lt] >> 24) & 0xFF);
        memcpy(body + 15, m.mask[lt], m.mask_len[lt]);
        blen = 15 + m.mask_len[lt];

        /* Fire-and-forget: the SET_MASK ack and the log records it enables flow
         * straight into the raw passthrough, and the bridge ignores non-log
         * frames -- so we do not block fishing the ack out of a live log flood.
         * The command takes effect regardless (verified on RM520N-GL SDX62). */
        if (send_cmd(fd, DIAG_LOG_CONFIG_F, body, blen) != 0)
            return -1;
    }
    return 0;
}

#ifdef DIAG_CONFIG_SELFTEST
#include <stdio.h>

static int fail;

static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        fail = 1;
    }
}

int main(void) {
    diag_log_mask_t m;
    size_t i;

    memset(&m, 0, sizeof(m));

    /* Cross-checked against diaggulp._narrow_mask_bytes:
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
                check(m.mask_len[i] == 0, "only type 0xB touched");
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

    check(DIAG_TARGET_CODES_COUNT == 6 && DIAG_TARGET_CODES[0] == 0xB193 &&
              DIAG_TARGET_CODES[1] == 0xB0C0 && DIAG_TARGET_CODES[2] == 0xB192 &&
              DIAG_TARGET_CODES[3] == 0xB195 && DIAG_TARGET_CODES[4] == 0xB821 &&
              DIAG_TARGET_CODES[5] == 0xB97F,
          "target codes == {0xB193,0xB0C0,0xB192,0xB195,0xB821,0xB97F}");

    /* Full target set mask math, incl. the high-item NR codes 0xB821 (item
     * 0x821 = 2081 -> byte 260, bit 1) and 0xB97F (item 0x97F = 2431 -> byte
     * 303, bit 7). Needs a type-0xB range past 2431.
     *   0xB0C0 item 192 -> byte 24 bit 0 (0x01)
     *   0xB192 item 402 -> byte 50 bit 2 (0x04)
     *   0xB193 item 403 -> byte 50 bit 3 (0x08)
     *   0xB195 item 405 -> byte 50 bit 5 (0x20)   => byte 50 == 0x2C
     *   0xB821 item 2081 -> byte 260 bit 1 (0x02)
     *   0xB97F item 2431 -> byte 303 bit 7 (0x80) */
    {
        memset(&m, 0, sizeof(m));
        m.bitsizes[0xB] = 4096;
        check(diag_config_narrow_mask(DIAG_TARGET_CODES, DIAG_TARGET_CODES_COUNT,
                                      &m) == 0, "full target set narrow_mask ok");
        check(m.mask_len[0xB] == 512, "type 0xB mask len == 512 (bitsize 4096)");
        check(m.mask[0xB][24] == 0x01, "byte 24 == 0x01 (0xB0C0)");
        check(m.mask[0xB][50] == 0x2C, "byte 50 == 0x2C (0xB192|0xB193|0xB195)");
        check(m.mask[0xB][260] == 0x02, "byte 260 == 0x02 (0xB821)");
        check(m.mask[0xB][303] == 0x80, "byte 303 == 0x80 (0xB97F)");
        for (i = 0; i < DIAG_MAX_MASK_BYTES; i++)
            if (i != 24 && i != 50 && i != 260 && i != 303)
                check(m.mask[0xB][i] == 0, "no stray bits set (full set)");
    }

    if (fail) {
        fprintf(stderr, "diag_config selftest FAILED\n");
        return 1;
    }
    printf("diag_config selftest OK\n");
    return 0;
}
#endif /* DIAG_CONFIG_SELFTEST */
