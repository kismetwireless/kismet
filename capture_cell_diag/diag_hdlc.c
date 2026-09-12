/* diag_hdlc.c - HDLC framing for the Qualcomm DIAG transport.
 *
 * See diag_hdlc.h for the wire format. The CRC and unescape logic are kept
 * byte-identical to diaggrok's diaggrok/hdlc.py so the Phase 1 diaggrok bridge
 * can validate this deframer against a reference decoder.
 *
 * Compile the self-test with:
 *   cc -DDIAG_HDLC_SELFTEST -Wall -Wextra -Werror diag_hdlc.c -o /tmp/diag_hdlc_selftest
 */
#include "diag_hdlc.h"

#include <string.h>

#define HDLC_ESC   0x7D
#define HDLC_FLAG  0x7E
#define HDLC_XOR   0x20

/* CRC-16/X-25: reflected poly 0x8408, init 0xFFFF, xorout 0xFFFF.
 * Bit-serial form (no table) to keep the module dependency-free; DIAG frames
 * are small and this runs off the capture thread, so the cost is negligible. */
uint16_t diag_hdlc_crc16(const uint8_t *data, size_t len) {
    uint16_t crc = 0xFFFF;
    size_t i;
    int b;

    for (i = 0; i < len; i++) {
        crc ^= data[i];
        for (b = 0; b < 8; b++)
            crc = (crc & 1) ? (uint16_t)((crc >> 1) ^ 0x8408) : (uint16_t)(crc >> 1);
    }
    return (uint16_t)(crc ^ 0xFFFF);
}

size_t diag_hdlc_unescape(const uint8_t *in, size_t inlen,
                          uint8_t *out, size_t outcap) {
    size_t i = 0, o = 0;

    while (i < inlen) {
        if (in[i] == HDLC_ESC && i + 1 < inlen) {
            if (o >= outcap)
                return 0;
            out[o++] = (uint8_t)(in[i + 1] ^ HDLC_XOR);
            i += 2;
        } else {
            if (o >= outcap)
                return 0;
            out[o++] = in[i];
            i += 1;
        }
    }
    return o;
}

int diag_hdlc_check_crc(const uint8_t *frame, size_t *len) {
    size_t n = *len;
    uint16_t got, want;

    if (n < 2)
        return 0;

    want = (uint16_t)(frame[n - 2] | (frame[n - 1] << 8)); /* little-endian */
    got = diag_hdlc_crc16(frame, n - 2);
    if (got != want)
        return 0;

    *len = n - 2;
    return 1;
}

/* Escape src into dst, appending 0x7D 0x5E / 0x7D 0x5D for 0x7E / 0x7D.
 * Returns bytes written, or (size_t)-1 on overflow. */
static size_t escape_into(const uint8_t *src, size_t srclen,
                          uint8_t *dst, size_t dstcap, size_t off) {
    size_t i;
    for (i = 0; i < srclen; i++) {
        if (src[i] == HDLC_FLAG || src[i] == HDLC_ESC) {
            if (off + 2 > dstcap)
                return (size_t)-1;
            dst[off++] = HDLC_ESC;
            dst[off++] = (uint8_t)(src[i] ^ HDLC_XOR);
        } else {
            if (off + 1 > dstcap)
                return (size_t)-1;
            dst[off++] = src[i];
        }
    }
    return off;
}

size_t diag_hdlc_build(uint8_t cmd, const uint8_t *body, size_t bodylen,
                       uint8_t *out, size_t outcap) {
    uint8_t scratch[1024];
    uint16_t crc;
    size_t plen, off;

    /* Assemble cmd || body, compute CRC over it. */
    if (1 + bodylen + 2 > sizeof(scratch))
        return 0;
    scratch[0] = cmd;
    if (bodylen)
        memcpy(scratch + 1, body, bodylen);
    plen = 1 + bodylen;

    crc = diag_hdlc_crc16(scratch, plen);
    scratch[plen] = (uint8_t)(crc & 0xFF);
    scratch[plen + 1] = (uint8_t)((crc >> 8) & 0xFF);
    plen += 2;

    /* Escape everything, then append the unescaped 0x7E terminator. */
    off = escape_into(scratch, plen, out, outcap, 0);
    if (off == (size_t)-1)
        return 0;
    if (off + 1 > outcap)
        return 0;
    out[off++] = HDLC_FLAG;
    return off;
}

#ifdef DIAG_HDLC_SELFTEST
#include <stdio.h>

static int fail;

static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        fail = 1;
    }
}

int main(void) {
    /* 1. CRC vectors cross-checked against diaggrok.hdlc.crc16_ccitt. */
    check(diag_hdlc_crc16((const uint8_t *)"123456789", 9) == 0x906E,
          "crc16(\"123456789\") == 0x906E");
    {
        const uint8_t v1[] = {0x10, 0x00, 0x11, 0x22, 0x33, 0x44};
        check(diag_hdlc_crc16(v1, sizeof(v1)) == 0x444C, "crc16 vector 1 == 0x444C");
        check(diag_hdlc_crc16((const uint8_t *)"kismet-diag", 11) == 0x0F96,
              "crc16(\"kismet-diag\") == 0x0F96");
    }

    /* 2. Unescape: 7D 5E -> 7E, 7D 5D -> 7D, literals pass through. */
    {
        const uint8_t in[] = {0x10, 0x7D, 0x5E, 0x7D, 0x5D, 0xAB};
        uint8_t out[16];
        size_t n = diag_hdlc_unescape(in, sizeof(in), out, sizeof(out));
        const uint8_t want[] = {0x10, 0x7E, 0x7D, 0xAB};
        check(n == 4 && memcmp(out, want, 4) == 0, "unescape 7D5E/7D5D");
    }

    /* 3. Round trip: build(cmd,body) then unescape + check_crc recovers it. */
    {
        const uint8_t body[] = {0x00, 0x00, 0x00, 0x01, 0x02, 0x7E, 0x7D};
        uint8_t wire[64], unesc[64];
        size_t wlen = diag_hdlc_build(0x73, body, sizeof(body), wire, sizeof(wire));
        check(wlen > 0, "build produced a frame");
        check(wire[wlen - 1] == 0x7E, "frame ends with 0x7E flag");

        /* Strip trailing flag, unescape, verify CRC + payload. */
        size_t ulen = diag_hdlc_unescape(wire, wlen - 1, unesc, sizeof(unesc));
        check(ulen > 0, "unescape of built frame");
        check(diag_hdlc_check_crc(unesc, &ulen) == 1, "CRC verifies on round trip");
        check(ulen == 1 + sizeof(body), "recovered length == cmd + body");
        check(unesc[0] == 0x73, "recovered cmd byte");
        check(memcmp(unesc + 1, body, sizeof(body)) == 0, "recovered body bytes");
    }

    /* 4. Corrupted CRC is rejected. */
    {
        uint8_t frame[] = {0x10, 0x00, 0x00, 0x00}; /* bogus trailing CRC */
        size_t n = sizeof(frame);
        check(diag_hdlc_check_crc(frame, &n) == 0, "bad CRC rejected");
    }

    if (fail) {
        fprintf(stderr, "diag_hdlc selftest FAILED\n");
        return 1;
    }
    printf("diag_hdlc selftest OK\n");
    return 0;
}
#endif /* DIAG_HDLC_SELFTEST */
