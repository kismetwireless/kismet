/* diag_clockanchor.c - host<->modem-ts64 clock anchor. See diag_clockanchor.h.
 *
 * libc-only. Framing and CRC ride diag_hdlc.c (one implementation of the DIAG
 * HDLC rules in this directory). The JSON escaper is a parallel of cellat's
 * atlog.c, so the ClockAnchor record escapes exactly like cellat's.
 */

#include "diag_clockanchor.h"
#include "diag_hdlc.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* DIAG error responses: <code> <echo of the offending request...>. */
#define DIAG_BAD_CMD_F  0x13
#define DIAG_BAD_PARM_F 0x14
#define DIAG_BAD_LEN_F  0x15

/* JSON-escape a NUL-terminated src (NULL -> "") into out, always terminated.
 * '"' and '\\' and the C0 set are escaped; everything else passes through.
 * Returns 0, or -1 on overflow. */
static int json_escape(const char *src, char *out, size_t outsz) {
    size_t pos = 0;

    if (out == NULL || outsz == 0)
        return -1;
    out[0] = '\0';
    for (size_t i = 0; src && src[i]; i++) {
        unsigned char c = (unsigned char)src[i];
        char esc[8];
        const char *rep = NULL;
        size_t n;
        switch (c) {
            case '"':  rep = "\\\""; break;
            case '\\': rep = "\\\\"; break;
            case '\b': rep = "\\b";  break;
            case '\f': rep = "\\f";  break;
            case '\n': rep = "\\n";  break;
            case '\r': rep = "\\r";  break;
            case '\t': rep = "\\t";  break;
            default:   break;
        }
        if (rep == NULL && c < 0x20) {
            snprintf(esc, sizeof(esc), "\\u%04x", c);
            rep = esc;
        }
        if (rep == NULL) {
            esc[0] = (char)c;
            esc[1] = '\0';
            rep = esc;
        }
        n = strlen(rep);
        if (pos + n + 1 > outsz) {
            out[0] = '\0';
            return -1;
        }
        memcpy(out + pos, rep, n);
        pos += n;
        out[pos] = '\0';
    }
    return 0;
}

size_t diag_clockanchor_build_request(uint8_t *out, size_t cap) {
    return diag_hdlc_build(DIAG_TS_F_OPCODE, NULL, 0, out, cap);
}

void diag_tsf_scan_reset(diag_tsf_scan_t *s) {
    memset(s, 0, sizeof(*s));
}

/* Classify one complete (escaped) frame body. */
static diag_tsf_result_t classify(const uint8_t *raw, size_t rawlen,
                                  uint64_t *ts64_out) {
    uint8_t body[DIAG_TSF_SCAN_MAX];
    size_t n = diag_hdlc_unescape(raw, rawlen, body, sizeof(body));

    if (n == 0 || !diag_hdlc_check_crc(body, &n) || n == 0)
        return DIAG_TSF_NONE;

    if (body[0] == DIAG_TS_F_OPCODE && n >= 9) {
        uint64_t v = 0;
        for (int i = 8; i >= 1; i--)
            v = (v << 8) | body[i];
        if (ts64_out)
            *ts64_out = v;
        return DIAG_TSF_RESPONSE;
    }
    if ((body[0] == DIAG_BAD_CMD_F || body[0] == DIAG_BAD_PARM_F ||
         body[0] == DIAG_BAD_LEN_F) && n >= 2 && body[1] == DIAG_TS_F_OPCODE)
        return DIAG_TSF_REJECTED;
    return DIAG_TSF_NONE;
}

diag_tsf_result_t diag_tsf_scan_feed(diag_tsf_scan_t *s, const uint8_t *buf,
                                     size_t len, uint64_t *ts64_out) {
    for (size_t i = 0; i < len; i++) {
        uint8_t b = buf[i];
        if (b == 0x7E) {
            diag_tsf_result_t r = DIAG_TSF_NONE;
            if (!s->overlong && s->len > 0)
                r = classify(s->buf, s->len, ts64_out);
            s->len = 0;
            s->overlong = 0;
            if (r != DIAG_TSF_NONE)
                return r;
            continue;
        }
        if (s->overlong)
            continue;
        if (s->len >= sizeof(s->buf)) {
            s->overlong = 1;     /* a LOG/F3 frame -- never a TS_F reply */
            continue;
        }
        s->buf[s->len++] = b;
    }
    return DIAG_TSF_NONE;
}

void diag_clockanchor_midpoint(const struct timeval *tv_send, uint64_t mono_send,
                               uint64_t mono_recv, struct timeval *tv_mid,
                               uint64_t *mono_mid) {
    uint64_t half = mono_recv > mono_send ? (mono_recv - mono_send) / 2 : 0;
    uint64_t usec = (uint64_t)tv_send->tv_usec + half / 1000ULL;

    tv_mid->tv_sec  = tv_send->tv_sec + (time_t)(usec / 1000000ULL);
    tv_mid->tv_usec = (suseconds_t)(usec % 1000000ULL);
    *mono_mid = mono_send + half;
}

void diag_clockanchor_iso8601(char *out, size_t outsz, const struct timeval *tv) {
    struct tm tm;
    time_t t = tv->tv_sec;

    gmtime_r(&t, &tm);
    snprintf(out, outsz, "%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ",
             tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
             tm.tm_hour, tm.tm_min, tm.tm_sec, (long)tv->tv_usec);
}

int diag_clockanchor_format_record(char *out, size_t outsz,
                                   const char *source_name, uint64_t seq,
                                   const char *edge, const char *host_utc,
                                   uint64_t host_mono_ns, uint64_t ts64,
                                   uint64_t host_rtt_ns) {
    char e_source[512], e_edge[32], e_hostutc[128];

    if (out == NULL || outsz == 0)
        return -1;
    out[0] = '\0';
    if (json_escape(source_name, e_source, sizeof(e_source)) < 0 ||
        json_escape(edge, e_edge, sizeof(e_edge)) < 0 ||
        json_escape(host_utc, e_hostutc, sizeof(e_hostutc)) < 0)
        return -1;

    int n = snprintf(out, outsz,
        "{\"schema\": \"clock-anchor/1\", \"transport\": \"diag\", "
        "\"source_name\": \"%s\", \"seq\": %llu, \"edge\": \"%s\", "
        "\"host_utc\": \"%s\", \"host_mono_ns\": %llu, "
        "\"source_clock_kind\": \"modem_ts64\", \"source_clock_value\": \"%llu\", "
        "\"host_rtt_ns\": %llu}\n",
        e_source, (unsigned long long)seq, e_edge, e_hostutc,
        (unsigned long long)host_mono_ns, (unsigned long long)ts64,
        (unsigned long long)host_rtt_ns);
    if (n < 0 || (size_t)n >= outsz) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

