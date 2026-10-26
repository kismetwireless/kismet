/* cell_log.c - the CellLog record (see cell_log.h).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "cell_log.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

/* Bounded append; sets *overflow and keeps the buffer terminated. */
static void append(char *out, size_t out_sz, size_t *off, int *overflow,
                   const char *fmt, ...) {
    if (*overflow || *off >= out_sz)
        return;
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(out + *off, out_sz - *off, fmt, ap);
    va_end(ap);
    if (n < 0 || (size_t)n >= out_sz - *off) {
        *overflow = 1;
        *off = out_sz - 1;
        return;
    }
    *off += (size_t)n;
}

/* One byte as JSON string content. Bytes past 0x7f are escaped too, so modem
 * text that is not UTF-8 still leaves the record valid JSON. */
static int escape_byte(unsigned char c, char *esc) {
    switch (c) {
        case '"':  memcpy(esc, "\\\"", 2); return 2;
        case '\\': memcpy(esc, "\\\\", 2); return 2;
        case '\n': memcpy(esc, "\\n", 2);  return 2;
        case '\r': memcpy(esc, "\\r", 2);  return 2;
        case '\t': memcpy(esc, "\\t", 2);  return 2;
        default:
            if (c < 0x20 || c > 0x7e)
                return snprintf(esc, 7, "\\u%04x", c);
            esc[0] = (char)c;
            return 1;
    }
}

static void json_kv(char *out, size_t out_sz, size_t *off, int *overflow,
                    const char *key, const char *value) {
    char esc[8];

    if (key == NULL || value == NULL || value[0] == '\0')
        return;
    append(out, out_sz, off, overflow, ",\"%s\":\"", key);
    for (const unsigned char *c = (const unsigned char *)value; *c && !*overflow; c++) {
        int n = escape_byte(*c, esc);
        esc[n] = '\0';
        append(out, out_sz, off, overflow, "%s", esc);
    }
    append(out, out_sz, off, overflow, "\"");
}

static void header(char *out, size_t out_sz, size_t *off, int *overflow,
                   const char *src, const char *kind,
                   const struct timeval *tv, uint64_t mono_ns) {
    struct tm tm;
    time_t sec = tv->tv_sec;

    gmtime_r(&sec, &tm);
    append(out, out_sz, off, overflow, "{\"schema\":\"%s\"", CELL_LOG_SCHEMA);
    json_kv(out, out_sz, off, overflow, "src", src);
    json_kv(out, out_sz, off, overflow, "kind", kind);
    append(out, out_sz, off, overflow,
           ",\"ts_utc\":\"%04d-%02d-%02dT%02d:%02d:%02d.%06ldZ\""
           ",\"ts_mono_ns\":%llu",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec, (long)tv->tv_usec,
           (unsigned long long)mono_ns);
}

int cell_log_session_json(char *out, size_t outsz, const char *src,
                          const struct timeval *tv, uint64_t mono_ns,
                          const cell_log_kv_t *kv, size_t nkv) {
    if (out == NULL || outsz == 0)
        return -1;
    out[0] = '\0';
    if (src == NULL || tv == NULL || (kv == NULL && nkv > 0))
        return -1;

    size_t off = 0;
    int overflow = 0;

    header(out, outsz, &off, &overflow, src, "session", tv, mono_ns);
    for (size_t i = 0; i < nkv; i++)
        json_kv(out, outsz, &off, &overflow, kv[i].key, kv[i].value);
    append(out, outsz, &off, &overflow, "}");

    if (overflow) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

/* Room kept after the text for `","text_len":<u64>}` and the NUL. */
#define CELL_LOG_TAIL 40

int cell_log_entry_json(char *out, size_t outsz, const char *src,
                        const struct timeval *tv, uint64_t mono_ns,
                        const char *dir, const char *text, size_t textlen) {
    if (out == NULL || outsz == 0)
        return -1;
    out[0] = '\0';
    if (src == NULL || tv == NULL || dir == NULL || (text == NULL && textlen > 0))
        return -1;

    size_t off = 0;
    int overflow = 0;

    header(out, outsz, &off, &overflow, src, "log", tv, mono_ns);
    json_kv(out, outsz, &off, &overflow, "dir", dir);
    append(out, outsz, &off, &overflow, ",\"text\":\"");
    if (overflow || off + CELL_LOG_TAIL > outsz) {
        out[0] = '\0';
        return -1;
    }

    size_t i;
    char esc[8];
    for (i = 0; i < textlen; i++) {
        int n = escape_byte((unsigned char)text[i], esc);
        if (off + (size_t)n + CELL_LOG_TAIL > outsz)
            break;
        memcpy(out + off, esc, (size_t)n);
        off += (size_t)n;
    }
    out[off] = '\0';

    append(out, outsz, &off, &overflow, "\"");
    if (i < textlen)
        append(out, outsz, &off, &overflow, ",\"text_len\":%zu", textlen);
    append(out, outsz, &off, &overflow, "}");

    if (overflow) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}

size_t cell_log_hex(const uint8_t *buf, size_t len, char *out, size_t outsz) {
    static const char digits[] = "0123456789abcdef";
    size_t i;

    if (out == NULL || outsz == 0)
        return 0;
    for (i = 0; i < len && buf != NULL && 2 * i + 2 < outsz; i++) {
        out[2 * i] = digits[buf[i] >> 4];
        out[2 * i + 1] = digits[buf[i] & 0x0f];
    }
    out[2 * i] = '\0';
    return i;
}
