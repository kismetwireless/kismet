/* atlog.c - raw AT command/response JSONL tee sink. See atlog.h.
 *
 * The path-resolution half is a deliberate parallel of
 * capture_cell_diag/diag_rawlog.c (sanitize_component / expand_tokens /
 * resolve): the two helpers are separate link units in separate directories and
 * cannot share a TU without a build change, exactly like the cellat/celldiag
 * bool-option-parse split documented in cellat_options.h. The differences that
 * matter are the synthesized name (cellat-<imei>-<ts>.jsonl, not celldiag ...
 * .hdlc) and the JSON serialization, which rawlog does not need.
 */

#include "atlog.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ---- path resolution (parallel of diag_rawlog_resolve) ---- */

static int append(char *dst, size_t *pos, size_t cap, const char *src) {
    size_t n = strlen(src);
    if (*pos + n + 1 > cap) {
        dst[*pos < cap ? *pos : cap - 1] = '\0';
        return -1;
    }
    memcpy(dst + *pos, src, n);
    *pos += n;
    dst[*pos] = '\0';
    return 0;
}

static int append_char(char *dst, size_t *pos, size_t cap, char c) {
    char s[2] = { c, '\0' };
    return append(dst, pos, cap, s);
}

/* Copy `in` into `out`, replacing any byte not in [A-Za-z0-9._-] with '_', and
 * collapsing a wholly-dot result (".", "..", "...") to a single '_' so a
 * garbled/hostile IMEI or model cannot become a traversal component. See the
 * matching note in diag_rawlog.c. */
static void sanitize_component(const char *in, char *out, size_t outsz) {
    size_t j = 0;
    int all_dots = 1;
    if (outsz == 0)
        return;
    for (size_t i = 0; in && in[i] && j + 1 < outsz; i++) {
        unsigned char c = (unsigned char)in[i];
        if (isalnum(c) || c == '.' || c == '_' || c == '-')
            out[j++] = (char)c;
        else
            out[j++] = '_';
        if (out[j - 1] != '.')
            all_dots = 0;
    }
    out[j] = '\0';
    if (j > 0 && all_dots) {
        out[0] = '_';
        out[1] = '\0';
    }
}

static int expand_tokens(const char *spec, const char *imei,
                         const char *model_s, const char *ts,
                         char *out, size_t *pos, size_t outsz) {
    for (size_t i = 0; spec[i]; i++) {
        if (spec[i] != '%') {
            if (append_char(out, pos, outsz, spec[i]) != 0)
                return -1;
            continue;
        }
        char n = spec[i + 1];
        const char *rep = NULL;
        switch (n) {
            case 'i': rep = imei ? imei : ""; break;
            case 'm': rep = model_s; break;
            case 't': rep = ts; break;
            case '%': rep = "%"; break;
            default:  rep = NULL; break;
        }
        if (rep == NULL) {
            if (append_char(out, pos, outsz, '%') != 0)
                return -1;
            continue;
        }
        if (append(out, pos, outsz, rep) != 0)
            return -1;
        i++;  /* consume the token letter */
    }
    return 0;
}

int atlog_resolve(const char *spec, const char *imei, const char *model,
                  time_t now, char *out, size_t outsz) {
    char ts[32];
    char model_s[128];
    char imei_s[64];
    char expanded[1024];
    size_t pos = 0;

    if (spec == NULL || out == NULL || outsz == 0)
        return -1;

    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tmv);

    sanitize_component(model ? model : "modem", model_s, sizeof(model_s));
    if (model_s[0] == '\0')
        strcpy(model_s, "modem");

    sanitize_component(imei ? imei : "", imei_s, sizeof(imei_s));

    if (expand_tokens(spec, imei_s, model_s, ts, expanded, &pos, sizeof(expanded)) != 0)
        return -1;

    size_t elen = strlen(expanded);
    struct stat st;
    int is_dir = (elen > 0 && expanded[elen - 1] == '/') ||
                 (stat(expanded, &st) == 0 && S_ISDIR(st.st_mode));

    if (is_dir) {
        char fname[256];
        int need_slash = !(elen > 0 && expanded[elen - 1] == '/');
        snprintf(fname, sizeof(fname), "%scellat-%s-%s.jsonl",
                 need_slash ? "/" : "",
                 imei_s[0] ? imei_s : "unknown", ts);
        if (elen + strlen(fname) + 1 > outsz)
            return -1;
        memcpy(out, expanded, elen);
        strcpy(out + elen, fname);
    } else {
        if (elen + 1 > outsz)
            return -1;
        memcpy(out, expanded, elen + 1);
    }
    return 0;
}

/* ---- JSON serialization ---- */

/* Escape src[0..len) and APPEND into out[*pos..outsz), keeping out
 * NUL-terminated. Returns 0 on success, -1 on overflow. The public
 * atlog_json_escape() is a thin wrapper that escapes from a fresh offset. */
static int json_escape_append(char *out, size_t *pos, size_t outsz,
                              const char *src, size_t len) {
    for (size_t i = 0; src && i < len; i++) {
        unsigned char c = (unsigned char)src[i];
        const char *shortesc = NULL;
        char u[8];
        switch (c) {
            case '"':  shortesc = "\\\""; break;
            case '\\': shortesc = "\\\\"; break;
            case '\b': shortesc = "\\b";  break;
            case '\f': shortesc = "\\f";  break;
            case '\n': shortesc = "\\n";  break;
            case '\r': shortesc = "\\r";  break;
            case '\t': shortesc = "\\t";  break;
            default:   break;
        }
        if (shortesc == NULL && c < 0x20) {
            snprintf(u, sizeof(u), "\\u%04x", c);
            shortesc = u;
        }
        if (shortesc != NULL) {
            if (append(out, pos, outsz, shortesc) != 0)
                return -1;
        } else {
            if (append_char(out, pos, outsz, (char)c) != 0)
                return -1;
        }
    }
    return 0;
}

int atlog_json_escape(const char *src, size_t len, char *out, size_t outsz) {
    size_t pos = 0;
    if (out == NULL || outsz == 0)
        return -1;
    out[0] = '\0';
    if (json_escape_append(out, &pos, outsz, src, len) != 0)
        return -1;
    return (int)pos;
}

/* Append `, "<key>": <u64>` -- or `null` for 0, the "never reached" value of
 * the exchange's inner instants. */
static int append_mono_or_null(char *out, size_t *pos, size_t outsz,
                               const char *key, uint64_t ns) {
    char kv[64];
    if (ns == 0)
        snprintf(kv, sizeof(kv), ", \"%s\": null", key);
    else
        snprintf(kv, sizeof(kv), ", \"%s\": %llu", key, (unsigned long long)ns);
    return append(out, pos, outsz, kv);
}

int atlog_format_record(char *out, size_t outsz,
                        uint64_t ts_mono_ns, const char *ts_utc,
                        const char *cmd, const char *response,
                        double duration_ms, const char *err,
                        uint64_t tx_done_ns, uint64_t first_rx_ns,
                        uint64_t rx_done_ns) {
    /* Build the record by appending directly into `out` so there is no giant
     * escape scratch on the stack: an AT response caps at ~128KB and its
     * worst-case escape is 6x, which is not a stack frame we want in the
     * capture thread. Every field passes through the same bounds-checked
     * append/escape path, so an overflow is reported (record dropped + counted)
     * rather than truncating a half-written JSON line to disk. */
    size_t pos = 0;
    char head[64];

    if (out == NULL || outsz == 0 || ts_utc == NULL)
        return -1;
    out[0] = '\0';

    snprintf(head, sizeof(head), "{\"ts_mono_ns\": %llu, \"ts_utc\": \"",
             (unsigned long long)ts_mono_ns);
    if (append(out, &pos, outsz, head) != 0) return -1;
    if (json_escape_append(out, &pos, outsz, ts_utc, strlen(ts_utc)) != 0) return -1;

    if (append(out, &pos, outsz, "\", \"cmd\": \"") != 0) return -1;
    if (json_escape_append(out, &pos, outsz, cmd ? cmd : "",
                           cmd ? strlen(cmd) : 0) != 0) return -1;

    if (append(out, &pos, outsz, "\", \"response\": \"") != 0) return -1;
    if (json_escape_append(out, &pos, outsz, response ? response : "",
                           response ? strlen(response) : 0) != 0) return -1;

    snprintf(head, sizeof(head), "\", \"duration_ms\": %.2f, \"err\": ", duration_ms);
    if (append(out, &pos, outsz, head) != 0) return -1;

    if (err != NULL) {
        if (append(out, &pos, outsz, "\"") != 0) return -1;
        if (json_escape_append(out, &pos, outsz, err, strlen(err)) != 0) return -1;
        if (append(out, &pos, outsz, "\"") != 0) return -1;
    } else {
        if (append(out, &pos, outsz, "null") != 0) return -1;
    }
    /* The exchange's inner instants, appended after every key an older
     * reader knows, so its records are unchanged up to here. */
    if (append_mono_or_null(out, &pos, outsz, "tx_done_ns", tx_done_ns) != 0) return -1;
    if (append_mono_or_null(out, &pos, outsz, "first_rx_ns", first_rx_ns) != 0) return -1;
    if (append_mono_or_null(out, &pos, outsz, "rx_done_ns", rx_done_ns) != 0) return -1;
    if (append(out, &pos, outsz, "}\n") != 0) return -1;
    return 0;
}

int atlog_write(int fd, const char *buf, size_t len) {
    size_t off = 0;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}
