/* diag_rawlog.c - raw DIAG byte-stream tee sink. See diag_rawlog.h. */

#include "diag_rawlog.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Append src to dst[*pos..cap), NUL-terminating. Returns 0 on success, -1 if
 * it would overflow (dst then holds a truncated-but-terminated prefix, and the
 * caller treats the whole resolve as failed). */
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

/* Copy `in` into `out` (bounded by outsz), replacing every byte that is not in
 * [A-Za-z0-9._-] with '_'. Firmware/model strings carry spaces and slashes that
 * must not leak into a path component.
 *
 * '.' is allowed because legitimate firmware/model strings embed it (e.g.
 * "A0.300"). But an all-dots RESULT is the filesystem's own "." (self) and ".."
 * (parent) - a component of exactly ".." used as a directory via %i/ or %m/
 * would still climb out of the intended tree (blocking '/' alone does not stop
 * it, since the '/' comes from the operator's spec, not the token). A garbled or
 * hostile modem-reported IMEI/model of ".." is thus a real traversal vector, so
 * neutralize any wholly-dot component to a single '_'. Non-traversal names that
 * merely contain dots ("A0.300", "a..b") are unaffected - only all-dot strings
 * (".", "..", "...") collapse. */
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

/* Expand %i/%m/%t/%% tokens from `spec` into out[*pos..outsz). Returns 0 on
 * success, -1 on overflow. A trailing lone '%' is emitted literally. */
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
            /* Unknown token (or trailing '%'): emit the '%' literally, let the
             * following char be processed normally on the next iteration. */
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

int diag_rawlog_resolve(const char *spec, const char *imei, const char *model,
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

    /* Sanitize the IMEI the same way as the model: it too is used as a path
     * component (both in %i and the dir-mode auto-filename), and this reusable
     * resolver cannot trust its caller to have validated it. A garbled/hostile
     * IMEI carrying a '/' would otherwise inject a path separator and escape the
     * intended directory. Normal 15-digit IMEIs pass through unchanged. */
    sanitize_component(imei ? imei : "", imei_s, sizeof(imei_s));

    /* Expand tokens into a scratch buffer first so we can stat() the result to
     * decide the directory-vs-file question on the real (expanded) path. */
    if (expand_tokens(spec, imei_s, model_s, ts, expanded, &pos, sizeof(expanded)) != 0)
        return -1;

    size_t elen = strlen(expanded);
    struct stat st;
    int is_dir = (elen > 0 && expanded[elen - 1] == '/') ||
                 (stat(expanded, &st) == 0 && S_ISDIR(st.st_mode));

    if (is_dir) {
        char fname[256];
        int need_slash = !(elen > 0 && expanded[elen - 1] == '/');
        snprintf(fname, sizeof(fname), "%scelldiag-%s-%s.hdlc",
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

/* Split `path` at the extension of its LAST component: "/a.b/cap.hdlc" ->
 * stem "/a.b/cap", ext ".hdlc". A leading dot is a hidden name, not an
 * extension (".hdlc" -> stem ".hdlc", ext ""). Returns the stem length. */
static size_t split_ext(const char *path, const char **ext) {
    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    const char *dot = strrchr(base, '.');
    if (dot == NULL || dot == base) {
        *ext = path + strlen(path);
        return strlen(path);
    }
    *ext = dot;
    return (size_t)(dot - path);
}

int diag_rawlog_open_session(const char *path, time_t now, char *out,
                             size_t outsz, int *diverted) {
    if (diverted)
        *diverted = 0;
    if (path == NULL || out == NULL || outsz == 0) {
        errno = EINVAL;
        return -1;
    }
    size_t plen = strlen(path);
    if (plen + 1 > outsz) {
        errno = ENAMETOOLONG;
        return -1;
    }

    /* The operator's own path first. O_EXCL answers "is it new?" atomically;
     * only an EEXIST needs the size question. */
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_APPEND, 0644);
    if (fd < 0 && errno == EEXIST) {
        fd = open(path, O_WRONLY | O_APPEND);
        if (fd >= 0) {
            struct stat st;
            if (fstat(fd, &st) == 0 && S_ISREG(st.st_mode) && st.st_size > 0) {
                close(fd);
                fd = -2;       /* an earlier session's bytes: divert */
            }
        }
    }
    if (fd != -2) {
        if (fd >= 0)
            memcpy(out, path, plen + 1);
        return fd;
    }

    char ts[32];
    struct tm tmv;
    gmtime_r(&now, &tmv);
    strftime(ts, sizeof(ts), "%Y%m%dT%H%M%SZ", &tmv);

    const char *ext;
    size_t stem_len = split_ext(path, &ext);
    /* A %t spec already stamped this second into the stem: count, don't
     * stamp it twice ("cap-<ts>-<ts>.hdlc"). */
    char stem[1024];
    if (stem_len >= sizeof(stem)) {
        errno = ENAMETOOLONG;
        return -1;
    }
    memcpy(stem, path, stem_len);
    stem[stem_len] = '\0';
    int stamped = strstr(stem, ts) != NULL;

    for (int n = stamped ? 2 : 1; n < 1000; n++) {
        char cand[1024];
        int w;
        if (stamped)
            w = snprintf(cand, sizeof(cand), "%s-%d%s", stem, n, ext);
        else if (n == 1)
            w = snprintf(cand, sizeof(cand), "%s-%s%s", stem, ts, ext);
        else
            w = snprintf(cand, sizeof(cand), "%s-%s-%d%s", stem, ts, n, ext);
        if (w < 0 || (size_t)w >= sizeof(cand) || (size_t)w + 1 > outsz) {
            errno = ENAMETOOLONG;
            return -1;
        }
        fd = open(cand, O_WRONLY | O_CREAT | O_EXCL | O_APPEND, 0644);
        if (fd >= 0) {
            memcpy(out, cand, (size_t)w + 1);
            if (diverted)
                *diverted = 1;
            return fd;
        }
        if (errno != EEXIST)
            return -1;
    }
    errno = EEXIST;
    return -1;
}

int diag_rawlog_write(int fd, const uint8_t *buf, size_t len) {
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
