/* diag_capmeta.c - capture-config provenance sidecar writer. See diag_capmeta.h.
 *
 * The JSON escape/append helpers are a deliberate parallel of
 * capture_cell_at/atlog.c's: the two helpers are separate link units in separate
 * directories and cannot share a TU without a build change, exactly like the
 * cellat/celldiag split documented in atlog.c. The escaping rule is identical
 * (that is the point -- one wire format), so a byte-for-byte parallel is the
 * cheapest way to keep them equal.
 */

#include "diag_capmeta.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ---- bounded append primitives (parallel of atlog.c) ---- */

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

/* Escape src[0..len) and APPEND into out[*pos..outsz), keeping out
 * NUL-terminated. Returns 0 on success, -1 on overflow. */
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

int diag_capmeta_json_escape(const char *src, size_t len, char *out, size_t outsz) {
    size_t pos = 0;
    if (out == NULL || outsz == 0)
        return -1;
    out[0] = '\0';
    if (json_escape_append(out, &pos, outsz, src, len) != 0)
        return -1;
    return (int)pos;
}

/* ---- path helpers ---- */

const char *diag_capmeta_basename(const char *path) {
    const char *slash;
    if (path == NULL)
        return "";
    slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

int diag_capmeta_sidecar_path(const char *rawlog_path, char *out, size_t outsz) {
    static const char suffix[] = ".capture_meta.json";
    size_t plen;
    if (rawlog_path == NULL || out == NULL || outsz == 0)
        return -1;
    plen = strlen(rawlog_path);
    if (plen + sizeof(suffix) > outsz)   /* sizeof(suffix) counts its NUL */
        return -1;
    memcpy(out, rawlog_path, plen);
    memcpy(out + plen, suffix, sizeof(suffix));  /* copies the NUL too */
    return 0;
}

/* ---- record formatting ---- */

/* Append one  "key": "escaped-value",  pair (caller supplies trailing sep). */
static int append_str_field(char *out, size_t *pos, size_t outsz,
                            const char *key, const char *val, const char *tail) {
    if (append(out, pos, outsz, "\"") != 0) return -1;
    if (append(out, pos, outsz, key) != 0) return -1;
    if (append(out, pos, outsz, "\": \"") != 0) return -1;
    if (json_escape_append(out, pos, outsz, val ? val : "",
                           val ? strlen(val) : 0) != 0) return -1;
    if (append(out, pos, outsz, "\"") != 0) return -1;
    if (append(out, pos, outsz, tail) != 0) return -1;
    return 0;
}

int diag_capmeta_format(char *out, size_t outsz,
                        time_t host_utc,
                        const char *imei, const char *model,
                        const char *firmware, const char *make,
                        const char *product_model, const char *identity,
                        const char *mask_preset,
                        const char *f3_preset, const char *diag_node,
                        const char *rawlog_basename) {
    size_t pos = 0;
    char iso[32];
    struct tm tmv;

    if (out == NULL || outsz == 0)
        return -1;
    out[0] = '\0';

    gmtime_r(&host_utc, &tmv);
    strftime(iso, sizeof(iso), "%Y-%m-%dT%H:%M:%SZ", &tmv);

    if (append(out, &pos, outsz, "{\"schema\": \"celldiag-capmeta/1\", ") != 0)
        return -1;
    /* host_utc_start is a controlled strftime output, but escape it anyway so
     * the one escape path is the only one that ever touches the buffer. */
    if (append_str_field(out, &pos, outsz, "host_utc_start", iso, ", ") != 0)
        return -1;
    if (append_str_field(out, &pos, outsz, "imei", imei, ", ") != 0)
        return -1;
    if (append_str_field(out, &pos, outsz, "model", model, ", ") != 0)
        return -1;
    if (append_str_field(out, &pos, outsz, "firmware", firmware, ", ") != 0)
        return -1;
    if (append_str_field(out, &pos, outsz, "make", make, ", ") != 0)
        return -1;
    if (append_str_field(out, &pos, outsz, "product_model", product_model, ", ") != 0)
        return -1;
    if (append_str_field(out, &pos, outsz, "identity", identity, ", ") != 0)
        return -1;
    if (append_str_field(out, &pos, outsz, "mask_preset", mask_preset, ", ") != 0)
        return -1;
    if (append_str_field(out, &pos, outsz, "f3_preset", f3_preset, ", ") != 0)
        return -1;
    if (append_str_field(out, &pos, outsz, "diag_node", diag_node, ", ") != 0)
        return -1;
    if (append_str_field(out, &pos, outsz, "rawlog", rawlog_basename, "") != 0)
        return -1;
    if (append(out, &pos, outsz, "}\n") != 0)
        return -1;
    return 0;
}

int diag_capmeta_write(const char *path, const char *buf, size_t len) {
    int fd;
    size_t off = 0;
    if (path == NULL || buf == NULL)
        return -1;
    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return -1;
    while (off < len) {
        ssize_t w = write(fd, buf + off, len - off);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        off += (size_t)w;
    }
    if (close(fd) != 0)
        return -1;
    return 0;
}
