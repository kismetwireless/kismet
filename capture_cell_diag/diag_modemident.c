/* diag_modemident.c - the ModemIdentity record (see diag_modemident.h).
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 */

#include "diag_modemident.h"

#include <ctype.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>

void modemident_clear(modemident_t *id) {
    if (id != NULL)
        memset(id, 0, sizeof(*id));
}

int modemident_imei_ok(const char *s) {
    if (s == NULL)
        return 0;
    size_t n = 0;
    for (; s[n]; n++)
        if (s[n] < '0' || s[n] > '9')   /* not isdigit(): locale-free */
            return 0;
    return n == MODEMIDENT_IMEI_DIGITS;
}

long modemident_followup_ms(long prior_read_ms, int prior_got_value) {
    if (prior_got_value && prior_read_ms >= MODEMIDENT_UNTERMINATED_AFTER_MS)
        return MODEMIDENT_UNTERMINATED_READ_MS;
    return MODEMIDENT_READ_MS;
}

int modemident_has_product(const modemident_t *id) {
    return id != NULL && (id->make[0] || id->model[0] || id->firmware[0]);
}

/* The ATI-style labels a firmware may put on a CGMI/CGMM/CGMR reply. Matched
 * case-insensitively and only at the start of the line. */
static const char *const k_labels[] = { "Manufacturer:", "Model:", "Revision:" };

/* Is [s, s+n) a line that carries no value? */
static int line_is_framing(const char *s, size_t n) {
    if (n == 0)
        return 1;
    if (n == 2 && strncmp(s, "OK", 2) == 0)
        return 1;
    if (n == 5 && strncmp(s, "ERROR", 5) == 0)
        return 1;
    if (n >= 4 && (strncmp(s, "+CME", 4) == 0 || strncmp(s, "+CMS", 4) == 0))
        return 1;
    /* A command echo. The helpers' readers already drop an exact echo of the
     * command they sent; this also catches one they did not (a modem whose
     * echo was left on answering a DIFFERENT prior command). Narrow on
     * purpose: "AT+..." or a bare "AT" / "ATI" / "ATE0". A value that merely
     * STARTS with "AT" -- an "AT&T"-branded CGMI -- is a value. */
    if ((n >= 3 && strncasecmp(s, "AT+", 3) == 0) ||
        (n == 2 && strncasecmp(s, "AT", 2) == 0) ||
        (n == 3 && strncasecmp(s, "ATI", 3) == 0) ||
        (n == 4 && strncasecmp(s, "ATE0", 4) == 0))
        return 1;
    return 0;
}

int modemident_value(const char *resp, char *out, size_t out_sz) {
    if (out == NULL || out_sz == 0)
        return 0;
    out[0] = '\0';
    if (resp == NULL)
        return 0;

    const char *p = resp;
    while (*p) {
        const char *eol = p;
        while (*eol && *eol != '\n' && *eol != '\r')
            eol++;

        /* Trim both ends of [s, e). */
        const char *s = p, *e = eol;
        while (s < e && (*s == ' ' || *s == '\t'))
            s++;
        while (e > s && (e[-1] == ' ' || e[-1] == '\t'))
            e--;

        if (!line_is_framing(s, (size_t)(e - s))) {
            /* `+CODE: value` -- strip the response code, but only when the
             * colon precedes any space (the same rule as cellat's
             * at_line_value): a version string that merely CONTAINS a colon
             * must survive intact. */
            if (*s == '+') {
                const char *colon = memchr(s, ':', (size_t)(e - s));
                const char *space = memchr(s, ' ', (size_t)(e - s));
                if (colon != NULL && (space == NULL || colon < space))
                    s = colon + 1;
            } else {
                for (size_t i = 0; i < sizeof(k_labels) / sizeof(k_labels[0]); i++) {
                    size_t ln = strlen(k_labels[i]);
                    if ((size_t)(e - s) >= ln && strncasecmp(s, k_labels[i], ln) == 0) {
                        s += ln;
                        break;
                    }
                }
            }
            while (s < e && (*s == ' ' || *s == '\t'))
                s++;

            /* A code or label with nothing after it is not a value; keep
             * looking rather than returning an empty "measurement". */
            if (s < e) {
                size_t n = (size_t)(e - s);
                if (n > out_sz - 1)
                    n = out_sz - 1;
                memcpy(out, s, n);
                out[n] = '\0';
                return 1;
            }
        }

        p = eol;
        while (*p == '\n' || *p == '\r')
            p++;
    }
    return 0;
}

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

int modemident_label(const modemident_t *id, const char *suffix,
                     char *out, size_t out_sz) {
    if (out == NULL || out_sz == 0)
        return -1;
    out[0] = '\0';
    if (id == NULL)
        return 0;

    size_t off = 0;
    int overflow = 0;
    int have_name = 0;

    if (id->make[0]) {
        append(out, out_sz, &off, &overflow, "%s", id->make);
        have_name = 1;
    }
    if (id->model[0]) {
        append(out, out_sz, &off, &overflow, "%s%s", have_name ? " " : "",
               id->model);
        have_name = 1;
    }
    if (id->firmware[0]) {
        if (have_name)
            append(out, out_sz, &off, &overflow, " (%s)", id->firmware);
        else
            append(out, out_sz, &off, &overflow, "%s", id->firmware);
    }
    if (id->imei[0])
        append(out, out_sz, &off, &overflow, "%sIMEI:%s", off ? " " : "",
               id->imei);
    if (suffix != NULL && suffix[0])
        append(out, out_sz, &off, &overflow, "%s", suffix);

    return overflow ? -1 : 0;
}

/* `"key":"<escaped value>"`, preceded by a comma. Omitted when value is empty. */
static void json_kv(char *out, size_t out_sz, size_t *off, int *overflow,
                    const char *key, const char *value) {
    if (value == NULL || value[0] == '\0')
        return;
    append(out, out_sz, off, overflow, ",\"%s\":\"", key);
    for (const unsigned char *c = (const unsigned char *)value; *c && !*overflow; c++) {
        switch (*c) {
            case '"':  append(out, out_sz, off, overflow, "\\\""); break;
            case '\\': append(out, out_sz, off, overflow, "\\\\"); break;
            case '\n': append(out, out_sz, off, overflow, "\\n"); break;
            case '\r': append(out, out_sz, off, overflow, "\\r"); break;
            case '\t': append(out, out_sz, off, overflow, "\\t"); break;
            default:
                if (*c < 0x20)
                    append(out, out_sz, off, overflow, "\\u%04x", *c);
                else
                    append(out, out_sz, off, overflow, "%c", *c);
        }
    }
    append(out, out_sz, off, overflow, "\"");
}

int modemident_json(const modemident_t *id, const char *source_type,
                    const char *method, const char *at_port, const char *label,
                    char *out, size_t out_sz) {
    if (out == NULL || out_sz == 0)
        return -1;
    out[0] = '\0';

    size_t off = 0;
    int overflow = 0;

    append(out, out_sz, &off, &overflow, "{\"v\":%d", MODEMIDENT_SCHEMA);
    json_kv(out, out_sz, &off, &overflow, "source_type", source_type);
    json_kv(out, out_sz, &off, &overflow, "method", method);
    if (id != NULL) {
        json_kv(out, out_sz, &off, &overflow, "imei", id->imei);
        json_kv(out, out_sz, &off, &overflow, "make", id->make);
        json_kv(out, out_sz, &off, &overflow, "model", id->model);
        json_kv(out, out_sz, &off, &overflow, "firmware", id->firmware);
    }
    json_kv(out, out_sz, &off, &overflow, "at_port", at_port);
    json_kv(out, out_sz, &off, &overflow, "label", label);
    append(out, out_sz, &off, &overflow, "}");

    if (overflow) {
        out[0] = '\0';
        return -1;
    }
    return 0;
}
