/*
    This file is part of Kismet

    Kismet is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    Kismet is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Kismet; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

    cellat_lock -- see cellat_lock.h.
*/

#include "cellat_lock.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

/* A colon list of band numbers ("1:2:66"), and nothing else. */
static int is_band_list(const char *s) {
    if (s == NULL || !isdigit((unsigned char)s[0]))
        return 0;
    int saw_nonzero = 0;
    for (const char *p = s; *p; p++) {
        if (*p == ':') {
            if (!isdigit((unsigned char)p[1]))
                return 0;
        } else if (!isdigit((unsigned char)*p)) {
            return 0;
        } else if (*p != '0') {
            saw_nonzero = 1;
        }
    }
    return saw_nonzero;   /* R01A08's bare `0` is not a list */
}

/* A RAT preference as the modem spells it: letters, digits, ':' (LTE:NR5G). */
static int is_mode(const char *s) {
    if (s == NULL || s[0] == '\0')
        return 0;
    for (const char *p = s; *p; p++)
        if (!isalnum((unsigned char)*p) && *p != ':')
            return 0;
    return 1;
}

int cellat_lock_parse_read(const char *resp, const char *key,
                           char *out, size_t out_sz) {
    if (resp == NULL || key == NULL || out == NULL || out_sz == 0)
        return 0;
    char needle[96];
    snprintf(needle, sizeof(needle), "+QNWPREFCFG: \"%s\",", key);
    const char *p = strstr(resp, needle);
    if (p == NULL)
        return 0;
    p += strlen(needle);
    while (*p == ' ')
        p++;
    size_t n = strcspn(p, "\r\n");
    while (n > 0 && (p[n - 1] == ' ' || p[n - 1] == '\t'))
        n--;
    /* Refused, not truncated: a clipped band list is a DIFFERENT list, and
     * this value is what a restore writes back. */
    if (n == 0 || n >= out_sz)
        return 0;
    char val[CELLAT_LOCK_BANDS_MAX];
    if (n >= sizeof(val))
        return 0;
    memcpy(val, p, n);
    val[n] = '\0';

    int ok = strcmp(key, "mode_pref") == 0 ? is_mode(val) : is_band_list(val);
    if (!ok)
        return 0;
    memcpy(out, val, n + 1);
    return 1;
}

/* The first line of `resp` starting with `prefix` (after optional spaces),
 * copied without its line ending; NULL when there is none. */
static const char *find_line(const char *resp, const char *prefix,
                             char *line, size_t line_sz) {
    const char *p = resp;
    size_t pl = strlen(prefix);
    while (p != NULL && *p) {
        while (*p == '\r' || *p == '\n' || *p == ' ')
            p++;
        size_t n = strcspn(p, "\r\n");
        if (n >= pl && strncmp(p, prefix, pl) == 0) {
            if (n >= line_sz)
                n = line_sz - 1;
            memcpy(line, p, n);
            line[n] = '\0';
            return line;
        }
        p += n;
    }
    return NULL;
}

static void trim_both(char *s) {
    size_t n = strlen(s);
    while (n > 0 && isspace((unsigned char)s[n - 1]))
        s[--n] = '\0';
    size_t i = 0;
    while (s[i] && isspace((unsigned char)s[i]))
        i++;
    if (i)
        memmove(s, s + i, n - i + 1);
}

int cellat_lock_parse_selrat_read(const char *resp, char *out, size_t out_sz) {
    char line[256];
    if (resp == NULL || out == NULL || out_sz < 3 ||
        find_line(resp, "!SELRAT:", line, sizeof(line)) == NULL)
        return 0;
    /* "!SELRAT: 00, Automatic" -- the index is 1-2 hex digits before ',' */
    char *v = line + strlen("!SELRAT:");
    while (*v == ' ')
        v++;
    size_t n = 0;
    while (isxdigit((unsigned char)v[n]))
        n++;
    if (n < 1 || n > 2 || v[n] != ',')
        return 0;
    memcpy(out, v, n);
    out[n] = '\0';
    return 1;
}

int cellat_lock_parse_selrat_list(const char *resp, cellat_lock_settings_t *s) {
    if (resp == NULL || s == NULL)
        return 0;
    int found = 0;
    const char *p = resp;
    while (*p) {
        while (*p == '\r' || *p == '\n')
            p++;
        size_t n = strcspn(p, "\r\n");
        char line[128];
        if (n > 0 && n < sizeof(line)) {
            memcpy(line, p, n);
            line[n] = '\0';
            /* "<idx>, <name>": the index, then the name matched WHOLE */
            size_t k = 0;
            while (isxdigit((unsigned char)line[k]))
                k++;
            if (k >= 1 && k <= 2 && line[k] == ',') {
                char name[96];
                snprintf(name, sizeof(name), "%s", line + k + 1);
                trim_both(name);
                line[k] = '\0';
                if (strcasecmp(name, "LTE Only") == 0) {
                    snprintf(s->rat_lte, sizeof(s->rat_lte), "%s", line);
                    found = 1;
                } else if (strcasecmp(name, "NR 5G Only") == 0 ||
                           strcasecmp(name, "5G Only") == 0) {
                    snprintf(s->rat_nr, sizeof(s->rat_nr), "%s", line);
                    found = 1;
                }
            }
        }
        p += n;
    }
    return found;
}

int cellat_lock_parse_ws46_read(const char *resp, char *out, size_t out_sz) {
    char line[128];
    if (resp == NULL || out == NULL || out_sz < 3 ||
        find_line(resp, "+WS46:", line, sizeof(line)) == NULL)
        return 0;
    char *v = line + strlen("+WS46:");
    while (*v == ' ')
        v++;
    size_t n = 0;
    while (isdigit((unsigned char)v[n]))
        n++;
    if (n < 1 || n > 3 || (v[n] != '\0' && !isspace((unsigned char)v[n])))
        return 0;
    memcpy(out, v, n);
    out[n] = '\0';
    return 1;
}

int cellat_lock_parse_ws46_list(const char *resp, cellat_lock_settings_t *s) {
    char line[256];
    if (resp == NULL || s == NULL || find_line(resp, "+WS46:", line, sizeof(line)) == NULL)
        return 0;
    char *open = strchr(line, '(');
    if (open == NULL)
        return 0;
    int found = 0;
    char *save = NULL;
    for (char *tok = strtok_r(open + 1, ",)", &save); tok; tok = strtok_r(NULL, ",)", &save)) {
        trim_both(tok);
        /* whole numbers only: 128 is not 28 (TS 27.007: 28 = E-UTRAN only,
         * 35 = NG-RAN only) */
        if (strcmp(tok, "28") == 0) {
            snprintf(s->rat_lte, sizeof(s->rat_lte), "28");
            found = 1;
        } else if (strcmp(tok, "35") == 0) {
            snprintf(s->rat_nr, sizeof(s->rat_nr), "35");
            found = 1;
        }
    }
    return found;
}

int cellat_lock_parse_cnmp_read(const char *resp, char *out, size_t out_sz) {
    char line[128];
    if (resp == NULL || out == NULL || out_sz < 4 ||
        find_line(resp, "+CNMP:", line, sizeof(line)) == NULL)
        return 0;
    char *v = line + strlen("+CNMP:");
    while (*v == ' ')
        v++;
    size_t n = 0;
    while (isdigit((unsigned char)v[n]))
        n++;
    if (n < 1 || n > 3 || (v[n] != '\0' && !isspace((unsigned char)v[n])))
        return 0;
    /* 100 = "UNKNOW": the RAT mask matches no row of the table. The
     * SIM8202G-M2 lists 100 in =? yet answers ERROR to AT+CNMP=100, so a
     * lock taken from here could never be restored. */
    if (n == 3 && strncmp(v, "100", 3) == 0)
        return -1;
    memcpy(out, v, n);
    out[n] = '\0';
    return 1;
}

int cellat_lock_parse_cnmp_list(const char *resp, cellat_lock_settings_t *s) {
    char line[256];
    if (resp == NULL || s == NULL || find_line(resp, "+CNMP:", line, sizeof(line)) == NULL)
        return 0;
    char *open = strchr(line, '(');
    if (open == NULL)
        return 0;
    int found = 0;
    char *save = NULL;
    for (char *tok = strtok_r(open + 1, ",)", &save); tok; tok = strtok_r(NULL, ",)", &save)) {
        trim_both(tok);
        /* whole numbers only (SIM8200 manual V1.01 §4.2.11: 38 = LTE Only,
         * 71 = NR5G) */
        if (strcmp(tok, "38") == 0) {
            snprintf(s->rat_lte, sizeof(s->rat_lte), "38");
            found = 1;
        } else if (strcmp(tok, "71") == 0) {
            snprintf(s->rat_nr, sizeof(s->rat_nr), "71");
            found = 1;
        }
    }
    return found;
}

int cellat_lock_parse_qcfg_scanmode(const char *resp, char *out, size_t out_sz) {
    char line[128];
    if (resp == NULL || out == NULL || out_sz < 3 ||
        find_line(resp, "+QCFG: \"nwscanmode\",", line, sizeof(line)) == NULL)
        return 0;
    char *v = line + strlen("+QCFG: \"nwscanmode\",");
    size_t n = 0;
    while (isdigit((unsigned char)v[n]))
        n++;
    if (n < 1 || n > 2)
        return 0;
    memcpy(out, v, n);
    out[n] = '\0';
    return 1;
}

int cellat_lock_parse_qcfg_band(const char *resp, char *out, size_t out_sz) {
    char line[256];
    if (resp == NULL || out == NULL || out_sz < 2 ||
        find_line(resp, "+QCFG: \"band\",", line, sizeof(line)) == NULL)
        return 0;
    /* <gw>,<lte>,<tds> -- the SECOND field */
    char *f = strchr(line + strlen("+QCFG: \"band\","), ',');
    if (f == NULL)
        return 0;
    f++;
    if (f[0] == '0' && (f[1] == 'x' || f[1] == 'X'))
        f += 2;
    size_t n = 0;
    while (isxdigit((unsigned char)f[n]))
        n++;
    if (n < 1 || n > 16 || n >= out_sz || (f[n] != ',' && f[n] != '\0'))
        return 0;
    unsigned long long m = strtoull(f, NULL, 16);
    if (m == 0)
        return 0;
    snprintf(out, out_sz, "%llx", m);
    return 1;
}

/* Call fn(band) for each band in a colon list; stops when fn returns nonzero. */
static int for_each_band(const char *list, int (*fn)(const char *band, void *ctx),
                         void *ctx) {
    char work[CELLAT_LOCK_BANDS_MAX];
    snprintf(work, sizeof(work), "%s", list ? list : "");
    char *save = NULL;
    for (char *tok = strtok_r(work, ":", &save); tok; tok = strtok_r(NULL, ":", &save)) {
        int r = fn(tok, ctx);
        if (r)
            return r;
    }
    return 0;
}

typedef struct {
    char (*out)[CELLAT_LOCK_CHAN_MAX];
    size_t n, max;
    const char *prefix;
} chan_ctx_t;

static int add_chan(const char *band, void *vctx) {
    chan_ctx_t *c = (chan_ctx_t *)vctx;
    if (c->n >= c->max)
        return 1;
    snprintf(c->out[c->n++], CELLAT_LOCK_CHAN_MAX, "%s%s", c->prefix, band);
    return 0;
}

size_t cellat_lock_channels(const cellat_lock_settings_t *orig,
                            char out[][CELLAT_LOCK_CHAN_MAX], size_t max) {
    if (orig == NULL || out == NULL)
        return 0;
    chan_ctx_t c = { out, 0, max, "" };
    if (orig->backend == CELLAT_LOCK_QCFG) {
        /* AUTO, LTE, then one channel per LTE band set in the mask as found. */
        unsigned long long m = strtoull(orig->lte_band, NULL, 16);
        const char *h[2] = { "AUTO", "LTE" };
        for (int i = 0; i < 2 && c.n < max; i++)
            snprintf(out[c.n++], CELLAT_LOCK_CHAN_MAX, "%s", h[i]);
        for (int b = 1; b <= 64 && c.n < max; b++)
            if (m >> (b - 1) & 1ULL)
                snprintf(out[c.n++], CELLAT_LOCK_CHAN_MAX, "LTE-B%d", b);
        return c.n;
    }
    if (orig->backend != CELLAT_LOCK_QNWPREF) {
        /* RAT only: AUTO, then LTE / NR5G where the modem listed a code. */
        const char *h[3] = { "AUTO", orig->rat_lte[0] ? "LTE" : NULL,
                             orig->rat_nr[0] ? "NR5G" : NULL };
        for (int i = 0; i < 3 && c.n < max; i++)
            if (h[i] != NULL)
                snprintf(out[c.n++], CELLAT_LOCK_CHAN_MAX, "%s", h[i]);
        return c.n;
    }
    const char *head[3] = { "AUTO", "LTE", "NR5G" };
    int have_nr = orig->nr5g_band[0] != '\0';
    for (int i = 0; i < 3; i++) {
        if (i == 2 && !have_nr)
            break;
        if (c.n >= max)
            return c.n;
        snprintf(out[c.n++], CELLAT_LOCK_CHAN_MAX, "%s", head[i]);
    }
    c.prefix = "LTE-B";
    for_each_band(orig->lte_band, add_chan, &c);
    c.prefix = "NR-n";
    if (have_nr)
        for_each_band(orig->nr5g_band, add_chan, &c);
    return c.n;
}

typedef struct { const char *want; int found; } has_ctx_t;

static int has_band(const char *band, void *vctx) {
    has_ctx_t *h = (has_ctx_t *)vctx;
    if (strcmp(band, h->want) == 0)
        h->found = 1;
    return h->found;
}

static int list_has(const char *list, const char *band) {
    has_ctx_t h = { band, 0 };
    for_each_band(list, has_band, &h);
    return h.found;
}

/* A band SET after `prefix`: "LTE-B2+4+66" -> "2:4:66" in `out`, the
 * colon form QNWPREFCFG writes and as-found lists use. One band is a set of
 * one. 0 unless every element is a non-empty run of digits with no leading
 * zero, with no duplicates -- "LTE-B2++4", "LTE-B2+2", "LTE-B02" and a
 * trailing '+' are refused rather than guessed at. */
static int band_set(const char *channel, const char *prefix, char *out, size_t out_sz) {
    size_t pl = strlen(prefix);
    if (strncasecmp(channel, prefix, pl) != 0)
        return 0;
    const char *p = channel + pl;
    size_t o = 0;
    out[0] = '\0';
    while (1) {
        const char *s = p;
        while (isdigit((unsigned char)*p))
            p++;
        size_t n = (size_t)(p - s);
        if (n == 0 || n > 4 || (n > 1 && s[0] == '0'))
            return 0;
        char one[8];
        memcpy(one, s, n);
        one[n] = '\0';
        if (out[0] && list_has(out, one))
            return 0;
        int w = snprintf(out + o, out_sz - o, "%s%s", o ? ":" : "", one);
        if (w < 0 || (size_t)w >= out_sz - o)
            return 0;
        o += (size_t)w;
        if (*p == '\0')
            return 1;
        if (*p != '+')
            return 0;
        p++;
    }
}

/* The band is COPIED: for_each_band hands out tokens of its own local
 * copy of the list, which is gone once it returns. */
typedef struct { const char *allowed; char missing[16]; } subset_ctx_t;

static int band_missing(const char *band, void *vctx) {
    subset_ctx_t *s = (subset_ctx_t *)vctx;
    if (!list_has(s->allowed, band)) {
        snprintf(s->missing, sizeof(s->missing), "%s", band);
        return 1;
    }
    return 0;
}

/* The first band of `set` not in `allowed`, copied to `out`; 0 when none. */
static int first_missing(const char *set, const char *allowed, char *out, size_t out_sz) {
    subset_ctx_t s = { allowed, "" };
    if (!for_each_band(set, band_missing, &s))
        return 0;
    snprintf(out, out_sz, "%s", s.missing);
    return 1;
}

typedef struct { unsigned long long mask; unsigned long long have; int bad; } mask_ctx_t;

static int add_to_mask(const char *band, void *vctx) {
    mask_ctx_t *m = (mask_ctx_t *)vctx;
    long n = strtol(band, NULL, 10);
    if (n < 1 || n > 64 || !(m->have >> (n - 1) & 1ULL)) {
        m->bad = (int)n;
        return 1;
    }
    m->mask |= 1ULL << (n - 1);
    return 0;
}

int cellat_lock_target(const cellat_lock_settings_t *orig, const char *channel,
                       cellat_lock_settings_t *target, char *err, size_t err_sz) {
    if (orig == NULL || channel == NULL || target == NULL)
        return -1;
    *target = *orig;
    int have_nr = orig->nr5g_band[0] != '\0';
    char set[CELLAT_LOCK_BANDS_MAX], miss[16];

    if (strcasecmp(channel, "AUTO") == 0)
        return 0;
    if (orig->backend == CELLAT_LOCK_QCFG) {
        if (strcasecmp(channel, "LTE") == 0) {
            snprintf(target->mode_pref, sizeof(target->mode_pref), "3");
            return 0;
        }
        if (band_set(channel, "LTE-B", set, sizeof(set))) {
            mask_ctx_t m = { 0, strtoull(orig->lte_band, NULL, 16), 0 };
            char work[CELLAT_LOCK_BANDS_MAX];
            snprintf(work, sizeof(work), "%s", set);
            if (for_each_band(work, add_to_mask, &m)) {
                snprintf(err, err_sz, "'%s': LTE band %d is not in this modem's band "
                         "mask as found (0x%s)", channel, m.bad, orig->lte_band);
                return -1;
            }
            snprintf(target->mode_pref, sizeof(target->mode_pref), "3");
            snprintf(target->lte_band, sizeof(target->lte_band), "%llx", m.mask);
            return 0;
        }
        snprintf(err, err_sz, "'%s': this modem (AT+QCFG) locks LTE and LTE bands "
                 "only; its channels are AUTO, LTE and LTE-B<n>[+<n>...]", channel);
        return -1;
    }
    if (orig->backend != CELLAT_LOCK_QNWPREF) {
        const char *code = strcasecmp(channel, "LTE") == 0 ? orig->rat_lte :
                           strcasecmp(channel, "NR5G") == 0 ? orig->rat_nr : NULL;
        if (code != NULL && code[0]) {
            snprintf(target->mode_pref, sizeof(target->mode_pref), "%s", code);
            return 0;
        }
        snprintf(err, err_sz, "'%s': this modem locks the RAT only (%s), and its "
                 "channels are AUTO%s%s", channel,
                 orig->backend == CELLAT_LOCK_SELRAT ? "AT!SELRAT" :
                 orig->backend == CELLAT_LOCK_CNMP ? "AT+CNMP" : "AT+WS46",
                 orig->rat_lte[0] ? ", LTE" : "", orig->rat_nr[0] ? ", NR5G" : "");
        return -1;
    }
    if (strcasecmp(channel, "LTE") == 0) {
        snprintf(target->mode_pref, sizeof(target->mode_pref), "LTE");
        return 0;
    }
    if (strcasecmp(channel, "NR5G") == 0) {
        if (!have_nr)
            goto no_nr;
        snprintf(target->mode_pref, sizeof(target->mode_pref), "NR5G");
        return 0;
    }
    if (band_set(channel, "LTE-B", set, sizeof(set))) {
        if (first_missing(set, orig->lte_band, miss, sizeof(miss))) {
            snprintf(err, err_sz, "'%s': LTE band %s is not among the bands this "
                     "modem had enabled (%s)", channel, miss, orig->lte_band);
            return -1;
        }
        snprintf(target->mode_pref, sizeof(target->mode_pref), "LTE");
        snprintf(target->lte_band, sizeof(target->lte_band), "%s", set);
        return 0;
    }
    if (band_set(channel, "NR-n", set, sizeof(set))) {
        if (!have_nr)
            goto no_nr;
        if (first_missing(set, orig->nr5g_band, miss, sizeof(miss))) {
            snprintf(err, err_sz, "'%s': NR band n%s is not among the SA bands this "
                     "modem had enabled (%s)", channel, miss, orig->nr5g_band);
            return -1;
        }
        snprintf(target->mode_pref, sizeof(target->mode_pref), "NR5G");
        snprintf(target->nr5g_band, sizeof(target->nr5g_band), "%s", set);
        return 0;
    }
    snprintf(err, err_sz, "unknown channel '%s': cellat channels are AUTO, LTE, "
             "NR5G, LTE-B<band>[+<band>...] and NR-n<band>[+<band>...]", channel);
    return -1;

no_nr:
    snprintf(err, err_sz, "'%s': this modem reported no usable NR standalone band "
             "list, so it has no NR channels", channel);
    return -1;
}

size_t cellat_lock_writes(const cellat_lock_settings_t *cur,
                          const cellat_lock_settings_t *target,
                          char cmds[][CELLAT_LOCK_CMD_MAX], size_t max) {
    size_t n = 0;
    if (cur == NULL || target == NULL || cmds == NULL)
        return 0;
    if (target->backend == CELLAT_LOCK_QCFG) {
        /* 0 for GSM/WCDMA and TD-SCDMA = "no change" (QCFG manual §5.4):
         * only the LTE mask this code set is ever written or restored. */
        if (n < max && target->lte_band[0] && strcmp(cur->lte_band, target->lte_band) != 0)
            snprintf(cmds[n++], CELLAT_LOCK_CMD_MAX, "AT+QCFG=\"band\",0,%s,0,1",
                     target->lte_band);
        if (n < max && target->mode_pref[0] && strcmp(cur->mode_pref, target->mode_pref) != 0)
            snprintf(cmds[n++], CELLAT_LOCK_CMD_MAX, "AT+QCFG=\"nwscanmode\",%s,1",
                     target->mode_pref);
        return n;
    }
    if (target->backend != CELLAT_LOCK_QNWPREF) {
        if (n < max && target->mode_pref[0] && strcmp(cur->mode_pref, target->mode_pref) != 0)
            snprintf(cmds[n++], CELLAT_LOCK_CMD_MAX,
                     target->backend == CELLAT_LOCK_SELRAT ? "AT!SELRAT=%s" :
                     target->backend == CELLAT_LOCK_CNMP ? "AT+CNMP=%s" : "AT+WS46=%s",
                     target->mode_pref);
        return n;
    }
    if (n < max && target->lte_band[0] && strcmp(cur->lte_band, target->lte_band) != 0)
        snprintf(cmds[n++], CELLAT_LOCK_CMD_MAX, "AT+QNWPREFCFG=\"lte_band\",%s",
                 target->lte_band);
    if (n < max && target->nr5g_band[0] && strcmp(cur->nr5g_band, target->nr5g_band) != 0)
        snprintf(cmds[n++], CELLAT_LOCK_CMD_MAX, "AT+QNWPREFCFG=\"nr5g_band\",%s",
                 target->nr5g_band);
    if (n < max && target->mode_pref[0] && strcmp(cur->mode_pref, target->mode_pref) != 0)
        snprintf(cmds[n++], CELLAT_LOCK_CMD_MAX, "AT+QNWPREFCFG=\"mode_pref\",%s",
                 target->mode_pref);
    return n;
}

void cellat_lock_note_write(cellat_lock_settings_t *cur,
                            const cellat_lock_settings_t *target, const char *cmd) {
    if (cur == NULL || target == NULL || cmd == NULL)
        return;
    if (strstr(cmd, "\"lte_band\"") != NULL || strncmp(cmd, "AT+QCFG=\"band\"", 14) == 0)
        snprintf(cur->lte_band, sizeof(cur->lte_band), "%s", target->lte_band);
    else if (strstr(cmd, "\"nr5g_band\"") != NULL)
        snprintf(cur->nr5g_band, sizeof(cur->nr5g_band), "%s", target->nr5g_band);
    else
        snprintf(cur->mode_pref, sizeof(cur->mode_pref), "%s", target->mode_pref);
}

static const char *backend_name(int b) {
    return b == CELLAT_LOCK_SELRAT ? "selrat" : b == CELLAT_LOCK_WS46 ? "ws46" :
           b == CELLAT_LOCK_QCFG ? "qcfg" : b == CELLAT_LOCK_CNMP ? "cnmp" : "qnwpref";
}

int cellat_lock_state_write(const char *path, const char *imei,
                            const cellat_lock_settings_t *orig) {
    if (path == NULL || imei == NULL || orig == NULL) {
        errno = EINVAL;
        return -1;
    }
    /* Written to a temp name and renamed, so a crash mid-write can never leave
     * a half file that a later open would refuse -- or worse, half-restore. */
    char tmp[1024];
    snprintf(tmp, sizeof(tmp), "%s.tmp", path);
    FILE *f = fopen(tmp, "w");
    if (f == NULL)
        return -1;
    int ok = fprintf(f,
        "# cellat band/RAT lock: this modem's settings AS FOUND, before a lock\n"
        "# was written. A cellat source restores them from here on\n"
        "# its next open, then deletes this file.\n"
        "imei=%s\nbackend=%s\nmode_pref=%s\nlte_band=%s\nnr5g_band=%s\n"
        "rat_lte=%s\nrat_nr=%s\n",
        imei, backend_name(orig->backend), orig->mode_pref, orig->lte_band,
        orig->nr5g_band, orig->rat_lte, orig->rat_nr) > 0;
    ok = (fclose(f) == 0) && ok;
    if (!ok || rename(tmp, path) != 0) {
        int e = errno;
        unlink(tmp);
        errno = e ? e : EIO;
        return -1;
    }
    return 0;
}

int cellat_lock_state_read(const char *path, const char *imei, int backend,
                           cellat_lock_settings_t *orig, char *err, size_t err_sz) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        if (errno == ENOENT)
            return 0;
        snprintf(err, err_sz, "cannot read %s: %s", path, strerror(errno));
        return -1;
    }
    cellat_lock_settings_t s;
    memset(&s, 0, sizeof(s));
    char file_imei[64] = "";
    char file_backend[16] = "qnwpref";   /* a file with no backend line predates them */
    int have_mode = 0, have_lte = 0, have_nr = 0;
    char line[CELLAT_LOCK_BANDS_MAX + 64];
    while (fgets(line, sizeof(line), f) != NULL) {
        line[strcspn(line, "\r\n")] = '\0';
        if (line[0] == '#' || line[0] == '\0')
            continue;
        char *eq = strchr(line, '=');
        if (eq == NULL)
            continue;
        *eq = '\0';
        const char *v = eq + 1;
        if (strcmp(line, "imei") == 0)
            snprintf(file_imei, sizeof(file_imei), "%s", v);
        else if (strcmp(line, "backend") == 0)
            snprintf(file_backend, sizeof(file_backend), "%s", v);
        else if (strcmp(line, "rat_lte") == 0)
            snprintf(s.rat_lte, sizeof(s.rat_lte), "%s", v);
        else if (strcmp(line, "rat_nr") == 0)
            snprintf(s.rat_nr, sizeof(s.rat_nr), "%s", v);
        else if (strcmp(line, "mode_pref") == 0 && is_mode(v))
            have_mode = snprintf(s.mode_pref, sizeof(s.mode_pref), "%s", v) > 0;
        else if (strcmp(line, "lte_band") == 0) {
            /* validated below, once the backend is known: a colon list for
             * QNWPREF, a non-zero hex mask for QCFG */
            snprintf(s.lte_band, sizeof(s.lte_band), "%s", v);
            have_lte = 1;
        } else if (strcmp(line, "nr5g_band") == 0 && (v[0] == '\0' || is_band_list(v))) {
            snprintf(s.nr5g_band, sizeof(s.nr5g_band), "%s", v);
            have_nr = 1;
        }
    }
    fclose(f);
    if (imei != NULL && strcmp(file_imei, imei) != 0) {
        snprintf(err, err_sz, "%s holds settings for IMEI %s, not %s -- not "
                 "restoring another modem's settings", path,
                 file_imei[0] ? file_imei : "(none)", imei);
        return -1;
    }
    if (strcmp(file_backend, backend_name(backend)) != 0) {
        snprintf(err, err_sz, "%s holds %s settings, and this modem locks with %s "
                 "-- not restoring one command family's values through another",
                 path, file_backend, backend_name(backend));
        return -1;
    }
    int lte_ok = s.lte_band[0] == '\0' || (backend == CELLAT_LOCK_QCFG ?
                 (strspn(s.lte_band, "0123456789abcdefABCDEF") == strlen(s.lte_band) &&
                  strlen(s.lte_band) <= 16 && strtoull(s.lte_band, NULL, 16) != 0) :
                 is_band_list(s.lte_band));
    if (!lte_ok) {
        snprintf(err, err_sz, "%s has an unusable lte_band '%s' -- not restoring from it",
                 path, s.lte_band);
        return -1;
    }
    if (!have_mode || (backend == CELLAT_LOCK_QNWPREF && (!have_lte || !have_nr)) ||
        (backend == CELLAT_LOCK_QCFG && (!have_lte || s.lte_band[0] == '\0'))) {
        snprintf(err, err_sz, "%s is incomplete (mode_pref%s required) -- not "
                 "restoring from it", path,
                 backend == CELLAT_LOCK_QNWPREF ? ", lte_band and nr5g_band are" : " is");
        return -1;
    }
    s.backend = backend;
    *orig = s;
    return 1;
}

void cellat_lock_default_state_path(const char *imei, char *out, size_t out_sz) {
    const char *home = getenv("HOME");
    if (home != NULL && home[0] != '\0')
        snprintf(out, out_sz, "%s/.kismet/cellat-lock-%s.state", home, imei ? imei : "");
    else
        snprintf(out, out_sz, "/tmp/cellat-lock-%s.state", imei ? imei : "");
}
