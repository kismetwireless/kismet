/* diag_inventory.c - the per-(log_code, version) census.
 *
 * See diag_inventory.h for the rules; test_diag_inventory.c pins them.
 */

#include "diag_inventory.h"
#include "diag_inventory_codes.h"

#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

const uint16_t DIAG_INVENTORY_EMIT_CONTRACT_CODES[] = {
    0xB192, 0xB193, 0xB195, 0xB0C0, 0xB97F, 0x1476, 0x14D8,
};
const size_t DIAG_INVENTORY_EMIT_CONTRACT_COUNT =
    sizeof(DIAG_INVENTORY_EMIT_CONTRACT_CODES) /
    sizeof(DIAG_INVENTORY_EMIT_CONTRACT_CODES[0]);

const uint16_t DIAG_INVENTORY_NEVER_EMITS_CODES[] = { 0x14D8 };
const size_t DIAG_INVENTORY_NEVER_EMITS_COUNT =
    sizeof(DIAG_INVENTORY_NEVER_EMITS_CODES) /
    sizeof(DIAG_INVENTORY_NEVER_EMITS_CODES[0]);

int diag_inventory_is_emit_contract(uint16_t code) {
    for (size_t i = 0; i < DIAG_INVENTORY_EMIT_CONTRACT_COUNT; i++)
        if (DIAG_INVENTORY_EMIT_CONTRACT_CODES[i] == code)
            return 1;
    return 0;
}

size_t diag_inventory_known_count(void) {
    return sizeof(DIAG_INVENTORY_KNOWN_CODES) /
           sizeof(DIAG_INVENTORY_KNOWN_CODES[0]);
}

int diag_inventory_code_known(uint16_t code) {
    size_t lo = 0, hi = diag_inventory_known_count();
    while (lo < hi) {                    /* the table is sorted */
        size_t mid = lo + (hi - lo) / 2;
        if (DIAG_INVENTORY_KNOWN_CODES[mid] < code)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo < diag_inventory_known_count() &&
           DIAG_INVENTORY_KNOWN_CODES[lo] == code;
}

int diag_inventory_is_never_emits(uint16_t code) {
    for (size_t i = 0; i < DIAG_INVENTORY_NEVER_EMITS_COUNT; i++)
        if (DIAG_INVENTORY_NEVER_EMITS_CODES[i] == code)
            return 1;
    return 0;
}

typedef struct {
    uint16_t code;
    int16_t  ver;            /* -1..255 */
    uint64_t count;
    uint64_t decoded;
    uint64_t dropped;
    uint64_t emitted;
    uint64_t enrich_failed;
    uint64_t undecoded;      /* records no native leg read (native coverage) */
} inv_entry_t;

struct diag_inventory {
    size_t max_codes;
    size_t max_versions;

    inv_entry_t *e;          /* admitted keys, in arrival order */
    size_t       n;
    size_t       cap;

    /* Open-addressing index over e[]: slot holds entry index + 1, 0 = empty.
     * Grown at half load, so a lookup is O(1) on a full-mask replay too. */
    uint32_t *slot;
    size_t    nslots;        /* power of two */

    /* Versions admitted per code (DiagInventory.code_versions), and how many
     * codes have any -- the per-code and the distinct-code tiers. */
    uint16_t *code_versions; /* [65536] */
    size_t    codes;

    uint64_t overflow;
    int      native_coverage;  /* undecoded_native armed */
};

static uint32_t inv_key(uint16_t code, int ver) {
    return ((uint32_t)code << 16) | (uint32_t)(uint16_t)(ver + 1);
}

static size_t inv_hash(uint32_t k, size_t nslots) {
    k ^= k >> 16;
    k *= 0x7feb352dU;
    k ^= k >> 15;
    k *= 0x846ca68bU;
    k ^= k >> 16;
    return (size_t)k & (nslots - 1);
}

static int inv_index_grow(diag_inventory_t *inv) {
    size_t ns = inv->nslots ? inv->nslots * 2 : 64;
    uint32_t *s = calloc(ns, sizeof(*s));
    if (s == NULL)
        return -1;
    for (size_t i = 0; i < inv->n; i++) {
        size_t h = inv_hash(inv_key(inv->e[i].code, inv->e[i].ver), ns);
        while (s[h] != 0)
            h = (h + 1) & (ns - 1);
        s[h] = (uint32_t)(i + 1);
    }
    free(inv->slot);
    inv->slot = s;
    inv->nslots = ns;
    return 0;
}

diag_inventory_t *diag_inventory_new(size_t max_codes, size_t max_versions_per_code) {
    diag_inventory_t *inv = calloc(1, sizeof(*inv));
    if (inv == NULL)
        return NULL;
    inv->max_codes = max_codes ? max_codes : DIAG_INVENTORY_MAX_CODES;
    inv->max_versions = max_versions_per_code ? max_versions_per_code
                                              : DIAG_INVENTORY_MAX_VERSIONS;
    if (inv->max_versions > 257)
        inv->max_versions = 257;
    inv->code_versions = calloc(65536, sizeof(*inv->code_versions));
    if (inv->code_versions == NULL || inv_index_grow(inv) != 0) {
        diag_inventory_free(inv);
        return NULL;
    }
    return inv;
}

void diag_inventory_free(diag_inventory_t *inv) {
    if (inv == NULL)
        return;
    free(inv->e);
    free(inv->slot);
    free(inv->code_versions);
    free(inv);
}

static inv_entry_t *inv_find(const diag_inventory_t *inv, uint16_t code, int ver) {
    uint32_t k = inv_key(code, ver);
    size_t h = inv_hash(k, inv->nslots);
    while (inv->slot[h] != 0) {
        inv_entry_t *e = &inv->e[inv->slot[h] - 1];
        if (e->code == code && e->ver == ver)
            return e;
        h = (h + 1) & (inv->nslots - 1);
    }
    return NULL;
}

/* The key's entry, admitting it if both cap tiers allow; NULL (counted in
 * overflow) if not. */
static inv_entry_t *inv_admit(diag_inventory_t *inv, uint16_t code, int version) {
    inv_entry_t *e = inv_find(inv, code, version);
    if (e == NULL) {
        /* DiagInventory.record's two-tier admission. A new code is admitted
         * until the distinct-code ceiling; a new version of a known code
         * until that code's version budget (the byte-0-as-data guard). */
        uint16_t seen = inv->code_versions[code];
        if (seen == 0) {
            if (inv->codes >= inv->max_codes) {
                inv->overflow++;
                return NULL;
            }
        } else if (seen >= inv->max_versions) {
            inv->overflow++;
            return NULL;
        }
        if (inv->n == inv->cap) {
            size_t nc = inv->cap ? inv->cap * 2 : 32;
            inv_entry_t *ne = realloc(inv->e, nc * sizeof(*ne));
            if (ne == NULL)
                return NULL;     /* uncounted rather than miscounted */
            inv->e = ne;
            inv->cap = nc;
        }
        if ((inv->n + 1) * 2 > inv->nslots && inv_index_grow(inv) != 0)
            return NULL;
        if (seen == 0)
            inv->codes++;
        inv->code_versions[code] = (uint16_t)(seen + 1);

        e = &inv->e[inv->n];
        memset(e, 0, sizeof(*e));
        e->code = code;
        e->ver = (int16_t)version;
        size_t h = inv_hash(inv_key(code, version), inv->nslots);
        while (inv->slot[h] != 0)
            h = (h + 1) & (inv->nslots - 1);
        inv->slot[h] = (uint32_t)(inv->n + 1);
        inv->n++;
    }
    return e;
}

static int inv_version(int version) {
    return (version < -1 || version > 255) ? -1 : version;  /* not a byte */
}

void diag_inventory_record(diag_inventory_t *inv, uint16_t code, int version,
                           int decoded, uint64_t emitted, int enrich_failed) {
    if (inv == NULL)
        return;
    inv_entry_t *e = inv_admit(inv, code, inv_version(version));
    if (e == NULL)
        return;
    e->count++;
    if (decoded)
        e->decoded++;
    else
        e->dropped++;
    e->emitted += emitted;
    if (enrich_failed)
        e->enrich_failed++;
}

void diag_inventory_record_undecoded(diag_inventory_t *inv, uint16_t code,
                                     int version) {
    if (inv == NULL)
        return;
    inv_entry_t *e = inv_admit(inv, code, inv_version(version));
    if (e == NULL)
        return;
    e->count++;
    e->undecoded++;
}

void diag_inventory_set_native_coverage(diag_inventory_t *inv, int on) {
    if (inv != NULL)
        inv->native_coverage = on ? 1 : 0;
}

size_t diag_inventory_distinct(const diag_inventory_t *inv) {
    return inv ? inv->n : 0;
}

uint64_t diag_inventory_overflow(const diag_inventory_t *inv) {
    return inv ? inv->overflow : 0;
}

/* ---- Python float rendering ---------------------------------------------- */

void diag_inventory_py_float(char *buf, size_t n, double v) {
    if (n == 0)
        return;
    /* json.dumps's spellings for the non-finite values. */
    if (isnan(v)) { snprintf(buf, n, "NaN"); return; }
    if (isinf(v)) { snprintf(buf, n, v < 0 ? "-Infinity" : "Infinity"); return; }
    if (v == 0.0) { snprintf(buf, n, signbit(v) ? "-0.0" : "0.0"); return; }

    /* The shortest round-tripping digit string: the first precision at which
     * the correctly rounded %e reads back to v. That is the digit string
     * repr() chooses -- the closest of the shortest. */
    char e[40];
    for (int p = 0; p <= 16; p++) {
        snprintf(e, sizeof(e), "%.*e", p, v);
        if (strtod(e, NULL) == v)
            break;
    }
    /* e is "[-]d[.ddd]e[+-]XX": split it into sign, digits and exponent. */
    const char *s = e;
    int neg = 0;
    if (*s == '-') { neg = 1; s++; }
    char dig[24];
    size_t nd = 0;
    for (; *s && *s != 'e'; s++)
        if (*s >= '0' && *s <= '9' && nd < sizeof(dig) - 1)
            dig[nd++] = *s;
    while (nd > 1 && dig[nd - 1] == '0')
        nd--;
    dig[nd] = '\0';
    int exp10 = (*s == 'e') ? atoi(s + 1) : 0;
    int decpt = exp10 + 1;       /* value = 0.DIGITS x 10^decpt */

    char out[64];
    size_t o = 0;
    if (neg)
        out[o++] = '-';
    /* float_repr_style 'short' with mode 'r': exponent form when
     * decpt <= -4 or decpt > 16, i.e. outside [1e-4, 1e16). */
    if (decpt <= -4 || decpt > 16) {
        out[o++] = dig[0];
        if (nd > 1) {
            out[o++] = '.';
            memcpy(out + o, dig + 1, nd - 1);
            o += nd - 1;
        }
        int x = decpt - 1;
        o += (size_t)snprintf(out + o, sizeof(out) - o, "e%c%02d",
                              x < 0 ? '-' : '+', x < 0 ? -x : x);
    } else if (decpt <= 0) {
        out[o++] = '0';
        out[o++] = '.';
        for (int i = 0; i < -decpt; i++)
            out[o++] = '0';
        memcpy(out + o, dig, nd);
        o += nd;
    } else if ((size_t)decpt >= nd) {
        memcpy(out + o, dig, nd);
        o += nd;
        for (size_t i = nd; i < (size_t)decpt; i++)
            out[o++] = '0';
        out[o++] = '.';
        out[o++] = '0';
    } else {
        memcpy(out + o, dig, (size_t)decpt);
        o += (size_t)decpt;
        out[o++] = '.';
        memcpy(out + o, dig + decpt, nd - (size_t)decpt);
        o += nd - (size_t)decpt;
    }
    out[o] = '\0';
    snprintf(buf, n, "%s", out);
}

double diag_inventory_py_round3(double v) {
    if (!isfinite(v))
        return v;
    /* Python rounds the EXACT binary value to 3 decimal places, half to even,
     * and reads the decimal back. glibc's %.3f is that same correctly rounded
     * conversion, so the pair is round(v, 3) -- where round(v*1000)/1000 is
     * not, on the values whose x1000 product itself rounds. */
    char b[512];
    snprintf(b, sizeof(b), "%.3f", v);
    return strtod(b, NULL);
}

/* ---- Cadence ------------------------------------------------------------- */

void diag_inventory_cadence_arm(diag_inventory_cadence_t *c, double interval,
                                double now) {
    c->interval = interval;
    c->last = now;
}

int diag_inventory_cadence_due(diag_inventory_cadence_t *c, double now) {
    /* _LogEmitter._tally: `inv_interval > 0 and now - last_inv >= inv_interval` */
    if (c->interval > 0 && now - c->last >= c->interval) {
        c->last = now;
        return 1;
    }
    return 0;
}

/* ---- Wire rendering ------------------------------------------------------ */

/* snprintf-style appender: keeps counting once the buffer is full, so a short
 * buffer is a reported overrun, never a silent half-line. */
typedef struct {
    char  *p;
    size_t left;
    size_t total;
} wbuf_t;

static void wapp(wbuf_t *w, const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(w->p, w->left, fmt, ap);
    va_end(ap);
    if (n < 0)
        return;
    w->total += (size_t)n;
    if ((size_t)n >= w->left) {
        if (w->left > 0) {
            w->p += w->left - 1;
            w->left = 1;         /* keep the NUL slot; stop writing */
        }
    } else {
        w->p += n;
        w->left -= (size_t)n;
    }
}

/* The key as it is printed everywhere: 0x%04X/v<ver>. */
static void wkey(wbuf_t *w, const inv_entry_t *e) {
    wapp(w, "0x%04X/v%d", (unsigned)e->code, (int)e->ver);
}

static int is_unrec(const inv_entry_t *e) {
    return e->decoded == 0 && e->dropped > 0;
}
static int is_silent(const inv_entry_t *e) {
    return diag_inventory_is_emit_contract(e->code) && e->decoded > 0 &&
           e->emitted == 0;
}
static int is_silent_actionable(const inv_entry_t *e) {
    return is_silent(e) && !diag_inventory_is_never_emits(e->code);
}
static int is_enriched(const inv_entry_t *e) {
    return e->enrich_failed > 0;
}
static int is_undecoded(const inv_entry_t *e) {
    return e->undecoded > 0;
}

/* Python sorts the keys as (code, ver) tuples. */
static int cmp_key(const void *a, const void *b) {
    const inv_entry_t *x = *(const inv_entry_t *const *)a;
    const inv_entry_t *y = *(const inv_entry_t *const *)b;
    if (x->code != y->code)
        return x->code < y->code ? -1 : 1;
    if (x->ver != y->ver)
        return x->ver < y->ver ? -1 : 1;
    return 0;
}

/* _table's row_key: (0 if flagged else 1, -count, (code, ver)). An
 * undecoded_native row sorts between the two: it is worth a slot ahead of a
 * healthy row, but it is a to-do, not a finding, and on a full-mask stream
 * there are hundreds -- ahead of the findings they would push every silent
 * key off a 24-row table. Without native coverage no row has the state, so
 * the order is the Python one. */
static int table_tier(const inv_entry_t *e) {
    if (is_unrec(e) || is_silent(e) || is_enriched(e))
        return 0;
    return is_undecoded(e) ? 1 : 2;
}

static int cmp_table(const void *a, const void *b) {
    const inv_entry_t *x = *(const inv_entry_t *const *)a;
    const inv_entry_t *y = *(const inv_entry_t *const *)b;
    int fx = table_tier(x);
    int fy = table_tier(y);
    if (fx != fy)
        return fx < fy ? -1 : 1;
    if (x->count != y->count)
        return x->count > y->count ? -1 : 1;
    return cmp_key(a, b);
}

/* One status group: " name[k1, k2, ... +N more]", or nothing for an empty
 * list. Names the first DIAG_INVENTORY_STATUS_NAMED of the FULL list. */
static void wstatus_list(wbuf_t *w, const char *name,
                         inv_entry_t *const *sorted, size_t n,
                         int (*pred)(const inv_entry_t *), size_t total) {
    if (total == 0)
        return;
    wapp(w, " %s[", name);
    size_t shown = 0;
    for (size_t i = 0; i < n && shown < DIAG_INVENTORY_STATUS_NAMED; i++) {
        if (!pred(sorted[i]))
            continue;
        if (shown)
            wapp(w, ", ");
        wkey(w, sorted[i]);
        shown++;
    }
    if (total > DIAG_INVENTORY_STATUS_NAMED)
        wapp(w, " +%zu more", total - DIAG_INVENTORY_STATUS_NAMED);
    wapp(w, "]");
}

/* One bounded flag array: "name":["k1","k2",...], cut to WIRE_LIST_MAX. */
static void wlist(wbuf_t *w, const char *name, inv_entry_t *const *sorted,
                  size_t n, int (*pred)(const inv_entry_t *)) {
    wapp(w, ",\"%s\":[", name);
    size_t shown = 0;
    for (size_t i = 0; i < n && shown < DIAG_INVENTORY_WIRE_LIST_MAX; i++) {
        if (!pred(sorted[i]))
            continue;
        wapp(w, shown ? ",\"" : "\"");
        wkey(w, sorted[i]);
        wapp(w, "\"");
        shown++;
    }
    wapp(w, "]");
}

int diag_inventory_wire(const diag_inventory_t *inv, double now,
                        char *out, size_t out_len) {
    if (inv == NULL || out == NULL || out_len == 0)
        return -1;

    inv_entry_t **sorted = NULL, **table = NULL;
    if (inv->n > 0) {
        sorted = malloc(inv->n * sizeof(*sorted));
        table = malloc(inv->n * sizeof(*table));
        if (sorted == NULL || table == NULL) {
            free(sorted);
            free(table);
            return -1;
        }
        for (size_t i = 0; i < inv->n; i++)
            sorted[i] = table[i] = &inv->e[i];
        qsort(sorted, inv->n, sizeof(*sorted), cmp_key);
        qsort(table, inv->n, sizeof(*table), cmp_table);
    }

    size_t unrec = 0, silent = 0, actionable = 0, enriched = 0;
    uint64_t enrich_sum = 0;
    for (size_t i = 0; i < inv->n; i++) {
        const inv_entry_t *e = &inv->e[i];
        unrec += (size_t)is_unrec(e);
        silent += (size_t)is_silent(e);
        actionable += (size_t)is_silent_actionable(e);
        if (is_enriched(e)) {
            enriched++;
            enrich_sum += e->enrich_failed;
        }
    }

    /* undecoded_native, by CODE: the to-do list is "which codes need a native
     * leg", and every version of such a code is in the state at once. Taken
     * from the key-sorted view, so the list is sorted and each code once. */
    uint16_t *ucodes = NULL;
    size_t nu = 0;
    if (inv->native_coverage && inv->n > 0) {
        ucodes = malloc(inv->n * sizeof(*ucodes));
        if (ucodes == NULL) {
            free(sorted);
            free(table);
            return -1;
        }
        for (size_t i = 0; i < inv->n; i++)
            if (is_undecoded(sorted[i]) &&
                    (nu == 0 || ucodes[nu - 1] != sorted[i]->code))
                ucodes[nu++] = sorted[i]->code;
    }

    wbuf_t w = { out, out_len, 0 };
    char ts[64];
    diag_inventory_py_float(ts, sizeof(ts), diag_inventory_py_round3(now));

    /* summary()'s key order, which is load-bearing: everything the relay
     * reads comes before anything that grows with the data. */
    wapp(&w, "{\"type\":\"diag_inventory\",\"ts\":%s,\"distinct\":%zu,"
             "\"overflow\":%llu,\"unrecognized_total\":%zu,"
             "\"silent_total\":%zu,\"silent_actionable_total\":%zu,"
             "\"enrich_failed_total\":%zu",
         ts, inv->n, (unsigned long long)inv->overflow, unrec, silent,
         actionable, enriched);
    /* The native-only count, with the other totals: ahead of everything that
     * grows. Always present once armed, zero included. */
    if (inv->native_coverage)
        wapp(&w, ",\"undecoded_native_total\":%zu", nu);

    /* _status. */
    wapp(&w, ",\"status\":\"celldiag inventory: %zu (code,ver) key(s), "
             "%zu unrecognized, %zu silent", inv->n, unrec, silent);
    if (enriched)
        wapp(&w, ", %llu enrich-failed", (unsigned long long)enrich_sum);
    if (inv->overflow)
        wapp(&w, ", %llu over cap", (unsigned long long)inv->overflow);
    /* Only when nonzero, as enrich-failed: a permanent ", 0 undecoded-native"
     * on a fully covered wardrive stream would train the eye past it. */
    if (nu)
        wapp(&w, ", %zu undecoded-native", nu);
    wstatus_list(&w, "unrecognized", sorted, inv->n, is_unrec, unrec);
    wstatus_list(&w, "silent", sorted, inv->n, is_silent, silent);
    wstatus_list(&w, "enrich_failed", sorted, inv->n, is_enriched, enriched);
    if (nu) {
        wapp(&w, " undecoded_native[");
        for (size_t i = 0; i < nu && i < DIAG_INVENTORY_STATUS_NAMED; i++)
            wapp(&w, i ? ", 0x%04X" : "0x%04X", (unsigned)ucodes[i]);
        if (nu > DIAG_INVENTORY_STATUS_NAMED)
            wapp(&w, " +%zu more", nu - DIAG_INVENTORY_STATUS_NAMED);
        wapp(&w, "]");
    }
    wapp(&w, "\"");

    /* _table: flagged first, then by count, TABLE_ROWS of them. */
    wapp(&w, ",\"table\":\"");
    for (size_t i = 0; i < inv->n && i < DIAG_INVENTORY_TABLE_ROWS; i++) {
        const inv_entry_t *e = table[i];
        if (i)
            wapp(&w, ";");
        wkey(&w, e);
        wapp(&w, ",%llu,%llu,%llu,%llu,%llu,",
             (unsigned long long)e->count, (unsigned long long)e->decoded,
             (unsigned long long)e->dropped, (unsigned long long)e->emitted,
             (unsigned long long)e->enrich_failed);
        int any = 0;
        if (is_silent(e)) { wapp(&w, "s"); any = 1; }
        if (is_unrec(e))  { wapp(&w, "u"); any = 1; }
        if (is_enriched(e)) { wapp(&w, "e"); any = 1; }
        if (is_undecoded(e)) { wapp(&w, "n"); any = 1; }
        if (!any)
            wapp(&w, "-");
    }
    wapp(&w, "\"");

    wlist(&w, "unrecognized", sorted, inv->n, is_unrec);
    wlist(&w, "silent", sorted, inv->n, is_silent);
    wlist(&w, "enrich_failed", sorted, inv->n, is_enriched);
    if (inv->native_coverage) {
        wapp(&w, ",\"undecoded_native\":[");
        for (size_t i = 0; i < nu && i < DIAG_INVENTORY_WIRE_LIST_MAX; i++)
            wapp(&w, i ? ",\"0x%04X\"" : "\"0x%04X\"", (unsigned)ucodes[i]);
        wapp(&w, "]");
    }
    wapp(&w, "}");

    free(ucodes);
    free(sorted);
    free(table);
    return w.total > (size_t)INT32_MAX ? -1 : (int)w.total;
}
