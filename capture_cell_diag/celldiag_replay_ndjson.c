/* celldiag_replay_ndjson.c - the replay driver behind the golden observation
 * fixtures.
 *
 * Runs a built kismet_cap_cell_diag over a replay file by speaking the same
 * subset of the kismet_external v3 datasource protocol the pytest harness
 * (celltools/tests/kismet_capture_ipc.py) speaks, and prints what Kismet would
 * receive as CANONICAL NDJSON on stdout: one line per relayed cell observation,
 *
 *   {"gps":null,"obs":{...}}
 *   {"gps":{"fix":3,"lat":12.345678,"lon":-98.765432},"obs":{...}}
 *
 * Why a C driver: a golden check that needed a Python test harness to replay
 * would put Python back into the decode path's own proof.
 *
 * Why this program is ALSO the canonicalizer: a golden may have been rendered by
 * a different renderer than the one it is checked against, and two renderers can
 * spell the same value differently -- a log_tick above 2^53 as a float repr
 * (7.678363431711752e+16) or as 76783634317117525.0: the same double. Both
 * sides go through THIS canonical form, so there is one canonicalizer, not one
 * per renderer that could disagree with the other:
 *
 *   - object keys sorted (bytewise);
 *   - prov.captured_at dropped: a decode-time wall clock, different every run
 *     (the harness's _canon drops the same field);
 *   - a number written with a '.', 'e' or 'E' is a float, printed as the
 *     shortest %.Ng that round-trips, with ".0" added when that reads as an
 *     integer; any other number is an integer and keeps its digits. So
 *     2300 and 2300.0 stay distinct, while two spellings of one double agree;
 *   - strings re-escaped minimally (\" \\ and control characters only).
 *
 * Routing matches CellDiagRun: rows whose sub-JSON TYPE is a control or witness
 * type (ClockAnchor, RawAT, RawDiagDrop, DiagCrcCensus, cellat_stats,
 * ModemIdentity), and diag_stats / diag_census lines, are not observations and
 * are not printed. Status MESSAGEs go to stderr as "message: <text>", so a
 * caller can check the "decoder: " line, and each
 * diag_census line goes there as "census: <canonical JSON>".
 *
 * Usage:
 *   celldiag_replay_ndjson [--timeout S] <kismet_cap_cell_diag> <definition>
 *   celldiag_replay_ndjson --canon            (stdin JSON lines -> canonical)
 *   celldiag_replay_ndjson --selftest
 *
 * Exit: 0 ok; 2 the source refused to open, reported an ERROR, or the stream
 * desynced; 3 the run hit --timeout; 64 usage.
 *
 * libc only. The frame layout and the msgpack subset are the ones documented in
 * kismet_capture_ipc.py's "Wire spec".
 */
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* ── growable byte buffer ───────────────────────────────────────────────────── */
typedef struct {
    char *p;
    size_t n, cap;
} buf_t;

static void buf_put(buf_t *b, const void *s, size_t n) {
    if (b->n + n + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;
        while (cap < b->n + n + 1)
            cap *= 2;
        char *q = realloc(b->p, cap);
        if (q == NULL) {
            fprintf(stderr, "celldiag_replay_ndjson: out of memory\n");
            exit(70);
        }
        b->p = q;
        b->cap = cap;
    }
    memcpy(b->p + b->n, s, n);
    b->n += n;
    b->p[b->n] = '\0';
}

static void buf_str(buf_t *b, const char *s) { buf_put(b, s, strlen(s)); }

static void buf_chr(buf_t *b, char c) { buf_put(b, &c, 1); }

/* ── canonical JSON ─────────────────────────────────────────────────────────── */
enum { J_NULL, J_FALSE, J_TRUE, J_INT, J_FLOAT, J_STR, J_ARR, J_OBJ };

typedef struct jv {
    int kind;
    char *text;            /* J_INT: the digits; J_STR: decoded bytes; J_OBJ member: key */
    size_t len;            /* J_STR byte length */
    double num;            /* J_FLOAT */
    struct jv **items;     /* J_ARR elements / J_OBJ values */
    char **keys;           /* J_OBJ keys */
    size_t n;
} jv;

typedef struct {
    const char *s, *end;
    int bad;
} jp;

static void jp_ws(jp *p) {
    while (p->s < p->end && (*p->s == ' ' || *p->s == '\t' || *p->s == '\n' || *p->s == '\r'))
        p->s++;
}

static jv *jv_new(int kind) {
    jv *v = calloc(1, sizeof(*v));
    if (v == NULL)
        exit(70);
    v->kind = kind;
    return v;
}

static void jv_free(jv *v) {
    if (v == NULL)
        return;
    for (size_t i = 0; i < v->n; i++) {
        jv_free(v->items[i]);
        if (v->keys)
            free(v->keys[i]);
    }
    free(v->items);
    free(v->keys);
    free(v->text);
    free(v);
}

static void utf8_put(buf_t *b, unsigned cp) {
    char t[4];
    if (cp < 0x80) {
        t[0] = (char)cp;
        buf_put(b, t, 1);
    } else if (cp < 0x800) {
        t[0] = (char)(0xC0 | (cp >> 6));
        t[1] = (char)(0x80 | (cp & 0x3F));
        buf_put(b, t, 2);
    } else if (cp < 0x10000) {
        t[0] = (char)(0xE0 | (cp >> 12));
        t[1] = (char)(0x80 | ((cp >> 6) & 0x3F));
        t[2] = (char)(0x80 | (cp & 0x3F));
        buf_put(b, t, 3);
    } else {
        t[0] = (char)(0xF0 | (cp >> 18));
        t[1] = (char)(0x80 | ((cp >> 12) & 0x3F));
        t[2] = (char)(0x80 | ((cp >> 6) & 0x3F));
        t[3] = (char)(0x80 | (cp & 0x3F));
        buf_put(b, t, 4);
    }
}

static int hex4(const char *s, unsigned *out) {
    unsigned v = 0;
    for (int i = 0; i < 4; i++) {
        char c = s[i];
        v <<= 4;
        if (c >= '0' && c <= '9')
            v |= (unsigned)(c - '0');
        else if (c >= 'a' && c <= 'f')
            v |= (unsigned)(c - 'a' + 10);
        else if (c >= 'A' && c <= 'F')
            v |= (unsigned)(c - 'A' + 10);
        else
            return -1;
    }
    *out = v;
    return 0;
}

/* Decodes a JSON string at p->s (which points at the opening quote). */
static char *jp_string(jp *p, size_t *len) {
    buf_t b = {0};
    p->s++;
    while (p->s < p->end && *p->s != '"') {
        char c = *p->s++;
        if (c != '\\') {
            buf_chr(&b, c);
            continue;
        }
        if (p->s >= p->end)
            break;
        c = *p->s++;
        switch (c) {
        case '"': buf_chr(&b, '"'); break;
        case '\\': buf_chr(&b, '\\'); break;
        case '/': buf_chr(&b, '/'); break;
        case 'b': buf_chr(&b, '\b'); break;
        case 'f': buf_chr(&b, '\f'); break;
        case 'n': buf_chr(&b, '\n'); break;
        case 'r': buf_chr(&b, '\r'); break;
        case 't': buf_chr(&b, '\t'); break;
        case 'u': {
            unsigned cp;
            if (p->end - p->s < 4 || hex4(p->s, &cp) != 0) {
                p->bad = 1;
                break;
            }
            p->s += 4;
            if (cp >= 0xD800 && cp < 0xDC00 && p->end - p->s >= 6 &&
                p->s[0] == '\\' && p->s[1] == 'u') {
                unsigned lo;
                if (hex4(p->s + 2, &lo) == 0 && lo >= 0xDC00 && lo < 0xE000) {
                    cp = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                    p->s += 6;
                }
            }
            utf8_put(&b, cp);
            break;
        }
        default:
            p->bad = 1;
        }
    }
    if (p->s >= p->end)
        p->bad = 1;
    else
        p->s++;          /* closing quote */
    if (b.p == NULL)
        buf_put(&b, "", 0);
    *len = b.n;
    return b.p;
}

static jv *jp_value(jp *p, int depth);

static jv *jp_value(jp *p, int depth) {
    jp_ws(p);
    if (p->s >= p->end || depth > 64) {
        p->bad = 1;
        return jv_new(J_NULL);
    }
    char c = *p->s;
    if (c == '{' || c == '[') {
        int obj = (c == '{');
        jv *v = jv_new(obj ? J_OBJ : J_ARR);
        size_t cap = 0;
        p->s++;
        jp_ws(p);
        if (p->s < p->end && *p->s == (obj ? '}' : ']')) {
            p->s++;
            return v;
        }
        for (;;) {
            char *key = NULL;
            if (obj) {
                jp_ws(p);
                size_t kl;
                if (p->s >= p->end || *p->s != '"') {
                    p->bad = 1;
                    return v;
                }
                key = jp_string(p, &kl);
                jp_ws(p);
                if (p->s >= p->end || *p->s != ':') {
                    free(key);
                    p->bad = 1;
                    return v;
                }
                p->s++;
            }
            jv *item = jp_value(p, depth + 1);
            if (v->n == cap) {
                cap = cap ? cap * 2 : 8;
                v->items = realloc(v->items, cap * sizeof(*v->items));
                if (obj)
                    v->keys = realloc(v->keys, cap * sizeof(*v->keys));
            }
            v->items[v->n] = item;
            if (obj)
                v->keys[v->n] = key;
            v->n++;
            if (p->bad)
                return v;
            jp_ws(p);
            if (p->s < p->end && *p->s == ',') {
                p->s++;
                continue;
            }
            if (p->s < p->end && *p->s == (obj ? '}' : ']')) {
                p->s++;
                return v;
            }
            p->bad = 1;
            return v;
        }
    }
    if (c == '"') {
        jv *v = jv_new(J_STR);
        v->text = jp_string(p, &v->len);
        return v;
    }
    if (p->end - p->s >= 4 && memcmp(p->s, "null", 4) == 0) {
        p->s += 4;
        return jv_new(J_NULL);
    }
    if (p->end - p->s >= 4 && memcmp(p->s, "true", 4) == 0) {
        p->s += 4;
        return jv_new(J_TRUE);
    }
    if (p->end - p->s >= 5 && memcmp(p->s, "false", 5) == 0) {
        p->s += 5;
        return jv_new(J_FALSE);
    }
    /* A number. The token's spelling decides int vs float (see the header). */
    const char *start = p->s;
    int is_float = 0;
    while (p->s < p->end && strchr("+-0123456789.eE", *p->s) != NULL) {
        if (*p->s == '.' || *p->s == 'e' || *p->s == 'E')
            is_float = 1;
        p->s++;
    }
    if (p->s == start) {
        p->bad = 1;
        return jv_new(J_NULL);
    }
    size_t n = (size_t)(p->s - start);
    jv *v = jv_new(is_float ? J_FLOAT : J_INT);
    v->text = malloc(n + 1);
    memcpy(v->text, start, n);
    v->text[n] = '\0';
    if (is_float) {
        char *e;
        v->num = strtod(v->text, &e);
        if (*e != '\0')
            p->bad = 1;
    }
    return v;
}

/* The fewest significant digits that read back as exactly x, written in fixed
 * notation when the decimal exponent is in [-5, 17) and in %e otherwise, plus
 * ".0" when the fixed form would look like an integer. Deterministic for a
 * given double. Fixed notation is chosen over %g's switch to exponents, which
 * would print 2300.0 as "2.3e+03" and make the goldens hard to read. */
static void put_float(buf_t *b, double x) {
    char t[400];
    int digits = 17;
    if (x != x || x - x != 0) {          /* nan / inf: no JSON spelling exists */
        buf_str(b, "null");
        return;
    }
    for (int p = 1; p <= 17; p++) {
        snprintf(t, sizeof(t), "%.*e", p - 1, x);
        if (strtod(t, NULL) == x) {
            digits = p;
            break;
        }
    }
    snprintf(t, sizeof(t), "%.*e", digits - 1, x);
    int exp10 = atoi(strchr(t, 'e') + 1);
    if (exp10 >= -5 && exp10 < 17) {
        int decimals = digits - 1 - exp10;
        snprintf(t, sizeof(t), "%.*f", decimals > 0 ? decimals : 0, x);
    }
    buf_str(b, t);
    if (strpbrk(t, ".e") == NULL)
        buf_str(b, ".0");
}

static void put_string(buf_t *b, const char *s, size_t n) {
    buf_chr(b, '"');
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            buf_chr(b, '\\');
            buf_chr(b, (char)c);
        } else if (c < 0x20) {
            char t[8];
            snprintf(t, sizeof(t), "\\u%04x", c);
            buf_str(b, t);
        } else {
            buf_chr(b, (char)c);
        }
    }
    buf_chr(b, '"');
}

static const char *const *g_sort_keys;

static int key_cmp(const void *a, const void *b) {
    size_t i = *(const size_t *)a, j = *(const size_t *)b;
    return strcmp(g_sort_keys[i], g_sort_keys[j]);
}

/* `in_prov`: this object is the observation's prov block, whose captured_at
 * is the one volatile field and is dropped. */
static void put_canon(buf_t *b, const jv *v, int in_prov) {
    switch (v->kind) {
    case J_NULL: buf_str(b, "null"); return;
    case J_TRUE: buf_str(b, "true"); return;
    case J_FALSE: buf_str(b, "false"); return;
    case J_INT: buf_str(b, v->text); return;
    case J_FLOAT: put_float(b, v->num); return;
    case J_STR: put_string(b, v->text, v->len); return;
    case J_ARR:
        buf_chr(b, '[');
        for (size_t i = 0; i < v->n; i++) {
            if (i)
                buf_chr(b, ',');
            put_canon(b, v->items[i], 0);
        }
        buf_chr(b, ']');
        return;
    case J_OBJ: {
        size_t *ord = malloc((v->n ? v->n : 1) * sizeof(*ord));
        for (size_t i = 0; i < v->n; i++)
            ord[i] = i;
        g_sort_keys = (const char *const *)v->keys;
        qsort(ord, v->n, sizeof(*ord), key_cmp);
        buf_chr(b, '{');
        int first = 1;
        for (size_t k = 0; k < v->n; k++) {
            size_t i = ord[k];
            if (in_prov && strcmp(v->keys[i], "captured_at") == 0)
                continue;
            if (!first)
                buf_chr(b, ',');
            first = 0;
            put_string(b, v->keys[i], strlen(v->keys[i]));
            buf_chr(b, ':');
            put_canon(b, v->items[i], strcmp(v->keys[i], "prov") == 0);
        }
        buf_chr(b, '}');
        free(ord);
        return;
    }
    }
}

/* Canonicalizes one top-level observation object into `out`. 0 ok, -1 bad. */
static int canon_json(const char *s, size_t n, buf_t *out) {
    jp p = {s, s + n, 0};
    jv *v = jp_value(&p, 0);
    jp_ws(&p);
    if (p.s != p.end)
        p.bad = 1;
    if (!p.bad)
        put_canon(out, v, 0);
    jv_free(v);
    return p.bad ? -1 : 0;
}

/* ── msgpack subset (reader) ────────────────────────────────────────────────── */
typedef struct {
    const uint8_t *p, *end;
} mp_t;

static int mp_need(mp_t *m, size_t n) { return (size_t)(m->end - m->p) >= n ? 0 : -1; }

static uint64_t be(const uint8_t *p, int n) {
    uint64_t v = 0;
    for (int i = 0; i < n; i++)
        v = (v << 8) | p[i];
    return v;
}

/* Reads a map/array/str/bin header. Returns its count/length, or -1. */
static long mp_len(mp_t *m, int *kind) {
    if (mp_need(m, 1))
        return -1;
    uint8_t b = *m->p++;
    int w = 0;
    if (b >= 0x80 && b <= 0x8F) { *kind = 'm'; return b & 0x0F; }
    if (b >= 0x90 && b <= 0x9F) { *kind = 'a'; return b & 0x0F; }
    if (b >= 0xA0 && b <= 0xBF) { *kind = 's'; return b & 0x1F; }
    switch (b) {
    case 0xD9: *kind = 's'; w = 1; break;
    case 0xDA: *kind = 's'; w = 2; break;
    case 0xDB: *kind = 's'; w = 4; break;
    case 0xC4: *kind = 'b'; w = 1; break;
    case 0xC5: *kind = 'b'; w = 2; break;
    case 0xC6: *kind = 'b'; w = 4; break;
    case 0xDE: *kind = 'm'; w = 2; break;
    case 0xDF: *kind = 'm'; w = 4; break;
    case 0xDC: *kind = 'a'; w = 2; break;
    case 0xDD: *kind = 'a'; w = 4; break;
    default:
        m->p--;
        return -1;
    }
    if (mp_need(m, (size_t)w))
        return -1;
    long n = (long)be(m->p, w);
    m->p += w;
    return n;
}

/* Reads a scalar number. Returns 0 and sets *is_float / the outputs, or -1. */
static int mp_num(mp_t *m, int64_t *iv, double *dv, int *is_float) {
    if (mp_need(m, 1))
        return -1;
    uint8_t b = *m->p;
    *is_float = 0;
    if (b < 0x80) { m->p++; *iv = b; return 0; }
    if (b >= 0xE0) { m->p++; *iv = (int8_t)b; return 0; }
    static const struct { uint8_t tag; int w; int sgn; } ints[] = {
        {0xCC, 1, 0}, {0xCD, 2, 0}, {0xCE, 4, 0}, {0xCF, 8, 0},
        {0xD0, 1, 1}, {0xD1, 2, 1}, {0xD2, 4, 1}, {0xD3, 8, 1},
    };
    for (size_t i = 0; i < sizeof(ints) / sizeof(ints[0]); i++) {
        if (b != ints[i].tag)
            continue;
        if (mp_need(m, 1 + (size_t)ints[i].w))
            return -1;
        uint64_t u = be(m->p + 1, ints[i].w);
        if (ints[i].sgn && ints[i].w < 8 && (u >> (8 * ints[i].w - 1)))
            u |= ~0ULL << (8 * ints[i].w);
        *iv = (int64_t)u;
        m->p += 1 + ints[i].w;
        return 0;
    }
    if (b == 0xCA || b == 0xCB) {
        int w = (b == 0xCA) ? 4 : 8;
        if (mp_need(m, 1 + (size_t)w))
            return -1;
        uint64_t u = be(m->p + 1, w);
        if (w == 4) {
            uint32_t u32 = (uint32_t)u;
            float f;
            memcpy(&f, &u32, 4);
            *dv = f;
        } else {
            memcpy(dv, &u, 8);
        }
        *is_float = 1;
        m->p += 1 + w;
        return 0;
    }
    return -1;
}

static int mp_skip(mp_t *m, int depth) {
    if (mp_need(m, 1) || depth > 32)
        return -1;
    uint8_t b = *m->p;
    if (b == 0xC0 || b == 0xC2 || b == 0xC3) {
        m->p++;
        return 0;
    }
    int64_t iv;
    double dv;
    int fl;
    if (mp_num(m, &iv, &dv, &fl) == 0)
        return 0;
    int kind;
    long n = mp_len(m, &kind);
    if (n < 0)
        return -1;
    if (kind == 's' || kind == 'b') {
        if (mp_need(m, (size_t)n))
            return -1;
        m->p += n;
        return 0;
    }
    long items = (kind == 'm') ? 2 * n : n;
    for (long i = 0; i < items; i++)
        if (mp_skip(m, depth + 1))
            return -1;
    return 0;
}

/* Within the map at *m (header not yet read), finds integer key `key` and
 * leaves *val positioned at its value. 0 found, -1 not found / malformed. */
static int mp_map_find(mp_t m, int64_t key, mp_t *val) {
    int kind;
    long n = mp_len(&m, &kind);
    if (n < 0 || kind != 'm')
        return -1;
    for (long i = 0; i < n; i++) {
        int64_t k;
        double d;
        int fl;
        mp_t at = m;
        int is_int_key = (mp_num(&m, &k, &d, &fl) == 0 && !fl);
        if (!is_int_key) {
            m = at;
            if (mp_skip(&m, 0))
                return -1;
        }
        if (is_int_key && k == key) {
            *val = m;
            return 0;
        }
        if (mp_skip(&m, 0))
            return -1;
    }
    return -1;
}

static int mp_get_str(mp_t m, int64_t key, const char **s, size_t *n) {
    mp_t v;
    int kind;
    if (mp_map_find(m, key, &v))
        return -1;
    long len = mp_len(&v, &kind);
    if (len < 0 || kind != 's' || mp_need(&v, (size_t)len))
        return -1;
    *s = (const char *)v.p;
    *n = (size_t)len;
    return 0;
}

static int mp_get_num(mp_t m, int64_t key, double *out, int *is_float) {
    mp_t v;
    int64_t iv;
    double dv;
    if (mp_map_find(m, key, &v) || mp_num(&v, &iv, &dv, is_float))
        return -1;
    *out = *is_float ? dv : (double)iv;
    return 0;
}

/* ── v3 framing ─────────────────────────────────────────────────────────────── */
#define SIG 0xDECAFBADu
#define V3_SENTINEL 0xA9A9u
#define HDR_LEN 20
#define PKT_PING 2
#define PKT_MESSAGE 5
#define PKT_ERROR 6
#define PKT_OPENREQ 12
#define PKT_OPENREPORT 13
#define PKT_PACKET 16
#define DATAREPORT_FIELD_GPSBLOCK 1
#define DATAREPORT_FIELD_JSONBLOCK 5
#define SUB_JSON_FIELD_TYPE 1
#define SUB_JSON_FIELD_JSON 4
#define SUB_GPS_FIELD_LAT 1
#define SUB_GPS_FIELD_LON 2
#define SUB_GPS_FIELD_FIX 4

static void put_be(uint8_t *p, uint64_t v, int n) {
    for (int i = n - 1; i >= 0; i--) {
        p[i] = (uint8_t)(v & 0xFF);
        v >>= 8;
    }
}

static int write_all(int fd, const void *p, size_t n) {
    const uint8_t *q = p;
    while (n) {
        ssize_t w = write(fd, q, n);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        q += w;
        n -= (size_t)w;
    }
    return 0;
}

static int send_frame(int fd, unsigned type, unsigned seq, const uint8_t *pl, size_t n) {
    uint8_t h[HDR_LEN];
    put_be(h, SIG, 4);
    put_be(h + 4, V3_SENTINEL, 2);
    put_be(h + 6, 3, 2);
    put_be(h + 8, n, 4);
    put_be(h + 12, type, 2);
    put_be(h + 14, 0, 2);
    put_be(h + 16, seq, 4);
    if (write_all(fd, h, HDR_LEN))
        return -1;
    return n ? write_all(fd, pl, n) : 0;
}

static const char *const kNotObservationTypes[] = {
    "ClockAnchor", "RawAT", "RawDiagDrop", "DiagCrcCensus",
    "cellat_stats", "ModemIdentity",
};

typedef struct {
    int opened;          /* an OPENREPORT arrived */
    int open_code;
    int errors;
    int desync;
    long rows;
} run_t;

/* Same test as CellDiagRun._on_json: a control line declares its type. */
static int is_control_line(const char *js, size_t n) {
    static const char *const types[] = {"diag_stats", "diag_census"};
    buf_t flat = {0};
    for (size_t i = 0; i < n; i++)
        if (js[i] != ' ')
            buf_chr(&flat, js[i]);
    int hit = 0;
    for (size_t t = 0; t < 2 && flat.p; t++) {
        char pat[48];
        snprintf(pat, sizeof(pat), "\"type\":\"%s\"", types[t]);
        if (strstr(flat.p, pat))
            hit = 1;
    }
    free(flat.p);
    return hit;
}

static void on_packet(run_t *r, const uint8_t *pl, size_t n) {
    mp_t top = {pl, pl + n}, jb, gb;
    const char *js, *jt;
    size_t jsn, jtn;
    if (mp_map_find(top, DATAREPORT_FIELD_JSONBLOCK, &jb))
        return;                               /* a raw packet block only */
    if (mp_get_str(jb, SUB_JSON_FIELD_JSON, &js, &jsn))
        return;
    if (mp_get_str(jb, SUB_JSON_FIELD_TYPE, &jt, &jtn) == 0) {
        for (size_t i = 0; i < sizeof(kNotObservationTypes) / sizeof(*kNotObservationTypes); i++)
            if (strlen(kNotObservationTypes[i]) == jtn &&
                memcmp(kNotObservationTypes[i], jt, jtn) == 0)
                return;
    }
    if (is_control_line(js, jsn)) {
        /* The census table is what Kismet stores as the source's inventory, and
         * it is deterministic for a replay; diag_stats carries wall-clock
         * fields and is not. So only the census reaches stderr, canonical. */
        buf_t c = {0};
        if (strstr(js, "diag_census") != NULL && canon_json(js, jsn, &c) == 0)
            fprintf(stderr, "census: %s\n", c.p);
        free(c.p);
        return;
    }

    buf_t line = {0};
    buf_str(&line, "{\"gps\":");
    if (mp_map_find(top, DATAREPORT_FIELD_GPSBLOCK, &gb) == 0) {
        double lat, lon, fix;
        int lf, of, ff;
        buf_str(&line, "{\"fix\":");
        if (mp_get_num(gb, SUB_GPS_FIELD_FIX, &fix, &ff) == 0) {
            if (ff)
                put_float(&line, fix);
            else {
                char t[32];
                snprintf(t, sizeof(t), "%lld", (long long)fix);
                buf_str(&line, t);
            }
        } else {
            buf_str(&line, "null");
        }
        buf_str(&line, ",\"lat\":");
        if (mp_get_num(gb, SUB_GPS_FIELD_LAT, &lat, &lf) == 0)
            put_float(&line, lat);
        else
            buf_str(&line, "null");
        buf_str(&line, ",\"lon\":");
        if (mp_get_num(gb, SUB_GPS_FIELD_LON, &lon, &of) == 0)
            put_float(&line, lon);
        else
            buf_str(&line, "null");
        buf_chr(&line, '}');
    } else {
        buf_str(&line, "null");
    }
    buf_str(&line, ",\"obs\":");
    if (canon_json(js, jsn, &line) != 0) {
        fprintf(stderr, "error: relayed observation is not valid JSON: %.*s\n", (int)jsn, js);
        r->desync = 1;
        free(line.p);
        return;
    }
    buf_str(&line, "}\n");
    fwrite(line.p, 1, line.n, stdout);
    free(line.p);
    r->rows++;
}

static void on_frame(run_t *r, unsigned type, unsigned code, const uint8_t *pl, size_t n) {
    mp_t top = {pl, pl + n};
    const char *s;
    size_t sn;
    switch (type) {
    case PKT_PACKET:
        on_packet(r, pl, n);
        break;
    case PKT_OPENREPORT:
        r->opened = 1;
        r->open_code = (int)code;
        if (mp_get_str(top, 9, &s, &sn) == 0)
            fprintf(stderr, "open: code=%u %.*s\n", code, (int)sn, s);
        else
            fprintf(stderr, "open: code=%u\n", code);
        break;
    case PKT_MESSAGE:
        if (mp_get_str(top, 2, &s, &sn) == 0)
            fprintf(stderr, "message: %.*s\n", (int)sn, s);
        break;
    case PKT_ERROR:
        r->errors++;
        if (mp_get_str(top, 1, &s, &sn) == 0)
            fprintf(stderr, "error: %.*s\n", (int)sn, s);
        else
            fprintf(stderr, "error: (no text)\n");
        break;
    default:
        break;
    }
}

/* Consumes every complete frame at the front of `in`. */
static void drain_frames(run_t *r, buf_t *in) {
    size_t off = 0;
    while (in->n - off >= HDR_LEN) {
        const uint8_t *h = (const uint8_t *)in->p + off;
        if (be(h, 4) != SIG || be(h + 4, 2) != V3_SENTINEL) {
            fprintf(stderr, "error: frame desync at byte %zu\n", off);
            r->desync = 1;
            in->n = 0;
            return;
        }
        size_t len = (size_t)be(h + 8, 4);
        /* The server's MAX_EXTERNAL_FRAME_LEN: no more permissive than Kismet. */
        if (len + (HDR_LEN - 12) > 16384) {
            fprintf(stderr, "error: %zu B frame exceeds the server's frame cap\n", len);
            r->desync = 1;
        }
        if (in->n - off < HDR_LEN + len)
            break;
        on_frame(r, (unsigned)be(h + 12, 2), (unsigned)be(h + 14, 2), h + HDR_LEN, len);
        off += HDR_LEN + len;
    }
    memmove(in->p, in->p + off, in->n - off);
    in->n -= off;
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec + ts.tv_nsec / 1e9;
}

static int run_replay(const char *binary, const char *definition, double timeout) {
    int a[2], b[2];          /* a: driver -> binary; b: binary -> driver */
    if (pipe(a) || pipe(b)) {
        perror("pipe");
        return 70;
    }
    pid_t pid = fork();
    if (pid < 0) {
        perror("fork");
        return 70;
    }
    if (pid == 0) {
        char in_arg[32], out_arg[32];
        close(a[1]);
        close(b[0]);
        int devnull = open("/dev/null", O_RDWR);
        if (devnull >= 0) {
            dup2(devnull, 0);
            dup2(devnull, 1);
            dup2(devnull, 2);
        }
        snprintf(in_arg, sizeof(in_arg), "--in-fd=%d", a[0]);
        snprintf(out_arg, sizeof(out_arg), "--out-fd=%d", b[1]);
        execl(binary, binary, in_arg, out_arg, (char *)NULL);
        _exit(127);
    }
    close(a[0]);
    close(b[1]);
    signal(SIGPIPE, SIG_IGN);

    /* OPENREQ: {1: "<definition>"} */
    buf_t req = {0};
    size_t dl = strlen(definition);
    uint8_t hdr[6];
    buf_chr(&req, (char)0x81);
    buf_chr(&req, 0x01);
    if (dl < 0x20) {
        hdr[0] = (uint8_t)(0xA0 | dl);
        buf_put(&req, hdr, 1);
    } else if (dl <= 0xFF) {
        hdr[0] = 0xD9;
        hdr[1] = (uint8_t)dl;
        buf_put(&req, hdr, 2);
    } else {
        hdr[0] = 0xDA;
        put_be(hdr + 1, dl, 2);
        buf_put(&req, hdr, 3);
    }
    buf_put(&req, definition, dl);
    send_frame(a[1], PKT_OPENREQ, 1, (const uint8_t *)req.p, req.n);
    free(req.p);

    run_t r = {0};
    buf_t in = {0};
    double deadline = now_s() + timeout, next_ping = now_s() + 5.0;
    int timed_out = 1;
    while (now_s() < deadline) {
        if (now_s() >= next_ping) {
            /* Mandatory keepalive: the binary FATAL-exits after 15 s silence. */
            send_frame(a[1], PKT_PING, 0, NULL, 0);
            next_ping = now_s() + 5.0;
        }
        struct pollfd pf = {b[0], POLLIN, 0};
        int pr = poll(&pf, 1, 500);
        if (pr > 0) {
            char chunk[65536];
            ssize_t got = read(b[0], chunk, sizeof(chunk));
            if (got > 0) {
                buf_put(&in, chunk, (size_t)got);
                drain_frames(&r, &in);
                continue;
            }
            if (got == 0) {          /* drained and exited */
                timed_out = 0;
                break;
            }
            if (errno != EINTR)
                break;
        }
        int st;
        if (waitpid(pid, &st, WNOHANG) == pid) {
            char chunk[65536];
            ssize_t got;
            while ((got = read(b[0], chunk, sizeof(chunk))) > 0)
                buf_put(&in, chunk, (size_t)got);
            drain_frames(&r, &in);
            pid = -1;
            timed_out = 0;
            break;
        }
    }
    close(a[1]);
    close(b[0]);
    if (pid > 0) {
        kill(pid, SIGTERM);
        waitpid(pid, NULL, 0);
    }
    free(in.p);
    fflush(stdout);
    fprintf(stderr, "rows: %ld\n", r.rows);
    if (timed_out) {
        fprintf(stderr, "error: replay did not finish within %.0f s\n", timeout);
        return 3;
    }
    if (!r.opened || r.open_code != 1) {
        /* OPENREPORT code 1 is success; the pytest harness also accepts None
         * (no report at all), which a replay that relayed rows never is. */
        if (!(r.opened == 0 && r.rows > 0)) {
            fprintf(stderr, "error: the source did not open (code=%d)\n", r.open_code);
            return 2;
        }
    }
    return (r.errors || r.desync) ? 2 : 0;
}

/* ── --canon / --selftest ───────────────────────────────────────────────────── */
static int canon_stdin(void) {
    char *line = NULL;
    size_t cap = 0;
    ssize_t n;
    int rc = 0;
    while ((n = getline(&line, &cap, stdin)) >= 0) {
        while (n > 0 && (line[n - 1] == '\n' || line[n - 1] == '\r'))
            n--;
        if (n == 0)
            continue;
        buf_t out = {0};
        if (canon_json(line, (size_t)n, &out) != 0) {
            fprintf(stderr, "error: not JSON: %.*s\n", (int)n, line);
            rc = 2;
        } else {
            fwrite(out.p, 1, out.n, stdout);
            fputc('\n', stdout);
        }
        free(out.p);
    }
    free(line);
    return rc;
}

static int g_fail;

static void expect_canon(const char *name, const char *in, const char *want) {
    buf_t out = {0};
    int bad = canon_json(in, strlen(in), &out);
    if (want == NULL) {
        if (!bad) {
            printf("  FAIL %s: accepted invalid JSON as %s\n", name, out.p);
            g_fail++;
        } else {
            printf("  ok   %s (rejected)\n", name);
        }
    } else if (bad || strcmp(out.p, want) != 0) {
        printf("  FAIL %s:\n    got:  %s\n    want: %s\n", name, bad ? "(rejected)" : out.p, want);
        g_fail++;
    } else {
        printf("  ok   %s\n", name);
    }
    free(out.p);
}

static void expect_same(const char *name, const char *a, const char *b) {
    buf_t x = {0}, y = {0};
    canon_json(a, strlen(a), &x);
    canon_json(b, strlen(b), &y);
    if (x.p == NULL || y.p == NULL || strcmp(x.p, y.p) != 0) {
        printf("  FAIL %s:\n    a: %s\n    b: %s\n", name, x.p ? x.p : "?", y.p ? y.p : "?");
        g_fail++;
    } else {
        printf("  ok   %s\n", name);
    }
    free(x.p);
    free(y.p);
}

static void expect_differ(const char *name, const char *a, const char *b) {
    buf_t x = {0}, y = {0};
    canon_json(a, strlen(a), &x);
    canon_json(b, strlen(b), &y);
    if (x.p && y.p && strcmp(x.p, y.p) == 0) {
        printf("  FAIL %s: both canonicalize to %s\n", name, x.p);
        g_fail++;
    } else {
        printf("  ok   %s\n", name);
    }
    free(x.p);
    free(y.p);
}

static int selftest(void) {
    printf("celldiag_replay_ndjson canonical-form selftest\n");
    expect_canon("keys sorted", "{\"b\":1,\"a\":2}", "{\"a\":2,\"b\":1}");
    expect_canon("prov.captured_at dropped",
                 "{\"prov\":{\"captured_at\":1700000000.5,\"src\":\"diag\"},\"pci\":1}",
                 "{\"pci\":1,\"prov\":{\"src\":\"diag\"}}");
    expect_canon("captured_at kept outside prov", "{\"captured_at\":1}", "{\"captured_at\":1}");
    expect_canon("float keeps .0", "{\"x\":2300.0}", "{\"x\":2300.0}");
    expect_canon("shortest round trip", "{\"x\":2300.50000000000000}", "{\"x\":2300.5}");
    expect_canon("fixed notation below 1e17", "{\"x\":7.678363431711752e+16}",
                 "{\"x\":76783634317117520.0}");
    expect_canon("small fixed", "{\"x\":1.5e-3}", "{\"x\":0.0015}");
    expect_canon("exponent outside the fixed range", "{\"x\":1e20}", "{\"x\":1e+20}");
    expect_canon("nested arrays + objects",
                 "{\"beams\":[{\"z\":1,\"ssb_index\":2}],\"ok\":true,\"n\":null}",
                 "{\"beams\":[{\"ssb_index\":2,\"z\":1}],\"n\":null,\"ok\":true}");
    expect_canon("string escapes",
                 "{\"s\":\"a\\\"b\\\\c\\u0001\\u00e9\\/\"}",
                 "{\"s\":\"a\\\"b\\\\c\\u0001\xc3\xa9/\"}");
    /* The case that forced a canonical form (see the header). */
    expect_same("float repr == exact integer (one double)",
                "{\"log_tick\":7.678363431711752e+16}",
                "{\"log_tick\":76783634317117525.0}");
    expect_same("whitespace is not content", "{ \"a\" : [1, 2] }", "{\"a\":[1,2]}");
    expect_differ("int and float stay distinct", "{\"x\":2300}", "{\"x\":2300.0}");
    expect_differ("a missing key is a difference",
                  "{\"rsrp\":-104.19,\"pci\":236}", "{\"pci\":236}");
    expect_differ("adjacent doubles stay distinct", "{\"x\":1000.0}", "{\"x\":1000.0000000000001}");
    expect_canon("trailing garbage rejected", "{\"a\":1} x", NULL);
    expect_canon("truncated rejected", "{\"a\":", NULL);
    if (g_fail) {
        printf("FAIL: %d canonical-form check(s)\n", g_fail);
        return 1;
    }
    printf("PASS: all celldiag_replay_ndjson canonical-form checks\n");
    return 0;
}

static int usage(void) {
    fprintf(stderr,
            "usage: celldiag_replay_ndjson [--timeout S] <kismet_cap_cell_diag> <definition>\n"
            "       celldiag_replay_ndjson --canon     (JSON lines on stdin -> canonical)\n"
            "       celldiag_replay_ndjson --selftest\n");
    return 64;
}

int main(int argc, char **argv) {
    double timeout = 600.0;
    int i = 1;
    if (argc == 2 && strcmp(argv[1], "--selftest") == 0)
        return selftest();
    if (argc == 2 && strcmp(argv[1], "--canon") == 0)
        return canon_stdin();
    if (i + 1 < argc && strcmp(argv[i], "--timeout") == 0) {
        timeout = atof(argv[i + 1]);
        i += 2;
    }
    if (argc - i != 2 || timeout <= 0)
        return usage();
    return run_replay(argv[i], argv[i + 1], timeout);
}
