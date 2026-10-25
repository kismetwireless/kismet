/* diag_profile.c - per-model DIAG defaults from the capture_cell_at profiles.
 * See diag_profile.h for the contract. libc-only; no Kismet, no JSON library. */

#include "diag_profile.h"

#include <fnmatch.h>
#include <glob.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Cap on a profile file we will read whole into memory. The profiles are a few
 * KB; 1 MiB is generous headroom and bounds a pathological/hostile file. */
#define PROFILE_MAX_BYTES   (1024 * 1024)

static const char *skip_ws(const char *p) {
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    return p;
}

/* Parse a JSON string starting at `p` (which must point at the opening '"').
 * Writes the unescaped value to `out` (NUL-terminated). Returns a pointer just
 * past the closing quote, or NULL on malformed input or if the value does not
 * fit in `outsz`. Handles the escape subset the profiles use. */
static const char *parse_json_string(const char *p, char *out, size_t outsz) {
    if (*p != '"')
        return NULL;
    p++;
    size_t o = 0;
    while (*p && *p != '"') {
        char c = *p;
        if (c == '\\') {
            p++;
            switch (*p) {
                case '"':  c = '"';  break;
                case '\\': c = '\\'; break;
                case '/':  c = '/';  break;
                case 'n':  c = '\n'; break;
                case 't':  c = '\t'; break;
                case 'r':  c = '\r'; break;
                case 'b':  c = '\b'; break;
                case 'f':  c = '\f'; break;
                case 'u': {
                    /* Skip a \uXXXX escape; profiles use ASCII, so we do not
                     * decode to UTF-8 - emit '?' and move on. */
                    if (p[1] && p[2] && p[3] && p[4]) {
                        c = '?';
                        p += 4;
                    } else {
                        return NULL;
                    }
                    break;
                }
                case '\0': return NULL;  /* trailing backslash */
                default:   c = *p;       break;
            }
        }
        if (o + 1 >= outsz)
            return NULL;  /* would overflow: treat as absent */
        out[o++] = c;
        p++;
    }
    if (*p != '"')
        return NULL;  /* unterminated */
    out[o] = '\0';
    return p + 1;
}

/* Walk a JSON string starting at `p` (the opening '"') WITHOUT copying it, and
 * return a pointer just past its closing quote, or NULL if it is unterminated.
 * Mirrors parse_json_string's escape handling exactly -- the two must agree on
 * where a string ends, or the tokeniser and the value reader disagree about the
 * shape of the document. */
static const char *skip_json_string(const char *p) {
    if (*p != '"')
        return NULL;
    p++;
    while (*p && *p != '"') {
        if (*p == '\\') {
            p++;
            if (*p == '\0')
                return NULL;          /* trailing backslash */
            if (*p == 'u') {
                /* \uXXXX: four hex digits must be present. */
                if (!p[1] || !p[2] || !p[3] || !p[4])
                    return NULL;
                p += 4;
            }
        }
        p++;
    }
    return (*p == '"') ? p + 1 : NULL;
}

/* Advance *pp to the next top-of-scan string token, copy it into tok, and set
 * *pp just past its closing quote. Returns 1 if a token was found, 0 at end.
 * (Scans byte-wise; only complete "..." tokens are returned, so a '"' inside an
 * already-consumed token is never re-seen.)
 *
 * An OVERSIZED token must be stepped over in full, never by advancing one
 * byte past its opening quote. Doing the latter leaves the walk in anti-phase
 * for the rest of the document -- that string's closing quote then reads as an
 * opening quote, so from there on keys are parsed as values and values as keys,
 * and every subsequent lookup returns a confident, silent "absent". A profile
 * with a long string before its "diag" key (simcom_sim8202.json) then looks
 * like a profile with no "diag" object at all. Pinned by
 * test_oversized_token_does_not_desync_the_walk.
 *
 * An UNTERMINATED string is a different case and must end the walk: there is no
 * closing quote to resynchronise on, so any continuation is a guess. */
static int next_string_token(const char **pp, char *tok, size_t toksz) {
    const char *p = *pp;
    while (*p) {
        if (*p == '"') {
            const char *end = parse_json_string(p, tok, toksz);
            if (end == NULL) {
                /* Well-formed but too long for `tok`: skip the WHOLE string so
                 * the walk keeps its phase, and keep scanning. Malformed: stop. */
                const char *past = skip_json_string(p);
                if (past == NULL)
                    break;
                p = past;
                continue;
            }
            *pp = end;
            return 1;
        }
        p++;
    }
    *pp = p;
    return 0;
}

int diag_profile_json_string(const char *json, const char *key,
                             char *out, size_t outsz) {
    if (!json || !key)
        return 0;
    char tok[512];
    const char *p = json;
    while (next_string_token(&p, tok, sizeof(tok))) {
        if (strcmp(tok, key) != 0)
            continue;
        const char *q = skip_ws(p);
        if (*q != ':')
            continue;  /* this "key" occurrence is a value, not a key */
        q = skip_ws(q + 1);
        if (*q != '"')
            continue;  /* value is not a string (null / object / number) */
        if (parse_json_string(q, out, outsz) != NULL)
            return 1;
        /* value present but too long to fit: treat as absent */
        return 0;
    }
    return 0;
}

const char *diag_profile_json_object(const char *json, const char *key,
                                     size_t *len) {
    if (!json || !key)
        return NULL;
    char tok[512];
    const char *p = json;
    while (next_string_token(&p, tok, sizeof(tok))) {
        if (strcmp(tok, key) != 0)
            continue;
        const char *q = skip_ws(p);
        if (*q != ':')
            continue;
        q = skip_ws(q + 1);
        if (*q != '{')
            continue;  /* value is not an object */
        /* Brace-match, respecting string contents. */
        const char *start = q;
        int depth = 0;
        int in_str = 0;
        for (const char *r = q; *r; r++) {
            if (in_str) {
                if (*r == '\\' && r[1])
                    r++;             /* skip escaped char */
                else if (*r == '"')
                    in_str = 0;
                continue;
            }
            if (*r == '"')
                in_str = 1;
            else if (*r == '{')
                depth++;
            else if (*r == '}') {
                depth--;
                if (depth == 0) {
                    if (len)
                        *len = (size_t)(r - start) + 1;
                    return start;
                }
            }
        }
        return NULL;  /* unbalanced */
    }
    return NULL;
}

int diag_profile_glob_match(const char *pattern, const char *str) {
    if (!pattern || !str)
        return 0;
    return fnmatch(pattern, str, 0) == 0;
}

/* Read a whole file into a NUL-terminated malloc'd buffer, or NULL on error /
 * over-size. Caller frees. */
static char *read_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f)
        return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0 || sz > PROFILE_MAX_BYTES) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t got = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    buf[got] = '\0';
    return buf;
}

int diag_profile_json_int(const char *json, const char *key, int *out) {
    if (!json || !key || !out)
        return 0;
    char tok[512];
    const char *p = json;
    while (next_string_token(&p, tok, sizeof(tok))) {
        if (strcmp(tok, key) != 0)
            continue;
        const char *q = skip_ws(p);
        if (*q != ':')
            continue;  /* this "key" occurrence is a value, not a key */
        q = skip_ws(q + 1);
        /* Accept an optionally-signed base-10 integer only. A '.' / 'e' / 'E'
         * (float), a quote (string), '{'/'[' (object/array) or a letter (bool/
         * null) all fail as "not an integer". */
        const char *num = q;
        if (*num == '-' || *num == '+')
            num++;
        if (*num < '0' || *num > '9')
            continue;  /* not a number */
        char *endp = NULL;
        long v = strtol(q, &endp, 10);
        if (endp == q)
            continue;
        /* Reject a trailing fractional/exponent part: it's a float, not an int. */
        if (*endp == '.' || *endp == 'e' || *endp == 'E')
            continue;
        if (v < -2147483647L - 1 || v > 2147483647L)
            continue;  /* out of int range */
        *out = (int)v;
        return 1;
    }
    return 0;
}

/* Resolve the matched profile's "diag" object body into a fresh malloc'd,
 * NUL-terminated buffer (caller frees), or NULL if no profile's firmware_match
 * matches `firmware` or the matched profile has no "diag" object. Shared by
 * diag_profile_lookup and diag_profile_port_detect so the glob + firmware_match
 * + diag-scoping logic lives in one place. */
static char *matched_diag_body(const char *profiles_dir, const char *firmware) {
    if (!profiles_dir || !*profiles_dir || !firmware || !*firmware)
        return NULL;

    char pattern[1024];
    int n = snprintf(pattern, sizeof(pattern), "%s/*.json", profiles_dir);
    if (n < 0 || (size_t)n >= sizeof(pattern))
        return NULL;

    glob_t gl;
    memset(&gl, 0, sizeof(gl));
    if (glob(pattern, 0, NULL, &gl) != 0) {
        globfree(&gl);
        return NULL;
    }

    char *diagbuf = NULL;
    for (size_t i = 0; i < gl.gl_pathc && !diagbuf; i++) {
        char *json = read_file(gl.gl_pathv[i]);
        if (!json)
            continue;

        char fwmatch[256];
        if (diag_profile_json_string(json, "firmware_match", fwmatch,
                                     sizeof(fwmatch)) &&
            diag_profile_glob_match(fwmatch, firmware)) {
            size_t diaglen = 0;
            const char *diag = diag_profile_json_object(json, "diag", &diaglen);
            if (diag) {
                /* Scope everything to the "diag" object body so a same-named key
                 * elsewhere in the profile can't leak in. */
                diagbuf = malloc(diaglen + 1);
                if (diagbuf) {
                    memcpy(diagbuf, diag, diaglen);
                    diagbuf[diaglen] = '\0';
                }
            }
        }
        free(json);
    }

    globfree(&gl);
    return diagbuf;
}

int diag_profile_lookup(const char *profiles_dir, const char *firmware,
                        const char *key, char *out, size_t outsz) {
    if (!key)
        return 0;
    char *diagbuf = matched_diag_body(profiles_dir, firmware);
    if (!diagbuf)
        return 0;
    int found = diag_profile_json_string(diagbuf, key, out, outsz);
    free(diagbuf);
    return found;
}

int diag_profile_port_detect(const char *profiles_dir, const char *firmware,
                             struct diag_port_detect *out) {
    if (!out)
        return 0;
    memset(out, 0, sizeof(*out));

    char *diagbuf = matched_diag_body(profiles_dir, firmware);
    if (!diagbuf)
        return 0;

    size_t pdlen = 0;
    const char *pd = diag_profile_json_object(diagbuf, "port_detect", &pdlen);
    if (!pd) {
        free(diagbuf);
        return 0;
    }

    /* Copy the port_detect object body out so each field lookup is scoped to it
     * (a same-named key in a sibling diag field can't leak in). */
    char *pdbuf = malloc(pdlen + 1);
    if (!pdbuf) {
        free(diagbuf);
        return 0;
    }
    memcpy(pdbuf, pd, pdlen);
    pdbuf[pdlen] = '\0';

    diag_profile_json_string(pdbuf, "transport", out->transport,
                             sizeof(out->transport));
    diag_profile_json_string(pdbuf, "match", out->match, sizeof(out->match));
    if (diag_profile_json_int(pdbuf, "interface", &out->interface))
        out->has_interface = 1;
    diag_profile_json_string(pdbuf, "driver_path_glob", out->driver_path_glob,
                             sizeof(out->driver_path_glob));

    free(pdbuf);
    free(diagbuf);
    return 1;
}
