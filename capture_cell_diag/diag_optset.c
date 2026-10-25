/* diag_optset.c - runtime source-option parsing for the celldiag source.
 * See diag_optset.h for the contract and the reasoning.
 */

#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "diag_optset.h"

/* One table. `runtime` is what separates "not settable while running" from
 * "not an option at all", and both messages are generated from this table, so a
 * key cannot be added to the vocabulary without appearing in the errors.
 *
 * Why mask= and f3= are runtime=0: applying either means re-issuing a LOG_CONFIG / SET_ALL_RT_MASKS handshake --
 * a request/response on the very DIAG fd `capture_thread` is blocked reading,
 * driven from the framework's command thread. That is a reader-serialisation
 * design, not plumbing, and Kismet already ships the alternative: close_source
 * + open_source with the new definition. Declining it here is deliberate, and
 * the operator gets told which door to use instead of a success that changed
 * nothing. */
static const struct {
    const char       *name;
    diag_optset_key_t key;
    int               runtime;
    const char       *decline;   /* used iff !runtime */
} OPTSET_KEYS[] = {
    { "rawlog", DIAG_OPTSET_KEY_RAWLOG, 1, NULL },
    { "mask",   DIAG_OPTSET_KEY_MASK,   0,
      "the LOG mask is armed on the modem at open time; changing it means "
      "re-issuing the LOG_CONFIG handshake on the DIAG fd the capture thread "
      "is reading. Close and reopen the source with the new mask=" },
    { "f3",     DIAG_OPTSET_KEY_F3,     0,
      "the F3 severity floor is armed on the modem at open time; changing it "
      "means re-issuing SET_ALL_RT_MASKS on the DIAG fd the capture thread is "
      "reading. Close and reopen the source with the new f3=" },
    { "gsmtap", DIAG_OPTSET_KEY_GSMTAP, 0,
      "the GSMTAP sink is opened with the decoder at open time. Close and "
      "reopen the source with the new gsmtap=" },
};

#define OPTSET_KEYS_N (sizeof(OPTSET_KEYS) / sizeof(OPTSET_KEYS[0]))

const char *diag_optset_runtime_keys(void) { return "rawlog"; }
const char *diag_optset_known_keys(void)   { return "rawlog|mask|f3|gsmtap"; }

static void reset(diag_optset_t *out) {
    memset(out, 0, sizeof(*out));
    out->status = DIAG_OPTSET_BAD_SYNTAX;
    out->key    = DIAG_OPTSET_KEY_NONE;
}

/* Trim ASCII whitespace in place. A knob arriving from a web form picks up a
 * trailing newline or a leading space more often than not, and "rawlog=off\n"
 * failing as an unknown value would be a lie about what the operator typed. */
static void trim(char *s) {
    size_t len, i = 0;
    while (s[i] == ' ' || s[i] == '\t' || s[i] == '\r' || s[i] == '\n')
        i++;
    if (i)
        memmove(s, s + i, strlen(s + i) + 1);
    len = strlen(s);
    while (len && (s[len - 1] == ' ' || s[len - 1] == '\t' ||
                   s[len - 1] == '\r' || s[len - 1] == '\n'))
        s[--len] = '\0';
}

/* Does `value` contain a second `<known-key>=` after a delimiter? See the call
 * site for why this is not simply "contains ',' or '='". */
static int looks_like_a_second_setting(const char *value) {
    size_t i, k;
    for (i = 0; value[i] != '\0'; i++) {
        if (value[i] != ',' && value[i] != ' ' && value[i] != '\t')
            continue;
        for (k = 0; k < OPTSET_KEYS_N; k++) {
            const char *name = OPTSET_KEYS[k].name;
            size_t nlen = strlen(name);
            if (strncmp(value + i + 1, name, nlen) == 0 &&
                value[i + 1 + nlen] == '=')
                return 1;
        }
    }
    return 0;
}

void diag_optset_parse(const char *spec, diag_optset_t *out) {
    const char *eq;
    size_t klen, vlen, i;

    if (out == NULL)
        return;
    reset(out);

    if (spec == NULL || spec[0] == '\0') {
        snprintf(out->err, DIAG_OPTSET_ERR_MAX,
                 "empty runtime option; expected <key>=<value> (%s)",
                 diag_optset_runtime_keys());
        return;
    }

    eq = strchr(spec, '=');
    if (eq == NULL || eq == spec) {
        snprintf(out->err, DIAG_OPTSET_ERR_MAX,
                 "'%s' is not <key>=<value> (%s)", spec,
                 diag_optset_runtime_keys());
        return;
    }

    klen = (size_t)(eq - spec);
    if (klen >= sizeof(out->key_str)) {
        snprintf(out->err, DIAG_OPTSET_ERR_MAX,
                 "option key is %zu bytes, longer than the %zu-byte maximum",
                 klen, sizeof(out->key_str) - 1);
        return;
    }
    memcpy(out->key_str, spec, klen);
    out->key_str[klen] = '\0';

    vlen = strlen(eq + 1);
    if (vlen >= DIAG_OPTSET_VALUE_MAX) {
        out->status = DIAG_OPTSET_BAD_VALUE;
        snprintf(out->err, DIAG_OPTSET_ERR_MAX,
                 "%s= value is %zu bytes, longer than the %d-byte maximum "
                 "(not truncated: a shortened capture path writes a file "
                 "nobody can find)",
                 out->key_str, vlen, DIAG_OPTSET_VALUE_MAX - 1);
        return;
    }
    memcpy(out->value, eq + 1, vlen + 1);
    trim(out->value);
    trim(out->key_str);

    /* Exactly ONE pair, deliberately. The framework hands us a single opaque
     * string and reports a single success/failure for it, so a multi-pair form
     * would have no way to say "the first applied and the second did not" -- a
     * partial application reported as a whole one.
     *
     * But the test for it must be precise, not "the value contains ',' or ' '
     * or '='". Every one of those is legal in a file path, and `rawlog=` takes a
     * path: banning them would refuse `/captures/my run.hdlc` and `/a=b.hdlc`,
     * which are files a person can actually create. So the rule is a delimiter
     * followed by a KNOWN KEY followed by '=' -- the shape of a second setting,
     * not the characters a second setting happens to use. The check runs after
     * trim(), so "rawlog= off" is one pair, not two. */
    if (looks_like_a_second_setting(out->value)) {
        snprintf(out->err, DIAG_OPTSET_ERR_MAX,
                 "'%s' carries more than one setting; the runtime setter takes "
                 "exactly one <key>=<value> per request (there is no way to "
                 "report a half-applied pair)", spec);
        return;
    }

    for (i = 0; i < OPTSET_KEYS_N; i++) {
        if (strcmp(out->key_str, OPTSET_KEYS[i].name) != 0)
            continue;

        out->key = OPTSET_KEYS[i].key;

        if (!OPTSET_KEYS[i].runtime) {
            out->status = DIAG_OPTSET_OPEN_TIME_ONLY;
            snprintf(out->err, DIAG_OPTSET_ERR_MAX,
                     "'%s' is not settable while the source is running: %s",
                     out->key_str, OPTSET_KEYS[i].decline);
            return;
        }

        if (out->value[0] == '\0') {
            out->status = DIAG_OPTSET_BAD_VALUE;
            snprintf(out->err, DIAG_OPTSET_ERR_MAX,
                     "%s= needs a value; use '%s=off' to stop the tee",
                     out->key_str, out->key_str);
            return;
        }

        if (out->key == DIAG_OPTSET_KEY_RAWLOG) {
            /* The same two spellings f3= uses for "not armed", so an operator
             * does not have to remember which option spells it which way. */
            out->rawlog_disable = (strcmp(out->value, "off") == 0 ||
                                   strcmp(out->value, "none") == 0);
        }

        out->status = DIAG_OPTSET_OK;
        out->err[0] = '\0';
        return;
    }

    out->status = DIAG_OPTSET_UNKNOWN_KEY;
    snprintf(out->err, DIAG_OPTSET_ERR_MAX,
             "no celldiag option named '%s' (runtime-settable: %s; recognised "
             "but open-time only: mask, f3)",
             out->key_str, diag_optset_runtime_keys());
}

void diag_optset_set_value_error(diag_optset_t *out, const char *accepted) {
    if (out == NULL)
        return;
    out->status = DIAG_OPTSET_BAD_VALUE;
    snprintf(out->err, DIAG_OPTSET_ERR_MAX,
             "%s='%s' is not a valid value (expected %s)",
             out->key_str[0] ? out->key_str : "option", out->value,
             accepted ? accepted : "see the source option help");
}

int diag_optset_gsmtap_dest(const char *value, char *out, size_t outsz,
                            char *err, size_t errsz) {
    char host[64];
    const char *colon;
    long port = DIAG_GSMTAP_DEFAULT_PORT;
    struct in_addr a;

    if (err && errsz)
        err[0] = '\0';
    if (value == NULL || value[0] == '\0') {
        snprintf(err, errsz, "empty gsmtap= value; expected off, on, or "
                 "<ipv4>[:<port>]");
        return -1;
    }
    if (strcmp(value, "off") == 0 || strcmp(value, "none") == 0)
        return 0;
    if (strcmp(value, "on") == 0 || strcmp(value, "true") == 0)
        value = "127.0.0.1";

    colon = strchr(value, ':');
    if (colon != NULL && strchr(colon + 1, ':') != NULL) {
        snprintf(err, errsz, "gsmtap=%s: IPv6 is not supported (the GSMTAP "
                 "sink is IPv4); give an IPv4 address", value);
        return -1;
    }
    size_t hlen = colon ? (size_t)(colon - value) : strlen(value);
    if (hlen == 0 || hlen >= sizeof(host)) {
        snprintf(err, errsz, "gsmtap=%s: no host; expected <ipv4>[:<port>]",
                 value);
        return -1;
    }
    memcpy(host, value, hlen);
    host[hlen] = '\0';

    if (colon != NULL) {
        const char *ps = colon + 1;
        char *end = NULL;
        if (*ps < '0' || *ps > '9') {
            snprintf(err, errsz, "gsmtap=%s: port is not a number", value);
            return -1;
        }
        port = strtol(ps, &end, 10);
        if (*end != '\0' || port < 1 || port > 65535) {
            snprintf(err, errsz, "gsmtap=%s: port must be 1..65535", value);
            return -1;
        }
    }

    if (strcmp(host, "localhost") == 0)
        strcpy(host, "127.0.0.1");
    if (inet_pton(AF_INET, host, &a) != 1) {
        snprintf(err, errsz, "gsmtap=%s: '%s' is not an IPv4 address (a "
                 "hostname is refused so no DNS lookup sits between this "
                 "definition and a working sink; localhost is accepted)",
                 value, host);
        return -1;
    }
    int n = snprintf(out, outsz, "%s:%ld", host, port);
    if (n < 0 || (size_t)n >= outsz) {
        snprintf(err, errsz, "gsmtap=%s: destination does not fit", value);
        return -1;
    }
    return 1;
}
