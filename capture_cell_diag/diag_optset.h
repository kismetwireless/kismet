/* diag_optset.h - runtime source-option parsing for the celldiag source.
 *
 * Kismet has exactly ONE generic runtime setter for a datasource:
 * `POST /datasource/by-uuid/:uuid/set_channel`, which arrives here as the
 * CONFIGURE frame's channel string. So every runtime knob celldiag wants has to
 * multiplex through one opaque string, in the same `key=value` spelling the
 * source definition uses at open time:
 *
 *     rawlog=/captures/run.hdlc     start (or redirect) the raw DIAG tee
 *     rawlog=off                    stop the tee
 *
 * The classification is the point, not the parse. Three outcomes must stay
 * distinguishable, because an operator's next action differs for each:
 *
 *   - UNKNOWN key      -> you typed something this source has never heard of
 *   - OPEN_TIME_ONLY   -> a real celldiag option, just not settable while
 *                         running; close and reopen the source to change it
 *   - BAD_VALUE        -> right key, wrong value
 *
 * Collapsing OPEN_TIME_ONLY into UNKNOWN would send an operator hunting for a
 * typo in a correctly-spelled option, and collapsing it into OK would be worse:
 * a knob that reports success and changes nothing (for example, an `f3=all`
 * that is accepted on a replay source and silently does nothing).
 *
 * This module deliberately knows NOTHING about the f3/mask preset tables.
 * `F3_PRESETS` and the `mask=` table live in capture_cell_diag.c and are the
 * single source of truth for which *values* are legal; duplicating them here
 * would create two lists that drift apart. What this
 * module owns is the KEY vocabulary and the syntax. The caller validates the
 * value with the same table the open-time parse uses -- see
 * `diag_optset_set_value_error()` for how a caller reports that back.
 *
 * Pure libc, no Kismet dependency, so it is unit-tested standalone in
 * test_diag_optset.c (`make check` in this directory).
 */
#ifndef DIAG_OPTSET_H
#define DIAG_OPTSET_H

#include <stddef.h>

/* Longest value we will carry. A rawlog= spec is a path with %-tokens; PATH_MAX
 * plus room for the tokens, rounded. A longer one is a named error rather than
 * a truncation -- silently shortening a capture path is how you write a file
 * nobody can find. */
#define DIAG_OPTSET_VALUE_MAX 1024
#define DIAG_OPTSET_ERR_MAX   256

typedef enum {
    DIAG_OPTSET_OK = 0,          /* recognised, settable at runtime */
    DIAG_OPTSET_BAD_SYNTAX,      /* not a single key=value pair */
    DIAG_OPTSET_UNKNOWN_KEY,     /* no such celldiag option, at any time */
    DIAG_OPTSET_BAD_VALUE,       /* right key, value rejected */
    DIAG_OPTSET_OPEN_TIME_ONLY,  /* real option; not settable while running */
} diag_optset_status_t;

typedef enum {
    DIAG_OPTSET_KEY_NONE = 0,
    DIAG_OPTSET_KEY_RAWLOG,
    DIAG_OPTSET_KEY_MASK,
    DIAG_OPTSET_KEY_F3,
    DIAG_OPTSET_KEY_GSMTAP,
} diag_optset_key_t;

typedef struct {
    diag_optset_status_t status;
    diag_optset_key_t    key;
    char key_str[64];                       /* the key as spelled, for messages */
    char value[DIAG_OPTSET_VALUE_MAX];      /* the value as spelled */
    char err[DIAG_OPTSET_ERR_MAX];          /* operator-facing; empty iff OK */
    /* rawlog only: the value asked for the tee to STOP. Kept as a parsed fact
     * rather than re-derived by the caller, so "off" and "none" cannot come to
     * mean different things in two places. */
    int  rawlog_disable;
} diag_optset_t;

/* Parse one runtime knob string. Never fails: every outcome is a status plus a
 * populated `err` an operator can act on. `out` is fully initialised even on
 * the error paths, so a caller may report `key_str`/`value` unconditionally. */
void diag_optset_parse(const char *spec, diag_optset_t *out);

/* The accepted-key vocabulary, for help text and error messages. One string, so
 * a key added to the table below cannot go unmentioned in the errors. */
const char *diag_optset_runtime_keys(void);
const char *diag_optset_known_keys(void);

/* Fill `out->err` for a value the CALLER's table rejected, in the same voice as
 * the errors this module produces itself. Sets status to DIAG_OPTSET_BAD_VALUE.
 * `accepted` is the caller's own spelling list (e.g. F3_PRESET_NAMES) so the
 * message names the real accepted set rather than one this file guessed at. */
void diag_optset_set_value_error(diag_optset_t *out, const char *accepted);

/* ---- gsmtap= (open-time) -------------------------------------------------
 * The live GSMTAP destination, HOST:PORT. Validated here, at open, so a typo is
 * the open's own error rather than a sink that silently sends nowhere.
 *
 *   off | none            -> 0, sink off (the default when gsmtap= is absent)
 *   on  | true            -> 1, "127.0.0.1:4729" (Wireshark's GSMTAP port)
 *   <ipv4>[:<port>]       -> 1, port defaults to 4729
 *   localhost[:<port>]    -> 1, as 127.0.0.1
 *
 * IPv4 literals only (plus localhost), deliberately: the sink is an AF_INET
 * socket, and a hostname would put a DNS lookup -- and a way to fail --
 * between a correct definition and a working source. Returns -1 with `err`
 * filled for anything else; `out` ("a.b.c.d:port") is written only on 1. */
#define DIAG_GSMTAP_DEFAULT_PORT 4729
#define DIAG_GSMTAP_DEST_MAX     32   /* "255.255.255.255:65535" + NUL, rounded */
int diag_optset_gsmtap_dest(const char *value, char *out, size_t outsz,
                            char *err, size_t errsz);

#endif /* DIAG_OPTSET_H */
