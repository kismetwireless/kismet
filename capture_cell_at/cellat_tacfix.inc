/* cellat_tacfix.inc — CSURVC survey TAC=0 substitution.
 *
 * A CSURVC survey observation can report "tac":0 for a cell that IS the serving
 * cell (the survey line omits the TAC the serving-cell query knows). When such
 * an observation's cell_id matches the cached serving cell, substitute the
 * cached serving TAC so the observation is not emitted with a bogus TAC of 0.
 *
 * The replacement must skip the entire 7-char `"tac":0` token (`tac_p + 7`).
 * Skipping only 5 lands on the ':' and leaves ":0" behind, producing invalid
 * JSON (`"tac":<n>:0`). Kept in its own .inc so it is unit-testable
 * (test_cellat_tacfix.c) the same way the .inc parsers are.
 */
#ifndef CELLAT_TACFIX_INC
#define CELLAT_TACFIX_INC

#include <string.h>
#include <stdio.h>

/* Substitute cached_tac for a "tac":0 whose observation matches cached_cell_id.
 * `obs` is a serialized observation JSON string, modified in place, bounded by
 * obssz. Returns 1 if a substitution was made, 0 otherwise (no "tac":0, or the
 * cell_id did not match). */
static int cellat_apply_survey_tac(char *obs, size_t obssz,
                                   unsigned long cached_cell_id,
                                   unsigned long cached_tac) {
    /* "tac":0 only ever appears followed by ',' (more fields) or '}' (last). */
    char *tac_p = strstr(obs, "\"tac\":0,");
    if (!tac_p)
        tac_p = strstr(obs, "\"tac\":0}");
    if (!tac_p)
        return 0;

    /* The whole cell_id value, so 12 does not match 123 */
    char cid_needle[32];
    int cid_len = snprintf(cid_needle, sizeof(cid_needle), "\"cell_id\":%lu", cached_cell_id);
    const char *cid_p = obs;
    for (;;) {
        cid_p = strstr(cid_p, cid_needle);
        if (cid_p == NULL)
            return 0;
        if (cid_p[cid_len] == ',' || cid_p[cid_len] == '}')
            break;
        cid_p += cid_len;
    }

    char new_tac[32];
    int new_tac_len = snprintf(new_tac, sizeof(new_tac), "\"tac\":%lu", cached_tac);

    /* Replace the ENTIRE old `"tac":0` token -- 7 chars: " t a c " : 0.
     * Done in place; an observation that would not fit is left unchanged
     * rather than truncated into invalid JSON. */
    const size_t old_len = 7;
    size_t len = strlen(obs);
    size_t prefix_len = (size_t) (tac_p - obs);
    size_t tail_len = len - prefix_len - old_len;
    if (len - old_len + (size_t) new_tac_len >= obssz)
        return 0;

    memmove(tac_p + new_tac_len, tac_p + old_len, tail_len + 1);
    memcpy(tac_p, new_tac, (size_t) new_tac_len);
    return 1;
}

#endif /* CELLAT_TACFIX_INC */
