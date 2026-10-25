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

#ifndef JSON_BUF_MAX
#define JSON_BUF_MAX 4096
#endif

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

    char cid_needle[32];
    snprintf(cid_needle, sizeof(cid_needle), "\"cell_id\":%lu", cached_cell_id);
    if (!strstr(obs, cid_needle))
        return 0;

    char new_tac[32];
    int new_tac_len = snprintf(new_tac, sizeof(new_tac), "\"tac\":%lu", cached_tac);

    char fixed[JSON_BUF_MAX];
    size_t prefix_len = (size_t) (tac_p - obs);
    if (prefix_len + (size_t) new_tac_len >= sizeof(fixed))
        return 0;

    memcpy(fixed, obs, prefix_len);
    /* Skip the ENTIRE old `"tac":0` token — 7 chars: " t a c " : 0.
     * `tac_p + 5` would land on the ':' and leave ":0" behind. */
    char *old_end = tac_p + 7;
    memcpy(fixed + prefix_len, new_tac, new_tac_len);
    strcpy(fixed + prefix_len + new_tac_len, old_end);

    strncpy(obs, fixed, obssz - 1);
    obs[obssz - 1] = '\0';
    return 1;
}

#endif /* CELLAT_TACFIX_INC */
