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

    Selftest for the CSURVC survey TAC=0 substitution. The substitution must
    leave VALID JSON, not "tac":<n>:0.

    The anchor case is real: a `+5` advance (instead of `+7`) leaves the ":0"
    behind and produces survey rows like `"tac":28270:0`,
    which no strict json.loads accepts (kismetdb_to_cellndjson flags them).
    The `no stray ':0'` check below fails on that form.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "cellat_tacfix.inc"

static int failures = 0;

static void check(int cond, const char *name) {
    printf(cond ? "  ok   %s\n" : "  FAIL %s\n", name);
    if (!cond)
        failures++;
}

int main(void) {
    /* 1. regression: comma-terminated tac, cell_id matches -> substitute,
     *    result must be VALID JSON with no stray ":0". */
    char obs[JSON_BUF_MAX];
    strcpy(obs, "{\"cell_id\":123,\"tac\":0,\"earfcn\":800}");
    int r = cellat_apply_survey_tac(obs, sizeof(obs), 123, 28270);
    check(r == 1, "substitution applied when cell_id matches");
    check(strstr(obs, "\"tac\":28270,") != NULL, "tac replaced with cached value");
    check(strstr(obs, ":0") == NULL, "no stray ':0' left");
    check(strcmp(obs, "{\"cell_id\":123,\"tac\":28270,\"earfcn\":800}") == 0,
          "exact substituted string");

    /* 2. brace-terminated tac (last field). */
    char obs2[JSON_BUF_MAX];
    strcpy(obs2, "{\"cell_id\":7,\"tac\":0}");
    int r2 = cellat_apply_survey_tac(obs2, sizeof(obs2), 7, 42);
    check(r2 == 1, "brace-terminated: applied");
    check(strcmp(obs2, "{\"cell_id\":7,\"tac\":42}") == 0,
          "brace-terminated tac fixed, no ':0'");

    /* 3. no substitution when the cell_id does not match the cached serving. */
    char obs3[JSON_BUF_MAX];
    strcpy(obs3, "{\"cell_id\":999,\"tac\":0,\"earfcn\":1}");
    int r3 = cellat_apply_survey_tac(obs3, sizeof(obs3), 123, 28270);
    check(r3 == 0, "no substitution when cell_id mismatches");
    check(strstr(obs3, "\"tac\":0,") != NULL, "mismatched obs left untouched");

    /* 4. no "tac":0 present -> no-op, obs unchanged. */
    char obs4[JSON_BUF_MAX];
    strcpy(obs4, "{\"cell_id\":123,\"tac\":555}");
    int r4 = cellat_apply_survey_tac(obs4, sizeof(obs4), 123, 28270);
    check(r4 == 0, "no-op when there is no tac:0");
    check(strcmp(obs4, "{\"cell_id\":123,\"tac\":555}") == 0, "non-zero tac untouched");

    /* 5. a large cached_tac still yields valid JSON (no ':0' regardless). */
    char obs5[JSON_BUF_MAX];
    strcpy(obs5, "{\"cell_id\":5,\"tac\":0,\"pci\":10}");
    cellat_apply_survey_tac(obs5, sizeof(obs5), 5, 4294967295UL);
    check(strcmp(obs5, "{\"cell_id\":5,\"tac\":4294967295,\"pci\":10}") == 0,
          "large tac substituted cleanly");

    if (failures) {
        printf("FAILED %d check(s)\n", failures);
        return 1;
    }
    printf("ALL PASS\n");
    return 0;
}
