/*
 * test_cellat_std3gpp.c -- decode-core tests for cellat_std3gpp.inc
 * (generic 3GPP serving-cell commands + AT+COPS=? PLMN scan).
 *
 * Every fixture below is a VERBATIM transcript captured from three modems,
 * chosen for complementary
 * registration state:
 *   - EG25-G   : no SIM              (searching / deregistered edges)
 *   - LM960A18 : SIM, unregistered   (all-unknown signal; name-less scan ops)
 *   - RM520N-GL: SIM, 5G-SA, registered (the populated TAC/CI/AcT case)
 *
 * The one exception is CESQ_POPULATED, which is CONSTRUCTED from the TS 36.133
 * / TS 45.008 mapping tables: neither Quectel supports AT+CESQ (both ERROR) and
 * the only modem that does (the LM960) was unregistered and returned all-99/255.
 * It is labelled as constructed so no reader mistakes it for a real capture.
 *
 * Compile: includes cellat_qeng.inc (shared helpers) then cellat_std3gpp.inc,
 * exactly as the shipping binary does.
 */
#ifdef CELL_SELFTEST

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "cellat_selftest_json.h"
#include <sys/time.h>

#define JSON_BUF_MAX 4096
#define MAX_OBS 16

#include "cellat_qeng.inc"
#include "cellat_std3gpp.inc"

static int g_fails = 0;

static void check(int cond, const char *what) {
    printf(cond ? "  OK    %s\n" : "  FAIL  %s\n", what);
    if (!cond) g_fails++;
}

static void check_has(const char *json, const char *frag, const char *what) {
    if (json_has(json, frag)) {
        printf("  OK    %s\n", what);
    } else {
        printf("  FAIL  %s (expected %s)\n     in: %s\n", what, frag, json);
        g_fails++;
    }
}

static void check_lacks(const char *json, const char *frag, const char *what) {
    if (!strstr(json, frag)) {
        printf("  OK    %s\n", what);
    } else {
        printf("  FAIL  %s (unexpected %s)\n     in: %s\n", what, frag, json);
        g_fails++;
    }
}

/* NULL-safe string equality -- so a mutation that makes a mapper return NULL
 * fails a NAMED check here rather than segfaulting on strcmp() and killing the
 * run with no attribution. */
static int streq(const char *a, const char *b) {
    if (a == NULL || b == NULL) return a == b;
    return strcmp(a, b) == 0;
}

/* ------------------------- real modem fixtures ------------------------- */

/* CSQ: EG25-G no-SIM, rssi index 24 -> -113 + 2*24 = -65 dBm. */
static const char *CSQ_EG25 = "+CSQ: 24,99\r\n\r\nOK";
/* CSQ: LM960 unregistered -> rssi 99 (unknown) -> no observable. */
static const char *CSQ_UNKNOWN = "+CSQ: 99,99\r\n\r\nOK";

/* CESQ: LM960 unregistered -> every field unknown -> no observable. */
static const char *CESQ_UNKNOWN = "+CESQ: 99,99,255,255,255,255\r\n\r\nOK";
/* CESQ: CONSTRUCTED (see header). rxlev=99(unknown), ber=99, rscp=255,
 * ecno=255, rsrq=30 -> (30-40)/2 = -5 dB, rsrp=60 -> -140+60 = -80 dBm. */
static const char *CESQ_POPULATED = "+CESQ: 99,99,255,255,30,60\r\n\r\nOK";

/* Registration: unregistered edges (searching=2, not-searching=0). */
static const char *CEREG_SEARCHING   = "+CEREG: 2,2\r\n\r\nOK";
static const char *CREG_NOT_SEARCH   = "+CREG: 2,0\r\n\r\nOK";
/* C5GREG: RM520N-GL registered on 5G-SA. TAC 0x1A2B00, CI 0x1A2B4B017,
 * AcT 11 (NR connected to 5GCN). */
static const char *C5GREG_RM520N =
    "+C5GREG: 2,1,\"1A2B00\",\"1A2B4B017\",11,1,\"01\"\r\n\r\nOK";

/* COPS? : RM520N-GL, alphanumeric operator + AcT 11 (NR). */
static const char *COPS_Q_RM520N  = "+COPS: 0,0,\"Operator A\",11\r\n\r\nOK";
/* COPS? : deregistered, mode-only -> no operator. */
static const char *COPS_Q_DEREG   = "+COPS: 0\r\n\r\nOK";

/* COPS=? scans (the recorded shapes; the operators are synthetic). RM520N
 * leads with stat=2 (current). LM960 carries
 * two name-less operators (empty long/short, numeric present). */
static const char *COPS_SCAN_RM520N =
    "+COPS: (2,\"Operator A\",\"Operator A\",\"001001\",12),"
    "(1,\"Operator A\",\"Operator A\",\"001001\",7),"
    "(1,\"Operator B\",\"Operator B\",\"001002\",7),"
    "(1,\"001 010\",\"001 010\",\"001010\",7),"
    "(1,\"Operator B\",\"Operator B\",\"001002\",12),"
    "(1,\"Operator D\",\"Operator D\",\"001004\",7),"
    "(1,\"Operator C\",\"Operator C\",\"001003\",7),,(0-4),(0-2)\r\n\r\nOK";
static const char *COPS_SCAN_LM960 =
    "+COPS: (1,\"Operator A\",\"Operator A\",\"001001\",7),"
    "(1,\"Operator C\",\"Operator C\",\"001003\",7),"
    "(1,\"\",\"\",\"001010\",7),"
    "(1,\"Operator B\",\"Operator B\",\"001002\",7),"
    "(1,\"\",\"\",\"001004\",7),,(0-4),(0-2)\r\n\r\nOK";
static const char *COPS_SCAN_EG25 =
    "+COPS: (1,\"Operator B\",\"Operator B\",\"001002\",7),"
    "(1,\"Operator A\",\"Operator A\",\"001001\",7),,(0-4),(0-2)\r\n\r\nOK";

int main(void) {
    char obs[MAX_OBS][JSON_BUF_MAX];
    int n;

    printf("== stdat_act_to_rat (the cops_rat_name superset) ==\n");
    check(streq(stdat_act_to_rat(7), "LTE"),  "AcT 7 -> LTE");
    check(streq(stdat_act_to_rat(11), "NR"),  "AcT 11 -> NR (the gap cops_rat_name misses)");
    check(streq(stdat_act_to_rat(12), "NR"),  "AcT 12 -> NR");
    check(streq(stdat_act_to_rat(2), "WCDMA"), "AcT 2 -> WCDMA");
    check(streq(stdat_act_to_rat(4), "WCDMA"), "AcT 4 (HSDPA) -> WCDMA");
    check(streq(stdat_act_to_rat(0), "GSM"),  "AcT 0 -> GSM");
    check(stdat_act_to_rat(99) == NULL,       "AcT 99 -> unmodelled (NULL)");

    printf("== CSQ ==\n");
    n = parse_csq(CSQ_EG25, obs, MAX_OBS);
    check(n == 1, "CSQ 24 -> 1 record");
    if (n == 1) {
        check_has(obs[0], "\"rssi\":-65", "CSQ rssi idx 24 -> -65 dBm");
        check_has(obs[0], "\"observation_type\":\"csq\"", "CSQ observation_type");
        check_has(obs[0], "\"is_serving\":true", "CSQ is_serving");
        check_lacks(obs[0], "\"cell_id\"", "CSQ carries no cell identity");
    }
    check(parse_csq(CSQ_UNKNOWN, obs, MAX_OBS) == 0, "CSQ 99 (unknown) -> 0 records");

    printf("== CESQ ==\n");
    check(parse_cesq(CESQ_UNKNOWN, obs, MAX_OBS) == 0, "CESQ all-unknown -> 0 records");
    n = parse_cesq(CESQ_POPULATED, obs, MAX_OBS);
    check(n == 1, "CESQ populated (constructed) -> 1 record");
    if (n == 1) {
        check_has(obs[0], "\"rsrp\":-80", "CESQ rsrp idx 60 -> -80 dBm");
        check_has(obs[0], "\"rsrq\":-5", "CESQ rsrq idx 30 -> -5 dB");
        check_lacks(obs[0], "\"rssi\"", "CESQ rxlev 99 (unknown) -> no rssi");
        check_has(obs[0], "\"observation_type\":\"cesq\"", "CESQ observation_type");
    }

    printf("== registration (CREG/CEREG/C5GREG) ==\n");
    check(parse_reg(CEREG_SEARCHING, "+CEREG:", "LTE", obs, MAX_OBS) == 0,
          "CEREG searching (stat 2) -> 0 records");
    check(parse_reg(CREG_NOT_SEARCH, "+CREG:", "GSM", obs, MAX_OBS) == 0,
          "CREG not-registered (stat 0) -> 0 records");
    n = parse_reg(C5GREG_RM520N, "+C5GREG:", "NR", obs, MAX_OBS);
    check(n == 1, "C5GREG registered -> 1 record");
    if (n == 1) {
        /* TAC 0x1A2B00 = 1714944; CI computed here to avoid a hand-calc error */
        char frag[64];
        unsigned long ci = strtoul("1A2B4B017", NULL, 16);
        check_has(obs[0], "\"tac\":1714944", "C5GREG TAC hex 1A2B00 -> 1714944");
        snprintf(frag, sizeof(frag), "\"cell_id\":%lu", ci);
        check_has(obs[0], frag, "C5GREG CI hex 1A2B4B017 decoded");
        check_has(obs[0], "\"rat\":\"NR\"", "C5GREG AcT 11 -> NR");
        check_has(obs[0], "\"observation_type\":\"reg\"", "reg observation_type");
    }

    printf("== COPS? (current operator) ==\n");
    n = parse_cops_query(COPS_Q_RM520N, obs, MAX_OBS);
    check(n == 1, "COPS? with operator -> 1 record");
    if (n == 1) {
        check_has(obs[0], "\"operator_name\":\"Operator A\"", "COPS? operator name");
        check_has(obs[0], "\"rat\":\"NR\"", "COPS? AcT 11 -> NR");
    }
    check(parse_cops_query(COPS_Q_DEREG, obs, MAX_OBS) == 0,
          "COPS? mode-only (deregistered) -> 0 records");
    /* the scan form must NOT be mis-parsed by the query parser */
    check(parse_cops_query(COPS_SCAN_EG25, obs, MAX_OBS) == 0,
          "COPS? parser rejects the '(' scan form");

    printf("== COPS=? (PLMN scan) ==\n");
    n = parse_cops_scan(COPS_SCAN_RM520N, obs, MAX_OBS);
    check(n == 7, "RM520N scan -> 7 operators (trailing (0-4),(0-2) skipped)");
    if (n == 7) {
        /* op 0 is stat=2 (current) -> is_serving true; AcT 12 -> NR */
        check_has(obs[0], "\"operator_name\":\"Operator A\"", "scan op0 name");
        check_has(obs[0], "\"mcc\":\"001\"", "scan op0 mcc 001");
        check_has(obs[0], "\"mnc\":\"001\"", "scan op0 mnc 001");
        check_has(obs[0], "\"rat\":\"NR\"", "scan op0 AcT 12 -> NR");
        check_has(obs[0], "\"is_serving\":true", "scan op0 stat 2 -> is_serving");
        check_has(obs[0], "\"observation_type\":\"cops_scan\"", "scan observation_type");
        /* op 1 is stat=1 (available) -> is_serving false; AcT 7 -> LTE */
        check_has(obs[1], "\"rat\":\"LTE\"", "scan op1 AcT 7 -> LTE");
        check_has(obs[1], "\"is_serving\":false", "scan op1 stat 1 -> not serving");
        /* op 3 is "001 010" with a space in the name + numeric 001010 */
        check_has(obs[3], "\"mnc\":\"010\"", "scan op3 mnc preserves leading zero (010)");
    }

    n = parse_cops_scan(COPS_SCAN_LM960, obs, MAX_OBS);
    check(n == 5, "LM960 scan -> 5 operators");
    if (n == 5) {
        /* op 2 and op 4 are name-less: mcc/mnc present, no operator_name */
        check_has(obs[2], "\"mcc\":\"001\"", "scan name-less op carries mcc");
        check_lacks(obs[2], "\"operator_name\"", "scan name-less op omits operator_name");
    }

    n = parse_cops_scan(COPS_SCAN_EG25, obs, MAX_OBS);
    check(n == 2, "EG25 scan -> 2 operators");

    printf("== generic serving merge (fallback) ==\n");
    /* RM520N-GL real reads: C5GREG populated (5G-SA), COPS? Operator A/NR, CESQ
     * ERROR, CSQ 99 -> a 5G serving cell with identity + operator, no signal. */
    n = parse_generic_serving(C5GREG_RM520N, CEREG_SEARCHING, CREG_NOT_SEARCH,
                              COPS_Q_RM520N, "ERROR", CSQ_UNKNOWN, obs, MAX_OBS);
    check(n == 1, "generic merge (RM520N reads) -> 1 serving record");
    if (n == 1) {
        check_has(obs[0], "\"rat\":\"NR\"", "merge rat NR (from C5GREG AcT 11)");
        check_has(obs[0], "\"tac\":1714944", "merge TAC from C5GREG");
        check_has(obs[0], "\"operator_name\":\"Operator A\"", "merge operator from COPS?");
        check_lacks(obs[0], "\"rssi\"", "merge: CSQ 99 + CESQ ERROR -> no signal");
        check_has(obs[0], "\"observation_type\":\"generic\"", "merge observation_type");
    }
    /* Signal merge is per-field: CESQ supplies rsrp/rsrq, and CSQ fills the
     * rssi gap because CESQ's rxlev here is 99 (unknown). The result is the
     * most complete signal picture, not an all-or-nothing pick. */
    n = parse_generic_serving(C5GREG_RM520N, "", "", "", CESQ_POPULATED, CSQ_EG25,
                              obs, MAX_OBS);
    check(n == 1, "generic merge with signal -> 1 record");
    if (n == 1) {
        check_has(obs[0], "\"rsrp\":-80", "merge takes CESQ rsrp");
        check_has(obs[0], "\"rsrq\":-5", "merge takes CESQ rsrq");
        check_has(obs[0], "\"rssi\":-65", "merge fills rssi from CSQ when CESQ rxlev is unknown");
    }
    /* Registration commands answered but unregistered -> no cell identity ->
     * no observable, even with a good signal and a known operator. */
    check(parse_generic_serving("ERROR", CEREG_SEARCHING, CREG_NOT_SEARCH,
                                COPS_Q_RM520N, CESQ_POPULATED, CSQ_EG25,
                                obs, MAX_OBS) == 0,
          "generic merge: unregistered -> 0 records despite signal+operator");

    printf("== generic poll: which verbs a test-form reply drops ==\n");
    /* Replies are the shapes TS 27.007 gives a test command; not captures. */
#define REFUSED(r, what)   check(stdat_test_classify(r) == STDAT_TEST_REFUSED, what)
#define TRANSIENT(r, what) check(stdat_test_classify(r) == STDAT_TEST_TRANSIENT, what)
#define KEPT(r, what)      check(stdat_test_classify(r) == STDAT_TEST_KEPT, what)
    REFUSED("\r\nERROR\r\n", "plain ERROR -> refused");
    REFUSED("\nERROR", "plain ERROR, no CR -> refused");
    REFUSED("\r\n+CME ERROR: 4\r\n", "CME 4 -> refused");
    REFUSED("\r\n+CME ERROR: 3\r\n", "CME 3 (not allowed) -> refused");
    REFUSED("\r\n+CME ERROR: 100\r\n", "CME 100 (unknown) -> refused");
    REFUSED("\r\n+CME ERROR: 40\r\n", "CME 40 -> refused");
    REFUSED("\r\n+CME ERROR: 140\r\n", "CME 140 is not 14 -> refused");
    REFUSED("\r\n+CME ERROR: 14x\r\n", "CME 14x -> refused");
    REFUSED("\r\n+CME ERROR: 99999999999999999999\r\n", "huge code -> refused");
    REFUSED("\r\n+CME ERROR: operation not supported\r\n", "verbose CME 4 -> refused");
    REFUSED("\r\n+CME ERROR: unknown\r\n", "verbose unknown -> refused");
    REFUSED("\r\n+CME ERROR: not supported\r\n", "verbose not supported -> refused");
    REFUSED("\r\n+CME ERROR:\r\n", "empty CME body -> refused");
    REFUSED("\r\n+CME ERROR: SIM busy now\r\n", "busy text with trailing words -> refused");
    TRANSIENT("\r\n+CME ERROR: 14\r\n", "CME 14 (SIM busy) -> transient");
    TRANSIENT("\r\n+CME ERROR: 515\r\n", "CME 515 (init) -> transient");
    TRANSIENT("\r\n+CME ERROR: 10\r\n", "CME 10 (SIM not inserted) -> transient");
    TRANSIENT("\r\n+CME ERROR: 13\r\n", "CME 13 (SIM failure) -> transient");
    TRANSIENT("\r\n+CME ERROR 14\r\n", "colon-less +CME ERROR 14 -> transient");
    TRANSIENT("\r\n+CME ERROR:515 \r\n", "no space, trailing space -> transient");
    TRANSIENT("\r\n+CME ERROR : 14\r\n", "space before colon -> transient");
    TRANSIENT("\r\n+CME ERROR: busy\r\n", "verbose busy -> transient");
    TRANSIENT("\r\n+CME ERROR: SIM busy\r\n", "verbose SIM busy -> transient");
    TRANSIENT("\r\n+CME ERROR: sim not ready\r\n", "verbose SIM not ready -> transient");
    REFUSED("\r\n+CME ERROR 4\r\n", "colon-less CME 4 -> refused");
    KEPT("\r\n+CESQ: (0-63,99),(0-7,99),(0-96,255),(0-49,255),(0-34,255),(0-97,255)\r\n\r\nOK\r\n",
         "test-form list + OK -> kept");
    KEPT("\r\nOK\r\n", "bare OK -> kept");
    KEPT("\r\n+COPS: \"NOT OK\"\r\nOK\r\n", "OK inside a value does not end early");
    TRANSIENT("", "empty reply (timeout) -> transient");
    TRANSIENT(NULL, "no reply -> transient");
    TRANSIENT("\r\n+CESQ: (0-63,99)\r\n", "no terminal line (timed out mid-reply) -> transient");
    TRANSIENT("\r\nERRORS\r\n", "ERROR as a prefix is not a terminal line");
#undef REFUSED
#undef TRANSIENT
#undef KEPT
    {
        /* CESQ (4) busy on round 1, refused on round 2; the rest answer OK. */
        stdat_generic_t g;
        stdat_generic_reset(&g);
        const char *ok = "\r\nOK\r\n";
        for (int i = 0; i < STDAT_GENERIC_N; i++)
            if (STDAT_GENERIC_TEST[i] != NULL)
                stdat_generic_note(&g, i, 6, i == 4 ? "\r\n+CME ERROR: 14\r\n" : ok);
        stdat_generic_round_done(&g);
        check(!g.probed, "transient CME: probe runs again next poll");
        check(!(g.skip & (1u << 4)), "transient CME: verb stays in the poll");
        check(!(g.settled & (1u << 4)), "transient CME: verb not settled");
        check(stdat_generic_note(&g, 4, 6, "\r\n+CME ERROR: 4\r\n") == 1,
              "re-probe: CME 4 refuses");
        stdat_generic_round_done(&g);
        check(g.probed && (g.skip == (1u << 4)), "re-probe settles; only CESQ left out");

        stdat_generic_reset(&g);
        check(!g.probed && g.skip == 0 && g.settled == 0 && g.rounds == 0,
              "reset (open) clears probe state");

        for (int r = 0; r < STDAT_GENERIC_PROBE_ROUNDS; r++) {
            check(!g.probed, "busy forever: still probing under the cap");
            stdat_generic_note(&g, 5, 6, "\r\n+CME ERROR: 515\r\n");
            stdat_generic_round_done(&g);
        }
        check(g.probed && g.skip == 0, "busy forever: cap ends probing, verb kept");

        stdat_generic_reset(&g);
        check(stdat_generic_note(&g, 1, 0, "") == 0 && !(g.settled & (1u << 1)),
              "timeout (n == 0): not settled, probed again");
        check(stdat_generic_note(&g, 1, -1, "\r\nERROR\r\n") == 0 && !(g.settled & (1u << 1)),
              "serial error (n < 0): transient even with stale ERROR text");
        check(stdat_generic_note(&g, 2, 6, "\r\n+CME ERROR: 3\r\n") == 1 &&
              (g.skip & (1u << 2)) && (g.settled & (1u << 2)),
              "CME 3 refuses and settles");
        check(stdat_generic_note(&g, 0, 7, "\r\nERROR\r\n") == 1 && (g.skip & 1u),
              "plain ERROR refuses");
        check(stdat_generic_note(&g, 4, 6, "\r\n+CME ERROR 14\r\n") == 0 &&
              !(g.settled & (1u << 4)), "colon-less CME 14: not settled");
        for (int r = 0; r < STDAT_GENERIC_PROBE_ROUNDS; r++) {
            check(!g.probed, "timeout forever: still probing under the cap");
            stdat_generic_note(&g, 1, 0, "");
            stdat_generic_round_done(&g);
        }
        check(g.probed && !(g.skip & (1u << 1)), "timeout forever: cap ends probing, verb kept");

        stdat_generic_reset(&g);
        check(stdat_generic_note(&g, -1, 6, "ERROR") == 0 &&
              stdat_generic_note(&g, STDAT_GENERIC_N, 6, "ERROR") == 0 && g.skip == 0,
              "out-of-range index ignored");
    }
    {
        int cops = -1, probed = 0;
        for (int i = 0; i < STDAT_GENERIC_N; i++) {
            if (streq(STDAT_GENERIC_READ[i], "AT+COPS?"))
                cops = i;
            if (STDAT_GENERIC_TEST[i] != NULL) {
                probed++;
                /* the test form is the read's verb + "=?", never a scan */
                char want[32];
                size_t vl = strcspn(STDAT_GENERIC_READ[i], "?");
                snprintf(want, sizeof(want), "%.*s=?", (int)vl, STDAT_GENERIC_READ[i]);
                check(streq(STDAT_GENERIC_TEST[i], want), "test form matches its read verb");
            }
        }
        check(cops >= 0 && STDAT_GENERIC_TEST[cops] == NULL,
              "AT+COPS? is never probed (AT+COPS=? is the PLMN scan)");
        check(probed == STDAT_GENERIC_N - 1, "every other generic verb is probed");
        check(streq(STDAT_GENERIC_READ[4], "AT+CESQ") && streq(STDAT_GENERIC_READ[5], "AT+CSQ"),
              "read order matches parse_generic_serving's cesq, csq arguments");
    }

    printf("\n%s: %d failure(s)\n", g_fails ? "FAIL" : "PASS", g_fails);
    return g_fails ? 1 : 0;
}

#endif /* CELL_SELFTEST */
