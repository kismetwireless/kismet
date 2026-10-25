/* test_diag_profile.c - standalone unit tests for the celldiag profile reader.
 *
 * Links only diag_profile.c (libc, no Kismet), so it runs off the capture
 * framework: `make check` in this directory. Covers the narrow JSON string /
 * object extraction, the firmware_match glob, and the end-to-end
 * firmware -> profile -> diag.<key> lookup against on-disk fixture profiles
 * (written to a temp dir), so the mask_default and f3_default per-modem
 * defaults are proven offline.
 */

#include "diag_profile.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        failures++; \
    } \
} while (0)

/* Defined below; forward-declared so the port_detect fixtures above can use it. */
static int write_file(const char *path, const char *content);

/* ---- JSON string extraction ---- */

static void test_json_string_basic(void) {
    const char *j = "{ \"a\": \"one\", \"mask_default\": \"wardrive\" }";
    char out[64];
    CHECK(diag_profile_json_string(j, "mask_default", out, sizeof(out)) == 1,
          "mask_default should be found");
    CHECK(strcmp(out, "wardrive") == 0, "got '%s'", out);
    CHECK(diag_profile_json_string(j, "a", out, sizeof(out)) == 1, "a found");
    CHECK(strcmp(out, "one") == 0, "got '%s'", out);
}

static void test_json_string_absent_and_null(void) {
    char out[64];
    CHECK(diag_profile_json_string("{ \"x\": \"y\" }", "z", out, sizeof(out)) == 0,
          "absent key -> 0");
    CHECK(diag_profile_json_string("{ \"m\": null }", "m", out, sizeof(out)) == 0,
          "null value -> 0");
    CHECK(diag_profile_json_string("{ \"m\": 7 }", "m", out, sizeof(out)) == 0,
          "number value -> 0");
    CHECK(diag_profile_json_string("{ \"m\": { \"n\": \"1\" } }", "m",
                                   out, sizeof(out)) == 0, "object value -> 0");
}

static void test_json_string_key_not_value(void) {
    /* "wardrive" also appears as a VALUE; a lookup of key "wardrive" must not
     * match the value occurrence. */
    const char *j = "{ \"mask_default\": \"wardrive\", \"note\": \"x\" }";
    char out[64];
    CHECK(diag_profile_json_string(j, "wardrive", out, sizeof(out)) == 0,
          "value token must not match as a key");
}

static void test_json_string_escapes(void) {
    const char *j = "{ \"k\": \"a\\\"b\\\\c\" }";  /* value: a"b\c */
    char out[64];
    CHECK(diag_profile_json_string(j, "k", out, sizeof(out)) == 1, "escaped found");
    CHECK(strcmp(out, "a\"b\\c") == 0, "got '%s'", out);
}

static void test_json_string_too_long(void) {
    const char *j = "{ \"k\": \"abcdefghij\" }";
    char tiny[4];
    CHECK(diag_profile_json_string(j, "k", tiny, sizeof(tiny)) == 0,
          "overlong value -> absent, not truncated");
}

/* A string longer than the TOKENIZER's own 512-byte scratch must not
 * desynchronise the walk.
 *
 * test_json_string_too_long above passes a tiny `out`, which exercises the
 * caller's buffer -- a different path. The tokeniser has its own `tok[512]`.
 * A recovery that skips only past the OPENING quote of an oversized token and
 * rescans byte-wise puts the walk in anti-phase for the whole rest of the
 * file: every closing quote is then read as an opening quote, so keys and
 * values swap roles and every later lookup silently returns "absent".
 *
 * capture_cell_at/profiles/simcom_sim8202.json has an oversized string BEFORE
 * its "diag" key, so with that bug it reads as having no "diag" object at all.
 *
 * Both directions are asserted: the oversized value is absent (it does not
 * fit), and everything AFTER it is still readable (the walk kept its phase).
 */
static void test_oversized_token_does_not_desync_the_walk(void) {
    /* 600 bytes -- comfortably over the tokeniser's 512-byte scratch. */
    char big[601];
    memset(big, 'x', sizeof(big) - 1);
    big[sizeof(big) - 1] = '\0';

    char *j = malloc(sizeof(big) + 256);
    CHECK(j != NULL, "malloc");
    if (!j)
        return;
    snprintf(j, sizeof(big) + 256,
             "{ \"note\": \"%s\", \"after\": \"tail\", "
             "\"diag\": { \"mask_default\": \"wardrive\" } }", big);

    char out[64];
    CHECK(diag_profile_json_string(j, "note", out, sizeof(out)) == 0,
          "the oversized value itself is absent, not truncated");

    /* The regression: these two are what desync destroys. */
    CHECK(diag_profile_json_string(j, "after", out, sizeof(out)) == 1,
          "a STRING key after an oversized value must still be found "
          "(tokeniser lost its phase)");
    CHECK(strcmp(out, "tail") == 0, "got '%s'", out);

    size_t len = 0;
    const char *obj = diag_profile_json_object(j, "diag", &len);
    CHECK(obj != NULL,
          "an OBJECT key after an oversized value must still be found -- this "
          "is the simcom_sim8202.json failure mode");
    if (obj) {
        char *body = malloc(len + 1);
        if (body) {
            memcpy(body, obj, len);
            body[len] = '\0';
            CHECK(diag_profile_json_string(body, "mask_default",
                                           out, sizeof(out)) == 1,
                  "diag.mask_default readable from the recovered slice");
            free(body);
        }
    }

    free(j);
}

/* An UNTERMINATED string is malformed, not merely oversized: there is no
 * closing quote to resynchronise on, so the walk must END rather than guess.
 * Guessing is what produced the desync above. */
static void test_unterminated_string_ends_the_walk(void) {
    const char *j = "{ \"a\": \"unterminated...";
    char out[64];
    CHECK(diag_profile_json_string(j, "a", out, sizeof(out)) == 0,
          "unterminated value -> absent");
    CHECK(diag_profile_json_string(j, "nope", out, sizeof(out)) == 0,
          "absent key in malformed json -> 0, no read past the end");
}

/* ---- JSON object slice ---- */

static void test_json_object_slice(void) {
    const char *j =
        "{ \"diag\": { \"mask_default\": \"full\", \"nested\": { \"a\": \"}\" } },"
        "  \"other\": { \"mask_default\": \"wardrive\" } }";
    size_t len = 0;
    const char *obj = diag_profile_json_object(j, "diag", &len);
    CHECK(obj != NULL, "diag object found");
    CHECK(obj && obj[0] == '{', "slice starts at brace");
    CHECK(obj && obj[len - 1] == '}', "slice ends at matching brace");
    /* The brace inside the nested string value "}" must not end the object
     * early: the slice must still contain the nested key. */
    char sub[64];
    memcpy(sub, obj, len < sizeof(sub) ? len : sizeof(sub) - 1);
    sub[len < sizeof(sub) ? len : sizeof(sub) - 1] = '\0';
    CHECK(strstr(sub, "nested") != NULL, "nested object retained in slice");
    /* And a key lookup scoped to the diag slice sees diag's value, not other's. */
    char out[64];
    CHECK(diag_profile_json_string(obj, "mask_default", out, sizeof(out)) == 1 &&
          strcmp(out, "full") == 0, "scoped lookup got '%s'", out);
}

static void test_json_object_absent(void) {
    size_t len = 99;
    CHECK(diag_profile_json_object("{ \"x\": \"y\" }", "diag", &len) == NULL,
          "absent object -> NULL");
    CHECK(diag_profile_json_object("{ \"diag\": \"notobj\" }", "diag", &len) == NULL,
          "string-valued key -> NULL");
}

/* ---- JSON integer extraction (port_detect.interface) ---- */

static void test_json_int(void) {
    int v = -999;
    CHECK(diag_profile_json_int("{ \"interface\": 0 }", "interface", &v) == 1 &&
          v == 0, "interface 0 got %d", v);
    CHECK(diag_profile_json_int("{ \"interface\": 4 }", "interface", &v) == 1 &&
          v == 4, "interface 4 got %d", v);
    CHECK(diag_profile_json_int("{ \"n\": -7 }", "n", &v) == 1 && v == -7,
          "negative got %d", v);
    /* Non-integer / absent values all fail cleanly. */
    CHECK(diag_profile_json_int("{ \"n\": \"5\" }", "n", &v) == 0, "string -> 0");
    CHECK(diag_profile_json_int("{ \"n\": 1.5 }", "n", &v) == 0, "float -> 0");
    CHECK(diag_profile_json_int("{ \"n\": null }", "n", &v) == 0, "null -> 0");
    CHECK(diag_profile_json_int("{ \"n\": true }", "n", &v) == 0, "bool -> 0");
    CHECK(diag_profile_json_int("{ \"x\": 3 }", "n", &v) == 0, "absent -> 0");
    /* Key-not-value: "5" appears only as a value; lookup of key "5" fails. */
    CHECK(diag_profile_json_int("{ \"a\": 5 }", "5", &v) == 0,
          "value token must not match as a key");
}

/* ---- port_detect descriptor ---- */

static void test_port_detect_end_to_end(void) {
    char tmpl[] = "/tmp/diagpd_XXXXXX";
    char *dir = mkdtemp(tmpl);
    CHECK(dir != NULL, "mkdtemp");
    if (!dir)
        return;

    char p1[512], p2[512], p3[512];
    snprintf(p1, sizeof(p1), "%s/rm520n.json", dir);
    snprintf(p2, sizeof(p2), "%s/mhi.json", dir);
    snprintf(p3, sizeof(p3), "%s/nodesc.json", dir);
    /* Reference modem: ttyUSB / interface 0 (the robust explicit form). */
    write_file(p1,
        "{ \"firmware_match\": \"RM520N*\","
        "  \"diag\": { \"mask_default\": \"wardrive\","
        "    \"port_detect\": { \"transport\": \"ttyUSB\", \"match\": \"interface\","
        "      \"interface\": 0, \"driver_path_glob\": null } } }");
    /* A hypothetical MHI/wwan modem: non-ttyUSB transport + a glob hint. */
    write_file(p2,
        "{ \"firmware_match\": \"T99W175*\","
        "  \"diag\": { \"port_detect\": { \"transport\": \"wwan_mhi\","
        "      \"driver_path_glob\": \"/dev/wwan*qcdm*\" } } }");
    /* A profile whose diag block has NO port_detect -> absent (use defaults). */
    write_file(p3,
        "{ \"firmware_match\": \"EG25G*\","
        "  \"diag\": { \"mask_default\": \"full\" } }");

    struct diag_port_detect pd;

    /* RM520N: full descriptor parsed. */
    CHECK(diag_profile_port_detect(dir, "RM520NGLAAR03A03M4G", &pd) == 1,
          "rm520n port_detect found");
    CHECK(strcmp(pd.transport, "ttyUSB") == 0, "transport '%s'", pd.transport);
    CHECK(strcmp(pd.match, "interface") == 0, "match '%s'", pd.match);
    CHECK(pd.has_interface == 1 && pd.interface == 0, "interface %d (has=%d)",
          pd.interface, pd.has_interface);
    CHECK(pd.driver_path_glob[0] == '\0', "null glob -> empty '%s'",
          pd.driver_path_glob);

    /* MHI: transport + glob set; match/interface absent -> defaults. */
    CHECK(diag_profile_port_detect(dir, "T99W175FOO", &pd) == 1,
          "mhi port_detect found");
    CHECK(strcmp(pd.transport, "wwan_mhi") == 0, "transport '%s'", pd.transport);
    CHECK(pd.match[0] == '\0', "absent match -> empty '%s'", pd.match);
    CHECK(pd.has_interface == 0, "absent interface -> has=0 (%d)", pd.has_interface);
    CHECK(strcmp(pd.driver_path_glob, "/dev/wwan*qcdm*") == 0, "glob '%s'",
          pd.driver_path_glob);

    /* No port_detect object -> 0, and *out zeroed so the caller uses defaults. */
    CHECK(diag_profile_port_detect(dir, "EG25GGBR07A08M2G", &pd) == 0,
          "no port_detect -> 0");
    CHECK(pd.transport[0] == '\0' && pd.has_interface == 0,
          "zeroed on 0-return");

    /* Unknown firmware / NULL guards. */
    CHECK(diag_profile_port_detect(dir, "LM960A9", &pd) == 0,
          "unknown firmware -> 0");
    CHECK(diag_profile_port_detect(NULL, "RM520N", &pd) == 0, "NULL dir -> 0");

    unlink(p1);
    unlink(p2);
    unlink(p3);
    rmdir(dir);
}

/* ---- glob ---- */

static void test_glob(void) {
    CHECK(diag_profile_glob_match("RM520N*", "RM520NGLAAR03A03M4G") == 1, "prefix*");
    CHECK(diag_profile_glob_match("RM520N*", "RM500Q") == 0, "non-match");
    CHECK(diag_profile_glob_match("EG25G*", "EG25GGBR07A08M2G") == 1, "eg25g");
    CHECK(diag_profile_glob_match("*", "anything") == 1, "star matches all");
}

/* ---- end-to-end lookup against on-disk fixtures ---- */

static int write_file(const char *path, const char *content) {
    FILE *f = fopen(path, "wb");
    if (!f)
        return -1;
    fputs(content, f);
    fclose(f);
    return 0;
}

static void test_lookup_end_to_end(void) {
    char tmpl[] = "/tmp/diagprof_XXXXXX";
    char *dir = mkdtemp(tmpl);
    CHECK(dir != NULL, "mkdtemp");
    if (!dir)
        return;

    char p1[512], p2[512];
    snprintf(p1, sizeof(p1), "%s/rm520n.json", dir);
    snprintf(p2, sizeof(p2), "%s/eg25g.json", dir);
    write_file(p1,
        "{ \"model\": \"rm520n-gl\", \"firmware_match\": \"RM520N*\","
        "  \"diag\": { \"mask_default\": \"wardrive\", \"f3_default\": \"off\" } }");
    write_file(p2,
        "{ \"model\": \"eg25g\", \"firmware_match\": \"EG25G*\","
        "  \"diag\": { \"mask_default\": \"full\" } }");

    char out[64];
    /* RM520N firmware selects the rm520n profile. */
    CHECK(diag_profile_lookup(dir, "RM520NGLAAR03A03M4G", "mask_default",
                              out, sizeof(out)) == 1 &&
          strcmp(out, "wardrive") == 0, "rm520n mask_default got '%s'", out);
    CHECK(diag_profile_lookup(dir, "RM520NGLAAR03A03M4G", "f3_default",
                              out, sizeof(out)) == 1 &&
          strcmp(out, "off") == 0, "rm520n f3_default got '%s'", out);
    /* EG25G firmware selects the eg25g profile (has no f3_default -> absent). */
    CHECK(diag_profile_lookup(dir, "EG25GGBR07A08M2G", "mask_default",
                              out, sizeof(out)) == 1 &&
          strcmp(out, "full") == 0, "eg25g mask_default got '%s'", out);
    CHECK(diag_profile_lookup(dir, "EG25GGBR07A08M2G", "f3_default",
                              out, sizeof(out)) == 0, "eg25g f3_default absent");
    /* Unknown firmware matches no profile. */
    CHECK(diag_profile_lookup(dir, "LM960A9", "mask_default",
                              out, sizeof(out)) == 0, "unknown firmware -> no match");
    /* Empty dir / NULL guards. */
    CHECK(diag_profile_lookup(NULL, "RM520N", "mask_default",
                              out, sizeof(out)) == 0, "NULL dir -> 0");
    CHECK(diag_profile_lookup(dir, "", "mask_default",
                              out, sizeof(out)) == 0, "empty firmware -> 0");

    unlink(p1);
    unlink(p2);
    rmdir(dir);
}

/* ---- the SHIPPED profiles dir ----
 *
 * Every test above runs against fixtures written to a temp dir, which proves
 * the reader works but says nothing about whether capture_cell_at/profiles/
 * actually covers the supported modems. A firmware string that matches no
 * shipped firmware_match glob makes matched_diag_body() return NULL and the
 * modem silently gets no DIAG profile at all. A missing profile has no failure
 * mode -- nothing errors, the source just never picks up per-modem
 * mask/f3/port_detect defaults -- so only a test against the REAL directory
 * can catch it.
 *
 * The count is pinned deliberately. A loop over a table that someone later
 * shrinks would keep passing while checking nothing, which is worse than no
 * test: it reports coverage it is not providing.
 */

#define SHIPPED_FIRMWARE_COUNT 5

static void test_shipped_profiles(void) {
    /* `make check` runs from capture_cell_diag/; the profiles live next door.
     * Overridable so an out-of-tree build can point at its own copy. */
    const char *dir = getenv("KP_PROFILES_DIR");
    if (!dir || !*dir)
        dir = "../capture_cell_at/profiles";

    struct stat st;
    if (stat(dir, &st) != 0 || !S_ISDIR(st.st_mode)) {
        fprintf(stderr, "SKIP shipped-profile checks: '%s' not a directory "
                        "(set KP_PROFILES_DIR)\n", dir);
        return;
    }

    /* One real firmware string per supported modem, exactly
     * as the device reports it via AT+CGMR. */
    static const struct { const char *firmware; const char *model; } fw[] = {
        { "EG25GGBR07A08M2G",             "quectel eg25-g"    },
        { "RM500QAEAAR11A03M4G",          "quectel rm500q-ae" },
        { "RM520NGLAAR03A04M4G",          "quectel rm520n-gl" },
        { "32.01.110",                    "telit lm960a18"    },
        { "LE13B04SIM8202M44A-M2",        "simcom sim8202g-m2"},
    };

    CHECK(sizeof(fw) / sizeof(fw[0]) == SHIPPED_FIRMWARE_COUNT,
          "firmware table has %zu entries, expected %d -- update the pin "
          "deliberately when adding a modem",
          sizeof(fw) / sizeof(fw[0]), SHIPPED_FIRMWARE_COUNT);

    int matched = 0;
    for (size_t i = 0; i < sizeof(fw) / sizeof(fw[0]); i++) {
        char out[64];
        /* mask_default is present in every shipped profile's diag block, so a
         * successful lookup proves the glob matched AND the diag object was
         * found -- the two halves matched_diag_body() can each fail at. */
        int ok = diag_profile_lookup(dir, fw[i].firmware, "mask_default",
                                     out, sizeof(out));
        CHECK(ok == 1, "%s: firmware '%s' matched NO shipped profile "
                       "(the modem would silently get no DIAG profile)",
              fw[i].model, fw[i].firmware);
        if (ok == 1)
            matched++;

        /* And the port must be resolvable, or the source falls back to the
         * 'lowest ttyUSB' guess that interface pinning exists to replace. */
        struct diag_port_detect pd;
        CHECK(diag_profile_port_detect(dir, fw[i].firmware, &pd) == 1,
              "%s: no port_detect descriptor", fw[i].model);
    }
    CHECK(matched == SHIPPED_FIRMWARE_COUNT,
          "%d of %d shipped firmwares matched a profile",
          matched, SHIPPED_FIRMWARE_COUNT);

    /* The SIM8202 glob leads with '*' because the SIMCom firmware string leads
     * with a build code (LE13B04...) rather than the model -- unlike every
     * other shipped profile, whose glob is a prefix. Pin both directions so a
     * later "tidy up" to a prefix glob fails here instead of on hardware. */
    CHECK(diag_profile_glob_match("*SIM8202*", "LE13B04SIM8202M44A-M2") == 1,
          "SIMCom infix glob must match a build-code-leading firmware string");
    CHECK(diag_profile_glob_match("SIM8202*", "LE13B04SIM8202M44A-M2") == 0,
          "a PREFIX glob must NOT match it -- that assumption is the bug");
    CHECK(diag_profile_glob_match("*SIM8202*", "RM500QAEAAR11A03M4G") == 0,
          "SIMCom glob must not steal a Quectel");

    /* The measured 0xB193 subpacket version is v48 on this modem, identical to
     * the RM500Q (every record in a capture). Both SDX55 profiles therefore
     * carry the same target_codes set; assert they agree so a future edit to
     * one is a deliberate divergence rather than a silent one. */
    char a[64], b[64];
    if (diag_profile_lookup(dir, "RM500QAEAAR11A03M4G", "mask_default",
                            a, sizeof(a)) == 1 &&
        diag_profile_lookup(dir, "LE13B04SIM8202M44A-M2", "mask_default",
                            b, sizeof(b)) == 1) {
        CHECK(strcmp(a, b) == 0,
              "SDX55 siblings disagree on mask_default: rm500q '%s' vs "
              "sim8202 '%s'", a, b);
    }
}

int main(void) {
    test_json_string_basic();
    test_json_string_absent_and_null();
    test_json_string_key_not_value();
    test_json_string_escapes();
    test_json_string_too_long();
    test_oversized_token_does_not_desync_the_walk();
    test_unterminated_string_ends_the_walk();
    test_json_object_slice();
    test_json_object_absent();
    test_json_int();
    test_port_detect_end_to_end();
    test_glob();
    test_lookup_end_to_end();
    test_shipped_profiles();

    if (failures == 0) {
        printf("PASS: all diag_profile tests\n");
        return 0;
    }
    fprintf(stderr, "FAILED: %d diag_profile test check(s)\n", failures);
    return 1;
}
