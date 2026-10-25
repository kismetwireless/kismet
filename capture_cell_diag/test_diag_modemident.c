/* test_diag_modemident.c - standalone tests for the ModemIdentity record.
 *
 * Links only diag_modemident.c (libc, no Kismet): `make check` here, and the
 * cellat directory's `make check` runs it too, because both helpers link it.
 *
 * Every AT reply below is a MEASURED one, verbatim, from a module survey or a
 * live drive -- not a constructed string. The value extraction has to be right
 * on real modems' spellings, and those disagree with one another in exactly
 * the ways that matter (a response-code prefix on one vendor, a colon inside a
 * firmware string on another).
 */

#include "diag_modemident.h"

#include <stdio.h>
#include <string.h>

static int failures = 0;

#define CHECK(cond, ...) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: ", __FILE__, __LINE__); \
        fprintf(stderr, __VA_ARGS__); \
        fprintf(stderr, "\n"); \
        failures++; \
    } \
} while (0)

/* modemident_value() over one reply; returns the value (static buffer). */
static const char *val(const char *resp) {
    static char out[256];
    modemident_value(resp, out, sizeof(out));
    return out;
}

static void test_value_extraction(void) {
    /* Quectel EG25-G (firmware EG25GGBR07A08M2G_01.003.01.003). The
     * model is `EG25`, NOT the product name `EG25-G`: the record keeps it. */
    CHECK(strcmp(val("Quectel\nOK"), "Quectel") == 0, "EG25-G CGMI");
    CHECK(strcmp(val("EG25\nOK"), "EG25") == 0, "EG25-G CGMM is EG25, verbatim");
    CHECK(strcmp(val("EG25GGBR07A08M2G\nOK"), "EG25GGBR07A08M2G") == 0,
          "EG25-G CGMR");

    /* Quectel RM520N-GL. */
    CHECK(strcmp(val("RM520N-GL\nOK"), "RM520N-GL") == 0, "RM520N-GL CGMM");

    /* SIMCom SIM8202G-M2 (firmware LE13B04SIM8202M44A-M2): CGMR is the one
     * reply among the tested modems that carries its response code. */
    CHECK(strcmp(val("SIMCOM INCORPORATED\nOK"), "SIMCOM INCORPORATED") == 0,
          "SIMCom CGMI, upper case and verbatim");
    CHECK(strcmp(val("SIMCOM_SIM8202G-M2\nOK"), "SIMCOM_SIM8202G-M2") == 0,
          "SIMCom CGMM");
    CHECK(strcmp(val("+CGMR: LE13B04SIM8202M44A-M2\nOK"),
                 "LE13B04SIM8202M44A-M2") == 0,
          "the +CGMR: response code is stripped");

    /* Sierra EM7565 (firmware SWI9X50C_01.08.04.00). The firmware
     * string CONTAINS colons -- a strip anchored on the first colon would
     * truncate it to "SWI9X50C_01.08.04.00 dbb5d0 jenkins 2018/08/21 21". */
    CHECK(strcmp(val("Sierra Wireless, Incorporated\nOK"),
                 "Sierra Wireless, Incorporated") == 0, "Sierra CGMI keeps its comma");
    CHECK(strcmp(val("SWI9X50C_01.08.04.00 dbb5d0 jenkins 2018/08/21 21:40:11\nOK"),
                 "SWI9X50C_01.08.04.00 dbb5d0 jenkins 2018/08/21 21:40:11") == 0,
          "a colon inside a firmware string survives");
    /* CONSTRUCTED, not measured -- the one rule-pin in this file. The Sierra
     * string above never reaches the response-code branch (it does not start
     * with '+'), so on its own it leaves the colon-before-space rule untested (a
     * mutation that stripped at ANY colon would survive). A '+'-led line whose first
     * colon comes AFTER a space is not "+CODE: value" and must be kept whole. */
    CHECK(strcmp(val("+49 build: 7\nOK"), "+49 build: 7") == 0,
          "a +-led value whose colon follows a space is not a response code");

    /* Telit LM960 (a drive container's RawAT row for AT+CGMM, and the
     * cellat.firmware field of the same drive). */
    CHECK(strcmp(val("LM960A18\nOK"), "LM960A18") == 0, "Telit CGMM");
    CHECK(strcmp(val("32.01.110\nOK"), "32.01.110") == 0, "Telit CGMR");

    /* Wire framing: CRLF, blank lines, and a command echo from a modem whose
     * echo was never turned off. None of them is a value. */
    CHECK(strcmp(val("\r\nRM520NGLAAR03A04M4G\r\n\r\nOK\r\n"),
                 "RM520NGLAAR03A04M4G") == 0, "CRLF and blank lines are framing");
    CHECK(strcmp(val("AT+CGMM\r\nEG25\r\nOK\r\n"), "EG25") == 0,
          "a command echo is not the value");
    CHECK(strcmp(val("ATI\r\nQuectel\r\nOK\r\n"), "Quectel") == 0,
          "a bare ATI echo is not the value");
    CHECK(strcmp(val("AT&T\nOK"), "AT&T") == 0,
          "a value that merely starts with AT is kept");

    /* The ATI-style label some firmwares put on these replies. */
    CHECK(strcmp(val("Manufacturer: SIMCOM INCORPORATED\nOK"),
                 "SIMCOM INCORPORATED") == 0, "Manufacturer: label stripped");
    CHECK(strcmp(val("Model: SIMCOM_SIM8202G-M2\nOK"),
                 "SIMCOM_SIM8202G-M2") == 0, "Model: label stripped");
    CHECK(strcmp(val("Revision: EG25GGBR07A08M2G\nOK"),
                 "EG25GGBR07A08M2G") == 0, "Revision: label stripped");

    /* No value: every one of these must yield "" and return 0. An ERROR
     * read AS the model would be written into the .kismet as a measurement. */
    char out[64];
    CHECK(modemident_value("ERROR", out, sizeof(out)) == 0 && out[0] == '\0',
          "ERROR is not a value");
    CHECK(modemident_value("+CME ERROR: 100", out, sizeof(out)) == 0 && out[0] == '\0',
          "+CME ERROR is not a value");
    CHECK(modemident_value("OK", out, sizeof(out)) == 0 && out[0] == '\0',
          "a bare OK is not a value");
    CHECK(modemident_value("", out, sizeof(out)) == 0 && out[0] == '\0',
          "an empty read is not a value");
    CHECK(modemident_value(NULL, out, sizeof(out)) == 0 && out[0] == '\0',
          "a NULL read is not a value");
    CHECK(modemident_value("+CGMR:\nOK", out, sizeof(out)) == 0 && out[0] == '\0',
          "a response code with nothing after it is not a value");

    /* The input is const: the helpers extract several things from one buffer
     * (celldiag's own at_first_value_line runs strtok_r on it afterwards). */
    char resp[] = "+CGMR: LE13B04SIM8202M44A-M2\nOK";
    modemident_value(resp, out, sizeof(out));
    CHECK(strcmp(resp, "+CGMR: LE13B04SIM8202M44A-M2\nOK") == 0,
          "the reply buffer is left untouched");

    /* Truncation is terminated, never an overrun. */
    char tiny[5];
    CHECK(modemident_value("EG25GGBR07A08M2G\nOK", tiny, sizeof(tiny)) == 1 &&
          strcmp(tiny, "EG25") == 0, "a short buffer truncates and terminates");
}

static modemident_t eg25g(void) {
    modemident_t id;
    modemident_clear(&id);
    snprintf(id.make, sizeof(id.make), "Quectel");
    snprintf(id.model, sizeof(id.model), "EG25");
    snprintf(id.firmware, sizeof(id.firmware), "EG25GGBR07A08M2G");
    snprintf(id.imei, sizeof(id.imei), "351234567847131");
    return id;
}

static void test_label(void) {
    char out[256];
    modemident_t id = eg25g();

    CHECK(modemident_label(&id, " DIAG", out, sizeof(out)) == 0 &&
          strcmp(out, "Quectel EG25 (EG25GGBR07A08M2G) IMEI:351234567847131 DIAG") == 0,
          "celldiag label, got '%s'", out);
    CHECK(modemident_label(&id, NULL, out, sizeof(out)) == 0 &&
          strcmp(out, "Quectel EG25 (EG25GGBR07A08M2G) IMEI:351234567847131") == 0,
          "cellat label, got '%s'", out);

    /* No make/model: the older firmware-first shape. */
    modemident_t fw_only;
    modemident_clear(&fw_only);
    snprintf(fw_only.firmware, sizeof(fw_only.firmware), "32.01.110");
    snprintf(fw_only.imei, sizeof(fw_only.imei), "351234567847131");
    CHECK(modemident_label(&fw_only, " DIAG", out, sizeof(out)) == 0 &&
          strcmp(out, "32.01.110 IMEI:351234567847131 DIAG") == 0,
          "firmware-only label, got '%s'", out);

    /* IMEI only (a celldiag source with no AT identity). */
    modemident_t imei_only;
    modemident_clear(&imei_only);
    snprintf(imei_only.imei, sizeof(imei_only.imei), "351234567847131");
    CHECK(modemident_label(&imei_only, " DIAG", out, sizeof(out)) == 0 &&
          strcmp(out, "IMEI:351234567847131 DIAG") == 0,
          "IMEI-only label, got '%s'", out);

    /* Make without model is still rendered. */
    modemident_t make_only = eg25g();
    make_only.model[0] = '\0';
    CHECK(modemident_label(&make_only, NULL, out, sizeof(out)) == 0 &&
          strcmp(out, "Quectel (EG25GGBR07A08M2G) IMEI:351234567847131") == 0,
          "make-only label, got '%s'", out);

    char tiny[8];
    CHECK(modemident_label(&id, NULL, tiny, sizeof(tiny)) == -1 &&
          strlen(tiny) < sizeof(tiny), "an undersized label buffer reports -1");
}

static void test_json(void) {
    char out[1024];
    modemident_t id = eg25g();

    CHECK(modemident_json(&id, "celldiag", MODEMIDENT_METHOD_AT, "/dev/ttyUSB14",
                          "Quectel EG25 (EG25GGBR07A08M2G) IMEI:351234567847131 DIAG",
                          out, sizeof(out)) == 0, "json fits");
    CHECK(strcmp(out,
          "{\"v\":1,\"source_type\":\"celldiag\",\"method\":\"at\","
          "\"imei\":\"351234567847131\",\"make\":\"Quectel\",\"model\":\"EG25\","
          "\"firmware\":\"EG25GGBR07A08M2G\",\"at_port\":\"/dev/ttyUSB14\","
          "\"label\":\"Quectel EG25 (EG25GGBR07A08M2G) IMEI:351234567847131 DIAG\"}") == 0,
          "json shape, got %s", out);

    /* Absent values are OMITTED, not written empty (schema rule). */
    modemident_t imei_only;
    modemident_clear(&imei_only);
    snprintf(imei_only.imei, sizeof(imei_only.imei), "351234567847131");
    CHECK(modemident_json(&imei_only, "celldiag", MODEMIDENT_METHOD_DEFINITION,
                          NULL, "", out, sizeof(out)) == 0 &&
          strcmp(out, "{\"v\":1,\"source_type\":\"celldiag\",\"method\":\"definition\","
                      "\"imei\":\"351234567847131\"}") == 0,
          "an unread value is omitted, got %s", out);
    CHECK(strstr(out, "\"make\"") == NULL && strstr(out, "\"\"") == NULL,
          "no empty-string values");

    /* A modem string is untrusted input: quotes, backslashes and control
     * bytes are escaped, so a hostile or corrupt reply cannot break the object
     * (or inject a key) on its way into kismetdb. */
    modemident_t evil = eg25g();
    snprintf(evil.model, sizeof(evil.model), "EG\"25\\x\n\x01");
    CHECK(modemident_json(&evil, "cellat", MODEMIDENT_METHOD_AT, NULL, NULL,
                          out, sizeof(out)) == 0, "escaped json fits");
    CHECK(strstr(out, "\"model\":\"EG\\\"25\\\\x\\n\\u0001\"") != NULL,
          "model escaped, got %s", out);

    /* Too small: -1 and an EMPTY buffer, never half an object. */
    char tiny[40];
    CHECK(modemident_json(&id, "celldiag", MODEMIDENT_METHOD_AT, NULL, NULL,
                          tiny, sizeof(tiny)) == -1 && tiny[0] == '\0',
          "an undersized json buffer yields -1 and \"\"");
}

static void test_has_product(void) {
    modemident_t id;
    modemident_clear(&id);
    CHECK(!modemident_has_product(&id), "a cleared identity has no product");
    snprintf(id.imei, sizeof(id.imei), "351234567847131");
    CHECK(!modemident_has_product(&id), "an IMEI alone is not a product");
    snprintf(id.firmware, sizeof(id.firmware), "32.01.110");
    CHECK(modemident_has_product(&id), "a firmware is a product");
}

static void test_imei_shape(void) {
    /* The value a PCIe RM520N-GL's desynced AT+CGSN read can return -- its
     * AT+CGMI reply -- and the names it would mint. */
    CHECK(!modemident_imei_ok("Quectel"), "a CGMI reply is not an IMEI");
    CHECK(modemident_imei_ok("351234567890123"), "a well-formed 15-digit IMEI");
    CHECK(modemident_imei_ok("351234567847530"), "a second well-formed IMEI");
    CHECK(!modemident_imei_ok(""), "empty");
    CHECK(!modemident_imei_ok(NULL), "NULL");
    CHECK(!modemident_imei_ok("86643606009824"), "14 digits (IMEI without check digit)");
    CHECK(!modemident_imei_ok("3512345678901231"), "16 digits (IMEISV): cannot be addressed");
    CHECK(!modemident_imei_ok("86643606009824O"), "a letter O in the last place");
    CHECK(!modemident_imei_ok(" 351234567890123"), "untrimmed: a leading space");
    CHECK(!modemident_imei_ok("OK"), "a bare final result");
}

static void test_followup_deadline(void) {
    /* A well-behaved modem (the EG25-G's CGMR: ~20 ms incl. OK) keeps 3 s. */
    CHECK(modemident_followup_ms(20, 1) == MODEMIDENT_READ_MS, "fast read keeps the full deadline");
    /* The T99W175: value in ~50 ms, no OK, so the read ran its whole 3 s. */
    CHECK(modemident_followup_ms(3000, 1) == MODEMIDENT_UNTERMINATED_READ_MS,
          "a value that arrived only by timing out shortens the follow-ups");
    /* A read that timed out with NOTHING is a silent/busy port, not an
     * unterminated one: shortening there could cut off a slow real answer. */
    CHECK(modemident_followup_ms(3000, 0) == MODEMIDENT_READ_MS,
          "a timed-out read with no value keeps the full deadline");
    CHECK(modemident_followup_ms(MODEMIDENT_UNTERMINATED_AFTER_MS - 1, 1) == MODEMIDENT_READ_MS,
          "just under the threshold is still a terminated reply");
    CHECK(modemident_followup_ms(MODEMIDENT_UNTERMINATED_AFTER_MS, 1) == MODEMIDENT_UNTERMINATED_READ_MS,
          "the threshold itself counts as unterminated");
}

int main(void) {
    test_followup_deadline();
    test_value_extraction();
    test_label();
    test_json();
    test_has_product();
    test_imei_shape();
    if (failures) {
        fprintf(stderr, "test_diag_modemident: %d failure(s)\n", failures);
        return 1;
    }
    printf("test_diag_modemident: all checks passed\n");
    return 0;
}
