/*
    test_cellat_lock -- selftest for the band/RAT lock logic.

    Every case that decides what gets WRITTEN to a modem's NV is here, because
    a wrong write survives a reboot:
      * the read parser refuses a band "list" that is not one (R01A08's `0`),
        so it is never offered and never written back;
      * a channel resolves to exactly one target, and AUTO is the settings AS
        FOUND, not the literal "AUTO";
      * the write plan writes only what differs, bands before the RAT, and
        never an empty list;
      * the state file restores only the modem it was written for.

    The read responses are the shapes captured from real modems (an RM520N-GL
    AT survey and an RM500Q command enumeration).
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "cellat_lock.h"

static int g_fails = 0;

#define CHECK(cond, ...) do {                                         \
        if (!(cond)) {                                                \
            fprintf(stderr, "  FAIL %s:%d: ", __func__, __LINE__);    \
            fprintf(stderr, __VA_ARGS__);                             \
            fprintf(stderr, "\n");                                    \
            g_fails++;                                                \
        }                                                             \
    } while (0)

static const char *RM520_MODE = "\r\n+QNWPREFCFG: \"mode_pref\",AUTO\r\n\r\nOK\r\n";
static const char *RM520_LTE =
    "\r\n+QNWPREFCFG: \"lte_band\",1:2:3:4:5:7:8:12:13:14:17:18:19:20:25:26:28:"
    "29:30:32:34:38:39:40:41:42:43:46:48:66:71\r\n\r\nOK\r\n";
static const char *RM520_NR =
    "\r\n+QNWPREFCFG: \"nr5g_band\",1:2:3:5:7:8:12:20:25:28:38:40:41:48:66:71:"
    "75:76:77:78:79\r\n\r\nOK\r\n";

static void orig_rm520(cellat_lock_settings_t *o) {
    memset(o, 0, sizeof(*o));
    cellat_lock_parse_read(RM520_MODE, "mode_pref", o->mode_pref, sizeof(o->mode_pref));
    cellat_lock_parse_read(RM520_LTE, "lte_band", o->lte_band, sizeof(o->lte_band));
    cellat_lock_parse_read(RM520_NR, "nr5g_band", o->nr5g_band, sizeof(o->nr5g_band));
}

static void test_parse_read(void) {
    char v[CELLAT_LOCK_BANDS_MAX];
    CHECK(cellat_lock_parse_read(RM520_MODE, "mode_pref", v, sizeof(v)) == 1 &&
          strcmp(v, "AUTO") == 0, "mode_pref: '%s'", v);
    CHECK(cellat_lock_parse_read(RM520_LTE, "lte_band", v, sizeof(v)) == 1 &&
          strncmp(v, "1:2:3:4:5", 9) == 0 && strstr(v, ":66:71") != NULL,
          "lte_band: '%s'", v);
    /* the key must match exactly, not as a prefix */
    CHECK(cellat_lock_parse_read(RM520_NR, "nr5g", v, sizeof(v)) == 0, "prefix matched");
    CHECK(cellat_lock_parse_read("\r\nERROR\r\n", "mode_pref", v, sizeof(v)) == 0,
          "ERROR parsed");
    /* R01A08: a band "list" of 0 is not a list */
    CHECK(cellat_lock_parse_read("+QNWPREFCFG: \"nr5g_band\",0\r\nOK", "nr5g_band",
                                 v, sizeof(v)) == 0, "a 0 band list was accepted");
    /* a quoted list (the rf_band shape) is not a writable colon list */
    CHECK(cellat_lock_parse_read("+QNWPREFCFG: \"lte_band\",\"1:3\"\r\nOK", "lte_band",
                                 v, sizeof(v)) == 0, "a quoted band list was accepted");
    /* a combined RAT preference is kept verbatim */
    CHECK(cellat_lock_parse_read("+QNWPREFCFG: \"mode_pref\",LTE:NR5G\r\nOK",
                                 "mode_pref", v, sizeof(v)) == 1 &&
          strcmp(v, "LTE:NR5G") == 0, "combined mode: '%s'", v);
    /* the RM500Q WLSN answer shape, lowercase-insensitive key match not wanted */
    CHECK(cellat_lock_parse_read("+QNWPREFCFG: \"mode_pref\",NR5G\r\nOK",
                                 "mode_pref", v, sizeof(v)) == 1 &&
          strcmp(v, "NR5G") == 0, "NR5G: '%s'", v);
    /* a value too long for the buffer is refused, not truncated into a
     * DIFFERENT band list that would later be written back */
    char tiny[6];
    CHECK(cellat_lock_parse_read(RM520_LTE, "lte_band", tiny, sizeof(tiny)) == 0,
          "an over-long list was truncated instead of refused");
}

static void test_channels(void) {
    cellat_lock_settings_t o;
    orig_rm520(&o);
    char ch[CELLAT_LOCK_CHANNELS_MAX][CELLAT_LOCK_CHAN_MAX];
    size_t n = cellat_lock_channels(&o, ch, CELLAT_LOCK_CHANNELS_MAX);
    CHECK(n == 3 + 31 + 21, "channel count %zu", n);
    CHECK(strcmp(ch[0], "AUTO") == 0 && strcmp(ch[1], "LTE") == 0 &&
          strcmp(ch[2], "NR5G") == 0, "head %s %s %s", ch[0], ch[1], ch[2]);
    CHECK(strcmp(ch[3], "LTE-B1") == 0, "first band %s", ch[3]);
    CHECK(strcmp(ch[3 + 30], "LTE-B71") == 0, "last LTE %s", ch[33]);
    CHECK(strcmp(ch[34], "NR-n1") == 0 && strcmp(ch[n - 1], "NR-n79") == 0,
          "NR %s .. %s", ch[34], ch[n - 1]);

    /* no usable NR list: no NR5G and no NR bands */
    o.nr5g_band[0] = '\0';
    n = cellat_lock_channels(&o, ch, CELLAT_LOCK_CHANNELS_MAX);
    CHECK(n == 2 + 31, "LTE-only count %zu", n);
    for (size_t i = 0; i < n; i++)
        CHECK(strncmp(ch[i], "NR", 2) != 0, "NR channel %s offered", ch[i]);

    /* the cap is honoured */
    n = cellat_lock_channels(&o, ch, 4);
    CHECK(n == 4, "cap: %zu", n);
}

static void test_target(void) {
    cellat_lock_settings_t o, t;
    char err[256];
    orig_rm520(&o);

    CHECK(cellat_lock_target(&o, "AUTO", &t, err, sizeof(err)) == 0 &&
          memcmp(&t, &o, sizeof(t)) == 0, "AUTO is not the settings as found");

    /* AUTO after a modem that was found LTE-only means LTE-only again */
    cellat_lock_settings_t o2 = o;
    snprintf(o2.mode_pref, sizeof(o2.mode_pref), "LTE");
    CHECK(cellat_lock_target(&o2, "auto", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "LTE") == 0, "AUTO wrote %s", t.mode_pref);

    CHECK(cellat_lock_target(&o, "LTE", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "LTE") == 0 && strcmp(t.lte_band, o.lte_band) == 0 &&
          strcmp(t.nr5g_band, o.nr5g_band) == 0, "LTE: %s", t.mode_pref);
    CHECK(cellat_lock_target(&o, "nr5g", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "NR5G") == 0, "NR5G: %s", t.mode_pref);
    CHECK(cellat_lock_target(&o, "LTE-B66", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "LTE") == 0 && strcmp(t.lte_band, "66") == 0 &&
          strcmp(t.nr5g_band, o.nr5g_band) == 0, "B66: %s %s", t.mode_pref, t.lte_band);
    CHECK(cellat_lock_target(&o, "NR-n41", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "NR5G") == 0 && strcmp(t.nr5g_band, "41") == 0 &&
          strcmp(t.lte_band, o.lte_band) == 0, "n41: %s %s", t.mode_pref, t.nr5g_band);

    /* a band the modem did not have enabled is refused, with a reason */
    err[0] = '\0';
    CHECK(cellat_lock_target(&o, "LTE-B99", &t, err, sizeof(err)) == -1 &&
          strstr(err, "99") != NULL, "B99: %s", err);
    /* "LTE-B6" must not match band 66 by prefix */
    CHECK(cellat_lock_target(&o, "LTE-B6", &t, err, sizeof(err)) == -1, "B6 matched 66");
    CHECK(cellat_lock_target(&o, "WCDMA", &t, err, sizeof(err)) == -1 && err[0],
          "an unknown channel was accepted");
    CHECK(cellat_lock_target(&o, "LTE-B", &t, err, sizeof(err)) == -1, "empty band");
    CHECK(cellat_lock_target(&o, "LTE-B66x", &t, err, sizeof(err)) == -1, "trailing junk");

    /* NR channels on a modem with no usable NR list */
    cellat_lock_settings_t o3 = o;
    o3.nr5g_band[0] = '\0';
    CHECK(cellat_lock_target(&o3, "NR5G", &t, err, sizeof(err)) == -1, "NR5G without NR");
    CHECK(cellat_lock_target(&o3, "NR-n41", &t, err, sizeof(err)) == -1, "n41 without NR");
}

static void test_writes(void) {
    cellat_lock_settings_t o, t;
    char err[256];
    char cmds[3][CELLAT_LOCK_CMD_MAX];
    orig_rm520(&o);

    /* nothing differs, nothing is written */
    CHECK(cellat_lock_writes(&o, &o, cmds, 3) == 0, "AUTO->AUTO wrote");

    cellat_lock_target(&o, "LTE-B66", &t, err, sizeof(err));
    size_t n = cellat_lock_writes(&o, &t, cmds, 3);
    CHECK(n == 2, "B66 writes %zu", n);
    CHECK(strcmp(cmds[0], "AT+QNWPREFCFG=\"lte_band\",66") == 0, "first %s", cmds[0]);
    CHECK(strcmp(cmds[1], "AT+QNWPREFCFG=\"mode_pref\",LTE") == 0, "second %s", cmds[1]);

    /* back to AUTO: the full list, then the RAT as found */
    n = cellat_lock_writes(&t, &o, cmds, 3);
    CHECK(n == 2, "restore writes %zu", n);
    CHECK(strncmp(cmds[0], "AT+QNWPREFCFG=\"lte_band\",1:2:3:", 31) == 0, "restore %s", cmds[0]);
    CHECK(strcmp(cmds[1], "AT+QNWPREFCFG=\"mode_pref\",AUTO") == 0, "restore %s", cmds[1]);

    /* an empty (unreadable) list is never written, even when it "differs" */
    cellat_lock_settings_t a = o, b = o;
    a.nr5g_band[0] = '\0';
    snprintf(b.nr5g_band, sizeof(b.nr5g_band), "41");
    n = cellat_lock_writes(&b, &a, cmds, 3);
    CHECK(n == 0, "an empty band list was written (%zu)", n);

    /* the cap is honoured */
    cellat_lock_target(&o, "NR-n41", &t, err, sizeof(err));
    cellat_lock_settings_t from;
    cellat_lock_target(&o, "LTE-B66", &from, err, sizeof(err));
    n = cellat_lock_writes(&from, &t, cmds, 3);
    CHECK(n == 3, "B66 -> n41 writes %zu", n);
    CHECK(strstr(cmds[0], "lte_band") && strstr(cmds[1], "nr5g_band") &&
          strstr(cmds[2], "mode_pref"), "order %s | %s | %s", cmds[0], cmds[1], cmds[2]);
    CHECK(cellat_lock_writes(&from, &t, cmds, 1) == 1, "cap");
}

static void test_state_file(void) {
    char path[] = "/tmp/test_cellat_lock_XXXXXX";
    int fd = mkstemp(path);
    CHECK(fd >= 0, "mkstemp");
    close(fd);
    unlink(path);

    cellat_lock_settings_t o, r;
    char err[256];
    orig_rm520(&o);

    CHECK(cellat_lock_state_read(path, "351234567890123", CELLAT_LOCK_QNWPREF, &r, err, sizeof(err)) == 0,
          "an absent file read as present");
    CHECK(cellat_lock_state_write(path, "351234567890123", &o) == 0, "write");
    memset(&r, 0, sizeof(r));
    CHECK(cellat_lock_state_read(path, "351234567890123", CELLAT_LOCK_QNWPREF, &r, err, sizeof(err)) == 1 &&
          memcmp(&r, &o, sizeof(r)) == 0, "round trip: %s", err);
    /* another modem's file is refused, loudly */
    err[0] = '\0';
    CHECK(cellat_lock_state_read(path, "999999999999999", CELLAT_LOCK_QNWPREF, &r, err, sizeof(err)) == -1 &&
          strstr(err, "351234567890123") != NULL, "foreign IMEI: %s", err);
    /* a malformed file is refused, never half-read */
    FILE *f = fopen(path, "w");
    fputs("imei=351234567890123\nmode_pref=AUTO\n", f);   /* no band keys */
    fclose(f);
    CHECK(cellat_lock_state_read(path, "351234567890123", CELLAT_LOCK_QNWPREF, &r, err, sizeof(err)) == -1,
          "a truncated file was accepted");
    unlink(path);

    char p[512];
    cellat_lock_default_state_path("351234567890123", p, sizeof(p));
    CHECK(strstr(p, "cellat-lock-351234567890123.state") != NULL, "default path %s", p);
}

/* ── RAT-only backends (Sierra AT!SELRAT, the Telit LM960) ───────────────
 * The strings are the captured answers: EM9190 SWIX55C_03.17.04 and
 * _01.07.19 AT surveys, LM960 32.01.1X0 command enumeration. */
static const char *SELRAT_0317 =
    "\r\n!SELRAT: Index, Name\r\n00, Automatic\r\n01, WCDMA Only\r\n06, LTE Only\r\n"
    "11, WCDMA and LTE Only\r\n20, NR 5G Only\r\n21, LTE and NR 5G Only\r\n"
    "22, WCDMA and NR 5G Only\r\n\r\nOK\r\n";
static const char *SELRAT_0107 =
    "\r\n!SELRAT: Index, Name\r\n00, Automatic\r\n01, UMTS 3G Only\r\n04, LTE Only\r\n"
    "05, 5G Only\r\n0E, UMTS and LTE Only\r\nOK\r\n";

static void selrat_orig(cellat_lock_settings_t *o, const char *list) {
    memset(o, 0, sizeof(*o));
    o->backend = CELLAT_LOCK_SELRAT;
    cellat_lock_parse_selrat_read("\r\n!SELRAT: 00, Automatic\r\n\r\nOK\r\n",
                                  o->mode_pref, sizeof(o->mode_pref));
    cellat_lock_parse_selrat_list(list, o);
}

static void test_selrat(void) {
    char v[16];
    cellat_lock_settings_t o, t;
    char err[256];
    char ch[CELLAT_LOCK_CHANNELS_MAX][CELLAT_LOCK_CHAN_MAX];
    char cmds[3][CELLAT_LOCK_CMD_MAX];

    CHECK(cellat_lock_parse_selrat_read("!SELRAT: 00, Automatic\r\nOK", v, sizeof(v)) == 1 &&
          strcmp(v, "00") == 0, "read '%s'", v);
    CHECK(cellat_lock_parse_selrat_read("!SELRAT: 0E, UMTS and LTE Only\r\nOK", v, sizeof(v)) == 1 &&
          strcmp(v, "0E") == 0, "hex read '%s'", v);
    CHECK(cellat_lock_parse_selrat_read("ERROR", v, sizeof(v)) == 0, "ERROR read");
    /* the "unknown" answer carries no usable index */
    CHECK(cellat_lock_parse_selrat_read("Unknown RAT mode. Use AT!SELRAT to set mode.\r\n07\r\nOK",
                                        v, sizeof(v)) == 0, "unknown-mode read accepted");

    /* matched by NAME: the same channel is 06 on one firmware and 04 on another */
    selrat_orig(&o, SELRAT_0317);
    CHECK(strcmp(o.rat_lte, "06") == 0 && strcmp(o.rat_nr, "20") == 0,
          "03.17.04: lte %s nr %s", o.rat_lte, o.rat_nr);
    selrat_orig(&o, SELRAT_0107);
    CHECK(strcmp(o.rat_lte, "04") == 0 && strcmp(o.rat_nr, "05") == 0,
          "01.07.19: lte %s nr %s", o.rat_lte, o.rat_nr);
    /* "WCDMA and LTE Only" / "LTE and NR 5G Only" are not LTE / NR only */
    cellat_lock_settings_t x;
    memset(&x, 0, sizeof(x));
    CHECK(cellat_lock_parse_selrat_list("!SELRAT: Index, Name\r\n11, WCDMA and LTE Only\r\n"
                                        "21, LTE and NR 5G Only\r\nOK", &x) == 0 &&
          x.rat_lte[0] == '\0' && x.rat_nr[0] == '\0', "a combined RAT matched");

    selrat_orig(&o, SELRAT_0317);
    size_t n = cellat_lock_channels(&o, ch, CELLAT_LOCK_CHANNELS_MAX);
    CHECK(n == 3 && strcmp(ch[0], "AUTO") == 0 && strcmp(ch[1], "LTE") == 0 &&
          strcmp(ch[2], "NR5G") == 0, "selrat channels %zu", n);

    CHECK(cellat_lock_target(&o, "LTE", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "06") == 0, "LTE -> %s", t.mode_pref);
    n = cellat_lock_writes(&o, &t, cmds, 3);
    CHECK(n == 1 && strcmp(cmds[0], "AT!SELRAT=06") == 0, "write %s", n ? cmds[0] : "-");
    n = cellat_lock_writes(&t, &o, cmds, 3);
    CHECK(n == 1 && strcmp(cmds[0], "AT!SELRAT=00") == 0, "restore %s", n ? cmds[0] : "-");
    CHECK(cellat_lock_target(&o, "NR5G", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "20") == 0, "NR5G -> %s", t.mode_pref);
    err[0] = '\0';
    CHECK(cellat_lock_target(&o, "LTE-B66", &t, err, sizeof(err)) == -1 &&
          strstr(err, "RAT") != NULL, "a band channel on a RAT-only modem: %s", err);
}

static void test_ws46(void) {
    char v[16];
    cellat_lock_settings_t o, t;
    char err[256];
    char ch[CELLAT_LOCK_CHANNELS_MAX][CELLAT_LOCK_CHAN_MAX];
    char cmds[3][CELLAT_LOCK_CMD_MAX];

    CHECK(cellat_lock_parse_ws46_read("+WS46: 31\r\n0", v, sizeof(v)) == 1 &&
          strcmp(v, "31") == 0, "read '%s'", v);
    CHECK(cellat_lock_parse_ws46_read("ERROR", v, sizeof(v)) == 0, "ERROR read");

    memset(&o, 0, sizeof(o));
    o.backend = CELLAT_LOCK_WS46;
    snprintf(o.mode_pref, sizeof(o.mode_pref), "31");
    CHECK(cellat_lock_parse_ws46_list("+WS46: (22,28,31)\r\n0", &o) == 1 &&
          strcmp(o.rat_lte, "28") == 0 && o.rat_nr[0] == '\0',
          "LM960 list: lte '%s' nr '%s'", o.rat_lte, o.rat_nr);
    size_t n = cellat_lock_channels(&o, ch, CELLAT_LOCK_CHANNELS_MAX);
    CHECK(n == 2 && strcmp(ch[1], "LTE") == 0, "LM960 channels %zu", n);
    CHECK(cellat_lock_target(&o, "NR5G", &t, err, sizeof(err)) == -1, "NR5G on an LTE-only list");
    CHECK(cellat_lock_target(&o, "LTE", &t, err, sizeof(err)) == 0, "LTE target");
    n = cellat_lock_writes(&o, &t, cmds, 3);
    CHECK(n == 1 && strcmp(cmds[0], "AT+WS46=28") == 0, "write %s", n ? cmds[0] : "-");
    n = cellat_lock_writes(&t, &o, cmds, 3);
    CHECK(n == 1 && strcmp(cmds[0], "AT+WS46=31") == 0, "restore %s", n ? cmds[0] : "-");

    cellat_lock_settings_t o5;
    memset(&o5, 0, sizeof(o5));
    CHECK(cellat_lock_parse_ws46_list("+WS46: (12,22,25,28,29,30,31,35,36,37)\r\nOK", &o5) == 1 &&
          strcmp(o5.rat_nr, "35") == 0, "a 5G list offers 35: '%s'", o5.rat_nr);
    /* 128 is not 28: the list is matched by whole numbers */
    cellat_lock_settings_t o6;
    memset(&o6, 0, sizeof(o6));
    CHECK(cellat_lock_parse_ws46_list("+WS46: (128,135)\r\nOK", &o6) == 0, "128 matched 28");
}

/* ── CNMP backend: SIMCom 5G (AT+CNMP) ──────────────────────────────────
 * Strings as a SIM8202G-M2 (LE13B04SIM8202M44A-M2) answers them:
 * 38 -> QMI mode pref 'lte' and an LTE camp in
 * ~2.6 s; 71 -> '5gnr' and an NR SA camp in ~2 s; 2 -> every RAT, the mask
 * the module ships with; 100 ("UNKNOW") is listed by =? but
 * answers ERROR on write. */
static const char *CNMP_LIST = "\r\n+CNMP: (2,14,38,71,54,55,109,100)\r\n\r\nOK\r\n";

static void test_cnmp(void) {
    char v[16];
    cellat_lock_settings_t o, t;
    char err[256];
    char ch[CELLAT_LOCK_CHANNELS_MAX][CELLAT_LOCK_CHAN_MAX];
    char cmds[3][CELLAT_LOCK_CMD_MAX];

    CHECK(cellat_lock_parse_cnmp_read("\r\n+CNMP: 2\r\n\r\nOK\r\n", v, sizeof(v)) == 1 &&
          strcmp(v, "2") == 0, "read '%s'", v);
    CHECK(cellat_lock_parse_cnmp_read("+CNMP: 109\r\nOK", v, sizeof(v)) == 1 &&
          strcmp(v, "109") == 0, "read 109 '%s'", v);
    CHECK(cellat_lock_parse_cnmp_read("ERROR", v, sizeof(v)) == 0, "ERROR read");
    CHECK(cellat_lock_parse_cnmp_read("+CNMP: 1009\r\nOK", v, sizeof(v)) == 0, "4 digits");
    /* 100 reads, but the modem refuses it back: a lock from it could never
     * be undone, so the read says "not restorable" rather than a value */
    CHECK(cellat_lock_parse_cnmp_read("\r\n+CNMP: 100\r\n\r\nOK\r\n", v, sizeof(v)) == -1,
          "100 must be refused as unrestorable");

    memset(&o, 0, sizeof(o));
    o.backend = CELLAT_LOCK_CNMP;
    snprintf(o.mode_pref, sizeof(o.mode_pref), "2");
    CHECK(cellat_lock_parse_cnmp_list(CNMP_LIST, &o) == 1 &&
          strcmp(o.rat_lte, "38") == 0 && strcmp(o.rat_nr, "71") == 0,
          "SIM8202 list: lte '%s' nr '%s'", o.rat_lte, o.rat_nr);
    size_t n = cellat_lock_channels(&o, ch, CELLAT_LOCK_CHANNELS_MAX);
    CHECK(n == 3 && strcmp(ch[0], "AUTO") == 0 && strcmp(ch[1], "LTE") == 0 &&
          strcmp(ch[2], "NR5G") == 0, "SIM8202 channels %zu", n);
    CHECK(cellat_lock_target(&o, "LTE", &t, err, sizeof(err)) == 0, "LTE target");
    n = cellat_lock_writes(&o, &t, cmds, 3);
    CHECK(n == 1 && strcmp(cmds[0], "AT+CNMP=38") == 0, "LTE write %s", n ? cmds[0] : "-");
    n = cellat_lock_writes(&t, &o, cmds, 3);
    CHECK(n == 1 && strcmp(cmds[0], "AT+CNMP=2") == 0, "restore %s", n ? cmds[0] : "-");
    CHECK(cellat_lock_target(&o, "NR5G", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "71") == 0, "NR5G -> %s", t.mode_pref);
    err[0] = '\0';
    CHECK(cellat_lock_target(&o, "LTE-B66", &t, err, sizeof(err)) == -1 &&
          strstr(err, "AT+CNMP") != NULL, "a band channel on CNMP: %s", err);

    /* whole numbers only: 138 is not 38, 710 is not 71; a 4G-only list
     * (SIM7600: no 71) offers no NR5G */
    cellat_lock_settings_t o2;
    memset(&o2, 0, sizeof(o2));
    CHECK(cellat_lock_parse_cnmp_list("+CNMP: (138,710)\r\nOK", &o2) == 0, "138 matched 38");
    memset(&o2, 0, sizeof(o2));
    CHECK(cellat_lock_parse_cnmp_list("+CNMP: (2,13,14,38,48,51,54)\r\nOK", &o2) == 1 &&
          strcmp(o2.rat_lte, "38") == 0 && o2.rat_nr[0] == '\0',
          "4G list: lte '%s' nr '%s'", o2.rat_lte, o2.rat_nr);
    /* 109 is LTE+NR5G, not NR only: a list without 71 offers no NR5G */
    memset(&o2, 0, sizeof(o2));
    CHECK(cellat_lock_parse_cnmp_list("+CNMP: (2,38,109)\r\nOK", &o2) == 1 &&
          o2.rat_nr[0] == '\0', "109 taken as NR only: nr '%s'", o2.rat_nr);
}

static void test_state_file_backends(void) {
    char path[] = "/tmp/test_cellat_lock_b_XXXXXX";
    int fd = mkstemp(path);
    close(fd);
    cellat_lock_settings_t o, r;
    char err[256];
    selrat_orig(&o, SELRAT_0317);
    CHECK(cellat_lock_state_write(path, "351234567890123", &o) == 0, "write");
    memset(&r, 0, sizeof(r));
    CHECK(cellat_lock_state_read(path, "351234567890123", CELLAT_LOCK_SELRAT, &r,
                                 err, sizeof(err)) == 1 &&
          r.backend == CELLAT_LOCK_SELRAT && strcmp(r.mode_pref, "00") == 0,
          "selrat round trip: %s", err);
    /* never through another command family */
    err[0] = '\0';
    CHECK(cellat_lock_state_read(path, "351234567890123", CELLAT_LOCK_QNWPREF, &r,
                                 err, sizeof(err)) == -1 && err[0], "cross-backend read: %s", err);
    /* a file from before the backends existed is QNWPREF */
    FILE *f = fopen(path, "w");
    fputs("imei=351234567890123\nmode_pref=AUTO\nlte_band=2:66\nnr5g_band=41\n", f);
    fclose(f);
    CHECK(cellat_lock_state_read(path, "351234567890123", CELLAT_LOCK_QNWPREF, &r,
                                 err, sizeof(err)) == 1 && strcmp(r.lte_band, "2:66") == 0,
          "legacy file: %s", err);
    /* a CNMP file round-trips, and is never read as another family's */
    memset(&o, 0, sizeof(o));
    o.backend = CELLAT_LOCK_CNMP;
    snprintf(o.mode_pref, sizeof(o.mode_pref), "2");
    cellat_lock_parse_cnmp_list(CNMP_LIST, &o);
    CHECK(cellat_lock_state_write(path, "351234567890123", &o) == 0, "cnmp write");
    memset(&r, 0, sizeof(r));
    CHECK(cellat_lock_state_read(path, "351234567890123", CELLAT_LOCK_CNMP, &r,
                                 err, sizeof(err)) == 1 &&
          r.backend == CELLAT_LOCK_CNMP && strcmp(r.mode_pref, "2") == 0 &&
          strcmp(r.rat_nr, "71") == 0, "cnmp round trip: %s", err);
    err[0] = '\0';
    CHECK(cellat_lock_state_read(path, "351234567890123", CELLAT_LOCK_WS46, &r,
                                 err, sizeof(err)) == -1 && strstr(err, "cnmp") != NULL,
          "cnmp file read as ws46: %s", err);
    unlink(path);
}

/* ── QCFG backend: the EG25-G family (AT+QCFG "nwscanmode" + "band") ──────
 * Strings as captured (EG25GGBR07A08M2G_A0.301 AT survey) and
 * as the QCFG manual V1.3 §5.2 / §5.4 documents them. */
static const char *QCFG_BAND = "\r\n+QCFG: \"band\",0xbff,0x1e00b0e18df,0x0\r\n\r\nOK\r\n";

static void qcfg_orig(cellat_lock_settings_t *o) {
    memset(o, 0, sizeof(*o));
    o->backend = CELLAT_LOCK_QCFG;
    cellat_lock_parse_qcfg_scanmode("\r\n+QCFG: \"nwscanmode\",0\r\n\r\nOK\r\n",
                                    o->mode_pref, sizeof(o->mode_pref));
    cellat_lock_parse_qcfg_band(QCFG_BAND, o->lte_band, sizeof(o->lte_band));
}

static void test_qcfg(void) {
    char v[64];
    cellat_lock_settings_t o, t;
    char err[256];
    char ch[CELLAT_LOCK_CHANNELS_MAX][CELLAT_LOCK_CHAN_MAX];
    char cmds[3][CELLAT_LOCK_CMD_MAX];

    CHECK(cellat_lock_parse_qcfg_scanmode("+QCFG: \"nwscanmode\",3\r\nOK", v, sizeof(v)) == 1 &&
          strcmp(v, "3") == 0, "scanmode '%s'", v);
    /* the LTE mask, bare hex (the manual writes it back without 0x) */
    CHECK(cellat_lock_parse_qcfg_band(QCFG_BAND, v, sizeof(v)) == 1 &&
          strcmp(v, "1e00b0e18df") == 0, "band '%s'", v);
    CHECK(cellat_lock_parse_qcfg_band("+QCFG: \"band\",0xbff,0x0,0x0\r\nOK", v, sizeof(v)) == 0,
          "a zero LTE mask ('no change') accepted");
    CHECK(cellat_lock_parse_qcfg_band("ERROR", v, sizeof(v)) == 0, "ERROR band");

    qcfg_orig(&o);
    size_t n = cellat_lock_channels(&o, ch, CELLAT_LOCK_CHANNELS_MAX);
    /* 0x1e00b0e18df: B1,B2,B3,B4,B5,B7,B8,B12,B13,B18,B19,B20,B25,B26,B28,B38,B39,B40,B41 */
    CHECK(n == 2 + 19, "qcfg channels %zu", n);
    CHECK(strcmp(ch[0], "AUTO") == 0 && strcmp(ch[1], "LTE") == 0 &&
          strcmp(ch[2], "LTE-B1") == 0 && strcmp(ch[n - 1], "LTE-B41") == 0,
          "qcfg channels %s .. %s", ch[2], ch[n - 1]);
    for (size_t i = 0; i < n; i++)
        CHECK(strncmp(ch[i], "NR", 2) != 0, "an NR channel on an LTE-only part: %s", ch[i]);

    CHECK(cellat_lock_target(&o, "LTE-B12", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "3") == 0 && strcmp(t.lte_band, "800") == 0,
          "B12 -> %s %s", t.mode_pref, t.lte_band);
    n = cellat_lock_writes(&o, &t, cmds, 3);
    /* bands first, GSM/WCDMA and TDS as 0 = NO CHANGE (QCFG manual §5.4) */
    CHECK(n == 2 && strcmp(cmds[0], "AT+QCFG=\"band\",0,800,0,1") == 0 &&
          strcmp(cmds[1], "AT+QCFG=\"nwscanmode\",3,1") == 0,
          "B12 writes: %s | %s", n > 0 ? cmds[0] : "-", n > 1 ? cmds[1] : "-");
    n = cellat_lock_writes(&t, &o, cmds, 3);
    CHECK(n == 2 && strcmp(cmds[0], "AT+QCFG=\"band\",0,1e00b0e18df,0,1") == 0 &&
          strcmp(cmds[1], "AT+QCFG=\"nwscanmode\",0,1") == 0,
          "restore: %s | %s", n > 0 ? cmds[0] : "-", n > 1 ? cmds[1] : "-");
    /* the lever bookkeeping: each accepted write moves `cur` to `target`,
     * so the restore from there writes BOTH levers back (a band-mask write
     * booked as a RAT write would never be restored). */
    {
        cellat_lock_settings_t cur = o, tg;
        cellat_lock_target(&o, "LTE-B12", &tg, err, sizeof(err));
        char w[3][CELLAT_LOCK_CMD_MAX];
        size_t k = cellat_lock_writes(&cur, &tg, w, 3);
        for (size_t i = 0; i < k; i++)
            cellat_lock_note_write(&cur, &tg, w[i]);
        CHECK(memcmp(&cur, &tg, sizeof(cur)) == 0, "cur did not reach the lock");
        CHECK(cellat_lock_writes(&cur, &o, w, 3) == 2, "the restore must write band AND RAT");
    }
    CHECK(cellat_lock_target(&o, "LTE-B66", &t, err, sizeof(err)) == -1, "B66 not in the mask");
    CHECK(cellat_lock_target(&o, "NR5G", &t, err, sizeof(err)) == -1, "NR5G on an LTE-only part");

    /* the state file keeps the hex mask and reads back only as qcfg */
    char path[] = "/tmp/test_cellat_lock_q_XXXXXX";
    int fd = mkstemp(path);
    close(fd);
    cellat_lock_settings_t r;
    CHECK(cellat_lock_state_write(path, "351234567890123", &o) == 0, "qcfg write");
    memset(&r, 0, sizeof(r));
    CHECK(cellat_lock_state_read(path, "351234567890123", CELLAT_LOCK_QCFG, &r,
                                 err, sizeof(err)) == 1 && strcmp(r.lte_band, "1e00b0e18df") == 0 &&
          strcmp(r.mode_pref, "0") == 0, "qcfg round trip: %s", err);
    CHECK(cellat_lock_state_read(path, "351234567890123", CELLAT_LOCK_QNWPREF, &r,
                                 err, sizeof(err)) == -1, "qcfg file read as qnwpref");
    unlink(path);
}

/* A band SET is ONE channel -- a Lock target and a Hop element. */
static void test_band_sets(void) {
    cellat_lock_settings_t o, t;
    char err[256];
    char cmds[3][CELLAT_LOCK_CMD_MAX];
    orig_rm520(&o);

    CHECK(cellat_lock_target(&o, "LTE-B2+4+12+66+71", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "LTE") == 0 && strcmp(t.lte_band, "2:4:12:66:71") == 0 &&
          strcmp(t.nr5g_band, o.nr5g_band) == 0, "set: %s %s", t.mode_pref, t.lte_band);
    /* the order as given, and the prefix case-insensitive like every preset */
    CHECK(cellat_lock_target(&o, "lte-b66+2", &t, err, sizeof(err)) == 0 &&
          strcmp(t.lte_band, "66:2") == 0, "order: %s", t.lte_band);
    CHECK(cellat_lock_target(&o, "NR-n41+77", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "NR5G") == 0 && strcmp(t.nr5g_band, "41:77") == 0 &&
          strcmp(t.lte_band, o.lte_band) == 0, "NR set: %s %s", t.mode_pref, t.nr5g_band);
    /* one band is a set of one: the existing spelling is unchanged */
    CHECK(cellat_lock_target(&o, "LTE-B66", &t, err, sizeof(err)) == 0 &&
          strcmp(t.lte_band, "66") == 0, "single: %s", t.lte_band);

    /* one band the modem did not have refuses the WHOLE set, and names it */
    err[0] = '\0';
    CHECK(cellat_lock_target(&o, "LTE-B2+99+66", &t, err, sizeof(err)) == -1 &&
          strstr(err, "band 99") != NULL, "B2+99+66: %s", err);
    err[0] = '\0';
    CHECK(cellat_lock_target(&o, "NR-n41+100", &t, err, sizeof(err)) == -1 &&
          strstr(err, "n100") != NULL, "n41+100: %s", err);
    /* per element, "6" is not "66" */
    CHECK(cellat_lock_target(&o, "LTE-B2+6", &t, err, sizeof(err)) == -1, "B6 matched 66");

    /* malformed sets are refused, never guessed at */
    const char *bad[] = { "LTE-B2++4", "LTE-B2+", "LTE-B+2", "LTE-B2+2", "LTE-B02",
                          "LTE-B2+4x", "LTE-B2,4", "LTE-B2 +4", "LTE-B12345" };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        CHECK(cellat_lock_target(&o, bad[i], &t, err, sizeof(err)) == -1,
              "malformed set accepted: %s", bad[i]);

    /* written like a single band: the list first, then the RAT */
    cellat_lock_target(&o, "LTE-B2+66", &t, err, sizeof(err));
    size_t n = cellat_lock_writes(&o, &t, cmds, 3);
    CHECK(n == 2 && strcmp(cmds[0], "AT+QNWPREFCFG=\"lte_band\",2:66") == 0 &&
          strcmp(cmds[1], "AT+QNWPREFCFG=\"mode_pref\",LTE") == 0,
          "set writes %zu: %s | %s", n, cmds[0], cmds[1]);

    /* AT+QCFG (EG25-G): a set ORs its bits into the one LTE mask */
    qcfg_orig(&o);
    CHECK(cellat_lock_target(&o, "LTE-B2+12", &t, err, sizeof(err)) == 0 &&
          strcmp(t.mode_pref, "3") == 0 && strcmp(t.lte_band, "802") == 0,
          "qcfg set -> %s %s", t.mode_pref, t.lte_band);
    err[0] = '\0';
    CHECK(cellat_lock_target(&o, "LTE-B2+66", &t, err, sizeof(err)) == -1 &&
          strstr(err, "66") != NULL, "qcfg B66 in a set: %s", err);
    /* a leading zero is malformed, not band 2: strtol would read "02" as 2 */
    CHECK(cellat_lock_target(&o, "LTE-B02", &t, err, sizeof(err)) == -1, "qcfg B02");
    CHECK(cellat_lock_target(&o, "LTE-B2+012", &t, err, sizeof(err)) == -1, "qcfg B2+012");
}

int main(void) {
    printf("cellat band/RAT lock selftest\n");
    test_parse_read();
    test_channels();
    test_target();
    test_writes();
    test_state_file();
    test_selrat();
    test_ws46();
    test_cnmp();
    test_state_file_backends();
    test_qcfg();
    test_band_sets();
    if (g_fails) {
        fprintf(stderr, "FAILED: %d check(s)\n", g_fails);
        return 1;
    }
    printf("PASS: all cellat_lock checks\n");
    return 0;
}
