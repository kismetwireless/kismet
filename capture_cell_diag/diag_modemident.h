/* diag_modemident.h - the (modem, source) identity both cell capture helpers
 * read from the modem and persist into the .kismet.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * A Kismet cell drive writes ONE .kismet for every modem in the car. Without
 * this record, the only per-source identity a container keeps is the IMEI in a
 * source name, and a celldiag source's `kismet.datasource.hardware` stays at
 * the bring-up placeholder "DIAG opening IMEI:<imei> DIAG", because the
 * deferred bring-up learns the firmware seconds later. A reader then cannot
 * tell which modem a stream came from without an outside inventory file.
 *
 * So each helper reads the modem's own answers at startup,
 *
 *     AT+CGMI  -> make        AT+CGMR -> firmware
 *     AT+CGMM  -> model       AT+CGSN -> imei
 *
 * and sends them as ONE `ModemIdentity` JSON record. The server does two
 * things with it (datasource_cell_diag.cc / datasource_cell_at.cc):
 *
 *   - sets the source's `kismet.datasource.cell.modem_*` fields and its
 *     `hardware` label, so the Sources panel and the kismetdb `datasources`
 *     row name the modem;
 *   - lets it through to the packet chain, so kismetdb logs it as a
 *     `ModemIdentity` row in `data`: timestamped, one per open, and still there
 *     if the source is later reopened against a reflashed unit.
 *
 * The same four reads feed each helper's `--list` / list_interfaces answer, so
 * a source that is NOT open yet already shows the modem it would be, which is
 * what an operator choosing between sources needs.
 *
 * Every value is the modem's own answer, verbatim apart from response-code
 * framing. Quectel's EG25-G answers AT+CGMM with `EG25`, not `EG25-G`; SIMCom
 * answers AT+CGMI with `SIMCOM INCORPORATED`. Normalising those here would put
 * a guess where a measurement belongs. Mapping a make/model to a product family
 * is the reader's job, done with the reader's catalog.
 *
 * Record contract, schema v1 (a key whose value was not read is OMITTED, never
 * written empty -- an empty string would read as "the modem said nothing"):
 *
 *   v            1
 *   source_type  "celldiag" | "cellat"
 *   method       "at"          the four values were read over AT on at_port
 *                "definition"  no AT identity was possible (a celldiag MHI
 *                              source whose AT node its cellat sibling holds);
 *                              `imei` is then the IMEI the SOURCE WAS ADDRESSED
 *                              BY, not a measurement, and no other value is set
 *                "sibling"     written by the SERVER, never a helper: a
 *                              "definition" celldiag source adopted the values a
 *                              same-IMEI source of the same server read over
 *                              AT (on a PCIe modem, the paired cellat that
 *                              holds the only AT node). at_port is the node the
 *                              SIBLING read them on. It follows the source's
 *                              own "definition" row, so the latest row wins.
 *                "vouched"     written by a celldiag HELPER whose AT
 *                              scan met a port held by another process: the
 *                              holder (its paired cellat) had read the four
 *                              values over AT on at_port and published them
 *                              (diag_identvouch.h), and this helper validated
 *                              that record against the live node and the
 *                              holder's liveness. Second-hand, like "sibling",
 *                              but it is what LOCATED the modem's DIAG port.
 *   imei, make, model, firmware, at_port, label
 *
 * `label` is the display string the server installs as the source's hardware:
 * "<make> <model> (<firmware>) IMEI:<imei><suffix>", parts omitted when absent.
 *
 * Pure libc, no Kismet link, so it is selftested standalone
 * (test_diag_modemident.c) and linked by both helpers.
 */
#ifndef DIAG_MODEMIDENT_H
#define DIAG_MODEMIDENT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The kismetdb `data.type` of the record, and the JSON routing type the two
 * cell datasources intercept. One spelling, used by the helpers, the server and
 * any reader. */
#define MODEMIDENT_TYPE   "ModemIdentity"
#define MODEMIDENT_SCHEMA 1

#define MODEMIDENT_METHOD_AT         "at"
#define MODEMIDENT_METHOD_DEFINITION "definition"
#define MODEMIDENT_METHOD_SIBLING    "sibling"   /* server-side only */
#define MODEMIDENT_METHOD_VOUCHED    "vouched"   /* holder's record */

typedef struct {
    char make[96];
    char model[96];
    char firmware[256];
    char imei[32];
} modemident_t;

void modemident_clear(modemident_t *id);

/* The deadline for the make / model reads, from how the PREVIOUS info read on
 * the same port went.
 *
 * Some firmware answers an info command with its value and NO final result
 * code: on a Foxconn T99W175, AT+CGMR / +CGSN / +CGMI / +CGMM each deliver the
 * value in ~50 ms and then nothing, so a reader waiting for "OK" spends its
 * whole deadline -- 3 s -- on every one, while a bare "AT" gets its OK at once.
 * Four reads at full deadline make a --list take 12 s, longer than a Sources
 * panel can wait.
 *
 * So: a previous read that produced a value but took at least
 * MODEMIDENT_UNTERMINATED_AFTER_MS has shown this port does not terminate info
 * replies, and the follow-ups get MODEMIDENT_UNTERMINATED_READ_MS -- ten times
 * the value's measured arrival. Any other port keeps the full
 * MODEMIDENT_READ_MS, so a well-behaved modem is read exactly as before. */
#define MODEMIDENT_READ_MS              3000
#define MODEMIDENT_UNTERMINATED_AFTER_MS 2000
#define MODEMIDENT_UNTERMINATED_READ_MS  500
long modemident_followup_ms(long prior_read_ms, int prior_got_value);

/* The info reads' idle gap. The follow-up deadline above still left the
 * FIRST reads of such a port -- its IMEI and firmware -- at 3 s each, ~7 s per
 * --list per unit. So each single-line info read (AT+CGMR / +CGSN / +CGMI /
 * +CGMM) is issued through the readers' "info" form, which ends the exchange
 * once a value line has arrived and the port has then been silent this long.
 *
 * A modem that terminates answers in one burst (7-27 ms per exchange on the
 * modems tested, the T99W175 aside), so its OK ends the read first and its dialogue
 * is unchanged. One that terminates LATE has its OK land in the next read; a
 * bare OK before any value line therefore does not end an info read, the gap
 * does. Never used for a slow command (AT+QSCAN, AT#CSURVC, AT+COPS=?), whose
 * answer may legitimately pause. */
#define MODEMIDENT_INFO_IDLE_MS 200

/* 1 when at least one of make / model / firmware was read. An identity holding
 * only an IMEI says WHICH unit, not WHAT it is. */
int modemident_has_product(const modemident_t *id);

/* 1 when `s` has an IMEI's shape: exactly MODEMIDENT_IMEI_DIGITS ASCII digits,
 * nothing else.
 *
 * An AT+CGSN read is not trusted by position alone. A reply left on the port by
 * an earlier prober can land after the pre-command flush and be taken as the
 * answer: a PCIe RM520N-GL can be listed as "cellat-Quectel", its AT+CGMI
 * reply, and the IMEI also names the band-lock state file. Exactly 15,
 * not "14-17": a source is addressed as cellat-/celldiag-<15 digits> and both
 * definition parsers refuse any other length, so a looser check would still
 * mint names that cannot be opened. */
#define MODEMIDENT_IMEI_DIGITS 15
int modemident_imei_ok(const char *s);

/* Copy the value line of an AT reply into `out`: the first line that is not
 * blank, not a command echo ("AT..."), and not a final/error result (OK, ERROR,
 * +CME ..., +CMS ...). A leading response code ("+CGMR: ", "+CGSN: ") is
 * stripped, but ONLY when its colon precedes any space, so a firmware string
 * that merely contains a colon (Sierra's "... 2018/08/21 21:40:11") survives.
 * A leading "Manufacturer:" / "Model:" / "Revision:" label (the ATI-style
 * spelling some firmwares use for these commands) is stripped the same way.
 * Trailing CR/space is trimmed. `resp` is not modified.
 *
 * Returns 1 when a value was found, else 0 with out[0] == '\0'. */
int modemident_value(const char *resp, char *out, size_t out_sz);

/* The display label: "<make> <model> (<firmware>) IMEI:<imei><suffix>". With
 * neither make nor model it is the older shape "<firmware> IMEI:<imei>",
 * so an identity read from a firmware-only probe still renders sensibly.
 * `suffix` may be NULL (celldiag passes " DIAG").
 *
 * Returns 0, or -1 if `out` was too small (out is then truncated but
 * terminated). */
int modemident_label(const modemident_t *id, const char *suffix,
                     char *out, size_t out_sz);

/* The ModemIdentity JSON object (schema above). `method` is one of the
 * MODEMIDENT_METHOD_* spellings; `at_port` and `label` may be NULL or "".
 *
 * Returns 0, or -1 if `out` was too small -- in which case out[0] == '\0' so a
 * caller can never send half an object. */
int modemident_json(const modemident_t *id, const char *source_type,
                    const char *method, const char *at_port, const char *label,
                    char *out, size_t out_sz);

#ifdef __cplusplus
}
#endif

#endif
