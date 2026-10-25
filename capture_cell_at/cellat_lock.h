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

    cellat_lock -- band/RAT lock as the source's CHANNELS.

    The Wi-Fi source's channel buttons, Lock and Hop, for a cell modem. A
    channel is a named lock preset:

        AUTO        the modem's settings AS FOUND at open (the default)
        LTE         LTE only, every LTE band the modem had enabled
        NR5G        NR standalone only, every NR band it had enabled
        LTE-B<n>    LTE only, band n only
        NR-n<n>     NR SA only, band n only
        LTE-B<n>+<m>...   LTE only, exactly that SET of bands, e.g.
                    LTE-B2+4+12+66 -- one channel, so it is a Lock target and a
                    Hop list element like any preset. NR-n<n>+<m>... likewise.
                    Every band must be one the modem had enabled as found.
                    Not advertised as a preset (the sets are combinatorial):
                    set it by channel= or the set_channel route.

    Lock = Kismet's set_channel; Hop = Kismet's channel hop over a chosen list.
    Nothing is written to the modem until a channel other than AUTO is set.

    Every lever here is written to the modem's NV. A lock survives a reboot,
    so a modem must never be left locked:
      * the settings AS FOUND are saved to a host state file BEFORE the first
        write, and removed only after a restore succeeds;
      * the capture's teardown restores them;
      * the next open finds a state file a crashed session left and restores
        from it first, and then treats the FILE, not the modem, as the
        original settings, because the modem may still be locked.

    Backends, each PROBED at open and never asserted from the vendor name:

      QNWPREF  Quectel AT+QNWPREFCFG (RM500Q / RM520N-GL and siblings): RAT
               and the LTE / NR-SA band lists, so every channel above.
      SELRAT   Sierra AT!SELRAT=<index> (EM9190 / EM9291): RAT only.
               The index table differs by firmware -- "LTE Only" is 04 on
               01.07.19 and 06 on 03.17.04 -- so the LTE and NR indices are
               read BY NAME from AT!SELRAT=? at open, never from a table.
      QCFG     Quectel AT+QCFG (EG25-G and the EC2x/EG2x family, where
               QNWPREFCFG answers ERROR): RAT via "nwscanmode" (3 = LTE only)
               and ONE LTE band via "band". The GSM/WCDMA and TD-SCDMA fields
               are written as 0, which the QCFG manual V1.3 §5.4 defines as
               "no change", so only the LTE mask is ever touched; it is kept
               as bare hex, the form the manual writes back.
      WS46     3GPP AT+WS46=<n> (Telit LM960): RAT only. The codes come from
               AT+WS46=? (the LM960 offers 22,28,31): 28 = E-UTRAN only, 35 =
               NG-RAN only; AUTO is whatever was read.
      CNMP     SIMCom AT+CNMP=<mode> (SIM8202G-M2 and the SIM82xx/SIM7600
               lines): RAT only. 38 = LTE only, 71 = NR5G, read from
               AT+CNMP=? by whole number. On a SIM8202G-M2
               (LE13B04SIM8202M44A-M2) each write applies at once
               (LTE camp ~2.6 s, NR SA ~2 s), and 2 restores the as-found
               every-RAT mask byte for byte. A read of 100 ("UNKNOW": the mask
               matches no table row) is listed by =? but ERRORs on write, so a
               modem found at 100 is offered NO lock -- it could not be undone.

    A RAT-only backend offers AUTO, LTE and (when the modem lists it) NR5G --
    no band channels. Other vendors' band commands are not wired up yet:
    Telit AT#BND needs a CFUN cycle and a 30 s read; SIMCom bands
    (AT+CNBP / AT+CBANDCFG) are not wired up.

    Pure libc, so test_cellat_lock runs with no modem and no framework.
*/

#ifndef __CELLAT_LOCK_H__
#define __CELLAT_LOCK_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CELLAT_LOCK_MODE_MAX    64
#define CELLAT_LOCK_BANDS_MAX   512
#define CELLAT_LOCK_CHAN_MAX    16
/* A requested or in-force lock: presets fit CELLAT_LOCK_CHAN_MAX, a band SET
 * ("LTE-B2+4+12+66+71") does not. A longer request is refused whole,
 * never truncated -- a truncated set would lock the modem to the WRONG bands. */
#define CELLAT_LOCK_SET_MAX     64
#define CELLAT_LOCK_CHANNELS_MAX 160
#define CELLAT_LOCK_CMD_MAX     (CELLAT_LOCK_BANDS_MAX + 64)

typedef enum {
    CELLAT_LOCK_QNWPREF = 0,   /* Quectel AT+QNWPREFCFG: RAT + band lists */
    CELLAT_LOCK_SELRAT  = 1,   /* Sierra AT!SELRAT=<index>: RAT only */
    CELLAT_LOCK_WS46    = 2,   /* 3GPP AT+WS46=<n>: RAT only */
    CELLAT_LOCK_QCFG    = 3,   /* Quectel AT+QCFG "nwscanmode" + "band" (EG25-G) */
    CELLAT_LOCK_CNMP    = 4,   /* SIMCom AT+CNMP=<mode>: RAT only */
} cellat_lock_backend_t;

/* One set of the levers, verbatim as the modem spells them, plus the
 * vocabulary a RAT-only backend needs to reach LTE / NR (read at open). An
 * empty band list means "not readable on this modem": it is never offered as
 * a channel and never written. */
typedef struct {
    int  backend;                           /* cellat_lock_backend_t */
    char mode_pref[CELLAT_LOCK_MODE_MAX];   /* QNWPREF "AUTO"/"LTE"/"NR5G"/"LTE:NR5G";
                                             * SELRAT "06"; WS46 "31"; CNMP "2" */
    char lte_band[CELLAT_LOCK_BANDS_MAX];   /* QNWPREF: "1:2:3:66:71";
                                             * QCFG: the LTE mask, bare hex "1e00b0e18df" */
    char nr5g_band[CELLAT_LOCK_BANDS_MAX];  /* QNWPREF only: SA bands, "41:71:77" */
    char rat_lte[8];                        /* SELRAT/WS46/CNMP: the code for LTE only; "" = none */
    char rat_nr[8];                         /* SELRAT/WS46/CNMP: the code for NR only; "" = none */
} cellat_lock_settings_t;

/* The value of `+QNWPREFCFG: "<key>",<value>` in a read's response.
 *
 * Returns 1 and copies the value (surrounding quotes and whitespace removed),
 * 0 when the response carries no such line. A band list that is not a colon
 * list of band numbers -- R01A08's `"nr5g_band",0`, or a quoted list from the
 * `rf_band` family -- is NOT a usable list: returns 0, so it is neither offered
 * nor ever written back (whether writing `0` restores anything is untested). */
int cellat_lock_parse_read(const char *resp, const char *key,
                           char *out, size_t out_sz);

/* The RAT-only backends' reads:
 *   "!SELRAT: 00, Automatic"   -> "00"   (1-2 hex digits)
 *   "+WS46: 31"                -> "31"   (decimal)
 * and their lists, which fill rat_lte / rat_nr and return 1 when at least one
 * was found:
 *   AT!SELRAT=?  rows "<idx>, <name>": "LTE Only" -> LTE; "NR 5G Only" or
 *                "5G Only" -> NR (names matched whole, case-insensitive)
 *   AT+WS46=?    "+WS46: (22,28,31)": 28 -> LTE, 35 -> NR */
int cellat_lock_parse_selrat_read(const char *resp, char *out, size_t out_sz);
int cellat_lock_parse_selrat_list(const char *resp, cellat_lock_settings_t *s);
int cellat_lock_parse_ws46_read(const char *resp, char *out, size_t out_sz);
int cellat_lock_parse_ws46_list(const char *resp, cellat_lock_settings_t *s);

/* CNMP: "+CNMP: 2" -> "2" (1-3 decimal digits). Returns -1 for 100, which
 * the modem reports but will not take back, so no lock may start
 * from it. The list "+CNMP: (2,14,38,71,...)" gives 38 -> LTE, 71 -> NR,
 * whole numbers only. */
int cellat_lock_parse_cnmp_read(const char *resp, char *out, size_t out_sz);
int cellat_lock_parse_cnmp_list(const char *resp, cellat_lock_settings_t *s);

/* QCFG reads: +QCFG: "nwscanmode",<n> -> "<n>"; +QCFG: "band",<gw>,<lte>,<tds>
 * -> the LTE mask as bare lowercase hex. A zero mask is refused: 0 means "no
 * change" on the write side and would restore nothing. */
int cellat_lock_parse_qcfg_scanmode(const char *resp, char *out, size_t out_sz);
int cellat_lock_parse_qcfg_band(const char *resp, char *out, size_t out_sz);

/* The channel names for these settings, in display order: AUTO, LTE, NR5G
 * (only with a usable NR list), then each LTE band, then each NR band.
 * Returns the count; `out` receives up to `max` names of up to
 * CELLAT_LOCK_CHAN_MAX bytes each. */
size_t cellat_lock_channels(const cellat_lock_settings_t *orig,
                            char out[][CELLAT_LOCK_CHAN_MAX], size_t max);

/* What `channel` means for a modem whose settings as found are `orig`.
 * Returns 0 and fills `target`, or -1 with a reason in `err` (an unknown
 * channel, or a band this modem did not have enabled). Case-insensitive. */
int cellat_lock_target(const cellat_lock_settings_t *orig, const char *channel,
                       cellat_lock_settings_t *target, char *err, size_t err_sz);

/* The AT writes that take the modem from `cur` to `target`, in the order to
 * send them: band lists first, then the RAT, so a band lock never runs for a
 * moment under a RAT it was not meant for. Only differing levers are written,
 * and an empty band list is never written. Returns the count (0..3). */
size_t cellat_lock_writes(const cellat_lock_settings_t *cur,
                          const cellat_lock_settings_t *target,
                          char cmds[][CELLAT_LOCK_CMD_MAX], size_t max);

/* Record in `cur` that `cmd` -- one of cellat_lock_writes()' commands toward
 * `target` -- was accepted by the modem. The lever is decided HERE, from the
 * command family, not by the caller: a helper that matched only the
 * QNWPREFCFG spellings would book an AT+QCFG="band" write as a RAT write, and
 * the close would then restore the RAT but leave the band mask locked. */
void cellat_lock_note_write(cellat_lock_settings_t *cur,
                            const cellat_lock_settings_t *target, const char *cmd);

/* The crash-restore state file: the settings AS FOUND, written before the
 * first write to the modem. `imei` and the backend are recorded and checked
 * on read, so a file can never restore one modem's settings onto another, or
 * one command family's values through another's. (A file with no backend line
 * predates the RAT-only backends and is QNWPREF.)
 * write: 0 ok, -1 errno. read: 1 found (orig filled), 0 absent,
 * -1 unreadable/malformed/another modem's (`err` says which). */
int cellat_lock_state_write(const char *path, const char *imei,
                            const cellat_lock_settings_t *orig);
int cellat_lock_state_read(const char *path, const char *imei, int backend,
                           cellat_lock_settings_t *orig, char *err, size_t err_sz);

/* The default state-file path for `imei`: $HOME/.kismet/cellat-lock-<imei>.state
 * (Kismet's own per-user directory), or /tmp when HOME is unset. */
void cellat_lock_default_state_path(const char *imei, char *out, size_t out_sz);

#ifdef __cplusplus
}
#endif

#endif
