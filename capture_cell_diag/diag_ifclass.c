/* diag_ifclass.c - USB-descriptor classification of a modem's DIAG interface.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * ---------------------------------------------------------------------------
 * Why this exists
 * ---------------------------------------------------------------------------
 * The fallback DIAG pick is "the ttyUSB with the LOWEST USB interface number
 * on the IMEI-matched USB device" -- the Qualcomm QCDM if00 convention, which
 * is a convention, not an invariant.
 *
 * The cost of getting that wrong is NOT a fast error. A LOG_CONFIG handshake
 * against a non-DIAG port cannot be distinguished from a slow modem, so it
 * waits out DIAG_RESP_TIMEOUT_S (20 s) per exchange. With celldiag_probe:
 *
 *     correct DIAG port  -> handshake succeeds in    0.02 s
 *     wrong port         -> handshake fails in 20.01 s (one deadline)
 *     wrong port         -> handshake fails in 60.05 s (three deadlines)
 *
 * So one mis-detected port costs 20-60 s of bring-up, far more than the AT
 * IMEI port scan (about 1.4 s for 27 ttyUSB nodes).
 *
 * The USB interface descriptor identifies DIAG deterministically, from sysfs,
 * with no device I/O at all.
 *
 * ---------------------------------------------------------------------------
 * Measured basis for the signature set
 * ---------------------------------------------------------------------------
 * Every ttyUSB on a six-modem test host, descriptor triple vs. an actual
 * celldiag_probe LOG_CONFIG handshake:
 *
 *   usbdev    vid:pid      if  cls/sub/prot   probe result
 *   1-3.2     1bc7:1040    00  ff/ff/ff       HANDSHAKE OK      (Telit LM960)
 *   1-3.3     2c7c:0700    00  ff/ff/ff       HANDSHAKE OK
 *   1-3.4.1   2c7c:0800    00  ff/ff/30       HANDSHAKE OK      (RM500Q)
 *   1-3.4.4   2c7c:0125    00  ff/ff/ff       correct port, SPC-gated (EG25-G)
 *   1-4       2c7c:0512    00  ff/ff/ff       HANDSHAKE OK
 *   2-3.4.3   2c7c:0801    00  ff/ff/30       HANDSHAKE OK      (RM520N-GL)
 *   1-3.1     05c6:90ad    00  ff/ff/30       (Qualcomm reference composition)
 *   1-2       1a86:7523    00  ff/01/02       ch341 USB-serial, NOT a modem
 *
 * and every AT / modem / NMEA / QMI-ish sibling on those same devices carried
 * ff/00/00, ff/00/40 or ff/fe/ff -- never ff/ff/*.
 *
 * Hence: DIAG == class 0xff AND subclass 0xff AND protocol in {0xff, 0x30}.
 *   - ff/ff/ff is the classic QCDM function.
 *   - ff/ff/30 is the newer Qualcomm composition (SDX55/SDX62 and the 05c6
 *     reference design) -- the same DIAG function, different protocol byte.
 *
 * TWO cases this fixes that lowest-interface cannot:
 *   1. A non-modem serial adapter enumerating on the matched device (the
 *      ch341 above is if00 -- lowest-interface would select it outright).
 *   2. 2c7c:0700, where if00/if01/if02 are ALL ff/ff/ff and if02 answers AT:
 *      descriptor + lowest-among-candidates still lands on if00 (verified).
 *
 * Conservative by construction: an unrecognised triple is NOT DIAG, and if no
 * candidate is classified the caller falls back to the
 * lowest-interface pick. So a composition this table has never seen degrades
 * to the if00 convention instead of to a wrong answer.
 */
#include "diag_ifclass.h"

#include <stddef.h>

#define USB_CLASS_VENDOR   0xff
#define USB_SUBCLASS_DIAG  0xff
#define USB_PROTO_QCDM     0xff   /* classic QCDM */
#define USB_PROTO_QC_NEW   0x30   /* SDX55/SDX62 + 05c6 reference composition */

int diag_ifclass_is_diag(int cls, int sub, int prot) {
    if (cls != USB_CLASS_VENDOR || sub != USB_SUBCLASS_DIAG)
        return 0;
    return prot == USB_PROTO_QCDM || prot == USB_PROTO_QC_NEW;
}

const char *diag_ifclass_label(int cls, int sub, int prot) {
    if (cls < 0 || sub < 0 || prot < 0)
        return "unreadable descriptor";
    if (diag_ifclass_is_diag(cls, sub, prot))
        return prot == USB_PROTO_QC_NEW ? "DIAG (ff/ff/30)" : "DIAG (ff/ff/ff)";
    if (cls == USB_CLASS_VENDOR && sub == 0x00)
        return "AT/NMEA-class (ff/00/xx)";
    if (cls == USB_CLASS_VENDOR)
        return "vendor-specific, non-DIAG";
    return "non-vendor class";
}

int diag_ifclass_count(const struct diag_ifcand *cands, int n) {
    int count = 0;
    if (!cands)
        return 0;
    for (int i = 0; i < n; i++) {
        if (diag_ifclass_is_diag(cands[i].cls, cands[i].sub, cands[i].prot))
            count++;
    }
    return count;
}

int diag_ifclass_pick(const struct diag_ifcand *cands, int n) {
    int best = -1;

    if (!cands)
        return -1;

    for (int i = 0; i < n; i++) {
        if (!diag_ifclass_is_diag(cands[i].cls, cands[i].sub, cands[i].prot))
            continue;
        if (best < 0) {
            best = i;
            continue;
        }
        /* Lowest bInterfaceNumber wins. A candidate whose interface number
         * could not be read ranks LAST among DIAG-classified candidates --
         * eligible (it is still a DIAG function) but never preferred over one
         * we can actually order. */
        int bi = cands[best].if_num, ci = cands[i].if_num;
        if (bi < 0 && ci >= 0)
            best = i;
        else if (bi >= 0 && ci >= 0 && ci < bi)
            best = i;
    }

    return best;
}
