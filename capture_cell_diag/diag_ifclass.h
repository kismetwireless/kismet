/* diag_ifclass.h - USB-descriptor classification of a modem's DIAG interface.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Part of per-modem DIAG port auto-detection. See diag_ifclass.c for the
 * measured basis of the signature set.
 *
 * Pure libc: no sysfs, no Kismet link, so it unit-tests standalone
 * (test_diag_ifclass.c). The caller gathers the descriptor triple from sysfs
 * and hands it here.
 */
#ifndef DIAG_IFCLASS_H
#define DIAG_IFCLASS_H

#ifdef __cplusplus
extern "C" {
#endif

/* One candidate tty on the IMEI-matched USB device, with its USB interface
 * descriptor. Any field the caller could not read must be set to -1 (NOT 0 --
 * 0 is a legitimate bInterfaceNumber and a legitimate class byte). */
struct diag_ifcand {
    char path[256];
    int  if_num;    /* bInterfaceNumber, -1 if unreadable */
    int  cls;       /* bInterfaceClass, -1 if unreadable */
    int  sub;       /* bInterfaceSubClass, -1 if unreadable */
    int  prot;      /* bInterfaceProtocol, -1 if unreadable */
};

/* 1 if the descriptor triple is a known Qualcomm DIAG/QCDM signature.
 * Deliberately conservative: an unrecognised triple returns 0 so the caller
 * falls back to the lowest-interface heuristic rather than
 * selecting a port this function cannot vouch for. */
int diag_ifclass_is_diag(int cls, int sub, int prot);

/* Human label for a triple ("QCDM (ff/ff/ff)", "AT/NMEA (ff/00/00)", ...),
 * for the actionable detection diagnostics. Never NULL. */
const char *diag_ifclass_label(int cls, int sub, int prot);

/* Select the DIAG node among `cands` by descriptor: the DIAG-signature
 * candidate with the lowest bInterfaceNumber. Returns its index, or -1 when
 * no candidate carries a DIAG signature -- which the caller must treat as
 * "descriptor classification declined", falling back to lowest-interface.
 * Candidates with an unreadable if_num are eligible but rank last. */
int diag_ifclass_pick(const struct diag_ifcand *cands, int n);

/* Number of candidates carrying a DIAG signature (diagnostics/tests). */
int diag_ifclass_count(const struct diag_ifcand *cands, int n);

#ifdef __cplusplus
}
#endif

#endif /* DIAG_IFCLASS_H */
