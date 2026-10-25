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

    DIAG node classification for the NON-ttyUSB transports.

    diag_ifclass.{c,h} auto-detects the DIAG port on USB modems by USB
    interface descriptor (class ff / sub ff / proto {ff,30}). That method does not
    exist off USB: a PCIe modem reached over MHI has no USB descriptor to read.

    Off USB the function is encoded in the NODE NAME instead, and there are two
    incompatible conventions -- which is the whole reason this needs a classifier
    rather than one glob:

    1. MAINLINE wwan subsystem (drivers/net/wwan, `mhi_pci_generic` + `wwan`).
       Ports are named "wwan<N><type><M>": wwan0at0, wwan0mbim0, wwan0qmi0,
       wwan0qcdm0, wwan0firehose0. DIAG is the "qcdm" type -- Qualcomm
       DIAGNOSTIC MONITOR. Nothing in the name contains the string "diag", so a
       substring search for "diag" finds the DIAG port on ZERO mainline parts.

    2. OUT-OF-TREE MHI drivers (Quectel/Telit vendor stacks). Nodes are named
       after the MHI channel, uppercase: /dev/mhi_DIAG, /dev/mhi_DUN,
       /dev/mhi_QMI0, /dev/mhi_SAHARA, /dev/mhi_QDSS. Here DIAG *is* "DIAG" --
       but "qcdm" appears nowhere, so the mainline rule finds nothing either.

    A classifier keyed on one convention silently finds nothing on the other, and
    "found nothing" is indistinguishable from "no modem attached". Hence one
    module that knows both, with the near-miss names it must REFUSE pinned in its
    tests: mhi_QDSS is a trace channel, not DIAG, and selecting it yields a port
    that opens fine and never answers a LOG_CONFIG, costing 20 s per exchange.

    Pure libc (no sysfs, no glob, no Kismet link): the caller supplies the node
    names it found, so this is unit-testable standalone -- the same shape as
    diag_ifclass, and the reason both can be tested on a host with no such
    hardware attached.
*/

#ifndef __DIAG_WWANPORT_H__
#define __DIAG_WWANPORT_H__

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Upper bound on wwan/MHI nodes enumerated in one pass. A host with several PCIe
 * modems exposes a handful of ports each; this is a bounded-scan guard, not a
 * capacity target -- overflowing it can only make the DIAG node LOOK absent
 * (an open error naming the fix), never make a wrong node get selected. */
#define DIAG_WWAN_MAX_NODES 64

/* Transport family a node name belongs to. */
typedef enum {
    DIAG_WWAN_NONE = 0,   /* not a recognized non-ttyUSB modem node */
    DIAG_WWAN_MAINLINE,   /* wwan subsystem: wwan0qcdm0, wwan0at0, ... */
    DIAG_WWAN_MHI_OOT,    /* out-of-tree MHI: mhi_DIAG, mhi_DUN, ... */
} diag_wwan_family_t;

/* Classify one node NAME (basename, e.g. "wwan0qcdm0" or "mhi_DIAG"; a full
 * /dev/... path is also accepted and reduced to its basename).
 *
 * Returns the family, and sets *is_diag to 1 iff this node is the DIAG/QCDM
 * function of that family. A recognized-but-not-DIAG node (wwan0at0, mhi_DUN)
 * returns its family with *is_diag == 0 -- the distinction matters because
 * "recognized sibling" is evidence a modem IS present on this transport, which
 * is what makes a "found the modem but not its DIAG node" diagnostic possible.
 *
 * `is_diag` may be NULL. */
diag_wwan_family_t diag_wwan_classify(const char *node, int *is_diag);

/* 1 iff this node is the AT-COMMAND surface of its family, 0 otherwise.
 *
 * The mirror of `is_diag`, and it needs the same table for the same reason: the
 * two families spell the AT function DIFFERENTLY. Mainline wwan calls it "at"
 * (wwan0at0); the out-of-tree MHI stack calls it "DUN" (mhi_DUN, Dial-Up
 * Networking). A search for "at" finds the AT port on ZERO out-of-tree parts; a
 * search for "dun" finds it on ZERO mainline parts.
 *
 * This exists so cellat can ADMIT nodes, not merely rank them. Its ttyUSB
 * scan is admitted by sysfs driver / vendor id (diag_portadmit.h), and
 * every port that rule admits is some serial function of a modem; that is not
 * true here. An unfiltered /dev/mhi_*
 * enumeration would write "ATI\r" into mhi_SAHARA -- the EDL/firehose protocol
 * channel -- and into wwan0firehose0. So the AT scan must select, and the only
 * safe selector is the one that already knows both naming conventions.
 *
 * A full /dev/... path is accepted and reduced to its basename. NULL, an empty
 * name, and any non-modem node return 0. */
int diag_wwan_is_at(const char *node);

/* Human label for the node's function ("diag", "at", "qmi", "mbim", "firehose",
 * "dun", "sahara", "trace", or "unknown"). For operator diagnostics; never
 * parsed. Returns a static string, never NULL. */
const char *diag_wwan_label(const char *node);

/* Pick the DIAG node out of `n` candidate names.
 *
 * Returns the index of the single DIAG node, or:
 *   -1  no candidate is a DIAG node
 *   -2  MORE THAN ONE candidate is a DIAG node (ambiguous)
 *
 * The ambiguous case is reported rather than resolved. Unlike ttyUSB, where a
 * sibling AT port anchors the selection to one physical modem by IMEI, two
 * wwan/MHI DIAG nodes carry nothing in their names tying either to a specific
 * modem -- so picking one would be a coin flip that presents as a working source
 * bound to the wrong device. An operator `diagport=` is the correct resolution,
 * and an explicit -2 is what lets the caller say so. */
int diag_wwan_pick(const char *const *nodes, int n);

/* Compose an operator-facing diagnostic for a failed selection, mirroring
 * diag_portdiag_format's role for ttyUSB: what was searched, what was found, and
 * what to do. `rc` is diag_wwan_pick's return. Always NUL-terminates. */
void diag_wwan_format(int rc, const char *const *nodes, int n,
                      char *out, size_t outsz);

#ifdef __cplusplus
}
#endif

#endif /* __DIAG_WWANPORT_H__ */
