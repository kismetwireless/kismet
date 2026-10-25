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

    cellat port-scan ADMISSION decisions.

    Why this exists: find_modem_ports() is `static` inside the
    capture-framework-linked translation unit, so neither which node names are
    AT nor whether /dev/wwan* and /dev/mhi_* are enumerated at all could be
    tested over a synthetic candidate list. This module extracts both. Same
    shape, and the same reason, as cellat_options.c and phy_cell_decisions:
    the DECISION is separable from the SYSCALL that feeds it. glob(2) supplies candidate paths;
    everything after that -- which source patterns are searched at all, which
    candidates are admitted, and how the result list is bounded -- is pure
    string logic that a test can drive with a synthetic candidate list on a host
    with no modem attached.

    The filter is a SAFETY PROPERTY, not a ranking hint -- on EVERY source.
    It is tempting to probe every ttyUSB/ttyACM candidate on the theory that
    each is *some* modem serial function and a wrong pick costs a timeout. A
    wrong pick costs another device its configuration: a probe sets 115200
    raw, flushes both queues and writes "AT\r\n", which can leave a GNSS
    receiver behind a CH340 bridge reading line noise until it is reconfigured.
    So those sources are SUSPECTED: diag_port_admit() (diag_portadmit.h)
    decides from sysfs, before open(), and admits only a tty bound to a
    cellular usb-serial driver (option / qcserial / sierra) or a cdc_acm tty on
    a cellular vendor id. The non-USB directories are a second case: /dev/mhi_* also holds SAHARA and BHI (the EDL
    bootloader / firmware-download channels), QDSS (trace) and the IP data
    channels; /dev/wwan* holds wwan0firehose0. An UNFILTERED enumeration would
    write "ATI\r" into the EDL channel of every PCIe modem on the host during a
    routine source scan. So the scan must SELECT, and the only safe selector is
    diag_wwan_is_at() -- the classifier that already knows both non-USB naming
    conventions, shared with celldiag so the two sources can never both claim
    one node.

    A node type that is UNKNOWN to the classifier is REFUSED, not admitted.
    /dev/mhi_ADB and /dev/mhi_BHI are not in the classifier's channel table;
    both are refused by that fail-closed default.
    The selftest pins them BY NAME anyway, because "refused because the table
    says so" and "refused because the table has never heard of it" are the same
    outcome today and a one-line table edit apart tomorrow.
*/

#ifndef __CELLAT_PORTSCAN_H__
#define __CELLAT_PORTSCAN_H__

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Width of one entry in the caller's port array. find_modem_ports() has always
 * used 256; named here so the truncation rule below is stated against a
 * constant rather than a literal repeated at each strncpy. */
#define CELLAT_PORT_PATH_MAX 256

/* How candidates matched by a source pattern are treated. */
typedef enum {
    /* Every candidate is admitted (length and NULL checks only). Correct ONLY
     * for paths the OPERATOR named -- CELLAT_EXTRA_PORTS / CELLAT_SCAN_PORTS
     * -- where the naming is the decision. No scan SOURCE uses it: a wrong
     * pick does not merely cost a timeout when it reconfigures a GNSS
     * receiver. */
    CELLAT_SCAN_UNFILTERED = 0,

    /* Only nodes diag_wwan_is_at() affirms are admitted. Required for any
     * directory that also exposes a bootloader/firmware-download channel. */
    CELLAT_SCAN_CLASSIFIED = 1,

    /* USB serial ttys: admitted only when diag_port_admit() finds a
     * suspected cell modem in sysfs -- a cellular usb-serial driver, or cdc_acm
     * on a cellular vendor id. A refused tty is never opened. */
    CELLAT_SCAN_SUSPECTED = 2,
} cellat_scan_filter_t;

typedef struct {
    const char *pattern;            /* glob(3) pattern */
    cellat_scan_filter_t filter;
    const char *why;                /* operator-facing note; never parsed */
} cellat_scan_source_t;

/* The source patterns find_modem_ports() enumerates, in scan order.
 *
 * Exported so a test can assert the NON-USB patterns are present at all. A
 * build in which
 * diag_wwan_is_at() is perfect but /dev/wwan* is never globbed discovers
 * nothing on an inline-attached modem, and looks exactly like "no modem
 * attached". */
const cellat_scan_source_t *cellat_scan_sources(size_t *n);

/* Admission verdict for one candidate path found under `filter`.
 *
 * Returns 1 to admit, 0 to refuse. Refuses NULL, the empty string, and any path
 * that would not fit CELLAT_PORT_PATH_MAX -- see cellat_scan_add().
 *
 * Under CELLAT_SCAN_SUSPECTED this reads sysfs (at cellat_scan_sysfs_root()),
 * never the device node, and a refusal is recorded for cellat_scan_refusals()
 * and logged once per path per process to the refusal stream. */
int cellat_scan_admit(cellat_scan_filter_t filter, const char *path);

/* The sysfs root CELLAT_SCAN_SUSPECTED reads. DIAG_PORTADMIT_SYSFS ("/sys")
 * unless set; NULL restores it. Exists so the selftest can point the real
 * admission path at a fake tree -- production never sets it. */
void cellat_scan_set_sysfs_root(const char *root);
const char *cellat_scan_sysfs_root(void);

/* Where a SUSPECTED refusal's once-per-path line goes: stderr unless set; NULL
 * silences it (the selftest). */
void cellat_scan_set_refusal_log(FILE *f);

/* The candidates SUSPECTED refused since the last reset, as
 * "ttyUSB0(ch341-uart 1a86:7523),..." -- for the open's scan detail. Never
 * NULL; "" when nothing was refused. find_modem_ports() resets it per scan. */
void cellat_scan_refusals_reset(void);
const char *cellat_scan_refusals(void);

/* Append `path` to `ports[]` if cellat_scan_add's rules allow it.
 *
 * Returns 1 if appended, 0 otherwise. `*count` is advanced on append.
 *
 * REFUSES rather than TRUNCATES an over-long path. A bounded
 * `strncpy(dst, src, 255); dst[255] = '\0';` silently yields a DIFFERENT path
 * -- one that either does not exist (a modem that mysteriously stopped being
 * found) or, worse, names a real node that happens to be a prefix. A dropped
 * candidate is recoverable and diagnosable, a silently rewritten one is not.
 *
 * REFUSES a path already in `ports[]`. The scan patterns are mutually
 * disjoint, but CELLAT_EXTRA_PORTS is an operator-supplied glob list whose
 * documented use is "add a port the scan did not find" -- and naming one it DID
 * find is the obvious operator error. The downstream de-duplication cannot
 * catch it: it keys on the sysfs USB device id, and a non-USB node has none, so
 * get_usb_device_id() fails and the port is explicitly "treated as unique". A
 * duplicate /dev/mhi_DUN is therefore probed twice and, if it answers, reports
 * the same modem as two sources. */
int cellat_scan_add(char ports[][CELLAT_PORT_PATH_MAX], int *count, int max_ports,
                    cellat_scan_filter_t filter, const char *path);

/* Admission verdict for a path the OPERATOR named -- CELLAT_SCAN_PORTS
 * or CELLAT_EXTRA_PORTS -- rather than one a scan pattern found.
 *
 * Returns 1 to admit, 0 to refuse. `resolved` is the path's realpath(3), or
 * NULL when it has none (a dangling link, a glob that matched nothing real).
 *
 * A named path is trusted -- it is not the scan's business to second-guess it --
 * EXCEPT where it lands in a directory the scan itself treats as CLASSIFIED
 * (/dev/wwan*, /dev/mhi_*). There diag_wwan_is_at() still decides, because
 * `CELLAT_SCAN_PORTS=/dev/mhi_*` is the natural way to say "the PCIe modem's AT
 * node" and would otherwise write "AT" into mhi_SAHARA and mhi_BHI -- the EDL
 * and firmware-download channels -- on every open. The resolved path is checked
 * too, so a symlink cannot launder a SAHARA node past the classifier; a link to
 * a real AT node (e.g. /tmp/dun -> /dev/mhi_DUN) is admitted on its target. */
int cellat_scan_admit_named(const char *path, const char *resolved);

/* cellat_scan_add() for an operator-named path: cellat_scan_admit_named()
 * decides, and the same duplicate, bound and no-truncation rules apply. */
int cellat_scan_add_named(char ports[][CELLAT_PORT_PATH_MAX], int *count,
                          int max_ports, const char *path, const char *resolved);

#ifdef __cplusplus
}
#endif

#endif /* __CELLAT_PORTSCAN_H__ */
