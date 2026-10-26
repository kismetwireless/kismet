/* diag_identvouch.h - a port's holder vouches for the modem identity it read.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * The problem. Both cell capture helpers take an exclusive flock on a
 * tty before they speak AT on it. That claim is right -- two
 * processes sharing one AT port split each other's replies -- but it carries no
 * payload. A scanner that meets a held port learns only THAT it is held, never
 * by whom or for which modem.
 *
 * A typical setup pairs a cellat source and a celldiag source on every modem,
 * and celldiag maps IMEI -> DIAG port by AT-probing the modem's ports. The
 * paired cellat holds its AT port for the whole run. Without a vouch:
 *
 *   - a single-AT-port modem (a Foxconn T99W175) can NEVER be opened by its
 *     celldiag while its cellat runs;
 *   - a two-AT-port modem (the RM500Q-AE) opens only when its second port
 *     happens not to be mid-probe by some other source's scan.
 *
 * The one process that already KNOWS the answer is the holder: it verified the
 * IMEI on that very port. So the holder publishes what it read, as a small
 * record keyed by the port, and withdraws it on close. A scanner that meets a
 * held port may read the record, and accepts it only after validating it:
 *
 *   - the record names this port, schema v1, a 15-digit IMEI;
 *   - the port's device node is the SAME node instance the holder read: st_rdev,
 *     st_ino and the node's ctime all match. A USB re-enumeration re-creates the
 *     node, so a record that outlived its device can never vouch for whatever
 *     modem later gets the same name. A modem's IMEI does not change while its
 *     node exists; a firmware update re-enumerates;
 *   - the writer is still alive (kill(pid, 0)). Belt and braces: a record from
 *     a dead writer on a still-identical node would still be TRUE, but a record
 *     nobody stands behind is not accepted.
 *
 * A vouch is second-hand, and the record that consumes it must say so: the
 * celldiag ModemIdentity method is MODEMIDENT_METHOD_VOUCHED, never "at".
 *
 * Where records live: $KISMET_CELL_VOUCH_DIR when set (tests), else
 * /run/kismet-cell when running as root on a host that has /run, else
 * /tmp/kismet-cell-<euid>. The directory is created 0700 and REFUSED unless it
 * is a real directory (not a symlink) owned by this euid with no group/other
 * access -- the record steers which device a capture opens, so it must not be
 * writable by anyone else. Every failure here is silent and non-fatal: a vouch
 * that cannot be written or read leaves the scan exactly as it was before.
 *
 * Pure libc, no Kismet link: selftested standalone (test_diag_identvouch.c) and
 * linked by both helpers.
 */
#ifndef DIAG_IDENTVOUCH_H
#define DIAG_IDENTVOUCH_H

#include <stddef.h>
#include <sys/types.h>

#include "diag_modemident.h"

#ifdef __cplusplus
extern "C" {
#endif

#define IDENTVOUCH_SCHEMA  1
#define IDENTVOUCH_ENV_DIR "KISMET_CELL_VOUCH_DIR"

/* The record directory, created and verified; NULL when none is usable. The
 * returned pointer is to static storage, valid until the next call. */
const char *identvouch_dir(void);

/* Publish: this process holds `port` and verified `id` on it. Atomic (write a
 * temp file, rename). Returns 0, or -1 (silently) when it could not. `id` must
 * carry a 15-digit IMEI. */
int identvouch_publish(const char *port, const modemident_t *id);

/* Withdraw this process's record for `port`. A record another process wrote
 * (a newer holder of the same port) is left alone. */
void identvouch_withdraw(const char *port);

/* Look up a VALID vouch for `port` (see the rules above). Returns 1 and fills
 * `id_out` (and `writer_pid`, if non-NULL) when one exists, else 0 with
 * `id_out` cleared. */
int identvouch_lookup(const char *port, modemident_t *id_out, pid_t *writer_pid);

/* The record's file name for `port` under the directory: the path with '/'
 * mapped to '_' plus ".vouch" ("/dev/ttyUSB8" -> "_dev_ttyUSB8.vouch").
 * Exposed for the selftest. Returns 0, or -1 if `out` is too small. */
int identvouch_filename(const char *port, char *out, size_t out_sz);

#ifdef __cplusplus
}
#endif

#endif
