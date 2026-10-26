/* diag_privdrop.h - drop a setuid/setgid install's elevated ids in a forked
 * child.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * `make suidinstall` installs kismet_cap_cell_at and kismet_cap_cell_diag
 * setuid root, mode 4550, like every other Kismet capture. The few files the
 * captures write themselves (cell_safefile.h) are opened in a child that has
 * given the elevated ids up -- real ids become all three of
 * real/effective/saved -- so a path the caller cannot write as themselves
 * cannot be written through the capture.
 *
 * Not suid (ruid == euid, rgid == egid): a no-op, returns 0.
 *
 * FAILS CLOSED: if an id cannot be dropped, or can be regained afterwards,
 * this returns -1 and writes why into err. Callers _exit().
 * Header-only (static inline), so both captures and their selftests share one
 * implementation with no new object in either build. */

#ifndef __DIAG_PRIVDROP_H__
#define __DIAG_PRIVDROP_H__

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static inline int diag_child_drop_privs(char *err, size_t errsz) {
    uid_t ru = getuid(), eu = geteuid();
    gid_t rg = getgid(), eg = getegid();

    /* Group first: once the uid is gone, so is the right to change the gid. */
    if (eg != rg) {
        if (setregid(rg, rg) != 0) {
            snprintf(err, errsz, "setregid(%ld) failed: %s",
                     (long) rg, strerror(errno));
            return -1;
        }
    }
    if (eu != ru) {
        /* setreuid with the real id given also resets the SAVED id to the new
         * effective one (Linux, the BSDs, macOS), so nothing is kept to swap
         * back to. setuid() alone would not do that for a non-root suid. */
        if (setreuid(ru, ru) != 0) {
            snprintf(err, errsz, "setreuid(%ld) failed: %s",
                     (long) ru, strerror(errno));
            return -1;
        }
    }

    /* Prove it: every id is the real one, and the old ones cannot come back. */
    if (getuid() != ru || geteuid() != ru || getgid() != rg || getegid() != rg) {
        snprintf(err, errsz, "ids after drop are uid %ld/%ld gid %ld/%ld",
                 (long) getuid(), (long) geteuid(), (long) getgid(), (long) getegid());
        return -1;
    }
    if (eu != ru && setuid(eu) == 0) {
        snprintf(err, errsz, "uid %ld could be regained after the drop", (long) eu);
        return -1;
    }
    if (eg != rg && ru != 0 && setgid(eg) == 0) {
        snprintf(err, errsz, "gid %ld could be regained after the drop", (long) eg);
        return -1;
    }
    return 0;
}

#endif
