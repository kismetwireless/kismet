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
*/

#ifndef __WIRED_PRIV_H__
#define __WIRED_PRIV_H__

#include "../config.h"

#include <sys/types.h>

#include "../capture_framework.h"

/* What kismet_cap_wired is left with once it gives up its privileges */
typedef struct {
    /* Started with a real, effective or saved uid of 0 */
    int was_root;
    /* Started with a gid or supplementary group of 0 */
    int root_group;
    /* Switched from root (or gid 0) to uid and gid */
    int left_root;
    uid_t uid;
    gid_t gid;
    /* Still uid or gid 0, of a user namespace (a container's) which couldn't switch
     * and doesn't map them to root outside; why says why */
    int userns_root;
    /* /proc/sys bound read-only in the filesystem jail */
    int proc_sys_ro;
    /* No CAP_NET_RAW to keep, so no interface will open */
    int no_net_raw;
    /* Why the helper has to exit, or why it stays uid 0 of a user namespace */
    char why[STATUS_MAX];
} wired_priv_t;

/* Run once in main, after cf_handler_remote_capture: jails the filesystem with
 * /proc/sys read-only, cuts the capabilities to CAP_NET_RAW, and holding any uid 0
 * (real, effective or saved) switches to wired_unpriv_ids first, keeping CAP_NET_RAW
 * across the change; gids 0 and a supplementary group 0 are left too.  Without
 * capabilities, uid 0 still owns most of /proc/sys, /sys and /dev and can write
 * them.  In a user namespace which can't switch (uid 65534 isn't mapped, or
 * setgroups is denied) it stays uid 0 there.  In any user namespace but the
 * initial one, root or not, it then sets its real and saved ids to the effective
 * ones and exits when its uid, gid or a supplementary group isn't mapped or maps
 * to 0 of the parent namespace (root's own 'unshare -r'), or when /proc/sys shows
 * it's root further up the chain: its uid opens a sysctl only the initial uid 0
 * may, or a gid is the one root's group shows as.  A supplementary group shown as
 * the overflow gid can't be told from root's group, so it's fatal too.  Not seen:
 * a chain that maps the overflow gid itself to root's group, or a security module
 * refusing the initial root that open.  Last it sets
 * no_new_privs.  Returns 1, or -1 when the helper has to exit: a drop, the switch
 * or a check failed, it runs as root without libcap, or without libcap holds more
 * than CAP_NET_RAW */
int wired_drop_privileges(kis_capture_handler_t *caph, wired_priv_t *p);

/* Ids 0 held: a real, effective or saved uid or gid, or a supplementary group */
#define WIRED_ROOT_UID          0x1
#define WIRED_ROOT_GID          0x2
#define WIRED_ROOT_GROUPS       0x4

/* The WIRED_ROOT_* bits of the ids held, or -1 when they can't be read */
int wired_root_ids(void);

#endif
