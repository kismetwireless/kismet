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

#if defined(__linux__) && !defined(_GNU_SOURCE)
#define _GNU_SOURCE     /* setresuid, getresuid, setgroups, ST_NOATIME */
#endif

#include "wired_priv.h"

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include <linux/capability.h>
#include <linux/securebits.h>

#include "wired_util.h"

/* linux/prctl.h from 3.5 */
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS     38
#endif

/* The initial user namespace's inode, PROC_USER_INIT_INO in linux/proc_ns.h, fixed
 * since 3.8 */
#define WIRED_INIT_USERNS_INO   0xEFFFFFFDU

/* Ids 0 held: a real, effective or saved uid or gid, or a supplementary group */
#define WIRED_ROOT_UID          0x1
#define WIRED_ROOT_GID          0x2
#define WIRED_ROOT_GROUPS       0x4

static void wired_why_append(wired_priv_t *p, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));

static void wired_why_append(wired_priv_t *p, const char *fmt, ...) {
    size_t l = strnlen(p->why, sizeof(p->why));
    va_list ap;

    if (l >= sizeof(p->why) - 1)
        return;

    va_start(ap, fmt);
    vsnprintf(p->why + l, sizeof(p->why) - l, fmt, ap);
    va_end(ap);
}

/* The supplementary groups into a new array in *groups (NULL for none).  Returns
 * how many, or -1 */
static int wired_get_groups(gid_t **groups) {
    int n;

    *groups = NULL;

    if ((n = getgroups(0, NULL)) <= 0)
        return n;

    if ((*groups = calloc((size_t) n, sizeof(gid_t))) == NULL)
        return -1;

    /* A list which grew since the count fails with EINVAL */
    if ((n = getgroups(n, *groups)) < 0) {
        free(*groups);
        *groups = NULL;
    }

    return n;
}

/* The WIRED_ROOT_* bits of the ids held, or -1 when they can't be read */
static int wired_root_ids(void) {
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    gid_t *groups;
    int root = 0, n, i;

    if (getresuid(&ruid, &euid, &suid) < 0 || getresgid(&rgid, &egid, &sgid) < 0)
        return -1;

    if (ruid == 0 || euid == 0 || suid == 0)
        root |= WIRED_ROOT_UID;

    if (rgid == 0 || egid == 0 || sgid == 0)
        root |= WIRED_ROOT_GID;

    if ((n = wired_get_groups(&groups)) < 0)
        return -1;

    for (i = 0; i < n; i++) {
        if (groups[i] == 0)
            root |= WIRED_ROOT_GROUPS;
    }

    free(groups);
    return root;
}

/* 1 in any user namespace but the initial one.  Without the namespace file under a
 * /proc which is there, there are no user namespaces; a namespace file which can't
 * be read, or a /proc missing or covered, counts as a child */
static int wired_in_child_userns(void) {
    struct stat sb;

    if (stat("/proc/self/ns/user", &sb) < 0)
        return errno != ENOENT || stat("/proc/self", &sb) < 0;

    return sb.st_ino != WIRED_INIT_USERNS_INO;
}

/* 1 when the effective uid is the initial namespace's uid 0, whatever the uid maps
 * say: /proc/sys gives the owner's bits of its root-owned files to that one kuid
 * only, never for a capability (test_perm), and these are mode 0600.  0 when the
 * open is refused, -1 when neither file is there */
static int wired_uid_is_init_root(void) {
    static const char *const probes[] = {
        "/proc/sys/kernel/usermodehelper/bset", "/proc/sys/kernel/cad_pid",
    };
    size_t i;
    int fd;

    for (i = 0; i < sizeof(probes) / sizeof(probes[0]); i++) {
        if ((fd = open(probes[i], O_RDONLY | O_CLOEXEC | O_NOCTTY)) >= 0) {
            close(fd);
            return 1;
        }

        if (errno == EACCES || errno == EPERM)
            return 0;
    }

    return -1;
}

/* The kernel's overflow gid, and the group the kernel shows for root's group here:
 * kernel.overflowgid is a file of the initial root's.  Returns 1, or -1 */
static int wired_overflow_root_gid(gid_t *overflow, gid_t *root) {
    static const char *const path = "/proc/sys/kernel/overflowgid";
    char text[32];
    struct stat sb;
    unsigned long v;
    size_t len;

    if (wired_read_text(path, text, sizeof(text), &len) < 0)
        return -1;

    while (len > 0 && text[len - 1] == '\n')
        len--;

    if (wired_parse_uint(text, len, 0, UINT32_MAX, &v) < 0 || stat(path, &sb) < 0)
        return -1;

    *overflow = (gid_t) v;
    *root = sb.st_gid;
    return 1;
}

static void wired_why_set(wired_priv_t *p, const char *reason) {
    if (p->why[0] == 0)
        snprintf(p->why, sizeof(p->why), "%s", reason);
    else
        wired_why_append(p, "; %s", reason);
}

/* In a user namespace other than the initial one, ids a namespace maps to root
 * outside it are root.  The real and saved ids are first set to the effective
 * ones, which is always allowed and leaves one mapped uid and gid to look up.
 * Returns 1, or -1 with p->why saying why */
static int wired_userns_verify(wired_priv_t *p) {
    char uid_map[WIRED_PROC_TEXT_MAX], gid_map[WIRED_PROC_TEXT_MAX];
    char reason[STATUS_MAX];
    wired_userns_ids_t ids;
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    gid_t *groups = NULL;
    int n, r;

    memset(&ids, 0, sizeof(ids));

    if (getresuid(&ruid, &euid, &suid) < 0 || getresgid(&rgid, &egid, &sgid) < 0 ||
            setresgid(egid, egid, egid) < 0 || setresuid(euid, euid, euid) < 0) {
        snprintf(reason, sizeof(reason), "could not set its real and saved ids to its "
                "effective ones in its user namespace: %s", strerror(errno));
        wired_why_set(p, reason);
        return -1;
    }

    if (wired_read_text("/proc/self/uid_map", uid_map, sizeof(uid_map), &ids.uid_map_len) < 0 ||
            wired_read_text("/proc/self/gid_map", gid_map, sizeof(gid_map),
                &ids.gid_map_len) < 0) {
        wired_why_set(p, "could not read the uid and gid maps of its user namespace, or tell "
                "it from the host's; it needs /proc mounted");
        return -1;
    }

    if ((n = wired_get_groups(&groups)) < 0) {
        wired_why_set(p, "could not read its supplementary groups");
        return -1;
    }

    ids.uid_map = uid_map;
    ids.gid_map = gid_map;
    ids.uid = euid;
    ids.gid = egid;
    ids.groups = groups;
    ids.n_groups = (size_t) n;

    if ((ids.uid_is_root = wired_uid_is_init_root()) < 0 ||
            wired_overflow_root_gid(&ids.overflow_gid, &ids.root_gid) < 0) {
        free(groups);
        wired_why_set(p, "could not tell from /proc/sys/kernel what its ids are outside its "
                "user namespace");
        return -1;
    }

    r = wired_userns_ids_check(&ids, reason, sizeof(reason));
    free(groups);

    if (r < 0) {
        wired_why_set(p, reason);
        return -1;
    }

    return 1;
}

/* Bound onto itself and remounted read-only, in the jail's private mount namespace.
 * Not recursively, so mounts under it (binfmt_misc) are hidden too, unless a user
 * namespace has them locked to it */
static int wired_proc_sys_readonly(void) {
    static const struct {
        unsigned long st;
        unsigned long ms;
    } carry[] = {
        { ST_NOSUID, MS_NOSUID }, { ST_NODEV, MS_NODEV }, { ST_NOEXEC, MS_NOEXEC },
        { ST_NOATIME, MS_NOATIME }, { ST_NODIRATIME, MS_NODIRATIME },
        { ST_RELATIME, MS_RELATIME },
    };
    unsigned long flags = MS_BIND | MS_REMOUNT | MS_RDONLY;
    struct statvfs vfs;
    size_t i;

    if (mount("/proc/sys", "/proc/sys", NULL, MS_BIND, NULL) < 0 &&
            (errno != EINVAL || mount("/proc/sys", "/proc/sys", NULL, MS_BIND | MS_REC, NULL) < 0))
        return -1;

    /* The remount replaces every per-mount flag, and a user namespace can't change
     * the locked ones, atime included */
    if (statvfs("/proc/sys", &vfs) < 0)
        return -1;

    for (i = 0; i < sizeof(carry) / sizeof(carry[0]); i++) {
        if (vfs.f_flag & carry[i].st)
            flags |= carry[i].ms;
    }

    if (!(vfs.f_flag & (ST_NOATIME | ST_RELATIME)))
        flags |= MS_STRICTATIME;

    if (mount(NULL, "/proc/sys", NULL, flags, NULL) < 0 || statvfs("/proc/sys", &vfs) < 0 ||
            !(vfs.f_flag & ST_RDONLY))
        return -1;

    return 1;
}

/* Every uid 0, saved ones too, to wired_unpriv_ids with the permitted set kept, and
 * every gid 0 and the supplementary groups likewise; holding no uid 0, only the
 * gids change.  Returns 1, 0 when it can't switch in a child user namespace and
 * stays with its ids 0 there, or -1 */
static int wired_leave_root(wired_priv_t *p, int root) {
    const int uid_root = (root & WIRED_ROOT_UID) != 0;
    uid_t ruid, euid, suid;
    gid_t rgid, egid, sgid;
    const char *step;
    int bits, set_keep = 0, id_step = 0, e;

    p->uid = WIRED_NOBODY_ID;
    p->gid = WIRED_NOBODY_ID;

    if (getresuid(&ruid, &euid, &suid) < 0 || getresgid(&rgid, &egid, &sgid) < 0) {
        step = "read its ids";
        goto fail;
    }

    wired_unpriv_ids(ruid, rgid, &p->uid, &p->gid);

    if (uid_root) {
        /* The permitted set outlives the switch only with keep-caps, or with the
         * setuid fixup off; a locked keep-caps of 0 can't be changed */
        if ((bits = prctl(PR_GET_SECUREBITS, 0, 0, 0, 0)) < 0) {
            step = "read its securebits";
            goto fail;
        }

        if (!(bits & (SECBIT_KEEP_CAPS | SECBIT_NO_SETUID_FIXUP))) {
            if (prctl(PR_SET_KEEPCAPS, 1, 0, 0, 0) < 0) {
                step = "keep CAP_NET_RAW";
                goto fail;
            }

            set_keep = 1;
        }
    } else {
        p->uid = euid;
    }

    id_step = 1;

    if ((uid_root || (root & WIRED_ROOT_GROUPS)) && setgroups(0, NULL) < 0) {
        step = "clear its supplementary groups";
        goto fail;
    }

    if (setresgid(p->gid, p->gid, p->gid) < 0) {
        step = "set its gid";
        goto fail;
    }

    if (uid_root && setresuid(p->uid, p->uid, p->uid) < 0) {
        step = "set its uid";
        goto fail;
    }

    id_step = 0;

    if (getresuid(&ruid, &euid, &suid) < 0 || getresgid(&rgid, &egid, &sgid) < 0 ||
            wired_root_ids() != 0 || rgid != p->gid || egid != p->gid || sgid != p->gid ||
            (uid_root && (ruid != p->uid || euid != p->uid || suid != p->uid))) {
        errno = EPERM;
        step = "confirm its ids";
        goto fail;
    }

    if (set_keep)
        prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);

    p->left_root = 1;
    return 1;

fail:
    e = errno;

    if (set_keep)
        prctl(PR_SET_KEEPCAPS, 0, 0, 0, 0);

    if (uid_root)
        snprintf(p->why, sizeof(p->why), "could not %s switching from root to uid %u: %s",
                step, (unsigned int) p->uid, strerror(e));
    else
        snprintf(p->why, sizeof(p->why), "could not %s switching from gid 0 to gid %u: %s",
                step, (unsigned int) p->gid, strerror(e));

    if (!wired_in_child_userns()) {
        /* Root without CAP_SETUID and CAP_SETGID: a container's --cap-drop, or
         * SecureBits=noroot; root only gets here with libcap.  Without root, a
         * gid 0 needs CAP_SETGID, which only a libcap build may hold */
        if (id_step && e == EPERM)
            wired_why_append(p, "%s", uid_root ?
                    "; grant it CAP_SETUID and CAP_SETGID, or run it as a user with "
                    "'setcap cap_net_raw+ep kismet_cap_wired'" :
                    "; run it without gid 0 or group 0 (root's group)");
        return -1;
    }

    /* wired_userns_verify decides whether ids 0 of this namespace may stay */
    p->userns_root = 1;
    return 0;
}

/* Without libcap nothing can be dropped, so holding more than CAP_NET_RAW is fatal;
 * sets no_net_raw when CAP_NET_RAW isn't effective.  Returns 1, or -1 */
static int wired_caps_without_libcap(wired_priv_t *p) {
    const uint64_t raw = 1ULL << CAP_NET_RAW;
    char text[WIRED_PROC_TEXT_MAX];
    uint64_t prm, eff;
    size_t len;

    if (wired_read_text("/proc/self/status", text, sizeof(text), &len) < 0 ||
            wired_status_caps(text, len, &prm, &eff) < 0) {
        snprintf(p->why, sizeof(p->why), "was built without libcap and could not read its "
                "capabilities from /proc/self/status");
        return -1;
    }

    if (((prm | eff) & ~raw) != 0) {
        snprintf(p->why, sizeof(p->why), "was built without libcap and can't drop the "
                "capabilities it holds beyond CAP_NET_RAW (%016" PRIx64 "); give it only "
                "'setcap cap_net_raw+ep kismet_cap_wired'", prm | eff);
        return -1;
    }

    p->no_net_raw = (eff & raw) == 0;
    return 1;
}

int wired_drop_privileges(kis_capture_handler_t *caph, wired_priv_t *p) {
    /* CAP_SETUID and CAP_SETGID only until root is left */
    const int keep_switch[] = { CAP_NET_RAW, CAP_SETUID, CAP_SETGID };
    const int keep[] = { CAP_NET_RAW };
    int root, r;

    memset(p, 0, sizeof(*p));

    if ((root = wired_root_ids()) < 0) {
        snprintf(p->why, sizeof(p->why), "could not read its uids and groups: %s",
                strerror(errno));
        return -1;
    }

    p->was_root = (root & WIRED_ROOT_UID) != 0;
    p->root_group = (root & (WIRED_ROOT_GID | WIRED_ROOT_GROUPS)) != 0;

    /* Interfaces are opened later, on the server's request, with the CAP_NET_RAW
     * kept here; the sysfs, netlink and ethtool reads need no privilege */
    if (cf_jail_filesystem(caph) > 0)
        p->proc_sys_ro = wired_proc_sys_readonly() > 0;

    r = cf_drop_caps_keep(caph, keep_switch, sizeof(keep_switch) / sizeof(keep_switch[0]));

    if (r < 0) {
        snprintf(p->why, sizeof(p->why), "could not drop its capabilities to CAP_NET_RAW");
        return -1;
    }

    if (r == 0 && p->was_root) {
        snprintf(p->why, sizeof(p->why), "was built without libcap and can't drop root's "
                "capabilities; run it as a user with 'setcap cap_net_raw+ep kismet_cap_wired' "
                "instead");
        return -1;
    }

    if (r == 0 && wired_caps_without_libcap(p) < 0)
        return -1;

    if (root != 0 && wired_leave_root(p, root) < 0)
        return -1;

    /* Before the last drop, so that one sees a CAP_NET_RAW its setresuid cleared */
    if (wired_in_child_userns() && wired_userns_verify(p) < 0)
        return -1;

    if ((r = cf_drop_caps_keep(caph, keep, sizeof(keep) / sizeof(keep[0]))) < 0) {
        snprintf(p->why, sizeof(p->why), "could not drop its capabilities to CAP_NET_RAW");
        return -1;
    }

    if (r != 0)
        p->no_net_raw = r == 2;

    /* Nothing it could exec gains privileges from a setuid bit or file capability;
     * EINVAL is a kernel before 3.5 */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 && errno != EINVAL) {
        snprintf(p->why, sizeof(p->why), "could not set no_new_privs: %s", strerror(errno));
        return -1;
    }

    return 1;
}
