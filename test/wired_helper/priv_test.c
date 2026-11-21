/* Tests for kismet_cap_wired's privilege drop (capture_wired/wired_priv.c), run the
 * way the helper runs it, from a start holding every capability plus an ambient set.
 *
 *   make -C capture_wired test && test/wired_helper/priv_test [lock | nested | uid5 |
 *       noproc | uid5-noproc]
 *
 * Unprivileged it makes its own user and network namespaces, uid 0 in them mapped
 * to the caller's uid and nothing else mapped, so the switch from root can't
 * happen.  A caller with supplementary groups keeps them, unmapped, and the drop
 * has to fail, since they may be root's.  Without any it has to leave uid 0 of the
 * namespace with CAP_NET_RAW only, /proc/sys read-only and no_new_privs set.  The
 * read-only bind shows as EROFS opening kernel.ns_last_pid (mode 0666, so the
 * permission check passes) for writing.  What root itself could write there isn't
 * shown: /proc/sys checks the initial namespace's uid 0 (6.2), so uid 0 of another
 * needs capabilities for any of it.  With "lock", keep-caps is locked off first.
 * With "nested" a second user namespace inside the first maps its 0 to the first
 * one's 0, as root's own 'unshare -r' would to the host's root, and with "uid5" its
 * uid 5 to that 0, so no id 0 is held; the drop has to fail either way.  The
 * "noproc" forms cover /proc with an empty tmpfs just before the drop, which then
 * can't read the namespace's maps and has to fail.
 *
 * As real root it first moves to a network namespace of its own, so the
 * ip_forward checks never touch the host's.  It covers the switch itself, to
 * nobody, and with "suid UID GID" to that user, as a setuid-root start by that
 * user would have it, then that kernel.core_pattern (root's, mode 0644) can't be
 * written; each write tried puts back what it read, so nothing changes even if it
 * gets through.  With "lock" the switch can't keep CAP_NET_RAW, and the drop has to
 * fail.
 *
 * Exits 0 when every check passes, 1 on a failure, 77 when user namespaces can't
 * be had.
 */

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/capability.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>

#include <linux/securebits.h>

#include "../../capture_wired/wired_priv.h"
#include "../../capture_wired/wired_util.h"

static int failures = 0;
static int checks = 0;

#define CHECK(cond, ...) do { \
    checks++; \
    if (!(cond)) { \
        failures++; \
        printf("FAIL %s:%d: ", __FILE__, __LINE__); \
        printf(__VA_ARGS__); \
        printf("\n"); \
    } \
} while (0)

static unsigned long long cap_field(const char *name) {
    char l[256];
    unsigned long long v = ~0ULL;
    size_t n = strlen(name);
    FILE *f = fopen("/proc/self/status", "r");

    while (f != NULL && fgets(l, sizeof(l), f) != NULL) {
        if (strncmp(l, name, n) == 0 && l[n] == ':')
            v = strtoull(l + n + 1, NULL, 16);
    }

    if (f != NULL)
        fclose(f);

    return v;
}

static int write_file(const char *path, const char *s) {
    ssize_t r;
    int fd, e;

    if ((fd = open(path, O_WRONLY | O_CLOEXEC)) < 0)
        return -1;

    r = write(fd, s, strlen(s));
    e = errno;
    close(fd);
    errno = e;

    return r == (ssize_t) strlen(s) ? 0 : -1;
}

static int read_file(const char *path, char *out, size_t out_len) {
    ssize_t r;
    int fd;

    if ((fd = open(path, O_RDONLY | O_CLOEXEC)) < 0)
        return -1;

    r = read(fd, out, out_len - 1);
    close(fd);

    if (r < 0)
        return -1;

    out[r] = 0;
    return 0;
}

/* uid 0 of new user and network namespaces; 0, or -1 when they can't be had */
static int enter_userns(void) {
    char m[64];
    unsigned int u = (unsigned int) getuid(), g = (unsigned int) getgid();

    if (unshare(CLONE_NEWUSER | CLONE_NEWNET) < 0) {
        printf("skip: no user namespace: %s\n", strerror(errno));
        return -1;
    }

    snprintf(m, sizeof(m), "0 %u 1", u);

    if (write_file("/proc/self/setgroups", "deny") < 0 || write_file("/proc/self/uid_map", m) < 0)
        return -1;

    snprintf(m, sizeof(m), "0 %u 1", g);

    return write_file("/proc/self/gid_map", m);
}

/* From uid 0 of enter_userns, a user namespace inside it mapping id to that 0 */
static int enter_nested(const char *map) {
    if (unshare(CLONE_NEWUSER) < 0) {
        printf("skip: no nested user namespace: %s\n", strerror(errno));
        return -1;
    }

    if (write_file("/proc/self/setgroups", "deny") < 0 || write_file("/proc/self/uid_map", map) < 0 ||
            write_file("/proc/self/gid_map", map) < 0) {
        printf("skip: could not map the nested namespace: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

/* /proc covered by an empty tmpfs in a mount namespace of its own, as a launcher could */
static int hide_proc(void) {
    if (unshare(CLONE_NEWNS) < 0 || mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) < 0 ||
            mount("none", "/proc", "tmpfs", 0, NULL) < 0) {
        printf("skip: could not hide /proc: %s\n", strerror(errno));
        return -1;
    }

    return 0;
}

static unsigned long overflow_gid(void) {
    char buf[32];

    return read_file("/proc/sys/kernel/overflowgid", buf, sizeof(buf)) == 0 ? strtoul(buf, NULL, 10) : 65534;
}

/* Supplementary groups from outside the user namespace, which show as the overflow gid */
static int outside_groups(void) {
    gid_t g[256];
    int n = getgroups(256, g), i, r = 0;

    for (i = 0; i < n; i++) {
        if (g[i] == (gid_t) overflow_gid())
            r = 1;
    }

    return n < 0 ? 1 : r;
}

/* Inheritable and ambient NET_RAW, NET_ADMIN and SYS_ADMIN, as a parent could hand down */
static int raise_ambient(void) {
    cap_value_t l[3] = { CAP_NET_RAW, CAP_NET_ADMIN, CAP_SYS_ADMIN };
    cap_t c = cap_get_proc();
    int i, r;

    if (c == NULL)
        return -1;

    r = cap_set_flag(c, CAP_INHERITABLE, 3, l, CAP_SET) == 0 && cap_set_proc(c) == 0 ? 0 : -1;
    cap_free(c);

    for (i = 0; r == 0 && i < 3; i++) {
        if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, l[i], 0, 0) < 0)
            r = -1;
    }

    return r;
}

int main(int argc, char *argv[]) {
    const char *fwd = "/proc/sys/net/ipv4/ip_forward";
    const char *lastpid = "/proc/sys/kernel/ns_last_pid";
    const unsigned long long raw = 1ULL << CAP_NET_RAW;
    int real_root = getuid() == 0 && geteuid() == 0;
    int lock = argc > 1 && strcmp(argv[1], "lock") == 0;
    int nested = argc > 1 && strcmp(argv[1], "nested") == 0;
    int chain = argc > 1 && (strcmp(argv[1], "uid5") == 0 || strcmp(argv[1], "uid5-noproc") == 0);
    int noproc = argc > 1 && (strcmp(argv[1], "noproc") == 0 || strcmp(argv[1], "uid5-noproc") == 0);
    int outside = 0;
    char probe[] = "/tmp/priv_test.XXXXXX";
    struct stat sb;
    uid_t want_uid = WIRED_NOBODY_ID, r_uid, e_uid, s_uid;
    gid_t want_gid = WIRED_NOBODY_ID;
    kis_capture_handler_t *caph;
    wired_priv_t p;
    char buf[256] = "", status[WIRED_PROC_TEXT_MAX];
    uint64_t prm, eff;
    size_t status_len;
    int r;

    /* Never the host's ip_forward */
    if (real_root && unshare(CLONE_NEWNET) < 0) {
        printf("could not make a network namespace: %s\n", strerror(errno));
        return 2;
    }

    if ((nested || chain || noproc) && real_root) {
        printf("nested, uid5 and noproc run unprivileged\n");
        return 2;
    }

    if (argc > 3 && strcmp(argv[1], "suid") == 0) {
        if (!real_root) {
            printf("suid needs real root\n");
            return 2;
        }

        want_uid = (uid_t) strtoul(argv[2], NULL, 10);
        want_gid = (gid_t) strtoul(argv[3], NULL, 10);

        /* A setuid-root start: the user's real uid and gids, effective and saved uid root */
        if (want_uid == 0 || want_gid == 0 || setresgid(want_gid, want_gid, want_gid) < 0 ||
                setresuid(want_uid, 0, 0) < 0) {
            printf("could not take the ids of a setuid-root start: %s\n", strerror(errno));
            return 2;
        }
    } else if (!real_root) {
        if (enter_userns() < 0)
            return 77;

        /* With CAP_NET_ADMIN over its own network namespace, before the drop */
        CHECK(write_file(fwd, "1") == 0, "%s written before the drop: %s", fwd, strerror(errno));
        CHECK(write_file(fwd, "0") == 0, "and put back: %s", strerror(errno));

        /* What the drop's checks rely on: root's group isn't mapped here, so it
         * shows as the overflow gid; a mode 0600 sysctl of root's stays shut to uid
         * 0 of a namespace holding every capability there */
        CHECK(stat("/proc/sys/kernel/overflowgid", &sb) == 0 && sb.st_gid == (gid_t) overflow_gid(),
                "root's group shows as the overflow gid");
        {
            int fd = open("/proc/sys/kernel/usermodehelper/bset", O_RDONLY | O_CLOEXEC);

            CHECK(fd < 0 && errno == EACCES, "bset refused to uid 0 of the namespace: %s",
                    fd < 0 ? strerror(errno) : "opened");

            if (fd >= 0)
                close(fd);
        }

        if (chain) {
            int fd = mkstemp(probe);

            if (fd < 0) {
                printf("could not make %s: %s\n", probe, strerror(errno));
                return 2;
            }

            close(fd);
        }

        if (nested && enter_nested("0 0 1") < 0)
            return 77;

        /* 5 maps to uid 0 of the first namespace, the caller's uid on the host.  An
         * id two namespaces up shows as the id held, as root's would on a chain
         * ending at the host's root */
        if (chain) {
            int r2 = enter_nested("5 0 1");

            if (r2 == 0)
                CHECK(stat(probe, &sb) == 0 && sb.st_uid == 5 && sb.st_gid == 5,
                        "the caller's file shows as 5:5 two namespaces down");

            unlink(probe);

            if (r2 < 0)
                return 77;
        }

        outside = outside_groups();
    }

    {
        int fd = open(lastpid, O_WRONLY | O_CLOEXEC);

        CHECK(fd >= 0, "%s opens for writing before the drop: %s", lastpid, strerror(errno));

        if (fd >= 0)
            close(fd);

        /* The root check's open, which only the initial root passes */
        if (real_root) {
            fd = open("/proc/sys/kernel/usermodehelper/bset", O_RDONLY | O_CLOEXEC);
            CHECK(fd >= 0, "bset opens as root: %s", strerror(errno));

            if (fd >= 0)
                close(fd);
        }
    }

    if (noproc && hide_proc() < 0)
        return 77;

    if (lock) {
        CHECK(prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS_LOCKED, 0, 0, 0) == 0,
                "lock keep-caps off: %s", strerror(errno));
    }

    CHECK(raise_ambient() == 0, "raise an ambient set: %s", strerror(errno));

    if ((caph = cf_handler_init("priv_test")) == NULL) {
        printf("cf_handler_init failed\n");
        return 1;
    }

    r = wired_drop_privileges(caph, &p);

    printf("drop: r=%d was_root=%d left_root=%d uid=%u gid=%u userns_root=%d proc_sys_ro=%d "
            "no_net_raw=%d why=\"%s\"\n", r, p.was_root, p.left_root, (unsigned int) p.uid,
            (unsigned int) p.gid, p.userns_root, p.proc_sys_ro, p.no_net_raw, p.why);
    printf("caps: CapInh=%016llx CapPrm=%016llx CapEff=%016llx CapAmb=%016llx\n",
            cap_field("CapInh"), cap_field("CapPrm"), cap_field("CapEff"), cap_field("CapAmb"));

    /* uid 0 (or 5) of the nested namespace is uid 0 outside it; groups from outside
     * the namespace may be root's; root's switch with keep-caps locked can't keep
     * CAP_NET_RAW; without /proc the namespace can't be told from the host's.  All
     * fatal by design */
    if (noproc) {
        CHECK(r == -1 && !p.left_root, "drop refused");
        CHECK(strstr(p.why, "could not read the uid and gid maps") != NULL &&
                strstr(p.why, "grant it CAP_SETUID") == NULL, "why: %s", p.why);
        cf_handler_free(caph);
        printf("%s: %d checks, %d failed\n", failures ? "FAIL" : "ok", checks, failures);
        return failures != 0;
    }

    if (nested || chain || (!real_root && outside) || (real_root && lock)) {
        const char *want = nested ? "uid 0 of its user namespace maps to uid 0 of the parent" :
            chain ? "uid 5 of its user namespace maps to uid 0 of the parent" :
            real_root ? "keep CAP_NET_RAW" : "supplementary groups from outside";

        CHECK(r == -1 && !p.left_root, "drop refused");
        CHECK(strstr(p.why, want) != NULL && strstr(p.why, "could not tell") == NULL, "why: %s", p.why);
        cf_handler_free(caph);
        printf("%s: %d checks, %d failed\n", failures ? "FAIL" : "ok", checks, failures);
        return failures != 0;
    }

    CHECK(r == 1, "drop succeeds");
    CHECK(p.was_root, "started as root");
    CHECK(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1, "no_new_privs set");

    /* The parser the no-libcap build relies on, against the kernel's own text */
    CHECK(wired_read_text("/proc/self/status", status, sizeof(status), &status_len) == 0 &&
            wired_status_caps(status, status_len, &prm, &eff) == 0 &&
            prm == cap_field("CapPrm") && eff == cap_field("CapEff"), "status caps parse");
    CHECK(p.proc_sys_ro, "/proc/sys bound read-only");
    CHECK(!p.no_net_raw, "CAP_NET_RAW held");
    CHECK(cap_field("CapPrm") == raw && cap_field("CapEff") == raw, "only CAP_NET_RAW left");
    CHECK(cap_field("CapInh") == 0 && cap_field("CapAmb") == 0, "inheritable and ambient empty");
    CHECK(prctl(PR_GET_KEEPCAPS, 0, 0, 0, 0) == 0, "keep-caps off again");

    CHECK(getresuid(&r_uid, &e_uid, &s_uid) == 0, "getresuid");

    if (real_root) {
        int fd = open("/proc/sys/kernel/usermodehelper/bset", O_RDONLY | O_CLOEXEC);

        /* The open the drop's root check makes, refused once root is left */
        CHECK(fd < 0 && errno == EACCES, "bset refused after the switch: %s", fd < 0 ? strerror(errno) : "opened");

        if (fd >= 0)
            close(fd);

        CHECK(p.left_root && !p.userns_root, "left root");
        CHECK(p.uid == want_uid && p.gid == want_gid, "switched to %u:%u",
                (unsigned int) want_uid, (unsigned int) want_gid);
        CHECK(r_uid == want_uid && e_uid == want_uid && s_uid == want_uid, "no uid stays 0");
        CHECK(getegid() == want_gid && getgroups(0, NULL) == 0, "gid switched, no groups");
        CHECK(setresuid(0, 0, 0) < 0, "can't take uid 0 back");

        /* Owned by the initial root; refused to any other uid, and read-only now */
        if (read_file("/proc/sys/kernel/core_pattern", buf, sizeof(buf)) == 0) {
            CHECK(write_file("/proc/sys/kernel/core_pattern", buf) < 0 &&
                    (errno == EROFS || errno == EACCES), "kernel.core_pattern refused: %s",
                    strerror(errno));
        }
    } else {
        CHECK(!p.left_root && p.userns_root && p.why[0] != 0, "stays uid 0 of the namespace");
        CHECK(r_uid == 0 && e_uid == 0 && s_uid == 0, "uid 0 of the namespace");
    }

    /* The value read goes back, so a write which gets through changes nothing */
    CHECK(read_file(fwd, buf, sizeof(buf)) == 0, "%s still readable", fwd);
    CHECK(write_file(fwd, buf) < 0 && (errno == EROFS || errno == EACCES), "%s refused: %s",
            fwd, strerror(errno));

    {
        struct statvfs vfs;
        int fd = open(lastpid, O_WRONLY | O_CLOEXEC);
        int e = errno;

        CHECK(statvfs("/proc/sys", &vfs) == 0 && (vfs.f_flag & ST_RDONLY), "/proc/sys read-only");
        CHECK(fd < 0 && e == EROFS, "%s refused by the mount: %s", lastpid,
                fd < 0 ? strerror(e) : "opened");

        if (fd >= 0)
            close(fd);
    }

    {
        cap_value_t a = CAP_NET_ADMIN;
        cap_t c = cap_get_proc();
        int back = c != NULL && cap_set_flag(c, CAP_EFFECTIVE, 1, &a, CAP_SET) == 0 &&
            cap_set_proc(c) == 0;

        if (c != NULL)
            cap_free(c);

        CHECK(!back, "can't raise CAP_NET_ADMIN again");
    }

    cf_handler_free(caph);

    printf("%s: %d checks, %d failed\n", failures ? "FAIL" : "ok", checks, failures);

    return failures != 0;
}
