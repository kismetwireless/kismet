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

    See cell_discover.h for what this is and why.
*/

#if defined(CELL_SELFTEST) && defined(CELL_DISCOVER_SELFTEST)
#define _XOPEN_SOURCE 700
#define _DEFAULT_SOURCE
#endif

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#ifdef __linux__
#include <sys/sysmacros.h>   /* major(), minor(); <sys/types.h> on macOS */
#endif
#include <time.h>
#include <unistd.h>

#include "cell_discover.h"

int cell_name_usbdev_ok(const char *s) {
    if (s == NULL || strlen(s) >= CELL_NAME_USB_MAX)
        return 0;

    /* bus "-" port, then "." port per hub tier (USB allows 7 port levels);
     * each a 1-3 digit number */
    int groups = 0;
    while (1) {
        int digits = 0;
        while (isdigit((unsigned char) *s)) {
            s++;
            digits++;
        }
        if (digits == 0 || digits > 3)
            return 0;
        if (++groups > 8)
            return 0;
        if (*s == '\0')
            return groups >= 2;
        if (groups == 1 ? *s != '-' : *s != '.')
            return 0;
        s++;
    }
}

cell_name_kind_t cell_name_parse(const char *iface, const char *prefix,
                                 char *val, size_t valsz) {
    if (iface == NULL || prefix == NULL || val == NULL || valsz == 0)
        return CELL_NAME_BAD;
    val[0] = '\0';

    size_t pl = strlen(prefix);
    if (strncmp(iface, prefix, pl) != 0)
        return CELL_NAME_BAD;

    const char *r = iface + pl;
    if (*r == '\0')
        return CELL_NAME_ANY;
    if (*r != '-')
        return CELL_NAME_BAD;
    r++;

    if (strncmp(r, "usb", 3) == 0) {
        r += 3;
        if (!cell_name_usbdev_ok(r) || strlen(r) >= valsz)
            return CELL_NAME_BAD;
        memcpy(val, r, strlen(r) + 1);
        return CELL_NAME_USB;
    }

    if (strlen(r) != 15 || valsz < 16)
        return CELL_NAME_BAD;
    for (int i = 0; i < 15; i++) {
        if (!isdigit((unsigned char) r[i]))
            return CELL_NAME_BAD;
    }
    memcpy(val, r, 16);
    return CELL_NAME_IMEI;
}

static char g_root[PATH_MAX] = "";

static int rooted(char *out, size_t outsz, const char *fmt_path) {
    return (size_t) snprintf(out, outsz, "%s%s", g_root, fmt_path) < outsz;
}

/* A /proc snapshot of the device nodes other processes hold, taken once per
 * scan rather than once per port. */
#define BUSY_SNAP_MAX 512
#define BUSY_SNAP_TTL_MS 2000
/* How long the baseline taken before the capability drop is trusted. */
#define BUSY_BASE_TTL_MS 30000

typedef struct {
    pid_t pid;
    char comm[16];
    char path[64];
} snap_ent_t;

static snap_ent_t g_snap[BUSY_SNAP_MAX];
static int g_nsnap;
static int g_snap_valid;
static struct timespec g_snap_ts;
static pid_t g_mm_pid;

static snap_ent_t g_base[BUSY_SNAP_MAX];
static int g_nbase;
static int g_base_valid;
static struct timespec g_base_ts;

void cell_discover_set_root(const char *root) {
    snprintf(g_root, sizeof(g_root), "%s", root ? root : "");
    g_snap_valid = 0;
    g_base_valid = 0;
}

int cell_tty_usb_location(const char *dev_path, char *usbdev, size_t usbdevsz,
                          int *ifnum) {
    if (dev_path == NULL || *dev_path == '\0' || usbdev == NULL || usbdevsz == 0)
        return 0;
    usbdev[0] = '\0';

    char node[PATH_MAX];
    const char *from = realpath(dev_path, node) ? node : dev_path;
    const char *name = strrchr(from, '/');
    name = name ? name + 1 : from;
    if (*name == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return 0;

    char rel[PATH_MAX], link[PATH_MAX], dir[PATH_MAX];
    if ((size_t) snprintf(rel, sizeof(rel), "/sys/class/tty/%s/device", name) >= sizeof(rel) ||
        !rooted(link, sizeof(link), rel) || realpath(link, dir) == NULL)
        return 0;

    for (int up = 0; up < 3; up++) {
        char *slash = strrchr(dir, '/');
        if (slash == NULL)
            return 0;
        const char *base = slash + 1;
        const char *colon = strchr(base, ':');
        if (colon != NULL) {
            const char *dot = strrchr(colon, '.');
            size_t n = (size_t) (colon - base);
            char *end;
            if (dot == NULL || n == 0 || n >= usbdevsz)
                return 0;
            errno = 0;
            long i = strtol(dot + 1, &end, 10);
            if (errno != 0 || end == dot + 1 || *end != '\0' || i < 0 || i > 255)
                return 0;
            memcpy(usbdev, base, n);
            usbdev[n] = '\0';
            if (ifnum)
                *ifnum = (int) i;
            return 1;
        }
        if (slash == dir)
            return 0;
        *slash = '\0';
    }
    return 0;
}

static int read_small(const char *path, char *buf, size_t bufsz);

int cell_usb_matches(const char *usbdev, const char *want) {
    if (usbdev == NULL || want == NULL || *usbdev == '\0' || *want == '\0')
        return 0;
    if (strncmp(usbdev, "usb:", 4) != 0)
        return strcmp(usbdev, want) == 0;

    unsigned int bus, addr;
    char tail;
    if (sscanf(usbdev + 4, "%u-%u%c", &bus, &addr, &tail) != 2)
        return 0;
    if (!cell_name_usbdev_ok(want))
        return 0;

    char rel[96], path[PATH_MAX], buf[16];
    snprintf(rel, sizeof(rel), "/sys/bus/usb/devices/%s/busnum", want);
    if (!rooted(path, sizeof(path), rel) || read_small(path, buf, sizeof(buf)) < 0 ||
        strtoul(buf, NULL, 10) != bus)
        return 0;
    snprintf(rel, sizeof(rel), "/sys/bus/usb/devices/%s/devnum", want);
    if (!rooted(path, sizeof(path), rel) || read_small(path, buf, sizeof(buf)) < 0 ||
        strtoul(buf, NULL, 10) != addr)
        return 0;
    return 1;
}

void cell_pick_reset(cell_pick_t *p) {
    if (p != NULL)
        memset(p, 0, sizeof(*p));
}

void cell_pick_add(cell_pick_t *p, const char *port, const char *fw,
                   const char *imei, const char *usbdev) {
    if (p == NULL || imei == NULL || *imei == '\0')
        return;
    int stored = p->total < CELL_PICK_MAX ? p->total : CELL_PICK_MAX;
    for (int i = 0; i < stored; i++) {
        if (strcmp(p->m[i].imei, imei) == 0)
            return;
    }
    if (p->total < CELL_PICK_MAX) {
        cell_pick_modem_t *m = &p->m[p->total];
        snprintf(m->port, sizeof(m->port), "%s", port ? port : "");
        snprintf(m->fw, sizeof(m->fw), "%s", fw ? fw : "");
        snprintf(m->imei, sizeof(m->imei), "%s", imei);
        snprintf(m->usbdev, sizeof(m->usbdev), "%s", usbdev ? usbdev : "");
    }
    if (p->total < INT_MAX)
        p->total++;
}

void cell_pick_choices(const cell_pick_t *p, const char *prefix, char *buf,
                       size_t bufsz) {
    if (buf == NULL || bufsz == 0)
        return;
    buf[0] = '\0';
    if (p == NULL)
        return;
    size_t off = 0;
    int stored = p->total < CELL_PICK_MAX ? p->total : CELL_PICK_MAX;
    for (int i = 0; i < stored; i++) {
        const cell_pick_modem_t *m = &p->m[i];
        const char *base = strrchr(m->port, '/');
        base = base ? base + 1 : m->port;
        char usb[80] = "";
        if (m->usbdev[0] && strncmp(m->usbdev, "usb:", 4) != 0)
            snprintf(usb, sizeof(usb), ", or %s-usb%s", prefix, m->usbdev);
        int n = snprintf(buf + off, bufsz - off, "%s%s-%s (%s%s)", i ? "; " : "",
                         prefix, m->imei, base, usb);
        if (n < 0 || off + (size_t) n >= bufsz) {
            buf[off] = '\0';
            return;
        }
        off += (size_t) n;
    }
    if (p->total > stored)
        snprintf(buf + off, bufsz - off, "; and %d more", p->total - stored);
}

static int read_small(const char *path, char *buf, size_t bufsz) {
    int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, buf, bufsz - 1);
    close(fd);
    if (n < 0)
        return -1;
    buf[n] = '\0';
    return (int) n;
}

static void read_comm(pid_t pid, char *out, size_t outsz) {
    char path[PATH_MAX], rel[64];
    out[0] = '\0';
    snprintf(rel, sizeof(rel), "/proc/%d/comm", (int) pid);
    if (!rooted(path, sizeof(path), rel) || read_small(path, out, outsz) < 0) {
        out[0] = '\0';
        return;
    }
    out[strcspn(out, "\n")] = '\0';
}

/* The device nodes a scan could probe; nothing else is worth keeping. A PTY
 * slave is left out: its holder is normally the program that made the pair,
 * the far end of a socat shim or a test's fake modem. */
static int snap_wanted(const char *target) {
    static const char *const kPrefixes[] = {
        "/dev/tty", "/dev/wwan", "/dev/mhi_", "/dev/rfcomm",
    };
    if (strcmp(target, "/dev/tty") == 0)
        return 0;
    for (size_t i = 0; i < sizeof(kPrefixes) / sizeof(kPrefixes[0]); i++) {
        if (strncmp(target, kPrefixes[i], strlen(kPrefixes[i])) == 0)
            return 1;
    }
    return 0;
}

/* The Kismet cell binaries take flock() on every port they open, so they
 * are left to serial_open's busy handling (rescan, identity vouch). */
static int comm_takes_flock(const char *comm) {
    static const char *const kOurs[] = {
        "kismet_cap_cell", "cellat_serial_p", "celldiag_probe",
    };
    for (size_t i = 0; i < sizeof(kOurs) / sizeof(kOurs[0]); i++) {
        if (strncmp(comm, kOurs[i], strlen(kOurs[i])) == 0)
            return 1;
    }
    return 0;
}

static long ms_since(const struct timespec *t0) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (long) (now.tv_sec - t0->tv_sec) * 1000L +
        (long) (now.tv_nsec - t0->tv_nsec) / 1000000L;
}

static void snap_scan(snap_ent_t *ents, int *nents, pid_t *mm_pid) {
    *nents = 0;
    *mm_pid = 0;

    char procdir[PATH_MAX];
    if (!rooted(procdir, sizeof(procdir), "/proc"))
        return;
    DIR *pd = opendir(procdir);
    if (pd == NULL)
        return;

    pid_t self = getpid();
    struct dirent *pe;
    while ((pe = readdir(pd)) != NULL) {
        char *end;
        errno = 0;
        long pid = strtol(pe->d_name, &end, 10);
        if (errno != 0 || *end != '\0' || pid <= 0 || pid > INT_MAX || pid == self)
            continue;

        char comm[16];
        read_comm((pid_t) pid, comm, sizeof(comm));
        if (strcmp(comm, "ModemManager") == 0)
            *mm_pid = (pid_t) pid;
        if (comm_takes_flock(comm))
            continue;

        char fddir[PATH_MAX];
        if ((size_t) snprintf(fddir, sizeof(fddir), "%s/%s/fd", procdir,
                              pe->d_name) >= sizeof(fddir))
            continue;
        /* Another user's fd table is EACCES unless we are root: skipped. */
        DIR *fd = opendir(fddir);
        if (fd == NULL)
            continue;
        struct dirent *fe;
        while ((fe = readdir(fd)) != NULL && *nents < BUSY_SNAP_MAX) {
            if (fe->d_name[0] == '.')
                continue;
            char link[PATH_MAX], target[128];
            if ((size_t) snprintf(link, sizeof(link), "%s/%s", fddir,
                                  fe->d_name) >= sizeof(link))
                continue;
            ssize_t n = readlink(link, target, sizeof(target) - 1);
            if (n <= 0 || (size_t) n >= sizeof(ents[0].path))
                continue;
            target[n] = '\0';
            if (!snap_wanted(target))
                continue;
            snap_ent_t *e = &ents[(*nents)++];
            e->pid = (pid_t) pid;
            snprintf(e->comm, sizeof(e->comm), "%s", comm);
            memcpy(e->path, target, (size_t) n + 1);
        }
        closedir(fd);
    }
    closedir(pd);
}

static void snap_take(void) {
    if (g_snap_valid && ms_since(&g_snap_ts) < BUSY_SNAP_TTL_MS)
        return;
    clock_gettime(CLOCK_MONOTONIC, &g_snap_ts);
    g_snap_valid = 1;
    snap_scan(g_snap, &g_nsnap, &g_mm_pid);
}

void cell_discover_baseline(void) {
    pid_t mm;
    clock_gettime(CLOCK_MONOTONIC, &g_base_ts);
    snap_scan(g_base, &g_nbase, &mm);
    g_base_valid = 1;
}

static int pid_alive(pid_t pid) {
    return pid > 0 && (kill(pid, 0) == 0 || errno == EPERM);
}

/* A UUCP lock: LCK..<name>, the node's /dev path with '/' as '_'. The pid
 * inside is ASCII (HDB) or a 4-byte int (old UUCP). A lock with no pid we can
 * read is taken as held: guessing it stale would write into a live session. */
static int check_lockfile(const char *resolved, cell_busy_t *out) {
    static const char *const kDirs[] = { "/run/lock", "/var/lock" };
    char seen[2][PATH_MAX];
    int nseen = 0;

    const char *rel = strncmp(resolved, "/dev/", 5) == 0 ? resolved + 5 : NULL;
    if (rel == NULL) {
        rel = strrchr(resolved, '/');
        rel = rel ? rel + 1 : resolved;
    }
    char lname[128];
    if ((size_t) snprintf(lname, sizeof(lname), "LCK..%s", rel) >= sizeof(lname))
        return 0;
    for (char *c = lname + 5; *c; c++) {
        if (*c == '/')
            *c = '_';
    }

    for (size_t d = 0; d < sizeof(kDirs) / sizeof(kDirs[0]); d++) {
        char dir[PATH_MAX], real[PATH_MAX];
        if (!rooted(dir, sizeof(dir), kDirs[d]) || realpath(dir, real) == NULL)
            continue;
        int dup = 0;
        for (int i = 0; i < nseen; i++) {
            if (strcmp(seen[i], real) == 0)
                dup = 1;
        }
        if (dup)
            continue;
        snprintf(seen[nseen++], sizeof(seen[0]), "%s", real);

        char lpath[PATH_MAX];
        if ((size_t) snprintf(lpath, sizeof(lpath), "%s/%s", real, lname) >= sizeof(lpath))
            continue;
        char buf[64];
        int n = read_small(lpath, buf, sizeof(buf));
        if (n < 0)
            continue;

        long pid = 0;
        const char *p = buf;
        while (*p == ' ' || *p == '\t')
            p++;
        int ascii = 1;
        for (int i = 0; i < n; i++) {
            if (!isdigit((unsigned char) buf[i]) && !isspace((unsigned char) buf[i]))
                ascii = 0;
        }
        if (ascii && isdigit((unsigned char) *p)) {
            pid = strtol(p, NULL, 10);
        } else if (n == 4) {
            int32_t bin;
            memcpy(&bin, buf, sizeof(bin));
            pid = bin;
        }
        if (pid > INT_MAX)
            pid = 0;
        if (pid > 0 && (pid == getpid() || !pid_alive((pid_t) pid)))
            continue;

        out->why = CELL_BUSY_LOCKFILE;
        out->pid = (pid_t) (pid > 0 ? pid : 0);
        snprintf(out->lockfile, sizeof(out->lockfile), "%s/%s", kDirs[d], lname);
        if (out->pid > 0)
            read_comm(out->pid, out->comm, sizeof(out->comm));
        return 1;
    }
    return 0;
}

static int check_open(const char *resolved, cell_busy_t *out) {
    snap_take();
    for (int i = 0; i < g_nsnap; i++) {
        if (strcmp(g_snap[i].path, resolved) != 0)
            continue;
        out->why = CELL_BUSY_OPEN;
        out->pid = g_snap[i].pid;
        snprintf(out->comm, sizeof(out->comm), "%s", g_snap[i].comm);
        return 1;
    }
    /* The baseline sees holders the live scan cannot after the capability
     * drop; a holder still alive under the same name is taken as still
     * holding, since its fd table can no longer be read to check. */
    if (g_base_valid && ms_since(&g_base_ts) < BUSY_BASE_TTL_MS) {
        for (int i = 0; i < g_nbase; i++) {
            if (strcmp(g_base[i].path, resolved) != 0 || !pid_alive(g_base[i].pid))
                continue;
            char comm[16];
            read_comm(g_base[i].pid, comm, sizeof(comm));
            if (strcmp(comm, g_base[i].comm) != 0)
                continue;
            out->why = CELL_BUSY_OPEN;
            out->pid = g_base[i].pid;
            snprintf(out->comm, sizeof(out->comm), "%s", g_base[i].comm);
            return 1;
        }
    }
    return 0;
}

/* 1 if the udev database marks char device maj:min for ModemManager to leave
 * alone. */
static int udev_mm_ignored(unsigned int maj, unsigned int min) {
    char rel[64], path[PATH_MAX], buf[4096];
    snprintf(rel, sizeof(rel), "/run/udev/data/c%u:%u", maj, min);
    if (!rooted(path, sizeof(path), rel) || read_small(path, buf, sizeof(buf)) < 0)
        return 0;
    for (char *line = buf; line != NULL && *line; ) {
        char *nl = strchr(line, '\n');
        if (nl)
            *nl = '\0';
        if (strcmp(line, "E:ID_MM_DEVICE_IGNORE=1") == 0 ||
            strcmp(line, "E:ID_MM_PORT_IGNORE=1") == 0)
            return 1;
        line = nl ? nl + 1 : NULL;
    }
    return 0;
}

/* The USB device above a tty, by its "dev" attribute ("189:4"). */
static int usb_parent_devnum(const char *name, unsigned int *maj, unsigned int *min) {
    char rel[PATH_MAX], path[PATH_MAX], dir[PATH_MAX];
    if ((size_t) snprintf(rel, sizeof(rel), "/sys/class/tty/%s/device", name) >= sizeof(rel) ||
        !rooted(path, sizeof(path), rel) || realpath(path, dir) == NULL)
        return 0;

    /* usb-serial: port -> interface -> device; cdc_acm: interface -> device */
    for (int up = 0; up < 4; up++) {
        char attr[PATH_MAX], buf[32];
        struct stat st;
        if ((size_t) snprintf(attr, sizeof(attr), "%s/idVendor", dir) < sizeof(attr) &&
            stat(attr, &st) == 0) {
            if ((size_t) snprintf(attr, sizeof(attr), "%s/dev", dir) >= sizeof(attr) ||
                read_small(attr, buf, sizeof(buf)) < 0)
                return 0;
            return sscanf(buf, "%u:%u", maj, min) == 2;
        }
        char *slash = strrchr(dir, '/');
        if (slash == NULL || slash == dir)
            return 0;
        *slash = '\0';
    }
    return 0;
}

static int check_mm(const char *name, dev_t rdev, cell_busy_t *out) {
    snap_take();
    if (g_mm_pid == 0)
        return 0;
    if (udev_mm_ignored(major(rdev), minor(rdev)))
        return 0;
    unsigned int umaj, umin;
    if (usb_parent_devnum(name, &umaj, &umin) && udev_mm_ignored(umaj, umin))
        return 0;
    out->why = CELL_BUSY_MODEMMANAGER;
    out->pid = g_mm_pid;
    snprintf(out->comm, sizeof(out->comm), "ModemManager");
    return 1;
}

int cell_port_busy_node(const char *resolved, const char *name, dev_t rdev,
                        int check_modemmanager, cell_busy_t *out) {
    cell_busy_t scratch;
    if (out == NULL)
        out = &scratch;
    memset(out, 0, sizeof(*out));
    if (resolved == NULL || name == NULL)
        return 0;

    if (check_lockfile(resolved, out) || check_open(resolved, out))
        return 1;
    if (check_modemmanager && check_mm(name, rdev, out))
        return 1;
    return 0;
}

int cell_port_busy(const char *dev_path, int check_modemmanager, cell_busy_t *out) {
    if (out != NULL)
        memset(out, 0, sizeof(*out));
    if (dev_path == NULL || *dev_path != '/')
        return 0;

    char resolved[PATH_MAX];
    struct stat st;
    if (realpath(dev_path, resolved) == NULL || stat(resolved, &st) != 0 ||
        !S_ISCHR(st.st_mode))
        return 0;
    const char *name = strrchr(resolved, '/');
    name = name ? name + 1 : resolved;

    return cell_port_busy_node(resolved, name, st.st_rdev, check_modemmanager, out);
}

void cell_busy_label(const cell_busy_t *b, char *buf, size_t bufsz) {
    if (buf == NULL || bufsz == 0)
        return;
    buf[0] = '\0';
    if (b == NULL)
        return;

    char who[64];
    if (b->pid > 0)
        snprintf(who, sizeof(who), "%s (pid %d)", b->comm[0] ? b->comm : "?",
                 (int) b->pid);
    else
        snprintf(who, sizeof(who), "an unknown process");

    switch (b->why) {
        case CELL_BUSY_LOCKFILE:
            snprintf(buf, bufsz, "locked by %s, lock file %s", who, b->lockfile);
            break;
        case CELL_BUSY_OPEN:
            snprintf(buf, bufsz, "open in %s", who);
            break;
        case CELL_BUSY_MODEMMANAGER:
            snprintf(buf, bufsz, "managed by %s; stop ModemManager, set "
                     "ID_MM_DEVICE_IGNORE=1 on the modem in a udev rule, or name "
                     "the port with atport= to use it anyway", who);
            break;
        default:
            break;
    }
}

#define BUSY_LOGGED_MAX 64
static char g_logged[BUSY_LOGGED_MAX][64];
static int g_nlogged;

int cell_busy_log_once(FILE *f, const char *who, const char *dev_path,
                       const cell_busy_t *b) {
    if (f == NULL || dev_path == NULL || b == NULL || b->why == CELL_BUSY_NONE)
        return 0;
    for (int i = 0; i < g_nlogged; i++) {
        if (strcmp(g_logged[i], dev_path) == 0)
            return 0;
    }
    if (g_nlogged >= BUSY_LOGGED_MAX || strlen(dev_path) >= sizeof(g_logged[0]))
        return 0;
    snprintf(g_logged[g_nlogged++], sizeof(g_logged[0]), "%s", dev_path);

    char label[384];
    cell_busy_label(b, label, sizeof(label));
    fprintf(f, "%s: skip %s: %s\n", who ? who : "scan", dev_path, label);
    fflush(f);
    return 1;
}

#if defined(CELL_SELFTEST) && defined(CELL_DISCOVER_SELFTEST)

#include <ftw.h>

static int failures = 0;

static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    }
}

static char g_tree[PATH_MAX];

static void mkdir_p(const char *rel) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s%s", g_tree, rel);
    for (char *p = path + strlen(g_tree) + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(path, 0755);
            *p = '/';
        }
    }
    mkdir(path, 0755);
}

static void write_file(const char *rel, const char *text, size_t len) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s%s", g_tree, rel);
    FILE *f = fopen(path, "w");
    if (f == NULL) {
        perror(path);
        exit(2);
    }
    fwrite(text, 1, len, f);
    fclose(f);
}

static void write_text(const char *rel, const char *text) {
    write_file(rel, text, strlen(text));
}

static void link_rel(const char *target, const char *rel) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s%s", g_tree, rel);
    if (symlink(target, path) != 0) {
        perror(path);
        exit(2);
    }
}

static void unlink_rel(const char *rel) {
    char path[PATH_MAX];
    snprintf(path, sizeof(path), "%s%s", g_tree, rel);
    unlink(path);
}

static void fake_proc(int pid, const char *comm, const char *fd_target) {
    char rel[128], text[64];
    snprintf(rel, sizeof(rel), "/proc/%d/fd", pid);
    mkdir_p(rel);
    snprintf(rel, sizeof(rel), "/proc/%d/comm", pid);
    snprintf(text, sizeof(text), "%s\n", comm);
    write_text(rel, text);
    if (fd_target) {
        snprintf(rel, sizeof(rel), "/proc/%d/fd/3", pid);
        link_rel(fd_target, rel);
    }
}

static void test_names(void) {
    char v[32];
    check(cell_name_parse("cellat", "cellat", v, sizeof(v)) == CELL_NAME_ANY && !v[0],
          "bare cellat is ANY");
    check(cell_name_parse("cellat-123456789012345", "cellat", v, sizeof(v)) ==
          CELL_NAME_IMEI && strcmp(v, "123456789012345") == 0, "IMEI name");
    check(cell_name_parse("cellat-usb1-5.1", "cellat", v, sizeof(v)) == CELL_NAME_USB &&
          strcmp(v, "1-5.1") == 0, "USB name");
    check(cell_name_parse("cellat-usb2-1", "cellat", v, sizeof(v)) == CELL_NAME_USB,
          "USB name, no hub");
    check(cell_name_parse("celldiag", "cellat", v, sizeof(v)) == CELL_NAME_BAD,
          "other prefix");
    check(cell_name_parse("cellatx", "cellat", v, sizeof(v)) == CELL_NAME_BAD,
          "prefix plus junk");
    check(cell_name_parse("cellat-", "cellat", v, sizeof(v)) == CELL_NAME_BAD, "dash only");
    check(cell_name_parse("cellat-12345678901234", "cellat", v, sizeof(v)) == CELL_NAME_BAD,
          "14 digits");
    check(cell_name_parse("cellat-1234567890123456", "cellat", v, sizeof(v)) == CELL_NAME_BAD,
          "16 digits");
    check(cell_name_parse("cellat-12345678901234x", "cellat", v, sizeof(v)) == CELL_NAME_BAD,
          "IMEI with a letter");
    check(cell_name_parse("cellat-123456789012345", "cellat", v, 15) == CELL_NAME_BAD,
          "IMEI into a short buffer");

    static const char *const bad_usb[] = {
        "cellat-usb", "cellat-usb1", "cellat-usb1-", "cellat-usb-1", "cellat-usb1-5.",
        "cellat-usb1-5..1", "cellat-usb1.5", "cellat-usb1-5-1", "cellat-usb1-5.1x",
        "cellat-usb1234-5", "cellat-usb1-5/..", "cellat-usb1-5.1.2.3.4.5.6.7.8.9",
        "cellat-usb+1-5", "cellat-usb 1-5",
    };
    for (size_t i = 0; i < sizeof(bad_usb) / sizeof(bad_usb[0]); i++) {
        char what[96];
        snprintf(what, sizeof(what), "bad USB name %s", bad_usb[i]);
        check(cell_name_parse(bad_usb[i], "cellat", v, sizeof(v)) == CELL_NAME_BAD, what);
    }
    check(cell_name_parse("cellat-usb1-5.1", "cellat", v, 5) == CELL_NAME_BAD,
          "USB into a short buffer");
    check(cell_name_parse(NULL, "cellat", v, sizeof(v)) == CELL_NAME_BAD, "NULL name");
}

static void build_tree(void) {
    const char *tmp = getenv("TMPDIR");
    snprintf(g_tree, sizeof(g_tree), "%s/cell_discover.XXXXXX", tmp && *tmp ? tmp : "/tmp");
    if (mkdtemp(g_tree) == NULL) {
        perror("mkdtemp");
        exit(2);
    }
    mkdir_p("/run/lock");
    mkdir_p("/var");
    link_rel("../run/lock", "/var/lock");
    mkdir_p("/run/udev/data");

    /* One EG25-class modem: usb device 1-5.1 (c189:4), ttyUSB2 on if02 */
    mkdir_p("/sys/devices/usb1/1-5/1-5.1/1-5.1:1.2/ttyUSB2");
    write_text("/sys/devices/usb1/1-5/1-5.1/idVendor", "2c7c\n");
    write_text("/sys/devices/usb1/1-5/1-5.1/dev", "189:4\n");
    mkdir_p("/sys/class/tty/ttyUSB2");
    char target[PATH_MAX + 64];
    snprintf(target, sizeof(target), "%s/sys/devices/usb1/1-5/1-5.1/1-5.1:1.2/ttyUSB2", g_tree);
    link_rel(target, "/sys/class/tty/ttyUSB2/device");

    mkdir_p("/proc");
}

static int busy(int mm, cell_busy_t *b) {
    cell_discover_set_root(g_tree);   /* drop the snapshot between cases */
    return cell_port_busy_node("/dev/ttyUSB2", "ttyUSB2", makedev(188, 2), mm, b);
}

static void test_busy(void) {
    cell_busy_t b;
    char label[384];

    check(!busy(1, &b) && b.why == CELL_BUSY_NONE, "idle port is free");

    /* Lock file of a live process (our parent), then of a dead one */
    char text[32];
    snprintf(text, sizeof(text), "%10d\n", (int) getppid());
    write_text("/run/lock/LCK..ttyUSB2", text);
    check(busy(1, &b) && b.why == CELL_BUSY_LOCKFILE && b.pid == getppid(),
          "live ASCII lock is busy");
    cell_busy_label(&b, label, sizeof(label));
    check(strstr(label, "/run/lock/LCK..ttyUSB2") != NULL, "lock label names the file");

    write_text("/run/lock/LCK..ttyUSB2", "  1073741823\n");
    check(!busy(1, &b), "stale lock (dead pid) is free");

    snprintf(text, sizeof(text), "%10d\n", (int) getpid());
    write_text("/run/lock/LCK..ttyUSB2", text);
    check(!busy(1, &b), "our own lock is free");

    int32_t bin = (int32_t) getppid();
    write_file("/run/lock/LCK..ttyUSB2", (const char *) &bin, sizeof(bin));
    check(busy(1, &b) && b.pid == getppid(), "binary lock is busy");

    write_text("/run/lock/LCK..ttyUSB2", "garbage\n");
    check(busy(1, &b) && b.why == CELL_BUSY_LOCKFILE && b.pid == 0,
          "unreadable lock pid is busy");
    unlink_rel("/run/lock/LCK..ttyUSB2");

    write_text("/run/lock/LCK..ttyUSB20", "garbage\n");
    check(!busy(1, &b), "another port's lock does not match");
    unlink_rel("/run/lock/LCK..ttyUSB20");

    /* Open in a process that takes no lock */
    fake_proc(4242, "screen", "/dev/ttyUSB2");
    check(busy(1, &b) && b.why == CELL_BUSY_OPEN && b.pid == 4242 &&
          strcmp(b.comm, "screen") == 0, "open fd is busy");
    unlink_rel("/proc/4242/fd/3");
    link_rel("/dev/ttyUSB20", "/proc/4242/fd/3");
    check(!busy(1, &b), "a different node held is free");

    /* The baseline: a holder seen while privileged, whose fd table can no
     * longer be read */
    char prel[64];
    int pp = (int) getppid();
    fake_proc(pp, "picocom", "/dev/ttyUSB2");
    cell_discover_set_root(g_tree);
    cell_discover_baseline();
    snprintf(prel, sizeof(prel), "/proc/%d/fd/3", pp);
    unlink_rel(prel);
    check(cell_port_busy_node("/dev/ttyUSB2", "ttyUSB2", makedev(188, 2), 1, &b) &&
          b.why == CELL_BUSY_OPEN && b.pid == pp && strcmp(b.comm, "picocom") == 0,
          "baseline holder still alive is busy");
    snprintf(prel, sizeof(prel), "/proc/%d/comm", pp);
    write_text(prel, "bash\n");
    check(!cell_port_busy_node("/dev/ttyUSB2", "ttyUSB2", makedev(188, 2), 1, &b),
          "baseline pid reused by another program is free");
    check(!busy(1, &b), "set_root drops the baseline");

    /* Kismet's own sources and ourselves are left to flock() */
    fake_proc(4343, "kismet_cap_cell", "/dev/ttyUSB2");
    check(!busy(1, &b), "a kismet cell source holding it is left to flock");
    fake_proc((int) getpid(), "test", "/dev/ttyUSB2");
    check(!busy(1, &b), "our own fd is ignored");

    /* ModemManager */
    fake_proc(500, "ModemManager", NULL);
    check(busy(1, &b) && b.why == CELL_BUSY_MODEMMANAGER && b.pid == 500,
          "ModemManager running: busy");
    check(!busy(0, &b), "named port skips the ModemManager check");
    cell_busy_label(&b, label, sizeof(label));

    write_text("/run/udev/data/c188:2", "E:ID_MM_CANDIDATE=1\nE:ID_MM_PORT_IGNORE=1\n");
    check(!busy(1, &b), "port marked ID_MM_PORT_IGNORE is free");
    write_text("/run/udev/data/c188:2", "E:ID_MM_CANDIDATE=1\n");
    check(busy(1, &b), "candidate port without ignore is busy");
    write_text("/run/udev/data/c189:4", "E:ID_VENDOR_ID=2c7c\nE:ID_MM_DEVICE_IGNORE=1\n");
    check(!busy(1, &b), "USB device marked ID_MM_DEVICE_IGNORE is free");
    write_text("/run/udev/data/c189:4", "E:ID_MM_DEVICE_IGNORE=0\n");
    check(busy(1, &b), "ID_MM_DEVICE_IGNORE=0 is not ignored");

    /* Not a char device, not absolute */
    check(!cell_port_busy("usb:1-4:2", 1, &b), "libusb spec is never busy");
    check(!cell_port_busy("/nonexistent/ttyUSB9", 1, &b), "missing node is never busy");
}

static void test_usb_location(void) {
    char dev[32];
    int ifn = -1;

    cell_discover_set_root(g_tree);
    check(cell_tty_usb_location("/dev/ttyUSB2", dev, sizeof(dev), &ifn) &&
          strcmp(dev, "1-5.1") == 0 && ifn == 2, "usb-serial port: 1-5.1 if02");

    /* cdc_acm: the tty's device is the interface itself */
    mkdir_p("/sys/devices/usb3/3-2/3-2:1.4/tty/ttyACM0");
    mkdir_p("/sys/class/tty/ttyACM0");
    char target[PATH_MAX + 64];
    snprintf(target, sizeof(target), "%s/sys/devices/usb3/3-2/3-2:1.4", g_tree);
    link_rel(target, "/sys/class/tty/ttyACM0/device");
    ifn = -1;
    check(cell_tty_usb_location("/dev/ttyACM0", dev, sizeof(dev), &ifn) &&
          strcmp(dev, "3-2") == 0 && ifn == 4, "cdc_acm port: 3-2 if04");

    check(!cell_tty_usb_location("/dev/ttyACM0", dev, 3, &ifn), "short buffer refused");
    check(!cell_tty_usb_location("/dev/ttyS0", dev, sizeof(dev), &ifn), "no sysfs entry");
    check(!cell_tty_usb_location("", dev, sizeof(dev), &ifn), "empty path");
    cell_discover_set_root("");
}

static void test_pick(void) {
    cell_pick_t p;
    char buf[512];
    cell_pick_reset(&p);
    cell_pick_add(&p, "/dev/ttyUSB3", "fw", "111111111111111", "1-5.1");
    cell_pick_add(&p, "/dev/ttyUSB2", "fw", "111111111111111", "1-5.1");
    check(p.total == 1, "second port of one modem is one modem");
    cell_pick_add(&p, "/dev/ttyUSB7", "fw", "", "1-6");
    check(p.total == 1, "a modem with no IMEI is not addressable");
    cell_pick_add(&p, "usb:1-9:2", "fw", "222222222222222", "usb:1-9");
    check(p.total == 2, "two modems");
    cell_pick_choices(&p, "cellat", buf, sizeof(buf));
    check(strcmp(buf, "cellat-111111111111111 (ttyUSB3, or cellat-usb1-5.1); "
                 "cellat-222222222222222 (usb:1-9:2)") == 0, "choices text");
    for (int i = 0; i < 12; i++) {
        char imei[16];
        snprintf(imei, sizeof(imei), "3333333333333%02d", i);
        cell_pick_add(&p, "/dev/ttyUSB9", "fw", imei, "");
    }
    check(p.total == 14, "count past the stored limit");
    cell_pick_choices(&p, "cellat", buf, sizeof(buf));
    check(strstr(buf, "and 6 more") != NULL, "choices note the rest");
    cell_pick_choices(&p, "cellat", buf, 20);
    check(strlen(buf) < 20, "choices fit a short buffer");

    /* libusb ids map through the bus/device numbers */
    cell_discover_set_root(g_tree);
    mkdir_p("/sys/bus/usb/devices/1-5.1");
    write_text("/sys/bus/usb/devices/1-5.1/busnum", "1\n");
    write_text("/sys/bus/usb/devices/1-5.1/devnum", "9\n");
    check(cell_usb_matches("1-5.1", "1-5.1"), "same port matches");
    check(!cell_usb_matches("1-5.2", "1-5.1"), "other port");
    check(cell_usb_matches("usb:1-9", "1-5.1"), "libusb id on that port");
    check(!cell_usb_matches("usb:1-8", "1-5.1"), "libusb id elsewhere");
    check(!cell_usb_matches("usb:1-9", "../1-5.1"), "want is validated");
    cell_discover_set_root("");
}

static void test_log_once(void) {
    cell_busy_t b;
    memset(&b, 0, sizeof(b));
    b.why = CELL_BUSY_OPEN;
    b.pid = 7;
    snprintf(b.comm, sizeof(b.comm), "screen");
    FILE *f = tmpfile();
    check(f != NULL, "tmpfile");
    if (f == NULL)
        return;
    check(cell_busy_log_once(f, "cellat", "/dev/ttyUSB2", &b) == 1, "first log");
    check(cell_busy_log_once(f, "cellat", "/dev/ttyUSB2", &b) == 0, "second log muted");
    rewind(f);
    char line[256] = "";
    check(fgets(line, sizeof(line), f) != NULL &&
          strcmp(line, "cellat: skip /dev/ttyUSB2: open in screen (pid 7)\n") == 0,
          "log line text");
    fclose(f);
}

static int rm_one(const char *path, const struct stat *st, int flag, struct FTW *ftw) {
    (void) st;
    (void) flag;
    (void) ftw;
    return remove(path);
}

int main(void) {
    test_names();
    build_tree();
    test_busy();
    test_usb_location();
    test_pick();
    test_log_once();
    cell_discover_set_root("");

    if (failures) {
        fprintf(stderr, "%d failure(s); tree left at %s\n", failures, g_tree);
        return 1;
    }
    if (nftw(g_tree, rm_one, 16, FTW_DEPTH | FTW_PHYS) != 0)
        fprintf(stderr, "warning: could not remove %s\n", g_tree);
    printf("cell_discover selftest: all passed\n");
    return 0;
}

#endif
