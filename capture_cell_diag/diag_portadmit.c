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

    See diag_portadmit.h for what this is and why.
*/

#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include "diag_portadmit.h"

/* The usb-serial drivers that exist for cellular modems. sysfs reports a
 * usb-serial driver as its name plus the bus's driver number -- "option1" --
 * so `option` also matches when followed by digits only. qcserial and sierra
 * register without a number. */
static const char *const kCellSerialDrivers[] = { "option", "qcserial", "sierra" };

/* The vendors whose modems enumerate CDC-ACM AT ports. cdc_acm alone proves
 * nothing -- it binds u-blox GNSS receivers (1546), Arduinos and every other
 * CDC-ACM gadget -- so an acm tty is admitted only on one of these.
 *
 * Deliberately absent: 1546 (u-blox, whose cellular SARA/TOBY share the id
 * with its GNSS line), 0e8d (MediaTek, whose preloader and phones are also
 * cdc_acm) and 8087 (Intel, far more than modems). A modem from one of those
 * is named by the operator, like any modem behind a bridge. */
static const char *const kCellAcmVendors[] = {
    "05c6",   /* Qualcomm (reference designs, Foxconn T99W175 in 90ad mode) */
    "0bdb",   /* Ericsson */
    "1199",   /* Sierra Wireless */
    "12d1",   /* Huawei */
    "1410",   /* Novatel */
    "19d2",   /* ZTE */
    "1bbb",   /* T&A Mobile (TCL / Alcatel) */
    "1bc7",   /* Telit */
    "1e0e",   /* SIMCom (Qualcomm-based) */
    "2c7c",   /* Quectel */
    "2cb7",   /* Fibocom */
    "2cd2",   /* MikroTik (R11e-LTE) */
    "2dee",   /* MeiG */
    "305a",   /* Gosuncn */
    "33f8",   /* Rolling Wireless */
    "413c",   /* Dell (rebadged Sierra / Foxconn) */
};

/* Rule 4: interfaces of an ADMITTED modem that are measured never to
 * answer AT -- its DIAG and NMEA functions. Without this table, a scan that
 * walks every interface of a modem until one answers writes "AT\r\n" into
 * them, and flushes a GNSS reader's bytes, whenever the AT ports ahead of them
 * are held by a sibling source.
 *
 * Every entry is MEASURED, never inferred, and keyed by the exact VID:PID,
 * interface number AND class/subclass/protocol triple. A wrong entry refuses a
 * modem's AT port, so:
 *   - never per vendor: 2c7c:0700's if00-if02 are all ff/ff/ff and its if02
 *     answers AT+CGSN (diag_ifclass.c);
 *   - never without the triple: the NMEA and AT ports of the Quectels below are
 *     both ff/00/00, so the triple cannot tell them apart -- but it does tell a
 *     different composition (a usbcfg change, another firmware) from the one
 *     measured, and a port that does not match exactly keeps the verdict of
 *     rules 1-3.
 *
 * Basis, measured on USB-attached units unless noted. DIAG = ff/ff/{ff,30}, the
 * celldiag LOG_CONFIG handshake target (diag_ifclass.c). NMEA = the port a
 * passive read found streaming NMEA with GNSS on, which did not answer "AT".
 *   EG25-G    2c7c:0125  if01 streamed 342 sentences in 3 s (QGPSCFG outport
 *                        usbnmea); "AT" got NMEA back, no OK
 *   RM500Q-AE 2c7c:0800  if01 streamed 172 in 3 s; "AT" was echoed, no OK
 *   RM520N-GL 2c7c:0801  if01 is ff/00/40, recorded as NMEA by a survey of
 *                        a USB unit (if01 "echoes AT but doesn't parse"); the
 *                        triple is a test_diag_ifclass fixture. A PCIe
 *                        RM520N-GL has no ttyUSB at all (/dev/mhi_*,
 *                        diag_wwanport.h).
 *   LM960A18  1bc7:1040  if03 streamed 270 in 3 s; "AT" and "AT+CGMM" got NMEA
 *                        back, while if04/if05/if06 answered "LM960A18". */
typedef struct {
    const char *vidpid;
    int ifnum, cls, sub, prot;
    const char *role;
} portadmit_nonat_t;

static const portadmit_nonat_t kKnownNonAt[] = {
    { "2c7c:0125", 0, 0xff, 0xff, 0xff, "DIAG" },   /* Quectel EG25-G */
    { "2c7c:0125", 1, 0xff, 0x00, 0x00, "NMEA" },
    { "2c7c:0800", 0, 0xff, 0xff, 0x30, "DIAG" },   /* Quectel RM500Q-AE */
    { "2c7c:0800", 1, 0xff, 0x00, 0x00, "NMEA" },
    { "2c7c:0801", 0, 0xff, 0xff, 0x30, "DIAG" },   /* Quectel RM520N-GL */
    { "2c7c:0801", 1, 0xff, 0x00, 0x40, "NMEA" },
    { "1bc7:1040", 0, 0xff, 0xff, 0xff, "DIAG" },   /* Telit LM960A18 */
    { "1bc7:1040", 3, 0xff, 0x00, 0x00, "NMEA" },
};

/* How many parent directories above the tty's `device` to search for the USB
 * device's idVendor: a usb-serial port is two below it (port -> interface ->
 * device), a cdc_acm interface one. Three bounds the walk on a tty that has no
 * USB ancestor at all. */
#define PORTADMIT_UP_MAX 3

static int driver_is_cell_serial(const char *driver) {
    for (size_t i = 0; i < sizeof(kCellSerialDrivers) / sizeof(kCellSerialDrivers[0]); i++) {
        const char *name = kCellSerialDrivers[i];
        size_t n = strlen(name);
        if (strncmp(driver, name, n) != 0)
            continue;
        const char *rest = driver + n;
        if (*rest == '\0')
            return 1;
        /* Only `option` is numbered by the usb-serial bus ("option1"); a
         * "qcserial2" or an "optionx" is some other driver. */
        if (strcmp(name, "option") != 0)
            continue;
        while (isdigit((unsigned char)*rest))
            rest++;
        if (*rest == '\0')
            return 1;
    }
    return 0;
}

static int vid_is_cell_acm(const char *vidpid) {
    for (size_t i = 0; i < sizeof(kCellAcmVendors) / sizeof(kCellAcmVendors[0]); i++) {
        if (strncmp(vidpid, kCellAcmVendors[i], 4) == 0 && vidpid[4] == ':')
            return 1;
    }
    return 0;
}

/* The first line of a sysfs attribute, lower-cased hex, into out (4 chars). */
static int read_hex4(const char *dir, const char *attr, char out[5]) {
    char path[PATH_MAX];
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir, attr) >= sizeof(path))
        return 0;
    FILE *f = fopen(path, "r");
    if (!f)
        return 0;
    char line[16];
    int ok = fgets(line, sizeof(line), f) != NULL;
    fclose(f);
    if (!ok)
        return 0;
    for (int i = 0; i < 4; i++) {
        if (!isxdigit((unsigned char)line[i]))
            return 0;
        out[i] = (char)tolower((unsigned char)line[i]);
    }
    out[4] = '\0';
    return 1;
}

/* A sysfs attribute holding one byte as two hex digits ("02\n"), or -1. */
static int read_hex2(const char *dir, const char *attr) {
    char path[PATH_MAX];
    if ((size_t)snprintf(path, sizeof(path), "%s/%s", dir, attr) >= sizeof(path))
        return -1;
    FILE *f = fopen(path, "r");
    if (!f)
        return -1;
    char line[8];
    int ok = fgets(line, sizeof(line), f) != NULL;
    fclose(f);
    if (!ok || !isxdigit((unsigned char)line[0]) || !isxdigit((unsigned char)line[1]))
        return -1;
    line[2] = '\0';
    return (int)strtol(line, NULL, 16);
}

/* The role of a known non-AT interface (rule 4), or NULL. Any unread byte (-1)
 * matches nothing. */
static const char *known_nonat_role(const char *vidpid, int ifnum, int cls,
                                    int sub, int prot) {
    for (size_t i = 0; i < sizeof(kKnownNonAt) / sizeof(kKnownNonAt[0]); i++) {
        const portadmit_nonat_t *e = &kKnownNonAt[i];
        if (strcmp(vidpid, e->vidpid) == 0 && ifnum == e->ifnum &&
            cls == e->cls && sub == e->sub && prot == e->prot)
            return e->role;
    }
    return NULL;
}

static void verdict(diag_portadmit_t *v, int admit, const char *reason) {
    v->admit = admit;
    v->reason = reason;
}

int diag_port_admit(const char *sysfs_root, const char *dev_path,
                    diag_portadmit_t *out) {
    diag_portadmit_t local;
    diag_portadmit_t *v = out ? out : &local;
    memset(v, 0, sizeof(*v));
    v->ifnum = -1;
    verdict(v, 0, "no path");

    if (sysfs_root == NULL || *sysfs_root == '\0' || dev_path == NULL ||
        *dev_path == '\0')
        return 0;

    /* The basename selects the sysfs entry; the /dev node itself is never
     * touched -- not stat()ed, not opened. */
    const char *name = strrchr(dev_path, '/');
    name = name ? name + 1 : dev_path;
    if (*name == '\0' || strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
        return 0;

    char link[PATH_MAX], dev[PATH_MAX], root[PATH_MAX];
    if ((size_t)snprintf(link, sizeof(link), "%s/class/tty/%s/device", sysfs_root,
                         name) >= sizeof(link))
        return 0;
    if (realpath(link, dev) == NULL) {
        verdict(v, 0, "no sysfs device");
        return 0;
    }
    /* The walk up to the USB device stays inside the sysfs root. */
    if (realpath(sysfs_root, root) == NULL)
        snprintf(root, sizeof(root), "%s", sysfs_root);

    /* The bound driver: the basename of <device>/driver. */
    char drvlink[PATH_MAX], drvpath[PATH_MAX];
    if ((size_t)snprintf(drvlink, sizeof(drvlink), "%s/driver", dev) < sizeof(drvlink) &&
        realpath(drvlink, drvpath) != NULL) {
        const char *d = strrchr(drvpath, '/');
        d = d ? d + 1 : drvpath;
        /* Refused, not truncated: a clipped name could turn
         * "option123...x" into a digits-only suffix and be admitted. */
        size_t dn = strlen(d);
        if (dn >= sizeof(v->driver)) {
            verdict(v, 0, "driver name too long");
            return 0;
        }
        memcpy(v->driver, d, dn + 1);
    }

    /* The USB device's vendor:product, the nearest ancestor carrying idVendor,
     * and on the way up the interface's descriptor (rule 4): the interface is
     * the usb-serial port's parent, or the cdc_acm `device` itself, so it is
     * always met before the device. */
    char up[PATH_MAX];
    int cls = -1, sub = -1, prot = -1;
    snprintf(up, sizeof(up), "%s", dev);
    for (int i = 0; i <= PORTADMIT_UP_MAX; i++) {
        char vid[5], pid[5];
        if (v->ifnum < 0 && (v->ifnum = read_hex2(up, "bInterfaceNumber")) >= 0) {
            cls = read_hex2(up, "bInterfaceClass");
            sub = read_hex2(up, "bInterfaceSubClass");
            prot = read_hex2(up, "bInterfaceProtocol");
        }
        if (read_hex4(up, "idVendor", vid) && read_hex4(up, "idProduct", pid)) {
            snprintf(v->vidpid, sizeof(v->vidpid), "%s:%s", vid, pid);
            break;
        }
        char *slash = strrchr(up, '/');
        if (slash == NULL || slash == up)
            break;
        *slash = '\0';
        if (strncmp(up, root, strlen(root)) != 0 || strlen(up) <= strlen(root))
            break;
    }

    if (v->driver[0] == '\0') {
        verdict(v, 0, "no driver bound");
        return 0;
    }
    if (driver_is_cell_serial(v->driver)) {
        verdict(v, 1, "a cellular usb-serial driver");
    } else if (strcmp(v->driver, "cdc_acm") == 0) {
        if (!v->vidpid[0] || !vid_is_cell_acm(v->vidpid)) {
            verdict(v, 0, "cdc_acm without a cellular vendor id");
            return 0;
        }
        verdict(v, 1, "cdc_acm on a cellular vendor id");
    } else {
        verdict(v, 0, "not a cellular usb-serial driver");
        return 0;
    }

    /* Rule 4: a suspected modem, but one of its measured non-AT
     * interfaces. */
    v->role = known_nonat_role(v->vidpid, v->ifnum, cls, sub, prot);
    if (v->role != NULL) {
        verdict(v, 0, "a cell modem's known non-AT interface");
        return 0;
    }
    return 1;
}

void diag_portadmit_label(const diag_portadmit_t *v, char *buf, size_t bufsz) {
    if (buf == NULL || bufsz == 0)
        return;
    if (v == NULL) {
        buf[0] = '\0';
        return;
    }
    const char *drv = v->driver[0] ? v->driver : "no-driver";
    const char *id = v->vidpid[0] ? v->vidpid : "no-usb-id";
    if (v->role != NULL)
        snprintf(buf, bufsz, "%s %s if%02d %s", drv, id, v->ifnum, v->role);
    else
        snprintf(buf, bufsz, "%s %s", drv, id);
}

void diag_portadmit_note(char *buf, size_t bufsz, const char *dev_path,
                         const diag_portadmit_t *v) {
    if (buf == NULL || bufsz == 0)
        return;
    size_t off = strnlen(buf, bufsz);
    if (off >= bufsz) {
        buf[bufsz - 1] = '\0';
        return;
    }
    const char *base = dev_path ? strrchr(dev_path, '/') : NULL;
    base = base ? base + 1 : (dev_path ? dev_path : "?");
    char label[96], entry[192];
    diag_portadmit_label(v, label, sizeof(label));
    int n = snprintf(entry, sizeof(entry), "%s%s(%s)", off ? "," : "", base, label);
    /* A half-written port name is worse than none. */
    if (n < 0 || (size_t)n >= sizeof(entry) || off + (size_t)n + 1 > bufsz)
        return;
    memcpy(buf + off, entry, (size_t)n + 1);
}

/* Paths already logged by this process. A scan's universe is bounded (the
 * callers cap it at 64 ports), so a small table suffices; once it is full a
 * new refusal is not logged rather than logged on every scan. */
#define PORTADMIT_LOGGED_MAX 64
static char g_logged[PORTADMIT_LOGGED_MAX][64];
static int g_nlogged;

int diag_portadmit_log_once(FILE *f, const char *who, const char *dev_path,
                            const diag_portadmit_t *v, const char *hatch) {
    if (f == NULL || dev_path == NULL || v == NULL)
        return 0;
    for (int i = 0; i < g_nlogged; i++) {
        if (strcmp(g_logged[i], dev_path) == 0)
            return 0;
    }
    if (g_nlogged >= PORTADMIT_LOGGED_MAX || strlen(dev_path) >= sizeof(g_logged[0]))
        return 0;
    snprintf(g_logged[g_nlogged++], sizeof(g_logged[0]), "%s", dev_path);

    char label[96];
    diag_portadmit_label(v, label, sizeof(label));
    fprintf(f, "%s: skip %s: %s, %s (%s)\n", who ? who : "scan", dev_path, label,
            v->role != NULL ? "a cell modem's known non-AT port"
                            : "not a suspected cell modem",
            hatch ? hatch : "");
    fflush(f);
    return 1;
}

#ifdef DIAG_PORTADMIT_SELFTEST

#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;

static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    } else {
        printf("PASS: %s\n", what);
    }
}

/* --- a fake sysfs tree ------------------------------------------------------
 *
 * The two layouts a real /sys has for the two tty families, measured on a
 * test host:
 *
 *   usb-serial  /sys/class/tty/ttyUSB0/device -> .../usb1/1-2/1-2:1.0/ttyUSB0
 *               (the PORT; its `driver` is the usb-serial driver, e.g.
 *               ch341-uart or option1; idVendor is TWO levels up)
 *   cdc_acm     /sys/class/tty/ttyACM0/device -> .../usb1/1-3/1-3:1.0
 *               (the INTERFACE; its `driver` is cdc_acm; idVendor is ONE up)
 *
 * Absolute symlinks into the temp root, so realpath(3) resolves them exactly
 * as it resolves the kernel's relative ones. */
/* Short on purpose: every fake path is built into a PATH_MAX buffer from it. */
static char g_root[512];

static void mkdir_p(const char *path) {
    char tmp[PATH_MAX];
    snprintf(tmp, sizeof(tmp), "%s", path);
    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

static void write_file(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "cannot create %s: %s\n", path, strerror(errno));
        exit(2);
    }
    fputs(text, f);
    fclose(f);
}

static void link_to(const char *target, const char *linkpath) {
    if (symlink(target, linkpath) != 0) {
        fprintf(stderr, "cannot link %s -> %s: %s\n", linkpath, target,
                strerror(errno));
        exit(2);
    }
}

/* One USB device `busdev` (e.g. "1-2") with idVendor/idProduct. */
static void fake_usb_device(const char *busdev, const char *vid, const char *pid) {
    char p[PATH_MAX], f[PATH_MAX + 32];
    snprintf(p, sizeof(p), "%s/devices/pci0000:00/usb1/%s", g_root, busdev);
    mkdir_p(p);
    snprintf(f, sizeof(f), "%s/idVendor", p);
    write_file(f, vid);
    snprintf(f, sizeof(f), "%s/idProduct", p);
    write_file(f, pid);
}

/* A driver directory; `bus` is "usb-serial" or "usb". */
static void fake_driver(const char *bus, const char *driver, char *out, size_t outsz) {
    snprintf(out, outsz, "%s/bus/%s/drivers/%s", g_root, bus, driver);
    mkdir_p(out);
}

/* A usb-serial port: tty `name` on interface `busdev`:1.`ifnum`, bound to the
 * usb-serial `driver` (NULL: nothing bound). */
static void fake_usbserial(const char *name, const char *busdev, int ifnum,
                           const char *driver) {
    char port[PATH_MAX], cls[PATH_MAX], lnk[PATH_MAX + 32], drv[PATH_MAX];
    snprintf(port, sizeof(port), "%s/devices/pci0000:00/usb1/%s/%s:1.%d/%s",
             g_root, busdev, busdev, ifnum, name);
    mkdir_p(port);
    if (driver) {
        fake_driver("usb-serial", driver, drv, sizeof(drv));
        snprintf(lnk, sizeof(lnk), "%s/driver", port);
        link_to(drv, lnk);
    }
    snprintf(cls, sizeof(cls), "%s/class/tty/%s", g_root, name);
    mkdir_p(cls);
    snprintf(lnk, sizeof(lnk), "%s/device", cls);
    link_to(port, lnk);
}

/* A modem's usb-serial port on option1 WITH its interface descriptor, the
 * way the kernel writes it: two lower-case hex digits and a newline. */
static void fake_modem_port(const char *name, const char *busdev, int ifnum,
                            int cls, int sub, int prot) {
    static const char *const attr[] = { "bInterfaceNumber", "bInterfaceClass",
                                        "bInterfaceSubClass", "bInterfaceProtocol" };
    int val[] = { ifnum, cls, sub, prot };
    char f[PATH_MAX + 64], text[8];
    fake_usbserial(name, busdev, ifnum, "option1");
    for (int i = 0; i < 4; i++) {
        snprintf(f, sizeof(f), "%s/devices/pci0000:00/usb1/%s/%s:1.%d/%s",
                 g_root, busdev, busdev, ifnum, attr[i]);
        snprintf(text, sizeof(text), "%02x\n", val[i]);
        write_file(f, text);
    }
}

/* A cdc_acm tty: `device` is the interface itself. */
static void fake_acm(const char *name, const char *busdev, int ifnum) {
    char intf[PATH_MAX], cls[PATH_MAX], lnk[PATH_MAX + 32], drv[PATH_MAX];
    snprintf(intf, sizeof(intf), "%s/devices/pci0000:00/usb1/%s/%s:1.%d",
             g_root, busdev, busdev, ifnum);
    mkdir_p(intf);
    fake_driver("usb", "cdc_acm", drv, sizeof(drv));
    snprintf(lnk, sizeof(lnk), "%s/driver", intf);
    link_to(drv, lnk);
    snprintf(cls, sizeof(cls), "%s/class/tty/%s", g_root, name);
    mkdir_p(cls);
    snprintf(lnk, sizeof(lnk), "%s/device", cls);
    link_to(intf, lnk);
}

static void build_tree(void) {
    const char *tmp = getenv("TMPDIR");
    snprintf(g_root, sizeof(g_root), "%s/portadmit.XXXXXX",
             (tmp && *tmp) ? tmp : "/tmp");
    if (!mkdtemp(g_root)) {
        fprintf(stderr, "mkdtemp: %s\n", strerror(errno));
        exit(2);
    }

    /* A test host's own ports, as measured. */
    fake_usb_device("1-2", "1a86\n", "7523\n");        /* LG290P GNSS on a CH340 */
    fake_usbserial("ttyUSB0", "1-2", 0, "ch341-uart");
    fake_usb_device("1-4", "2c7c\n", "0125\n");        /* EG25-G */
    fake_usbserial("ttyUSB12", "1-4", 0, "option1");
    fake_usbserial("ttyUSB14", "1-4", 2, "option1");
    fake_usb_device("2-1", "1bc7\n", "1040\n");        /* LM960A18 */
    fake_usbserial("ttyUSB2", "2-1", 3, "option1");

    /* The other cellular usb-serial drivers. */
    fake_usb_device("1-5", "1199\n", "9071\n");        /* MC7455 */
    fake_usbserial("ttyUSB20", "1-5", 2, "qcserial");
    fake_usb_device("1-6", "1199\n", "68a2\n");        /* MC7700 */
    fake_usbserial("ttyUSB21", "1-6", 3, "sierra");
    /* A modem bound by new_id (the RC400L, quickstart Prerequisites): its
     * VID:PID is in no table, and the driver is what says "modem". */
    fake_usb_device("1-7", "05c6\n", "f622\n");
    fake_usbserial("ttyUSB22", "1-7", 1, "option1");

    /* The USB-UART bridges and the catch-all driver. */
    fake_usb_device("1-8", "0403\n", "6001\n");
    fake_usbserial("ttyUSB23", "1-8", 0, "ftdi_sio");
    fake_usb_device("1-9", "067b\n", "2303\n");
    fake_usbserial("ttyUSB24", "1-9", 0, "pl2303");
    fake_usb_device("1-10", "10c4\n", "ea60\n");
    fake_usbserial("ttyUSB25", "1-10", 0, "cp210x");
    fake_usb_device("1-11", "1a86\n", "55d4\n");       /* CH9102 */
    fake_usbserial("ttyUSB26", "1-11", 0, "ch341-uart");
    fake_usb_device("1-12", "1234\n", "5678\n");
    fake_usbserial("ttyUSB27", "1-12", 0, "generic");

    /* Driver names that merely START like a cellular one. */
    fake_usb_device("1-13", "2c7c\n", "0800\n");
    fake_usbserial("ttyUSB28", "1-13", 0, "optionx");
    fake_usbserial("ttyUSB29", "1-13", 1, "option");     /* bare, admitted */
    fake_usbserial("ttyUSB30", "1-13", 2, "option12");   /* digits, admitted */
    fake_usbserial("ttyUSB31", "1-13", 3, "qcserial2");  /* not a family spelling */

    /* A tty with no driver bound (mid-unbind). */
    fake_usb_device("1-14", "2c7c\n", "0801\n");
    fake_usbserial("ttyUSB32", "1-14", 0, NULL);

    /* cdc_acm: decided by vendor id. */
    fake_usb_device("1-3", "1546\n", "01a8\n");        /* u-blox GNSS */
    fake_acm("ttyACM0", "1-3", 0);
    fake_usb_device("1-15", "2cb7\n", "0007\n");       /* Fibocom L850-GL */
    fake_acm("ttyACM1", "1-15", 0);
    fake_usb_device("1-16", "2341\n", "0043\n");       /* Arduino Uno */
    fake_acm("ttyACM2", "1-16", 0);
    fake_usb_device("1-17", "1BC7\n", "1201\n");       /* upper-case hex: Telit */
    fake_acm("ttyACM3", "1-17", 0);

    /* Four supported modems' real port sets, WITH their interface
     * descriptors -- the fixtures above carry none, so rule 4 never applies to
     * them. Every triple was read from a test host's sysfs, and each role
     * was measured (see kKnownNonAt in the production half). */
    fake_usb_device("1-18", "2c7c\n", "0125\n");       /* EG25-G */
    fake_modem_port("ttyUSB40", "1-18", 0, 0xff, 0xff, 0xff);   /* DIAG */
    fake_modem_port("ttyUSB41", "1-18", 1, 0xff, 0x00, 0x00);   /* NMEA */
    fake_modem_port("ttyUSB42", "1-18", 2, 0xff, 0x00, 0x00);   /* AT */
    fake_modem_port("ttyUSB43", "1-18", 3, 0xff, 0x00, 0x00);   /* AT/modem */
    fake_usb_device("1-19", "2c7c\n", "0800\n");       /* RM500Q-AE */
    fake_modem_port("ttyUSB44", "1-19", 0, 0xff, 0xff, 0x30);   /* DIAG */
    fake_modem_port("ttyUSB45", "1-19", 1, 0xff, 0x00, 0x00);   /* NMEA */
    fake_modem_port("ttyUSB46", "1-19", 2, 0xff, 0x00, 0x00);   /* AT */
    fake_modem_port("ttyUSB47", "1-19", 3, 0xff, 0x00, 0x00);   /* AT/modem */
    fake_usb_device("1-20", "2c7c\n", "0801\n");       /* RM520N-GL (USB) */
    fake_modem_port("ttyUSB48", "1-20", 0, 0xff, 0xff, 0x30);   /* DIAG */
    fake_modem_port("ttyUSB49", "1-20", 1, 0xff, 0x00, 0x40);   /* NMEA */
    fake_modem_port("ttyUSB50", "1-20", 2, 0xff, 0x00, 0x00);   /* AT */
    fake_modem_port("ttyUSB51", "1-20", 3, 0xff, 0x00, 0x00);   /* AT */
    fake_usb_device("1-21", "1bc7\n", "1040\n");       /* LM960A18 */
    fake_modem_port("ttyUSB52", "1-21", 0, 0xff, 0xff, 0xff);   /* DIAG */
    fake_modem_port("ttyUSB53", "1-21", 3, 0xff, 0x00, 0x00);   /* NMEA */
    fake_modem_port("ttyUSB54", "1-21", 4, 0xff, 0x00, 0x00);   /* AT */
    fake_modem_port("ttyUSB55", "1-21", 5, 0xff, 0x00, 0x00);   /* AT */
    fake_modem_port("ttyUSB56", "1-21", 6, 0xff, 0x00, 0x00);   /* AT */
    /* 2c7c:0700 -- why the table is per VID:PID, never per vendor: if00-if02
     * are ALL ff/ff/ff and if02 answers AT+CGSN (diag_ifclass.c). */
    fake_usb_device("1-22", "2c7c\n", "0700\n");
    fake_modem_port("ttyUSB57", "1-22", 0, 0xff, 0xff, 0xff);
    fake_modem_port("ttyUSB58", "1-22", 1, 0xff, 0xff, 0xff);
    fake_modem_port("ttyUSB59", "1-22", 2, 0xff, 0xff, 0xff);
    /* A known VID:PID whose if01 does NOT carry the measured triple: some
     * other composition, so the entry does not apply. */
    fake_usb_device("1-23", "2c7c\n", "0801\n");
    fake_modem_port("ttyUSB60", "1-23", 1, 0xff, 0x00, 0x00);
    /* A known VID:PID + interface whose descriptor cannot be read. */
    fake_usb_device("1-24", "2c7c\n", "0125\n");
    fake_usbserial("ttyUSB61", "1-24", 1, "option1");
    {
        char f[PATH_MAX + 64];
        snprintf(f, sizeof(f), "%s/devices/pci0000:00/usb1/1-24/1-24:1.1/"
                 "bInterfaceNumber", g_root);
        write_file(f, "01\n");
    }

    /* cdc_acm with no USB ancestor carrying idVendor (a gadget-side tty). */
    {
        char intf[PATH_MAX], cls[PATH_MAX], lnk[PATH_MAX + 32], drv[PATH_MAX];
        snprintf(intf, sizeof(intf), "%s/devices/platform/gadget/acm.0", g_root);
        mkdir_p(intf);
        fake_driver("usb", "cdc_acm", drv, sizeof(drv));
        snprintf(lnk, sizeof(lnk), "%s/driver", intf);
        link_to(drv, lnk);
        snprintf(cls, sizeof(cls), "%s/class/tty/ttyACM4", g_root);
        mkdir_p(cls);
        snprintf(lnk, sizeof(lnk), "%s/device", cls);
        link_to(intf, lnk);
    }
}

static int admits(const char *dev) {
    diag_portadmit_t v;
    return diag_port_admit(g_root, dev, &v);
}

static void test_cellular_usbserial_admitted(void) {
    printf("-- cellular usb-serial drivers are admitted\n");
    check(admits("/dev/ttyUSB12"), "option1 (EG25-G) is admitted");
    check(admits("/dev/ttyUSB14"), "...on every interface of it");
    check(admits("/dev/ttyUSB2"), "option1 (LM960A18) is admitted");
    check(admits("/dev/ttyUSB20"), "qcserial is admitted");
    check(admits("/dev/ttyUSB21"), "sierra is admitted");
    check(admits("/dev/ttyUSB22"),
          "option1 on a new_id-bound VID:PID is admitted -- the driver decides");
    check(admits("/dev/ttyUSB29"), "a bare 'option' driver name is admitted");
    check(admits("/dev/ttyUSB30"), "'option' + digits is the same family");

    diag_portadmit_t v;
    diag_port_admit(g_root, "/dev/ttyUSB12", &v);
    check(strcmp(v.driver, "option1") == 0, "the verdict names the bound driver");
    check(strcmp(v.vidpid, "2c7c:0125") == 0,
          "...and the usb-serial port's vendor:product, two levels up");
    check(v.reason != NULL && *v.reason, "...and carries a reason");
}

static void test_bridges_refused(void) {
    diag_portadmit_t v;
    char label[128];

    printf("-- USB-UART bridges and unknown drivers are refused\n");
    check(!diag_port_admit(g_root, "/dev/ttyUSB0", &v),
          "ch341-uart (the LG290P GNSS reference) is REFUSED");
    diag_portadmit_label(&v, label, sizeof(label));
    check(strcmp(label, "ch341-uart 1a86:7523") == 0,
          "...labelled 'ch341-uart 1a86:7523' for the refusal line");
    check(!admits("/dev/ttyUSB23"), "ftdi_sio is refused");
    check(!admits("/dev/ttyUSB24"), "pl2303 is refused");
    check(!admits("/dev/ttyUSB25"), "cp210x is refused");
    check(!admits("/dev/ttyUSB26"), "ch341-uart on a CH9102 is refused");
    check(!admits("/dev/ttyUSB27"), "the 'generic' usb-serial driver is refused");
    check(!admits("/dev/ttyUSB28"),
          "'optionx' is refused -- a prefix is not the family");
    check(!admits("/dev/ttyUSB31"),
          "'qcserial2' is refused -- only option carries a digit suffix");

    check(!diag_port_admit(g_root, "/dev/ttyUSB32", &v),
          "a tty with NO driver bound is refused");
    diag_portadmit_label(&v, label, sizeof(label));
    check(strcmp(label, "no-driver 2c7c:0801") == 0,
          "...labelled 'no-driver 2c7c:0801'");
}

static void test_cdc_acm_by_vendor(void) {
    diag_portadmit_t v;
    char label[128];

    printf("-- cdc_acm is admitted only on a cellular vendor id\n");
    check(!diag_port_admit(g_root, "/dev/ttyACM0", &v),
          "cdc_acm on u-blox 1546 (a GNSS receiver) is REFUSED");
    diag_portadmit_label(&v, label, sizeof(label));
    check(strcmp(label, "cdc_acm 1546:01a8") == 0,
          "...labelled 'cdc_acm 1546:01a8' (idVendor is ONE level up for acm)");
    check(admits("/dev/ttyACM1"), "cdc_acm on Fibocom 2cb7 is admitted");
    check(!admits("/dev/ttyACM2"), "cdc_acm on an Arduino (2341) is refused");
    check(admits("/dev/ttyACM3"),
          "an upper-case idVendor (1BC7) still matches Telit");

    check(!diag_port_admit(g_root, "/dev/ttyACM4", &v),
          "cdc_acm with no USB vendor id is refused -- nothing says 'modem'");
    diag_portadmit_label(&v, label, sizeof(label));
    check(strcmp(label, "cdc_acm no-usb-id") == 0,
          "...labelled 'cdc_acm no-usb-id'");
}

static void test_no_sysfs_and_degenerate(void) {
    diag_portadmit_t v;

    printf("-- no sysfs entry, degenerate input\n");
    check(!diag_port_admit(g_root, "/dev/ttyUSB99", &v),
          "a tty with no sysfs device is refused (fail closed)");
    check(v.driver[0] == '\0' && v.vidpid[0] == '\0',
          "...and its verdict claims no driver and no id");
    check(!diag_port_admit(g_root, NULL, &v), "NULL path refused");
    check(!diag_port_admit(g_root, "", &v), "empty path refused");
    check(!diag_port_admit(NULL, "/dev/ttyUSB12", &v), "NULL root refused");
    check(diag_port_admit(g_root, "/dev/ttyUSB12", NULL) == 1,
          "a NULL verdict pointer is allowed -- the answer is the return value");

    /* The DEVICE NODE is never consulted: the directory part below does not
     * exist, and the verdict is the same, because only the basename selects
     * the sysfs entry. The scan decides without touching /dev. */
    check(admits("/nonexistent/ttyUSB12"),
          "the verdict comes from sysfs alone, never from the /dev node");
    check(!admits("/nonexistent/ttyUSB0"),
          "...in both directions");
}

static void test_known_nonat_refused(void) {
    diag_portadmit_t v;
    char label[128];

    printf("-- a modem's known non-AT interfaces are refused\n");
    check(!admits("/dev/ttyUSB40"), "EG25-G if00 (DIAG, ff/ff/ff) is refused");
    check(!admits("/dev/ttyUSB41"), "EG25-G if01 (NMEA) is refused");
    check(admits("/dev/ttyUSB42"), "EG25-G if02 (AT) is admitted");
    check(admits("/dev/ttyUSB43"), "EG25-G if03 (AT/modem) is admitted");
    check(!admits("/dev/ttyUSB44"), "RM500Q-AE if00 (DIAG, ff/ff/30) is refused");
    check(!admits("/dev/ttyUSB45"), "RM500Q-AE if01 (NMEA) is refused");
    check(admits("/dev/ttyUSB46") && admits("/dev/ttyUSB47"),
          "RM500Q-AE if02 and if03 (AT) are admitted");
    check(!admits("/dev/ttyUSB48"), "RM520N-GL if00 (DIAG, ff/ff/30) is refused");
    check(!admits("/dev/ttyUSB49"), "RM520N-GL if01 (NMEA, ff/00/40) is refused");
    check(admits("/dev/ttyUSB50") && admits("/dev/ttyUSB51"),
          "RM520N-GL if02 and if03 (AT) are admitted");
    check(!admits("/dev/ttyUSB52"), "LM960A18 if00 (DIAG) is refused");
    check(!admits("/dev/ttyUSB53"), "LM960A18 if03 (NMEA) is refused");
    check(admits("/dev/ttyUSB54") && admits("/dev/ttyUSB55") && admits("/dev/ttyUSB56"),
          "LM960A18 if04, if05 and if06 (AT) are admitted");

    check(admits("/dev/ttyUSB57") && admits("/dev/ttyUSB58") && admits("/dev/ttyUSB59"),
          "2c7c:0700 is admitted on every interface -- no vendor-wide rule "
          "(its if02 is ff/ff/ff AND answers AT)");
    check(admits("/dev/ttyUSB60"),
          "2c7c:0801 if01 with a triple other than the measured ff/00/40 is "
          "admitted -- the descriptor must match too");
    check(admits("/dev/ttyUSB61"),
          "a table VID:PID + interface whose class triple cannot be read is "
          "admitted (the rule 1-3 verdict stands)");

    diag_port_admit(g_root, "/dev/ttyUSB41", &v);
    check(v.ifnum == 1, "the verdict carries the interface number");
    check(v.role != NULL && strcmp(v.role, "NMEA") == 0,
          "...and the refused role");
    check(strcmp(v.driver, "option1") == 0 && strcmp(v.vidpid, "2c7c:0125") == 0,
          "...and still names the driver and vendor:product");
    diag_portadmit_label(&v, label, sizeof(label));
    check(strcmp(label, "option1 2c7c:0125 if01 NMEA") == 0,
          "labelled 'option1 2c7c:0125 if01 NMEA' for the refusal line");
    diag_port_admit(g_root, "/dev/ttyUSB52", &v);
    check(v.role != NULL && strcmp(v.role, "DIAG") == 0 && v.ifnum == 0,
          "LM960A18 if00 is refused as DIAG");

    diag_port_admit(g_root, "/dev/ttyUSB42", &v);
    check(v.admit == 1 && v.role == NULL && v.ifnum == 2,
          "an admitted AT port has no role, and still reports its interface");
    diag_portadmit_label(&v, label, sizeof(label));
    check(strcmp(label, "option1 2c7c:0125") == 0,
          "...and its label is unchanged by rule 4");
    diag_port_admit(g_root, "/dev/ttyUSB0", &v);
    check(v.role == NULL, "a bridge refusal carries no role");
}

static void test_log_once(void) {
    diag_portadmit_t v;
    char text[1024];
    FILE *f = tmpfile();

    printf("-- each refusal is logged once per path\n");
    if (!f) {
        check(0, "tmpfile() for the log stream");
        return;
    }
    diag_port_admit(g_root, "/dev/ttyUSB0", &v);
    check(diag_portadmit_log_once(f, "cellat", "/dev/ttyUSB0", &v,
                                  "name it in CELLAT_EXTRA_PORTS to probe it") == 1,
          "the first refusal of a path is logged");
    check(diag_portadmit_log_once(f, "cellat", "/dev/ttyUSB0", &v,
                                  "name it in CELLAT_EXTRA_PORTS to probe it") == 0,
          "...the second is not");
    diag_port_admit(g_root, "/dev/ttyACM0", &v);
    check(diag_portadmit_log_once(f, "cellat", "/dev/ttyACM0", &v, "x") == 1,
          "a different path is logged in its own right");
    check(diag_portadmit_log_once(NULL, "cellat", "/dev/ttyACM2", &v, "x") == 0,
          "a NULL stream logs nothing");

    rewind(f);
    size_t n = fread(text, 1, sizeof(text) - 1, f);
    text[n] = '\0';
    fclose(f);
    check(strstr(text, "cellat: skip /dev/ttyUSB0: ch341-uart 1a86:7523, not a "
                       "suspected cell modem (name it in CELLAT_EXTRA_PORTS to "
                       "probe it)\n") != NULL,
          "the line names the source, path, driver, id and the escape hatch");
    int lines = 0;
    for (const char *p = text; *p; p++)
        lines += (*p == '\n');
    check(lines == 2, "exactly two lines were written");

    /* A known non-AT interface is a modem: the line must not call it "not a
     * suspected cell modem", and must name the interface and role. */
    f = tmpfile();
    if (!f) {
        check(0, "tmpfile() for the second log stream");
        return;
    }
    diag_port_admit(g_root, "/dev/ttyUSB45", &v);
    diag_portadmit_log_once(f, "celldiag", "/dev/ttyUSB45", &v, "hatch");
    rewind(f);
    n = fread(text, 1, sizeof(text) - 1, f);
    text[n] = '\0';
    fclose(f);
    check(strcmp(text, "celldiag: skip /dev/ttyUSB45: option1 2c7c:0800 if01 NMEA, "
                       "a cell modem's known non-AT port (hatch)\n") == 0,
          "a known non-AT refusal names the interface and role, not 'not a modem'");
}

static void test_note(void) {
    diag_portadmit_t v;
    char buf[64] = "";
    char small[36] = "";

    printf("-- the one-line refusal summary\n");
    diag_port_admit(g_root, "/dev/ttyUSB0", &v);
    diag_portadmit_note(buf, sizeof(buf), "/dev/ttyUSB0", &v);
    diag_port_admit(g_root, "/dev/ttyACM0", &v);
    diag_portadmit_note(buf, sizeof(buf), "/dev/ttyACM0", &v);
    check(strcmp(buf, "ttyUSB0(ch341-uart 1a86:7523),ttyACM0(cdc_acm 1546:01a8)") == 0,
          "note: basename(driver vid:pid), comma-separated");
    diag_port_admit(g_root, "/dev/ttyUSB0", &v);
    diag_portadmit_note(small, sizeof(small), "/dev/ttyUSB0", &v);
    diag_portadmit_note(small, sizeof(small), "/dev/ttyUSB23", &v);
    check(strcmp(small, "ttyUSB0(ch341-uart 1a86:7523)") == 0,
          "note: an entry that does not fit is dropped whole");
}

static void cleanup(void) {
    char cmd[PATH_MAX + 16];
    if (g_root[0] && strstr(g_root, "portadmit.") != NULL) {
        snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_root);
        if (system(cmd) != 0)
            fprintf(stderr, "warning: could not remove %s\n", g_root);
    }
}

int main(void) {
    printf("diag_portadmit selftest (which ttys a scan may open)\n\n");
    build_tree();
    test_cellular_usbserial_admitted();
    test_bridges_refused();
    test_cdc_acm_by_vendor();
    test_no_sysfs_and_degenerate();
    test_known_nonat_refused();
    test_log_once();
    test_note();
    cleanup();

    printf("\n%s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}

#endif /* DIAG_PORTADMIT_SELFTEST */
