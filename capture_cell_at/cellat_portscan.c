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

    See cellat_portscan.h for what this is and why it is a separate TU.
*/

#include <fnmatch.h>
#include <string.h>

#include "cellat_portscan.h"
#include "../capture_cell_diag/diag_portadmit.h"
#include "../capture_cell_diag/diag_wwanport.h"

/* Scan order is significant only in that ttyUSB modems are by far the common
 * case and the caller bounds the total; the downstream sort re-orders by USB
 * device and interface number regardless. */
static const cellat_scan_source_t kSources[] = {
    { "/dev/ttyUSB*", CELLAT_SCAN_SUSPECTED,
      "USB serial -- also GNSS receivers and USB-UART bridges, whose owners a "
      "probe reconfigures: admitted only on a cellular usb-serial driver" },
    { "/dev/ttyACM*", CELLAT_SCAN_SUSPECTED,
      "USB CDC-ACM -- also u-blox GNSS and every CDC gadget: admitted only on a "
      "cellular vendor id" },
    { "/dev/wwan*",   CELLAT_SCAN_CLASSIFIED,
      "mainline wwan subsystem (wwan0at0); also holds wwan0firehose0 -- MUST filter" },
    { "/dev/mhi_*",   CELLAT_SCAN_CLASSIFIED,
      "out-of-tree MHI stack (mhi_DUN); also holds mhi_SAHARA/mhi_BHI (EDL) -- MUST filter" },
};

const cellat_scan_source_t *cellat_scan_sources(size_t *n) {
    if (n)
        *n = sizeof(kSources) / sizeof(kSources[0]);
    return kSources;
}

static const char *g_sysfs_root = DIAG_PORTADMIT_SYSFS;
static FILE *g_refusal_log;
static int g_refusal_log_set;
static char g_refused[512];

void cellat_scan_set_sysfs_root(const char *root) {
    g_sysfs_root = (root && *root) ? root : DIAG_PORTADMIT_SYSFS;
}

const char *cellat_scan_sysfs_root(void) {
    return g_sysfs_root;
}

void cellat_scan_set_refusal_log(FILE *f) {
    g_refusal_log = f;
    g_refusal_log_set = 1;
}

void cellat_scan_refusals_reset(void) {
    g_refused[0] = '\0';
}

const char *cellat_scan_refusals(void) {
    return g_refused;
}

int cellat_scan_admit(cellat_scan_filter_t filter, const char *path) {
    if (path == NULL || *path == '\0')
        return 0;

    /* strlen, not strnlen-with-a-cap: the caller's buffer is the constraint, and
     * a path at exactly CELLAT_PORT_PATH_MAX-1 still needs its NUL. */
    if (strlen(path) >= CELLAT_PORT_PATH_MAX)
        return 0;

    if (filter == CELLAT_SCAN_CLASSIFIED)
        return diag_wwan_is_at(path) ? 1 : 0;

    if (filter == CELLAT_SCAN_SUSPECTED) {
        diag_portadmit_t v;
        if (diag_port_admit(g_sysfs_root, path, &v))
            return 1;
        diag_portadmit_note(g_refused, sizeof(g_refused), path, &v);
        diag_portadmit_log_once(g_refusal_log_set ? g_refusal_log : stderr,
                                "cellat", path, &v,
                                "name it in CELLAT_EXTRA_PORTS, or use atport=, "
                                "to probe it");
        return 0;
    }

    return 1;
}

/* The bound, duplicate and append half shared by both add paths. `path` has
 * already been admitted, so its length fits. */
static int scan_append(char ports[][CELLAT_PORT_PATH_MAX], int *count,
                       const char *path) {
    for (int i = 0; i < *count; i++) {
        if (strcmp(ports[i], path) == 0)
            return 0;
    }

    /* Length was already checked by cellat_scan_admit(), so this cannot
     * truncate; the explicit NUL is belt-and-braces for a future caller that
     * reaches strcpy() without the admit gate. */
    memcpy(ports[*count], path, strlen(path) + 1);
    ports[*count][CELLAT_PORT_PATH_MAX - 1] = '\0';
    (*count)++;
    return 1;
}

int cellat_scan_add(char ports[][CELLAT_PORT_PATH_MAX], int *count, int max_ports,
                    cellat_scan_filter_t filter, const char *path) {
    if (ports == NULL || count == NULL)
        return 0;
    if (*count >= max_ports)
        return 0;
    if (!cellat_scan_admit(filter, path))
        return 0;
    return scan_append(ports, count, path);
}

/* 1 if `path` is one a CLASSIFIED scan pattern would have matched. Read off
 * kSources rather than a second list, so a directory added there as CLASSIFIED
 * is guarded on the named path too without anyone remembering to. */
static int under_classified_source(const char *path) {
    for (size_t i = 0; i < sizeof(kSources) / sizeof(kSources[0]); i++) {
        if (kSources[i].filter == CELLAT_SCAN_CLASSIFIED &&
            fnmatch(kSources[i].pattern, path, FNM_PATHNAME) == 0)
            return 1;
    }
    return 0;
}

int cellat_scan_admit_named(const char *path, const char *resolved) {
    /* NULL, empty and over-long are refused exactly as for a scanned path. */
    if (!cellat_scan_admit(CELLAT_SCAN_UNFILTERED, path))
        return 0;
    if (under_classified_source(path) && !diag_wwan_is_at(path))
        return 0;
    if (resolved && *resolved && under_classified_source(resolved) &&
        !diag_wwan_is_at(resolved))
        return 0;
    return 1;
}

int cellat_scan_add_named(char ports[][CELLAT_PORT_PATH_MAX], int *count,
                          int max_ports, const char *path, const char *resolved) {
    if (ports == NULL || count == NULL)
        return 0;
    if (*count >= max_ports)
        return 0;
    if (!cellat_scan_admit_named(path, resolved))
        return 0;
    return scan_append(ports, count, path);
}

#ifdef CELLAT_PORTSCAN_SELFTEST

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

static int failures = 0;

static void check(int cond, const char *what) {
    if (!cond) {
        printf("  FAIL: %s\n", what);
        failures++;
    } else {
        printf("  ok:   %s\n", what);
    }
}

/* --- group 1: the glob wiring itself ---------------------------------------
 *
 * A build whose classifier is perfect but which never globs /dev/wwan* discovers nothing on an
 * inline-attached modem and is indistinguishable from "no modem present". */
static void test_scan_sources(void) {
    size_t n = 0;
    const cellat_scan_source_t *s = cellat_scan_sources(&n);
    int have_ttyusb = 0, have_ttyacm = 0, have_wwan = 0, have_mhi = 0;

    printf("scan sources (the glob wiring)\n");
    check(s != NULL && n >= 4, "at least four source patterns are enumerated");

    for (size_t i = 0; i < n; i++) {
        if (strcmp(s[i].pattern, "/dev/ttyUSB*") == 0) have_ttyusb = 1;
        if (strcmp(s[i].pattern, "/dev/ttyACM*") == 0) have_ttyacm = 1;
        if (strcmp(s[i].pattern, "/dev/wwan*") == 0) {
            have_wwan = 1;
            check(s[i].filter == CELLAT_SCAN_CLASSIFIED,
                  "/dev/wwan* is CLASSIFIED -- it also holds wwan0firehose0");
        }
        if (strcmp(s[i].pattern, "/dev/mhi_*") == 0) {
            have_mhi = 1;
            check(s[i].filter == CELLAT_SCAN_CLASSIFIED,
                  "/dev/mhi_* is CLASSIFIED -- it also holds mhi_SAHARA/mhi_BHI (EDL)");
        }
    }

    check(have_ttyusb, "/dev/ttyUSB* is enumerated");
    check(have_ttyacm, "/dev/ttyACM* is enumerated");

    /* No scan SOURCE is unfiltered. ttyUSB/ttyACM also hold GNSS receivers
     * and USB-UART bridges, and a probe reconfigures its target -- so both are
     * decided from sysfs before any open. */
    for (size_t i = 0; i < n; i++) {
        if (strcmp(s[i].pattern, "/dev/ttyUSB*") == 0 ||
            strcmp(s[i].pattern, "/dev/ttyACM*") == 0)
            check(s[i].filter == CELLAT_SCAN_SUSPECTED,
                  "ttyUSB/ttyACM are SUSPECTED -- admitted only on sysfs evidence");
        check(s[i].filter != CELLAT_SCAN_UNFILTERED,
              "no scan source is UNFILTERED");
    }
    check(have_wwan, "/dev/wwan* is enumerated (the mainline wwan stack)");
    check(have_mhi, "/dev/mhi_* is enumerated (the out-of-tree MHI stack)");

    for (size_t i = 0; i < n; i++)
        check(s[i].why != NULL && *s[i].why,
              "every source carries an operator-facing rationale");
}

/* --- group 2: admission, both families ------------------------------------- */
static void test_admit_at_nodes(void) {
    printf("admission -- the AT surface of each family\n");
    check(cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/wwan0at0"),
          "wwan0at0 IS the mainline AT port");
    check(cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/mhi_DUN"),
          "mhi_DUN IS the out-of-tree AT port (DUN == Dial-Up Networking)");
    check(cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/wwan1at0"),
          "a second mainline device's AT port is admitted too");
}

/* --- group 3: the refusals that make this a SAFETY property ----------------
 *
 * Each name here, admitted, means cellat writes "ATI\r" into it during a
 * routine source scan. */
static void test_refuse_dangerous_nodes(void) {
    printf("refusal -- nodes an unfiltered glob would have probed\n");

    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/mhi_SAHARA"),
          "mhi_SAHARA is NOT AT -- probing it writes ATI into the EDL channel");
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/mhi_EDL"),
          "mhi_EDL is NOT AT -- the bootloader protocol channel");
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/wwan0firehose0"),
          "wwan0firehose0 is NOT AT -- the mainline flashing channel");
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/mhi_QDSS"),
          "mhi_QDSS is NOT AT -- a trace channel that opens and never answers");
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/mhi_IP_HW0"),
          "mhi_IP_HW0 is NOT AT -- the hardware IP data path");

    /* Real MHI channel names that are absent from the classifier's channel
     * table, so both are refused by the fail-closed default rather than by a
     * table row. Pinned by NAME so a future table edit that admits either goes
     * red HERE, on the safety property, and not merely in a coverage report.
     * BHI == Boot Host Interface: the firmware-download channel. */
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/mhi_BHI"),
          "mhi_BHI is NOT AT -- Boot Host Interface, the firmware-download channel");
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/mhi_ADB"),
          "mhi_ADB is NOT AT -- the ADB channel");
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/mhi_LOOPBACK"),
          "mhi_LOOPBACK is NOT AT -- it echoes, so a probe would look like a modem");

    /* The DIAG node of each family. Admitting one would have BOTH sources
     * claiming a single node -- the drift the shared classifier exists to
     * prevent. */
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/mhi_DIAG"),
          "mhi_DIAG is celldiag's node, not cellat's");
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/wwan0qcdm0"),
          "wwan0qcdm0 is celldiag's node, not cellat's");

    /* Not a character device at all. */
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/wwan0"),
          "wwan0 is the NETDEV, not a port");
}

/* --- group 4: UNFILTERED is for operator-named paths only ------------------
 *
 * UNFILTERED backs no scan source, but it is still the verdict for a path
 * the operator named. And the non-USB classifier is the wrong tool for
 * ttyUSB: diag_wwan_is_at() returns 0 for every ttyUSB name, so a "safer is
 * better" refactor that put ttyUSB behind it would find NOTHING on any USB
 * modem. That is why SUSPECTED is a third filter
 * (group 10), not CLASSIFIED reused. */
static void test_unfiltered_sources(void) {
    printf("unfiltered -- operator-named paths only\n");
    check(cellat_scan_admit(CELLAT_SCAN_UNFILTERED, "/tmp/cfw3212-at"),
          "a CELLAT_EXTRA_PORTS socat PTY is admitted -- it is named explicitly");
    check(cellat_scan_admit(CELLAT_SCAN_UNFILTERED, "/dev/ttyUSB0"),
          "a NAMED ttyUSB is admitted whatever it is bound to -- the escape "
          "hatch for a modem behind a USB-UART bridge");
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, "/dev/ttyUSB2"),
          "...and the non-USB classifier would REFUSE every ttyUSB");
}

/* --- group 5: degenerate inputs -------------------------------------------- */
static void test_degenerate(void) {
    printf("degenerate inputs\n");
    check(!cellat_scan_admit(CELLAT_SCAN_UNFILTERED, NULL), "NULL path refused");
    check(!cellat_scan_admit(CELLAT_SCAN_CLASSIFIED, NULL), "NULL path refused (classified)");
    check(!cellat_scan_admit(CELLAT_SCAN_UNFILTERED, ""), "empty path refused");
}

/* --- group 6: over-long paths are REFUSED, not truncated ------------------- */
static void test_overlong_is_refused_not_truncated(void) {
    char longpath[CELLAT_PORT_PATH_MAX + 64];
    char ports[8][CELLAT_PORT_PATH_MAX];
    int count = 0;

    printf("over-long paths\n");

    memset(longpath, 'x', sizeof(longpath) - 1);
    longpath[sizeof(longpath) - 1] = '\0';
    memcpy(longpath, "/dev/", 5);

    check(!cellat_scan_admit(CELLAT_SCAN_UNFILTERED, longpath),
          "a path longer than the buffer is REFUSED, not silently truncated");
    check(cellat_scan_add(ports, &count, 8, CELLAT_SCAN_UNFILTERED, longpath) == 0,
          "...and cellat_scan_add does not append it");
    check(count == 0, "...leaving the port list untouched");

    /* The boundary: the longest path that DOES fit, and the shortest that does
     * not. An off-by-one here either drops a legal path or writes a truncated
     * one -- both silent. */
    longpath[CELLAT_PORT_PATH_MAX - 1] = '\0';
    check(cellat_scan_admit(CELLAT_SCAN_UNFILTERED, longpath) == 1,
          "a path of exactly CELLAT_PORT_PATH_MAX-1 chars fits and is admitted");
    check(cellat_scan_add(ports, &count, 8, CELLAT_SCAN_UNFILTERED, longpath) == 1,
          "...and is appended");
    check(strlen(ports[0]) == CELLAT_PORT_PATH_MAX - 1,
          "...at full length, NUL-terminated");

    longpath[CELLAT_PORT_PATH_MAX] = '\0';
    longpath[CELLAT_PORT_PATH_MAX - 1] = 'x';
    check(cellat_scan_admit(CELLAT_SCAN_UNFILTERED, longpath) == 0,
          "one char longer is refused");
}

/* --- group 7: duplicates -- the defect the downstream dedup CANNOT catch ---- */
static void test_duplicate_refused(void) {
    char ports[8][CELLAT_PORT_PATH_MAX];
    int count = 0;

    printf("duplicate suppression\n");

    check(cellat_scan_add(ports, &count, 8, CELLAT_SCAN_CLASSIFIED, "/dev/mhi_DUN") == 1,
          "mhi_DUN admitted once");
    check(cellat_scan_add(ports, &count, 8, CELLAT_SCAN_UNFILTERED, "/dev/mhi_DUN") == 0,
          "the SAME path via CELLAT_EXTRA_PORTS is refused as a duplicate");
    check(count == 1,
          "...so a non-USB node named twice is probed once, not twice");

    /* Why this cannot be left to the caller: the downstream de-dup keys on the
     * sysfs USB device id, which a non-USB node does not have -- so it takes
     * the "no sysfs, treat as unique" branch and a duplicate survives it. */
    check(cellat_scan_add(ports, &count, 8, CELLAT_SCAN_UNFILTERED, "/dev/ttyUSB0") == 1,
          "a distinct path is still admitted after a duplicate was refused");
    check(count == 2, "...and the count advances only for real additions");
}

/* --- group 8: bounds ------------------------------------------------------- */
static void test_max_ports(void) {
    char ports[3][CELLAT_PORT_PATH_MAX];
    int count = 0;

    printf("max_ports bound\n");
    check(cellat_scan_add(ports, &count, 3, CELLAT_SCAN_UNFILTERED, "/dev/ttyUSB0") == 1, "1st fits");
    check(cellat_scan_add(ports, &count, 3, CELLAT_SCAN_UNFILTERED, "/dev/ttyUSB1") == 1, "2nd fits");
    check(cellat_scan_add(ports, &count, 3, CELLAT_SCAN_UNFILTERED, "/dev/ttyUSB2") == 1, "3rd fits");
    check(cellat_scan_add(ports, &count, 3, CELLAT_SCAN_UNFILTERED, "/dev/ttyUSB3") == 0,
          "4th is refused -- the array is full");
    check(count == 3, "the count never exceeds max_ports");
}

/* --- group 9: operator-named paths ----------------------------------------
 *
 * CELLAT_SCAN_PORTS replaces the scan universe, so a glob an operator writes
 * there -- `/dev/mhi_*` is the obvious one for a PCIe modem -- is enumerated
 * WITHOUT the source table's filter. The named-path verdict must still refuse
 * the EDL and firmware-download channels. */
static void test_named_paths(void) {
    char ports[8][CELLAT_PORT_PATH_MAX];
    int count = 0;

    printf("operator-named paths (CELLAT_SCAN_PORTS / CELLAT_EXTRA_PORTS)\n");
    check(cellat_scan_admit_named("/dev/pts/7", "/dev/pts/7"),
          "a PTY fake modem is admitted -- it is named explicitly");
    check(cellat_scan_admit_named("/tmp/cfw3212-at", NULL),
          "a socat PTY link with no resolvable target is admitted");
    check(cellat_scan_admit_named("/dev/ttyUSB2", "/dev/ttyUSB2"),
          "a named ttyUSB is admitted -- the classifier would refuse it");
    check(cellat_scan_admit_named("/dev/mhi_DUN", "/dev/mhi_DUN"),
          "a named mhi_DUN is admitted -- it IS the AT node");
    check(cellat_scan_admit_named("/dev/wwan0at0", NULL),
          "a named wwan0at0 is admitted");

    check(!cellat_scan_admit_named("/dev/mhi_SAHARA", "/dev/mhi_SAHARA"),
          "a named mhi_SAHARA is REFUSED -- `/dev/mhi_*` must not reach EDL");
    check(!cellat_scan_admit_named("/dev/mhi_BHI", NULL),
          "a named mhi_BHI is REFUSED -- the firmware-download channel");
    check(!cellat_scan_admit_named("/dev/mhi_DIAG", NULL),
          "a named mhi_DIAG is REFUSED -- celldiag's node, not cellat's");
    check(!cellat_scan_admit_named("/dev/wwan0firehose0", NULL),
          "a named wwan0firehose0 is REFUSED");

    check(!cellat_scan_admit_named("/tmp/modem", "/dev/mhi_SAHARA"),
          "a symlink cannot launder mhi_SAHARA past the classifier");
    check(cellat_scan_admit_named("/tmp/dun", "/dev/mhi_DUN"),
          "a symlink to mhi_DUN is admitted on its target");

    check(!cellat_scan_admit_named(NULL, NULL), "NULL refused");
    check(!cellat_scan_admit_named("", NULL), "empty refused");

    check(cellat_scan_add_named(ports, &count, 8, "/dev/pts/7", "/dev/pts/7") == 1,
          "add_named appends an admitted path");
    check(cellat_scan_add_named(ports, &count, 8, "/dev/pts/7", "/dev/pts/7") == 0,
          "...and refuses the same path named twice");
    check(cellat_scan_add_named(ports, &count, 8, "/dev/mhi_SAHARA", NULL) == 0,
          "...and refuses a refused node");
    check(count == 1 && strcmp(ports[0], "/dev/pts/7") == 0,
          "...leaving exactly the one admitted path");
}

/* --- group 10: SUSPECTED decides from sysfs, before any open --------------
 *
 * The real admission path (cellat_scan_add -> cellat_scan_admit ->
 * diag_port_admit) pointed at a fake sysfs tree holding two representative
 * ports: an LG290P GNSS receiver on a CH340 bridge, and an EG25-G AT port. The /dev paths do not exist on the test host and are never opened --
 * the verdicts come from the fake tree alone. */
static char g_root[512];

static void mk(const char *rel) {
    char p[1024];
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    for (char *c = p + 1; *c; c++) {
        if (*c == '/') {
            *c = '\0';
            mkdir(p, 0755);
            *c = '/';
        }
    }
    mkdir(p, 0755);
}

static void put(const char *rel, const char *text) {
    char p[1024];
    snprintf(p, sizeof(p), "%s/%s", g_root, rel);
    FILE *f = fopen(p, "w");
    if (f) {
        fputs(text, f);
        fclose(f);
    }
}

static void ln(const char *target_rel, const char *link_rel) {
    char t[1024], l[1024];
    snprintf(t, sizeof(t), "%s/%s", g_root, target_rel);
    snprintf(l, sizeof(l), "%s/%s", g_root, link_rel);
    if (symlink(t, l) != 0)
        printf("  (symlink %s failed)\n", link_rel);
}

static int build_fake_sysfs(void) {
    const char *tmp = getenv("TMPDIR");
    snprintf(g_root, sizeof(g_root), "%s/cellat_portscan.XXXXXX",
             (tmp && *tmp) ? tmp : "/tmp");
    if (!mkdtemp(g_root))
        return 0;
    mk("bus/usb-serial/drivers/ch341-uart");
    mk("bus/usb-serial/drivers/option1");
    /* ttyUSB0: the LG290P on a CH340 (1a86:7523). */
    mk("devices/usb1/1-2/1-2:1.0/ttyUSB0");
    put("devices/usb1/1-2/idVendor", "1a86\n");
    put("devices/usb1/1-2/idProduct", "7523\n");
    ln("bus/usb-serial/drivers/ch341-uart", "devices/usb1/1-2/1-2:1.0/ttyUSB0/driver");
    mk("class/tty/ttyUSB0");
    ln("devices/usb1/1-2/1-2:1.0/ttyUSB0", "class/tty/ttyUSB0/device");
    /* ttyUSB14: an EG25-G interface (2c7c:0125) on option. */
    mk("devices/usb1/1-4/1-4:1.2/ttyUSB14");
    put("devices/usb1/1-4/idVendor", "2c7c\n");
    put("devices/usb1/1-4/idProduct", "0125\n");
    ln("bus/usb-serial/drivers/option1", "devices/usb1/1-4/1-4:1.2/ttyUSB14/driver");
    mk("class/tty/ttyUSB14");
    ln("devices/usb1/1-4/1-4:1.2/ttyUSB14", "class/tty/ttyUSB14/device");
    /* ttyUSB13: the same EG25-G's if01, WITH its real descriptor -- the
     * NMEA port the scan must stay off. */
    mk("devices/usb1/1-4/1-4:1.1/ttyUSB13");
    put("devices/usb1/1-4/1-4:1.1/bInterfaceNumber", "01\n");
    put("devices/usb1/1-4/1-4:1.1/bInterfaceClass", "ff\n");
    put("devices/usb1/1-4/1-4:1.1/bInterfaceSubClass", "00\n");
    put("devices/usb1/1-4/1-4:1.1/bInterfaceProtocol", "00\n");
    ln("bus/usb-serial/drivers/option1", "devices/usb1/1-4/1-4:1.1/ttyUSB13/driver");
    mk("class/tty/ttyUSB13");
    ln("devices/usb1/1-4/1-4:1.1/ttyUSB13", "class/tty/ttyUSB13/device");
    return 1;
}

static void test_suspected_from_sysfs(void) {
    char ports[8][CELLAT_PORT_PATH_MAX];
    int count = 0;

    printf("SUSPECTED -- decided from sysfs before any open\n");
    if (!build_fake_sysfs()) {
        check(0, "a fake sysfs tree for the SUSPECTED filter");
        return;
    }
    cellat_scan_set_sysfs_root(g_root);
    cellat_scan_set_refusal_log(NULL);
    cellat_scan_refusals_reset();

    check(cellat_scan_add(ports, &count, 8, CELLAT_SCAN_SUSPECTED, "/dev/ttyUSB0") == 0,
          "ttyUSB0 on ch341-uart (the GNSS reference) is NOT added");
    check(cellat_scan_add(ports, &count, 8, CELLAT_SCAN_SUSPECTED, "/dev/ttyUSB14") == 1,
          "ttyUSB14 on option1 (an EG25-G) is added");
    check(count == 1 && strcmp(ports[0], "/dev/ttyUSB14") == 0,
          "...so the list the scan PROBES holds only the modem port");
    check(cellat_scan_add(ports, &count, 8, CELLAT_SCAN_SUSPECTED, "/dev/ttyUSB7") == 0,
          "a ttyUSB with no sysfs entry is refused (fail closed)");
    check(strcmp(cellat_scan_refusals(),
                 "ttyUSB0(ch341-uart 1a86:7523),ttyUSB7(no-driver no-usb-id)") == 0,
          "the refusals are recorded with their evidence, for the open's message");
    cellat_scan_refusals_reset();
    check(cellat_scan_refusals()[0] == '\0', "...and reset per scan");

    /* A suspected modem's own NMEA port is not probed either. */
    check(cellat_scan_add(ports, &count, 8, CELLAT_SCAN_SUSPECTED, "/dev/ttyUSB13") == 0,
          "ttyUSB13, the EG25-G's NMEA port (if01), is NOT added");
    check(count == 1, "...so the probe list still holds only the AT port");
    check(strcmp(cellat_scan_refusals(), "ttyUSB13(option1 2c7c:0125 if01 NMEA)") == 0,
          "...and the open's message names its interface and role");
    cellat_scan_refusals_reset();

    /* The escape hatch: the SAME bridge port, named by the operator. */
    check(cellat_scan_admit_named("/dev/ttyUSB0", "/dev/ttyUSB0"),
          "the bridge port NAMED in CELLAT_EXTRA_PORTS is admitted -- a modem "
          "behind a USB-UART bridge stays reachable");

    /* Production reads the real sysfs. */
    cellat_scan_set_sysfs_root(NULL);
    check(strcmp(cellat_scan_sysfs_root(), "/sys") == 0,
          "cellat_scan_set_sysfs_root(NULL) restores /sys");

    char cmd[600];
    snprintf(cmd, sizeof(cmd), "rm -rf '%s'", g_root);
    if (system(cmd) != 0)
        printf("  (could not remove %s)\n", g_root);
}

int main(void) {
    printf("cellat_portscan selftest (the glob wiring + admission)\n\n");
    test_scan_sources();
    test_admit_at_nodes();
    test_refuse_dangerous_nodes();
    test_unfiltered_sources();
    test_degenerate();
    test_overlong_is_refused_not_truncated();
    test_duplicate_refused();
    test_max_ports();
    test_named_paths();
    test_suspected_from_sysfs();

    printf("\n%s\n", failures == 0 ? "PASS" : "FAIL");
    return failures == 0 ? 0 : 1;
}

#endif /* CELLAT_PORTSCAN_SELFTEST */
