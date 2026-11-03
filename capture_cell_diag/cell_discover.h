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

    Modem discovery shared by cellat and celldiag: source names, and which
    serial ports another program is already using.

    Names: cellat-<15-digit IMEI> as before, plus
      cellat               the one attached modem; an error listing them if
                           there are several
      cellat-usb<bus-port> the modem on that physical USB port ("1-5.1", the
                           sysfs USB device name), so a name survives a SIM or
                           modem swap but not a move to another socket
    and the same with the celldiag prefix.

    Busy ports: a scan probes a port by opening it, setting 115200 raw and
    writing "AT", and the line settings belong to the tty, so a probe disturbs
    anything else reading that port. serial_open's flock() only stops programs
    that also take one (the Kismet cell sources do). This checks, before the
    open, for the programs that do not:
      - a live UUCP lock file (LCK..ttyUSB2 in /run/lock or /var/lock), as
        minicom, picocom, cu and ppp leave;
      - another process with the node open, from /proc/<pid>/fd -- a reader
        that takes no lock at all (screen, a script, gpsd). Only same-user
        processes are visible unless the source runs as root. The Kismet cell
        capture binaries are left to flock(), which already handles them
        (busy rescan, identity vouch), and PTY slaves are not checked: their
        holder is the program on the other end;
      - ModemManager, which owns every modem port it has not been told to
        ignore and will answer AT and reset line settings under a probe. A
        port or its USB device marked ID_MM_DEVICE_IGNORE / ID_MM_PORT_IGNORE
        in the udev database is free. A port the operator names (atport=, the
        *_PORTS variables) skips this check, so naming a port is the override.

    Pure libc. The filesystem root is a parameter so the selftest can build a
    fake /proc, lock directory and udev database.
*/

#ifndef __CELL_DISCOVER_H__
#define __CELL_DISCOVER_H__

#include <stddef.h>
#include <stdio.h>
#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    CELL_NAME_BAD = 0,
    CELL_NAME_IMEI,     /* val = the 15 digits */
    CELL_NAME_ANY,      /* val = "" */
    CELL_NAME_USB,      /* val = "1-5.1" */
} cell_name_kind_t;

/* Longest USB device name accepted ("1-5.1.2.3"), with its NUL. */
#define CELL_NAME_USB_MAX 32

/* Parse `iface` against `prefix` ("cellat" or "celldiag"). `val` gets the
 * IMEI or USB device name. CELL_NAME_BAD for anything else, including a
 * different prefix that happens to start with this one. */
cell_name_kind_t cell_name_parse(const char *iface, const char *prefix,
                                 char *val, size_t valsz);

/* 1 if `s` is a sysfs USB device name: bus-port(.port)*, digits only. */
int cell_name_usbdev_ok(const char *s);

/* The USB device ("1-5.1") and interface number above a tty node, from
 * sysfs: the first ancestor named <device>:<config>.<interface>. That is the
 * usb-serial port's parent, or a cdc_acm tty's own `device`. A by-id link
 * is followed to its node. 1 on success; `ifnum` may be NULL. */
int cell_tty_usb_location(const char *dev_path, char *usbdev, size_t usbdevsz,
                          int *ifnum);

/* 1 if the scan's device id `usbdev` ("1-5.1", or "usb:BUS-ADDR" for a
 * libusb port, mapped through /sys/bus/usb/devices) is USB device `want`. */
int cell_usb_matches(const char *usbdev, const char *want);

/* The modems a simple name's scan found, one per IMEI. */
#define CELL_PICK_MAX 8

typedef struct {
    char port[256];
    char fw[256];
    char imei[32];
    char usbdev[64];
} cell_pick_modem_t;

typedef struct {
    int total;      /* distinct modems seen; may pass CELL_PICK_MAX */
    cell_pick_modem_t m[CELL_PICK_MAX];
} cell_pick_t;

void cell_pick_reset(cell_pick_t *p);

/* Record a modem; a second port of an IMEI already seen is dropped. */
void cell_pick_add(cell_pick_t *p, const char *port, const char *fw,
                   const char *imei, const char *usbdev);

/* "cellat-<imei> (ttyUSB2, USB 1-5.1), ..." for an error asking which. */
void cell_pick_choices(const cell_pick_t *p, const char *prefix, char *buf,
                       size_t bufsz);

/* What made a port busy. */
typedef enum {
    CELL_BUSY_NONE = 0,
    CELL_BUSY_LOCKFILE,
    CELL_BUSY_OPEN,
    CELL_BUSY_MODEMMANAGER,
} cell_busy_why_t;

typedef struct {
    cell_busy_why_t why;
    pid_t pid;              /* the holder, 0 if unknown */
    char comm[32];          /* its process name, "" if unknown */
    char lockfile[256];     /* CELL_BUSY_LOCKFILE: the file found */
} cell_busy_t;

/* 1 if another program is using `dev_path`, with `out` saying who. A path
 * that is not a character device (a libusb "usb:" spec, a missing node)
 * is never busy here. check_mm = 0 for a port the operator named. */
int cell_port_busy(const char *dev_path, int check_mm, cell_busy_t *out);

/* "minicom (pid 1234) has a lock file /run/lock/LCK..ttyUSB2" and so on,
 * with the remedy for ModemManager. */
void cell_busy_label(const cell_busy_t *b, char *buf, size_t bufsz);

/* Print one line per busy port per process lifetime to `f`, as
 * "<who>: skip <path>: <label>". Returns 1 if it printed. */
int cell_busy_log_once(FILE *f, const char *who, const char *dev_path,
                       const cell_busy_t *b);

/* Record which device nodes other processes hold, for the open check to use
 * after the helper drops the privilege to read their fd tables. Call before
 * cf_jail_filesystem / cf_drop_most_caps; trusted for 30 s. */
void cell_discover_baseline(void);

/* Test hooks: prefix every absolute path read (/proc, /run, /var, /sys) with
 * `root` ("" = the real filesystem), and drop the cached /proc snapshot. */
void cell_discover_set_root(const char *root);

/* As cell_port_busy, for a node whose resolved path, tty name and device
 * number are already known. For the selftest, which cannot mknod. */
int cell_port_busy_node(const char *resolved, const char *name, dev_t rdev,
                        int check_mm, cell_busy_t *out);

#ifdef __cplusplus
}
#endif

#endif
