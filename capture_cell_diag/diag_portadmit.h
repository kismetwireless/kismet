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

    Which USB serial ttys a port scan may OPEN at all.

    Both capture sources find a modem by AT-probing candidate ttys. Treating
    every /dev/ttyUSB* and /dev/ttyACM* as a candidate ("every node is some
    serial function; a wrong pick costs a timeout") is wrong: a wrong pick
    costs more than that. Opening a tty to probe it sets 115200 raw 8N1,
    flushes both queues and writes "AT\r\n" -- and on Linux the line settings
    belong to the tty, not to the fd, so every other reader of that port
    inherits them. A u-blox-class GNSS receiver on a CH340 bridge, read by
    str2str at 460800, reads only line noise after one scan (gpsd may even
    latch onto the stream as Trimble TSIP).

    So the scan decides from sysfs, BEFORE open(), and a port this module
    does not admit is never opened: no open(), no tcsetattr(), no tcflush(), no
    "AT". The rule is an ALLOWLIST -- a device nobody has heard of is refused:

      1. Admit a tty bound to a usb-serial driver that exists for cellular
         modems: option (sysfs spells it "option1"), qcserial, sierra.
      2. Admit cdc_acm only on a cellular vendor id. cdc_acm also binds u-blox
         GNSS receivers (1546), Arduinos and every other CDC-ACM gadget, so the
         driver alone proves nothing.
      3. Refuse everything else: the USB-UART bridges (ch341-uart, ftdi_sio,
         pl2303, cp210x, ...), the "generic" usb-serial driver, a tty with no
         driver bound, and a name with no sysfs device at all.
      4. Of an admitted modem, refuse the interfaces MEASURED never to answer
         AT -- its DIAG and NMEA functions. A scan walks a modem's
         interfaces until one answers, so whenever a sibling source holds the
         AT ports it would otherwise go on to write "AT" into the DIAG node and
         flush an NMEA reader's bytes. A small table keyed by VID:PID +
         bInterfaceNumber + the class/subclass/protocol triple (kKnownNonAt,
         with its measured basis); a port matching no entry exactly, or whose
         descriptor cannot be read, keeps the verdict of rules 1-3. A modem
         not in the table is probed under rules 1-3 alone.

    A modem behind a USB-UART bridge (a SIM7600 hat on a CH340, a Quectel
    EVB's UART) enumerates as the BRIDGE and is refused. That is the price of
    an allowlist, and the escape hatch is the operator naming the port --
    CELLAT_EXTRA_PORTS / CELLAT_SCAN_PORTS / CELLDIAG_SCAN_PORTS / atport= --
    which never passes through this module. The refusal line names the driver,
    the vendor:product and that hatch, so a modem the rule misses is
    diagnosable from the log rather than simply absent.

    The /dev/wwan* and /dev/mhi_* nodes are not USB serial and keep their own
    classifier (diag_wwan_is_at, diag_wwanport.h).

    Pure libc. The sysfs ROOT is a parameter, so the selftest builds a fake
    tree in a temp directory -- the layouts of a real usb-serial port and a
    real cdc_acm interface, symlinks and all -- and needs no hardware.
*/

#ifndef __DIAG_PORTADMIT_H__
#define __DIAG_PORTADMIT_H__

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The real sysfs mount; the root every production caller passes. */
#define DIAG_PORTADMIT_SYSFS "/sys"

typedef struct {
    int admit;            /* 1: a suspected cell modem, probe it; 0: never open it */
    char driver[64];      /* the bound driver's sysfs name ("option1",
                             "ch341-uart"), "" when none is bound */
    char vidpid[10];      /* "1a86:7523", "" when no USB ancestor was found */
    int ifnum;            /* the USB interface's bInterfaceNumber, -1 unread */
    const char *role;     /* "DIAG" / "NMEA" when refused as a modem's known
                             non-AT interface (rule 4); else NULL */
    const char *reason;   /* static, operator-facing, never parsed */
} diag_portadmit_t;

/* Decide whether the tty `dev_path` (e.g. "/dev/ttyUSB0") may be probed,
 * reading only `<sysfs_root>/class/tty/<basename>/device`, its `driver` link
 * and the `idVendor`/`idProduct` of its USB device. Never opens `dev_path`.
 *
 * Returns out->admit. `out` is always filled; a NULL or empty argument is a
 * refusal. */
int diag_port_admit(const char *sysfs_root, const char *dev_path,
                    diag_portadmit_t *out);

/* "ch341-uart 1a86:7523" -- the verdict's evidence, for a refusal line. An
 * absent half is written as "no-driver" / "no-usb-id". A rule-4 refusal adds
 * the interface and role: "option1 2c7c:0125 if01 NMEA". Always
 * NUL-terminated. */
void diag_portadmit_label(const diag_portadmit_t *v, char *buf, size_t bufsz);

/* Append "<basename(dev_path)>(<label>)" to the comma-separated list in buf --
 * "ttyUSB0(ch341-uart 1a86:7523)" -- for a one-line scan summary. Whole
 * entries only: one that does not fit is dropped, and buf stays
 * NUL-terminated. */
void diag_portadmit_note(char *buf, size_t bufsz, const char *dev_path,
                         const diag_portadmit_t *v);

/* Log a refusal ONCE per path per process to `f` (NULL: log nothing), as
 *
 *   <who>: skip /dev/ttyUSB0: ch341-uart 1a86:7523, not a suspected cell modem
 *   (<hatch>)
 *
 * or, for a rule-4 refusal,
 *
 *   <who>: skip /dev/ttyUSB13: option1 2c7c:0125 if01 NMEA, a cell modem's
 *   known non-AT port (<hatch>)
 *
 * where `hatch` names how to probe it anyway. A scan runs at every source
 * open, on its rescans and on every list request, so an unconditional line
 * would repeat for the life of the helper. Returns 1 when it logged, 0 when
 * the path was already logged (or the once-table is full: logging is then
 * skipped rather than repeated). */
int diag_portadmit_log_once(FILE *f, const char *who, const char *dev_path,
                            const diag_portadmit_t *v, const char *hatch);

#ifdef __cplusplus
}
#endif

#endif /* __DIAG_PORTADMIT_H__ */
