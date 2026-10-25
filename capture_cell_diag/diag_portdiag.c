/* diag_portdiag.c - actionable DIAG-port-not-found message. See the header. */

#include "diag_portdiag.h"

#include <stdio.h>
#include <string.h>

/* Append "{a,b,c}" (or "{}") of the interface numbers to a bounded cursor. */
static int append_iface_set(char *out, size_t outsz, size_t pos,
                            const int *ifaces, int n_ifaces) {
    int w = snprintf(out + pos, pos < outsz ? outsz - pos : 0, "{");
    if (w > 0) pos += (size_t)w;
    for (int i = 0; i < n_ifaces; i++) {
        w = snprintf(out + pos, pos < outsz ? outsz - pos : 0,
                     "%s%d", i ? "," : "", ifaces[i]);
        if (w > 0) pos += (size_t)w;
    }
    w = snprintf(out + pos, pos < outsz ? outsz - pos : 0, "}");
    if (w > 0) pos += (size_t)w;
    return (int)pos;
}

int diag_portdiag_format(const char *imei, const char *at_port,
                         const char *usb_dev, const int *ifaces, int n_ifaces,
                         char *out, size_t outsz) {
    if (!out || outsz == 0)
        return 0;
    if (!imei) imei = "?";
    if (!at_port) at_port = "?";

    /* Case 1: the AT port's own USB device could not be resolved. */
    if (!usb_dev || !*usb_dev) {
        return snprintf(out, outsz,
            "Could not locate DIAG interface for IMEI %s: the AT port %s did not "
            "resolve to a USB device (non-USB modem? unexpected sysfs layout). "
            "Pass diagport=/dev/ttyUSBx explicitly.",
            imei, at_port);
    }

    /* Case 2: USB device resolved but no DIAG tty was usable. Report the
     * interfaces we DID see so the operator can tell a wrong-composition case
     * (DIAG on a non-if00 interface, or no ttyUSB DIAG at all - MHI/wwan) from a
     * missing modem. */
    size_t pos = 0;
    int w = snprintf(out, outsz,
        "Could not locate DIAG interface for IMEI %s (AT port %s -> USB device "
        "%s): ", imei, at_port, usb_dev);
    if (w > 0) pos += (size_t)w;

    if (n_ifaces <= 0) {
        w = snprintf(out + pos, pos < outsz ? outsz - pos : 0,
            "no /dev/ttyUSB* interfaces are present on that USB device. DIAG may "
            "be exposed over MHI/wwan (/dev/wwan*) or QMI-embedded rather than a "
            "ttyUSB, or the modem is in a USB composition without a DIAG "
            "function. Pass diagport= explicitly or change the USB composition.");
        if (w > 0) pos += (size_t)w;
        return (int)pos;
    }

    w = snprintf(out + pos, pos < outsz ? outsz - pos : 0,
        "ttyUSB interfaces present: ");
    if (w > 0) pos += (size_t)w;
    pos = (size_t)append_iface_set(out, outsz, pos, ifaces, n_ifaces);

    w = snprintf(out + pos, pos < outsz ? outsz - pos : 0,
        "; expected the DIAG function on the lowest interface (conventionally "
        "if00) but could not open it. Check the USB composition or pass "
        "diagport=/dev/ttyUSBx explicitly.");
    if (w > 0) pos += (size_t)w;
    return (int)pos;
}

int diag_portdiag_format_iface_missing(const char *imei, const char *at_port,
                                       const char *usb_dev, int want_if,
                                       const int *ifaces, int n_ifaces,
                                       char *out, size_t outsz) {
    if (!out || outsz == 0)
        return 0;
    if (!imei) imei = "?";
    if (!at_port) at_port = "?";
    if (!usb_dev) usb_dev = "?";

    size_t pos = 0;
    int w = snprintf(out, outsz,
        "Could not locate DIAG interface for IMEI %s (AT port %s -> USB device "
        "%s): this modem's profile pins DIAG to USB interface %d "
        "(diag.port_detect.interface), but that interface is not present; ",
        imei, at_port, usb_dev, want_if);
    if (w > 0) pos += (size_t)w;

    if (n_ifaces <= 0) {
        w = snprintf(out + pos, pos < outsz ? outsz - pos : 0,
            "no /dev/ttyUSB* interfaces are present on that USB device at all. "
            "The modem may be in a different USB composition than the profile "
            "expects, or DIAG may be on MHI/wwan. Fix the composition or pass "
            "diagport=/dev/ttyUSBx explicitly.");
        if (w > 0) pos += (size_t)w;
        return (int)pos;
    }

    w = snprintf(out + pos, pos < outsz ? outsz - pos : 0,
        "ttyUSB interfaces present: ");
    if (w > 0) pos += (size_t)w;
    pos = (size_t)append_iface_set(out, outsz, pos, ifaces, n_ifaces);

    w = snprintf(out + pos, pos < outsz ? outsz - pos : 0,
        ". The profile's port_detect.interface may be wrong for this "
        "composition; correct it or pass diagport=/dev/ttyUSBx explicitly.");
    if (w > 0) pos += (size_t)w;
    return (int)pos;
}

int diag_portdiag_format_transport(const char *imei, const char *transport,
                                   char *out, size_t outsz) {
    if (!out || outsz == 0)
        return 0;
    if (!imei) imei = "?";
    if (!transport || !*transport) transport = "?";

    return snprintf(out, outsz,
        "Could not auto-detect DIAG interface for IMEI %s: this modem's profile "
        "declares DIAG transport '%s', which celldiag does not yet auto-detect "
        "(only ttyUSB is supported today; MHI/wwan and QMI-embedded DIAG need a "
        "different capture path). Pass diagport=/dev/… explicitly to point at the "
        "DIAG node.",
        imei, transport);
}
