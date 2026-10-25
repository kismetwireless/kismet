/* diag_portdiag.h - actionable "DIAG port not found" diagnostic.
 *
 * When capture_cell_diag cannot auto-locate a modem's DIAG interface, a bare
 * "Could not locate DIAG interface for IMEI X" would hide the one thing an operator needs: WHY. The if00-is-DIAG assumption does not hold
 * universally (Sierra/Foxconn/Telit land DIAG on other interface numbers, or on
 * MHI/wwan with no ttyUSB at all), so the failure message should report what was
 * matched and what was enumerated, so the operator knows whether to fix the USB
 * composition or pass diagport= explicitly.
 *
 * This is the message formatter only - pure, libc-only, no sysfs reads and no
 * Kismet link - so it unit-tests standalone (test_diag_portdiag.c, `make
 * check`). find_diag_port() in capture_cell_diag.c gathers the sysfs facts (the
 * matched USB device id and the ttyUSB interface numbers present on it) and
 * hands them here to compose the operator-facing string.
 */
#ifndef DIAG_PORTDIAG_H
#define DIAG_PORTDIAG_H

#include <stddef.h>

/* Compose an actionable DIAG-port-not-found message into `out`.
 *
 *   imei      - the modem IMEI being resolved (never NULL)
 *   at_port   - the AT port the IMEI was matched on (never NULL)
 *   usb_dev   - the USB device id the AT port resolved to, or NULL/"" if the
 *               USB device itself could not be resolved
 *   ifaces    - array of ttyUSB bInterfaceNumber values found on usb_dev
 *   n_ifaces  - count in `ifaces` (0 => no ttyUSB siblings on that device)
 *
 * Always NUL-terminates `out` (truncating to fit). Returns the strlen it would
 * have written (like snprintf), so a caller can detect truncation.
 */
int diag_portdiag_format(const char *imei, const char *at_port,
                         const char *usb_dev, const int *ifaces, int n_ifaces,
                         char *out, size_t outsz);

/* Compose a message for a profile-declared DIAG transport that celldiag cannot
 * yet auto-detect (anything other than "ttyUSB" - e.g. "wwan_mhi",
 * "qmi_embedded"). Names the transport and points at diagport=, so a modem whose
 * profile pins a non-ttyUSB DIAG transport fails with an explanation rather than
 * a bare "not found". Always NUL-terminates `out`; returns the snprintf length.
 *
 *   imei      - the modem IMEI being resolved (NULL -> "?")
 *   transport - the profile's port_detect.transport value (NULL/"" -> "?")
 */
int diag_portdiag_format_transport(const char *imei, const char *transport,
                                   char *out, size_t outsz);

/* Compose a message for the EXACT-INTERFACE selection mode (profile
 * port_detect.match=="interface", interface==want_if) when that interface is
 * NOT present on the modem's USB device. The generic diag_portdiag_format()
 * would misleadingly blame the "lowest interface (if00)" convention here - but
 * the operator explicitly pinned interface `want_if` via the profile, so the
 * message must name THAT interface and list what was actually enumerated.
 * Always NUL-terminates `out`; returns the snprintf length (truncation-detectable).
 *
 *   imei      - the modem IMEI being resolved (never NULL)
 *   at_port   - the AT port the IMEI was matched on (never NULL)
 *   usb_dev   - the USB device id the AT port resolved to (never NULL/"")
 *   want_if   - the bInterfaceNumber the profile pinned but that is absent
 *   ifaces    - array of ttyUSB bInterfaceNumber values found on usb_dev
 *   n_ifaces  - count in `ifaces` (0 => no ttyUSB siblings on that device)
 */
int diag_portdiag_format_iface_missing(const char *imei, const char *at_port,
                                       const char *usb_dev, int want_if,
                                       const int *ifaces, int n_ifaces,
                                       char *out, size_t outsz);

#endif /* DIAG_PORTDIAG_H */
