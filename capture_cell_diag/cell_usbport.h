/* cell_usbport.h - a modem's serial interface over libusb, as a plain fd.
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * For a modem whose serial interfaces have no host driver (a Quectel module
 * on macOS, or one whose option/qcserial binding was removed), the capture
 * helpers name the interface "usb:BUS-ADDR:IF" wherever they would name a tty.
 * cell_usbport_open() claims that one interface through ../usbserial and
 * returns one end of a socketpair; a thread moves bytes between the other end
 * and the bulk endpoints. To the helper it is a non-tty port, like an MHI node:
 * no termios, poll()-bounded reads, EOF when the modem goes away.
 *
 * The claim is the exclusive lock (another process gets EWOULDBLOCK, as from
 * a held flock), so a paired cellat and celldiag each claim only their own
 * interface. Closing the fd releases the interface; a host driver taken with
 * usb=force gets it back.
 *
 * The address in the name changes when the modem re-enumerates, so a name is
 * also the identity of one enumeration of the device.
 *
 * Without HAVE_CELL_USBSERIAL (configure --disable-usbserial, or a tool that
 * does not link libusb) the names are still recognised, and opening one fails
 * with ENODEV.
 */
#ifndef CELL_USBPORT_H
#define CELL_USBPORT_H

#include <errno.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CELL_USBPORT_PREFIX "usb:"
#define CELL_USBPORT_SPEC_MAX 32
#define CELL_USBPORT_MAX 64

/* usb= source option */
typedef enum {
    CELL_USB_AUTO = 0,    /* interfaces no host driver has */
    CELL_USB_FORCE = 1,   /* every interface, taken from its host driver */
    CELL_USB_OFF = 2,
} cell_usb_mode_t;

typedef struct {
    char spec[CELL_USBPORT_SPEC_MAX];   /* usb:BUS-ADDR:IF */
    char dev[CELL_USBPORT_SPEC_MAX];    /* usb:BUS-ADDR, one physical modem */
    char model[64];
    char role[16];                      /* at, modem, diag, nmea */
    int ifnum;
    int cls, sub, prot;
    int driver;                         /* 1 host driver, 0 none, -1 unknown */
} cell_usbport_info_t;

static inline int cell_usbport_is_spec(const char *p) {
    return p != NULL && strncmp(p, CELL_USBPORT_PREFIX, 4) == 0;
}

/* "auto" / "force" / "off" (also yes/no); -1 for anything else */
int cell_usbport_mode_parse(const char *v);

/* Strict: usb:<1-255>-<1-127>:<0-31>. 0, or -1 for a malformed name. */
int cell_usbport_parse(const char *spec, int *bus, int *addr, int *ifnum);

#ifdef HAVE_CELL_USBSERIAL

void cell_usbport_set_mode(cell_usb_mode_t mode);
cell_usb_mode_t cell_usbport_mode(void);

/* Enumerate the attached modems' serial interfaces and return the ones the
 * mode admits. The full enumeration is kept for cell_usbport_info(). */
int cell_usbport_scan(cell_usbport_info_t *out, int max);

/* The last enumeration's entry for `spec` (enumerating if it has none).
 * 1 when found. */
int cell_usbport_info(const char *spec, cell_usbport_info_t *out);

/* Every interface of the modem `dev` ("usb:BUS-ADDR") in the last
 * enumeration, whatever the mode. */
int cell_usbport_siblings(const char *dev, cell_usbport_info_t *out, int max);

/* Claim the interface and return the fd, or -1 with errno: EWOULDBLOCK held by
 * another process, EBUSY a host driver has it (usb=force takes it), ENODEV no
 * such modem, EACCES no permission, EPERM usb=off. */
int cell_usbport_open(const char *spec);

#else

static inline void cell_usbport_set_mode(cell_usb_mode_t mode) { (void)mode; }
static inline cell_usb_mode_t cell_usbport_mode(void) { return CELL_USB_OFF; }
static inline int cell_usbport_scan(cell_usbport_info_t *out, int max) {
    (void)out; (void)max;
    return 0;
}
static inline int cell_usbport_info(const char *spec, cell_usbport_info_t *out) {
    (void)spec; (void)out;
    return 0;
}
static inline int cell_usbport_siblings(const char *dev, cell_usbport_info_t *out,
                                        int max) {
    (void)dev; (void)out; (void)max;
    return 0;
}
static inline int cell_usbport_open(const char *spec) {
    (void)spec;
    errno = ENODEV;
    return -1;
}

#endif

#ifdef __cplusplus
}
#endif

#endif
