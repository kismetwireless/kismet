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

/* Userspace USB serial ports over libusb, for devices whose serial interfaces
 * have no driver on the host, such as Quectel modems on macOS.  Each port is a
 * pair of bulk pipes; there is no baud rate or line discipline to emulate. */

#ifndef __USBSERIAL_H__
#define __USBSERIAL_H__

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

#include <libusb.h>

#define USBSERIAL_MAX_PORTS     8
#define USBSERIAL_RX_XFERS      4
#define USBSERIAL_RX_XFER_SIZE  16384
#define USBSERIAL_TX_XFER_SIZE  16384
#define USBSERIAL_TXQ_SIZE      (256 * 1024)

typedef struct {
    uint8_t ifnum;
    const char *role;
} usbserial_role_t;

typedef struct {
    uint16_t vid;
    uint16_t pid;
    const char *name;
    /* Terminated by a NULL role */
    const usbserial_role_t *roles;
} usbserial_model_t;

typedef struct usbserial_dev usbserial_dev_t;
typedef struct usbserial_port usbserial_port_t;

/* Data from the device; called on the event thread */
typedef void (*usbserial_rx_cb_t)(usbserial_port_t *port, const uint8_t *data,
        size_t len, void *aux);

/* The device stopped (unplugged, or a transfer failed); called once, on the
 * event thread */
typedef void (*usbserial_err_cb_t)(usbserial_dev_t *dev, const char *reason, void *aux);

const usbserial_model_t *usbserial_find_model(uint16_t vid, uint16_t pid);

/* Print the known devices that are attached, one per line */
int usbserial_list(FILE *out);

/* Open a device and claim its serial interfaces.  vid/pid 0 picks the first known
 * model attached; a bus or addr of -1 matches any.  Returns NULL with err filled in. */
usbserial_dev_t *usbserial_open(uint16_t vid, uint16_t pid, int bus, int addr,
        char *err, size_t errlen);

/* Start transfers and the event thread */
int usbserial_start(usbserial_dev_t *dev, usbserial_rx_cb_t rx_cb,
        usbserial_err_cb_t err_cb, void *aux, char *err, size_t errlen);

/* Stop transfers, release the interfaces and free everything */
void usbserial_close(usbserial_dev_t *dev);

size_t usbserial_num_ports(usbserial_dev_t *dev);
usbserial_port_t *usbserial_get_port(usbserial_dev_t *dev, size_t n);
const char *usbserial_model_name(usbserial_dev_t *dev);

const char *usbserial_port_role(usbserial_port_t *port);
uint8_t usbserial_port_ifnum(usbserial_port_t *port);

/* Queue data for the device; returns the number of bytes queued, which is less
 * than len when the queue is full, or -1 once the device has stopped */
ssize_t usbserial_write(usbserial_port_t *port, const uint8_t *data, size_t len);

/* Free space in a port's send queue */
size_t usbserial_tx_space(usbserial_port_t *port);

#endif
