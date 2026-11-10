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

/* USB transport, from morse_driver usb.c.
 *
 * Every access is a 12-byte command on the bulk OUT endpoint followed by a bulk data
 * phase on the IN (read) or OUT (write) endpoint.  The second bulk endpoint pair some
 * devices expose is unused by the driver.
 */

#include <errno.h>
#include <stdlib.h>

#include "mm8108.h"
#include "mm_util.h"

#define MM_USB_DIR_WRITE    0x00
#define MM_USB_DIR_READ     0x80
#define MM_USB_DIR_RESET    0x02

#define MM_USB_CMD_LEN      12
#define MM_USB_MAX_XFER     (16 * 1024)
#define MM_USB_TIMEOUT_MS   250
#define MM_USB_INT_LEN      8

static int mm_usb_bulk(struct mm8108_dev *dev, uint8_t ep, uint8_t *buf, size_t len) {
    const unsigned int pipe = (ep & USB_DIR_IN) ? usb_rcvbulkpipe(dev->udev, ep) :
        usb_sndbulkpipe(dev->udev, ep);
    int actual = 0;
    int r;

    if (len > MM_USB_MAX_XFER)
        return -EINVAL;

    if ((r = usb_bulk_msg(dev->udev, pipe, buf, (int) len, &actual, MM_USB_TIMEOUT_MS)) < 0)
        return r;

    if ((size_t) actual != len)
        return -EIO;

    return 0;
}

static int mm_usb_cmd(struct mm8108_dev *dev, uint32_t dir, uint32_t addr, uint32_t len) {
    uint8_t cmd[MM_USB_CMD_LEN];

    mm_put_le32(cmd, dir);
    mm_put_le32(cmd + 4, addr);
    mm_put_le32(cmd + 8, len);

    return mm_usb_bulk(dev, dev->ep_out, cmd, sizeof(cmd));
}

int mm_usb_mem_read(struct mm8108_dev *dev, uint32_t addr, uint8_t *buf, size_t len) {
    size_t offt = 0;
    int r;

    while (offt < len) {
        size_t chunk = len - offt;

        if (chunk > MM_USB_MAX_XFER)
            chunk = MM_USB_MAX_XFER;

        if ((r = mm_usb_cmd(dev, MM_USB_DIR_READ, addr + (uint32_t) offt, (uint32_t) chunk)) < 0)
            return r;

        if ((r = mm_usb_bulk(dev, dev->ep_in, buf + offt, chunk)) < 0)
            return r;

        offt += chunk;
    }

    return 0;
}

int mm_usb_mem_write(struct mm8108_dev *dev, uint32_t addr, const uint8_t *buf, size_t len) {
    size_t offt = 0;
    int r;

    while (offt < len) {
        size_t chunk = len - offt;

        if (chunk > MM_USB_MAX_XFER)
            chunk = MM_USB_MAX_XFER;

        if ((r = mm_usb_cmd(dev, MM_USB_DIR_WRITE, addr + (uint32_t) offt, (uint32_t) chunk)) < 0)
            return r;

        /* The bulk API takes a non-const buffer for both directions */
        if ((r = mm_usb_bulk(dev, dev->ep_out, (uint8_t *) buf + offt, chunk)) < 0)
            return r;

        offt += chunk;
    }

    return 0;
}

/* Digital reset of the chip which keeps the USB connection */
int mm_usb_ndr_reset(struct mm8108_dev *dev) {
    return mm_usb_cmd(dev, MM_USB_DIR_RESET, 0, 0);
}

/* The 8-byte payload isn't used by the driver; a completion only says the chip raised an
 * interrupt, and the interrupt status register says why. */
static void mm_usb_int_complete(struct urb *urb) {
    struct mm8108_dev *dev = urb->context;

    switch (urb->status) {
        case 0:
            dev->irq_pending = 1;
            dev->irq_count++;
            wake_up(&dev->irq_wq);
            break;
        case -ENOENT:
        case -ECONNRESET:
        case -ESHUTDOWN:
            dev->int_active = false;
            wake_up(&dev->irq_wq);
            return;
        case -ETIMEDOUT:
            break;
        default:
            dev->int_error = urb->status == -ENODEV ? -ENODEV : -EIO;
            dev->int_active = false;
            wake_up(&dev->irq_wq);
            return;
    }

    if (usb_submit_urb(urb, GFP_ATOMIC) < 0) {
        dev->int_error = -EIO;
        dev->int_active = false;
        wake_up(&dev->irq_wq);
    }
}

int mm_usb_int_start(struct mm8108_dev *dev) {
    int r;

    if (dev->int_active)
        return 0;

    if (dev->ep_int == 0)
        return mm_error(dev, -ENODEV, "USB device has no interrupt endpoint");

    if (dev->int_urb == NULL && (dev->int_urb = usb_alloc_urb(0, GFP_KERNEL)) == NULL)
        return mm_error(dev, -ENOMEM, "could not allocate the interrupt URB");

    usb_fill_int_urb(dev->int_urb, dev->udev, usb_rcvintpipe(dev->udev, dev->ep_int),
            dev->int_buf, MM_USB_INT_LEN, mm_usb_int_complete, dev, 1);

    dev->int_error = 0;
    dev->irq_pending = 0;
    dev->int_active = true;

    if ((r = usb_submit_urb(dev->int_urb, GFP_KERNEL)) < 0) {
        dev->int_active = false;
        return mm_error(dev, r, "could not start the interrupt URB: %d", r);
    }

    return 0;
}

void mm_usb_int_stop(struct mm8108_dev *dev) {
    if (dev->int_urb == NULL)
        return;

    usb_kill_urb(dev->int_urb);
    usb_free_urb(dev->int_urb);
    dev->int_urb = NULL;
    dev->int_active = false;
}

int mm_usb_int_wait(struct mm8108_dev *dev, unsigned int timeout_ms) {
    if (!dev->irq_pending && dev->int_error == 0 && timeout_ms > 0)
        wait_event_timeout(dev->irq_wq, dev->irq_pending || dev->int_error != 0,
                msecs_to_jiffies(timeout_ms));

    if (dev->int_error != 0)
        return dev->int_error;

    return dev->irq_pending ? 1 : 0;
}

/* Bulk IN and OUT for memory access, plus an interrupt IN which signals pending work */
int mm_usb_open(struct mm8108_dev *dev, struct usb_interface *intf) {
    const struct usb_host_interface *alt = intf->cur_altsetting;

    dev->intf = intf;
    dev->udev = interface_to_usbdev(intf);
    dev->ep_in = dev->ep_out = dev->ep_int = 0;

    for (int i = 0; i < alt->desc.bNumEndpoints; i++) {
        const struct usb_endpoint_descriptor *ep = &alt->endpoint[i].desc;
        const bool in = (ep->bEndpointAddress & USB_DIR_IN) != 0;

        if (usb_endpoint_xfer_bulk(ep)) {
            if (in && dev->ep_in == 0)
                dev->ep_in = ep->bEndpointAddress;
            else if (!in && dev->ep_out == 0)
                dev->ep_out = ep->bEndpointAddress;
        } else if (usb_endpoint_xfer_int(ep) && in && dev->ep_int == 0 &&
                le16_to_cpu(ep->wMaxPacketSize) >= MM_USB_INT_LEN) {
            dev->ep_int = ep->bEndpointAddress;
        }
    }

    if (dev->ep_in == 0 || dev->ep_out == 0)
        return mm_error(dev, -ENODEV, "USB device is missing bulk endpoints");

    if ((dev->int_buf = kzalloc(MM_USB_INT_LEN, GFP_KERNEL)) == NULL)
        return -ENOMEM;

    mm_log(dev, 2, "USB bulk in 0x%02x, bulk out 0x%02x, interrupt 0x%02x",
            dev->ep_in, dev->ep_out, dev->ep_int);

    return 0;
}

void mm_usb_close(struct mm8108_dev *dev) {
    mm_usb_int_stop(dev);
    kfree(dev->int_buf);
    dev->int_buf = NULL;
    dev->udev = NULL;
}
