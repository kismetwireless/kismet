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
#include <sys/time.h>

#include "mm8108.h"
#include "mm_util.h"

#define MM_USB_DIR_WRITE    0x00
#define MM_USB_DIR_READ     0x80
#define MM_USB_DIR_RESET    0x02

#define MM_USB_CMD_LEN      12
#define MM_USB_MAX_XFER     (16 * 1024)
#define MM_USB_TIMEOUT_MS   250

static int mm_usb_err(int r) {
    switch (r) {
        case LIBUSB_ERROR_TIMEOUT:
            return -ETIMEDOUT;
        case LIBUSB_ERROR_NO_DEVICE:
            return -ENODEV;
        case LIBUSB_ERROR_NO_MEM:
            return -ENOMEM;
        case LIBUSB_ERROR_BUSY:
            return -EBUSY;
        case LIBUSB_ERROR_ACCESS:
            return -EACCES;
        default:
            return -EIO;
    }
}

static int mm_usb_bulk(struct mm8108_dev *dev, uint8_t ep, uint8_t *buf, size_t len) {
    int actual = 0;
    int r;

    if (len > MM_USB_MAX_XFER)
        return -EINVAL;

    r = libusb_bulk_transfer(dev->handle, ep, buf, (int) len, &actual, MM_USB_TIMEOUT_MS);

    if (r < 0)
        return mm_usb_err(r);

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

        /* libusb takes a non-const buffer for both directions */
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
static void LIBUSB_CALL mm_usb_int_cb(struct libusb_transfer *xfer) {
    struct mm8108_dev *dev = xfer->user_data;

    switch (xfer->status) {
        case LIBUSB_TRANSFER_COMPLETED:
            dev->irq_pending = 1;
            dev->irq_count++;
            break;
        case LIBUSB_TRANSFER_CANCELLED:
            dev->int_active = false;
            return;
        case LIBUSB_TRANSFER_NO_DEVICE:
            dev->int_error = -ENODEV;
            dev->int_active = false;
            return;
        case LIBUSB_TRANSFER_TIMED_OUT:
            break;
        default:
            dev->int_error = -EIO;
            dev->int_active = false;
            return;
    }

    if (libusb_submit_transfer(xfer) < 0) {
        dev->int_error = -EIO;
        dev->int_active = false;
    }
}

int mm_usb_int_start(struct mm8108_dev *dev) {
    int r;

    if (dev->int_active)
        return 0;

    if (dev->ep_int == 0)
        return mm_error(dev, -ENODEV, "USB device has no interrupt endpoint");

    if (dev->int_xfer == NULL && (dev->int_xfer = libusb_alloc_transfer(0)) == NULL)
        return mm_error(dev, -ENOMEM, "could not allocate the interrupt transfer");

    libusb_fill_interrupt_transfer(dev->int_xfer, dev->handle, dev->ep_int, dev->int_buf,
            sizeof(dev->int_buf), mm_usb_int_cb, dev, 0);

    dev->int_error = 0;
    dev->irq_pending = 0;

    if ((r = libusb_submit_transfer(dev->int_xfer)) < 0)
        return mm_error(dev, mm_usb_err(r), "could not start the interrupt transfer: %s",
                libusb_strerror(r));

    dev->int_active = true;

    return 0;
}

void mm_usb_int_stop(struct mm8108_dev *dev) {
    if (dev->int_xfer == NULL)
        return;

    if (dev->int_active && libusb_cancel_transfer(dev->int_xfer) == 0) {
        const uint64_t expiry = mm_monotonic_ms() + 1000;

        /* The callback must run before the transfer can be freed */
        while (dev->int_active && mm_monotonic_ms() < expiry) {
            struct timeval tv = { 0, 10000 };
            libusb_handle_events_timeout_completed(dev->ctx, &tv, NULL);
        }
    }

    /* Leak rather than free a transfer libusb may still own */
    if (!dev->int_active)
        libusb_free_transfer(dev->int_xfer);

    dev->int_xfer = NULL;
    dev->int_active = false;
}

int mm_usb_int_wait(struct mm8108_dev *dev, unsigned int timeout_ms) {
    const uint64_t expiry = mm_monotonic_ms() + timeout_ms;

    while (!dev->irq_pending && dev->int_error == 0) {
        const uint64_t now = mm_monotonic_ms();
        struct timeval tv;
        int r;

        if (now >= expiry)
            return 0;

        tv.tv_sec = (time_t) ((expiry - now) / 1000);
        tv.tv_usec = (suseconds_t) ((expiry - now) % 1000) * 1000;

        if ((r = libusb_handle_events_timeout_completed(dev->ctx, &tv, &dev->irq_pending)) < 0 &&
                r != LIBUSB_ERROR_INTERRUPTED)
            return mm_usb_err(r);
    }

    if (dev->int_error != 0)
        return dev->int_error;

    return 1;
}

/* Bulk IN and OUT for memory access, plus an interrupt IN which signals pending work */
static int mm_usb_find_endpoints(struct mm8108_dev *dev, libusb_device *usbdev) {
    struct libusb_config_descriptor *config;
    const struct libusb_interface_descriptor *intf;
    int r;

    if ((r = libusb_get_active_config_descriptor(usbdev, &config)) < 0)
        return mm_error(dev, mm_usb_err(r), "could not read USB configuration: %s",
                libusb_strerror(r));

    if (config->bNumInterfaces < 1 || config->interface[0].num_altsetting < 1) {
        libusb_free_config_descriptor(config);
        return mm_error(dev, -ENODEV, "USB device has no usable interface");
    }

    intf = &config->interface[0].altsetting[0];
    dev->interface = intf->bInterfaceNumber;
    dev->ep_in = dev->ep_out = dev->ep_int = 0;

    for (int i = 0; i < intf->bNumEndpoints; i++) {
        const struct libusb_endpoint_descriptor *ep = &intf->endpoint[i];
        const uint8_t type = ep->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK;
        const bool in = (ep->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN;

        if (type == LIBUSB_TRANSFER_TYPE_BULK) {
            if (in && dev->ep_in == 0)
                dev->ep_in = ep->bEndpointAddress;
            else if (!in && dev->ep_out == 0)
                dev->ep_out = ep->bEndpointAddress;
        } else if (type == LIBUSB_TRANSFER_TYPE_INTERRUPT && in && dev->ep_int == 0 &&
                ep->wMaxPacketSize >= 8) {
            dev->ep_int = ep->bEndpointAddress;
        }
    }

    libusb_free_config_descriptor(config);

    if (dev->ep_in == 0 || dev->ep_out == 0)
        return mm_error(dev, -ENODEV, "USB device is missing bulk endpoints");

    mm_log(dev, 2, "USB interface %d, bulk in 0x%02x, bulk out 0x%02x, interrupt 0x%02x",
            dev->interface, dev->ep_in, dev->ep_out, dev->ep_int);

    return 0;
}

/* Opens the first MM8108, or the one at bus/address if both are >= 0 */
static int mm_usb_devinfo_cmp(const void *a, const void *b) {
    const struct mm_usb_devinfo *da = a, *db = b;
    return strcmp(da->path, db->path);
}

int mm_usb_list(libusb_context *ctx, struct mm_usb_devinfo *out, size_t max) {
    libusb_device **list = NULL;
    ssize_t count;
    size_t n = 0;

    if ((count = libusb_get_device_list(ctx, &list)) < 0)
        return mm_usb_err((int) count);

    for (ssize_t i = 0; i < count && n < max; i++) {
        struct libusb_device_descriptor desc;
        uint8_t ports[8];
        int nports, pos;

        if (libusb_get_device_descriptor(list[i], &desc) < 0 ||
                desc.idVendor != MM8108_USB_VID || desc.idProduct != MM8108_USB_PID)
            continue;

        out[n].bus = libusb_get_bus_number(list[i]);
        out[n].address = libusb_get_device_address(list[i]);

        pos = snprintf(out[n].path, sizeof(out[n].path), "%03d", out[n].bus);
        nports = libusb_get_port_numbers(list[i], ports, sizeof(ports));

        for (int p = 0; p < nports && pos > 0 && (size_t) pos < sizeof(out[n].path); p++)
            pos += snprintf(out[n].path + pos, sizeof(out[n].path) - pos, "-%03u", ports[p]);

        n++;
    }

    libusb_free_device_list(list, 1);

    qsort(out, n, sizeof(out[0]), mm_usb_devinfo_cmp);

    return (int) n;
}

int mm_usb_open(struct mm8108_dev *dev, int bus, int address) {
    libusb_device **list = NULL;
    libusb_device *found = NULL;
    ssize_t count;
    int r;

    count = libusb_get_device_list(dev->ctx, &list);
    if (count < 0)
        return mm_error(dev, mm_usb_err((int) count), "could not list USB devices: %s",
                libusb_strerror((int) count));

    for (ssize_t i = 0; i < count; i++) {
        struct libusb_device_descriptor desc;

        if (libusb_get_device_descriptor(list[i], &desc) < 0)
            continue;

        if (desc.idVendor != MM8108_USB_VID || desc.idProduct != MM8108_USB_PID)
            continue;

        if (bus >= 0 && address >= 0 &&
                (libusb_get_bus_number(list[i]) != bus ||
                 libusb_get_device_address(list[i]) != address))
            continue;

        found = list[i];
        break;
    }

    if (found == NULL) {
        libusb_free_device_list(list, 1);
        return mm_error(dev, -ENODEV, "no MM8108 USB device (%04x:%04x) found",
                MM8108_USB_VID, MM8108_USB_PID);
    }

    mm_log(dev, 1, "found MM8108 on USB bus %d address %d", libusb_get_bus_number(found),
            libusb_get_device_address(found));

    if ((r = mm_usb_find_endpoints(dev, found)) < 0) {
        libusb_free_device_list(list, 1);
        return r;
    }

    r = libusb_open(found, &dev->handle);
    libusb_free_device_list(list, 1);

    if (r < 0)
        return mm_error(dev, mm_usb_err(r), "could not open USB device: %s", libusb_strerror(r));

    /* The morse_usb kernel module will have claimed the device on Linux */
    if (libusb_kernel_driver_active(dev->handle, dev->interface) == 1) {
        if ((r = libusb_detach_kernel_driver(dev->handle, dev->interface)) < 0) {
            mm_usb_close(dev);
            return mm_error(dev, mm_usb_err(r), "could not detach kernel driver: %s",
                    libusb_strerror(r));
        }

        dev->kernel_driver_detached = true;
    }

    if ((r = libusb_claim_interface(dev->handle, dev->interface)) < 0) {
        mm_usb_close(dev);
        return mm_error(dev, mm_usb_err(r), "could not claim USB interface: %s",
                libusb_strerror(r));
    }

    return 0;
}

void mm_usb_close(struct mm8108_dev *dev) {
    if (dev->handle == NULL)
        return;

    mm_usb_int_stop(dev);

    libusb_release_interface(dev->handle, dev->interface);

    if (dev->kernel_driver_detached) {
        libusb_attach_kernel_driver(dev->handle, dev->interface);
        dev->kernel_driver_detached = false;
    }

    libusb_close(dev->handle);
    dev->handle = NULL;
}
