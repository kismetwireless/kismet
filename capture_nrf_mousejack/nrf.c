/*
  Derived from the Bastille Mousejack python code.
  While Kismet is generally licensed under the GPL2 license, this binary is
  derived from GPL3 code from Bastille, and as such, is under that license.
   
  Copyright (C) 2016 Bastille Networks
  Copyright (C) 2018 Mike Kershaw / dragorn@kismetwireless.net


  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../config.h"

#include "mousejack.h"

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

#include <libusb-1.0/libusb.h>

#define MOUSEJACK_USB_VENDOR        0x1915
#define MOUSEJACK_USB_PRODUCT       0x0102

int main(void) {
    libusb_context *libusb_ctx = NULL;
    int r;

    r = libusb_init(&libusb_ctx);

    if (r < 0) {
        printf("failed to init libusb\n");
        exit(1);
    }

    libusb_set_debug(libusb_ctx, 3);

    libusb_device **libusb_devs = NULL;
    libusb_device *matched_dev = NULL;
    ssize_t libusb_devices_cnt = 0;

    int matched_device = 0;
    char cap_if[32];

    libusb_device_handle *nrf_handle = NULL;

    libusb_devices_cnt = libusb_get_device_list(libusb_ctx, &libusb_devs);

    if (libusb_devices_cnt < 0) {
        printf("unable to iterate\n");
        return -1;
    }

    for (ssize_t i = 0; i < libusb_devices_cnt; i++) {
        struct libusb_device_descriptor dev;

        r = libusb_get_device_descriptor(libusb_devs[i], &dev);

        if (r < 0) {
            continue;
        }

        if (dev.idVendor == MOUSEJACK_USB_VENDOR && dev.idProduct == MOUSEJACK_USB_PRODUCT) {
            matched_device = 1;
            matched_dev = libusb_devs[i];
            break;
        }
    }

    if (!matched_device) {
        printf("unable to find mousejack\n");
        return -1;
    }

    libusb_free_device_list(libusb_devs, 1);

    /* Try to open it */
    r = libusb_open(matched_dev, &nrf_handle);
    if (r < 0) {
        printf("unable to open usb: %s\n", libusb_strerror((enum libusb_error) r));
        return -1;
    }

    /* Try to claim it */
    r = libusb_claim_interface(nrf_handle, 0);
    if (r < 0) {
        if (r == LIBUSB_ERROR_BUSY) {
            /* Try to detach the kernel driver */
            r = libusb_detach_kernel_driver(nrf_handle, 0);
            if (r < 0) {
                printf("Unable to open mousejack USB interface, and unable "
                        "to disconnect existing driver: %s", 
                        libusb_strerror((enum libusb_error) r));
                return -1;
            }
        } else {
            printf("Unable to open mousejack USB interface: %s",
                    libusb_strerror((enum libusb_error) r));
            return -1;
        }
    }

    printf("setting config\n");

    libusb_set_configuration(nrf_handle, 1);

    printf("ok");

}

