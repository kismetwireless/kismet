/*
 * Copyright (C) 2010 Willow Garage <http://www.willowgarage.com>
 * Copyright (C) 2004 - 2010 Ivo van Doorn <IvDoorn@gmail.com>
 * <http://rt2x00.serialmonkey.com>
 *
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 Inc
 *
 */

#include <errno.h>
#include <string.h>

#ifndef _WIN32
#include <unistd.h>
#else
#include <Windows.h>
#define usleep(x) Sleep((x) < 1000 ? 1 : (x) / 1000)
#endif

#include <stdlib.h>

#include "kernel/kernel.h"

#include "rt2800usb/rt2x00usb.h"
#include "rt2800usb/rt2x00reg.h"

#include "userspace/userspace.h"

/*
 * Interfacing with the HW.
 */
int rt2x00usb_vendor_request(struct rt2x00_dev *rt2x00dev,
        const uint8_t request, const uint8_t requesttype,
        const uint16_t offset, const uint16_t value,
        void *buffer, const uint16_t buffer_length,
        const int timeout) {

    struct libusb_device_handle *usb_dev = rt2x00dev->dev;

    int fail_count = 0;

    if (!test_bit(DEVICE_STATE_PRESENT, &rt2x00dev->flags)) {
        rt2x00_err(rt2x00dev, "No device present\n");
        return -ENODEV;
    }

    /* 
     * we use a simplified failure count instead of measuring time, so that
     * we don't introduce timeout errors on multi-platform builds; we don't
     * want to depend on linux (or posix) high-precision timespec
     */

    if (rt2x00dev->control_transfer_buffer_sz < LIBUSB_CONTROL_SETUP_SIZE + buffer_length) {
        if (rt2x00dev->control_transfer_buffer != NULL)
            free(rt2x00dev->control_transfer_buffer);

        rt2x00dev->control_transfer_buffer = 
            (unsigned char *) malloc(LIBUSB_CONTROL_SETUP_SIZE + buffer_length);

        if (rt2x00dev->control_transfer_buffer == NULL) {
            rt2x00_err(rt2x00dev, "No memory");
            return -ENOMEM;
        }

        rt2x00dev->control_transfer_buffer_sz = LIBUSB_CONTROL_SETUP_SIZE + buffer_length;
    }

    /*
     * We have to tie into the async io system with libusb here, we use a conditional
     * variable to determine when our command completes
     */

    if (rt2x00dev->control_transfer == NULL)
        rt2x00dev->control_transfer = libusb_alloc_transfer(0);

    libusb_fill_control_setup(rt2x00dev->control_transfer_buffer, requesttype, request, value, offset, buffer_length);
    memcpy(rt2x00dev->control_transfer_buffer + LIBUSB_CONTROL_SETUP_SIZE, buffer, buffer_length);
    libusb_fill_control_transfer(rt2x00dev->control_transfer, usb_dev, rt2x00dev->control_transfer_buffer, 
            rt2x00dev_control_cb, rt2x00dev, timeout / 2);

    do {
        rt2x00dev->usb_command_complete = false;
        libusb_submit_transfer(rt2x00dev->control_transfer);

        /* Wait for the cond to unlock */
        while (1) {
            pthread_mutex_lock(&rt2x00dev->usb_control_mutex);
            pthread_cond_wait(&rt2x00dev->usb_control_cond, &rt2x00dev->usb_control_mutex);

            if (!rt2x00dev->usb_command_complete)
                continue;

            pthread_mutex_unlock(&rt2x00dev->usb_control_mutex);
            break;
        }

        if (rt2x00dev->control_transfer->status == LIBUSB_TRANSFER_COMPLETED) {
            memcpy(buffer, rt2x00dev->control_transfer_buffer + LIBUSB_CONTROL_SETUP_SIZE, buffer_length);
            pthread_mutex_unlock(&rt2x00dev->usb_control_mutex);
            return 0;
        }

        if (rt2x00dev->control_transfer->status == LIBUSB_TRANSFER_NO_DEVICE) {
            clear_bit(DEVICE_STATE_PRESENT, &rt2x00dev->flags);
            pthread_mutex_unlock(&rt2x00dev->usb_control_mutex);
            rt2x00_err(rt2x00dev, "Device no longer available");
            return -ENODEV;
        }

        if (rt2x00dev->control_transfer->status == LIBUSB_TRANSFER_TIMED_OUT)
            fail_count++;

    } while (fail_count < 3);

    rt2x00_err(rt2x00dev,
            "Vendor Request 0x%02x failed for offset 0x%04x with error %d\n",
            request, offset, rt2x00dev->control_transfer->status);

    return -1;
}

int rt2x00usb_vendor_request_buff(struct rt2x00_dev *rt2x00dev,
				  const uint8_t request, const uint8_t requesttype,
				  const uint16_t offset, void *buffer,
				  const uint16_t buffer_length)
{
	int status = 0;
	unsigned char *tb;
	uint16_t off, len, bsize;

	mutex_lock(&rt2x00dev->csr_mutex);

	tb  = (unsigned char *)buffer;
	off = offset;
	len = buffer_length;
	while (len && !status) {
		bsize = min_t(uint16_t, CSR_CACHE_SIZE, len);
		status = rt2x00usb_vendor_req_buff_lock(rt2x00dev, request,
							requesttype, off, tb,
							bsize, REGISTER_TIMEOUT);

		tb  += bsize;
		len -= bsize;
		off += bsize;
	}

	mutex_unlock(&rt2x00dev->csr_mutex);

	if (status != 0) 
		rt2x00_err(rt2x00dev, "Radio USB request failed: %s", libusb_error_name(status));

	return status;
}

/*
 * Userspace buff_lock doesn't do any locking
 */
int rt2x00usb_vendor_req_buff_lock(struct rt2x00_dev *rt2x00dev,
				   const uint8_t request, const uint8_t requesttype,
				   const uint16_t offset, void *buffer,
				   const uint16_t buffer_length, const int timeout)
{
	int status;

	/*
	 * Check for Cache availability.
	 */
	if (unlikely(!rt2x00dev->csr.cache || buffer_length > CSR_CACHE_SIZE)) {
		rt2x00_err(rt2x00dev, "CSR cache not available\n");
		return -ENOMEM;
	}

	if (requesttype == USB_VENDOR_REQUEST_OUT)
		memcpy(rt2x00dev->csr.cache, buffer, buffer_length);

	status = rt2x00usb_vendor_request(rt2x00dev, request, requesttype,
					  offset, 0, rt2x00dev->csr.cache,
					  buffer_length, timeout);

	if (!status && requesttype == USB_VENDOR_REQUEST_IN)
		memcpy(buffer, rt2x00dev->csr.cache, buffer_length);

	if (status != 0) 
		rt2x00_err(rt2x00dev, "Radio CSR USB request failed: %s", libusb_error_name(status));

	return status;
}

int rt2x00usb_regbusy_read(struct rt2x00_dev *rt2x00dev,
        const unsigned int offset,
        const struct rt2x00_field32 field,
        uint32_t *reg) {
    unsigned int i;

    if (!test_bit(DEVICE_STATE_PRESENT, &rt2x00dev->flags))
        return -ENODEV;

    for (i = 0; i < REGISTER_USB_BUSY_COUNT; i++) {
        *reg = rt2x00usb_register_read_lock(rt2x00dev, offset);
        if (!rt2x00_get_field32(*reg, field))
            return 1;
        usleep(REGISTER_BUSY_DELAY);
    }

    rt2x00_err(rt2x00dev, "Indirect register access failed: offset=0x%.08x, value=0x%.08x\n",
            offset, *reg);
    *reg = ~0;

    return 0;
}

struct rt2x00_async_read_data {
    ___le32 reg;
    struct rt2x00_dev *rt2x00dev;
    bool (*callback)(struct rt2x00_dev *, int, uint32_t);
};

/* 
 * In the userspace port, async actually blocks and then calls the
 * cb; we'll find out if this causes problems
 */
void rt2x00usb_register_read_async(struct rt2x00_dev *rt2x00dev,
        const unsigned int offset,
        bool (*callback)(struct rt2x00_dev*, int, uint32_t)) {
    struct libusb_device_handle *usb_dev = rt2x00dev->dev;
    struct rt2x00_async_read_data *rd;
    int status;

    rd = (struct rt2x00_async_read_data *) malloc(sizeof(*rd));
    if (!rd)
        return;

    rd->rt2x00dev = rt2x00dev;
    rd->callback = callback;

    /* 
     * Implement the equivalent to rt2x00usb_register_read_async_cb and call
     * the provided cb directly; if the callback says to resubmit the request,
     * do so
     */
    do {
        status = libusb_control_transfer(usb_dev, USB_VENDOR_REQUEST_IN, USB_MULTI_READ,
                0, cpu_to_le16(offset), (unsigned char *) &rd->reg, cpu_to_le16(sizeof(uint32_t)), REGISTER_TIMEOUT);

        if (rd->callback(rd->rt2x00dev, status, le32_to_cpu(rd->reg)))
            continue;

        break;
    } while (1);
}

static int rt2x00usb_find_endpoints(struct rt2x00_dev *rt2x00dev) {
    struct libusb_config_descriptor *config = NULL;
    struct libusb_device_descriptor desc;
    int ret;

    /*
     * interface, config, endpoint, and altsetting iterators
     */
    unsigned int i, c, e;
    int a;

    bool found_in, found_out;


    ret = libusb_get_device_descriptor(rt2x00dev->base_dev, &desc);
    if (ret != LIBUSB_SUCCESS) {
        clear_bit(DEVICE_STATE_PRESENT, &rt2x00dev->flags);
        return -EPIPE;
    }

    /*
     * Walk through all available endpoints to search for "bulk in"
     * and "bulk out" endpoints. When we find such endpoints collect
     * the information we need from the descriptor and confirm they
     * exist.
     *
     * We don't get to use kernel queues so for now we just confirm
     * the device looks like we expect it to.
     */
    for (c = 0; c < desc.bNumConfigurations; c++) {
        ret = libusb_get_config_descriptor(rt2x00dev->base_dev, c, &config);

        if (ret != LIBUSB_SUCCESS) {
            clear_bit(DEVICE_STATE_PRESENT, &rt2x00dev->flags);
            rt2x00_err(rt2x00dev, "unable to retrieve device descriptors");
            return -EPIPE;
        }

        for (i = 0; i < config->bNumInterfaces; i++) {
            /*
             * We expect both out and in to be on the same interface
             */
            found_in = false;
            found_out = false;

            for (a = 0; a < config->interface[i].num_altsetting; a++) {
                for (e = 0; e < config->interface[i].altsetting[a].bNumEndpoints; e++) {
                    if ((config->interface[i].altsetting[a].endpoint[e].bmAttributes & LIBUSB_TRANSFER_TYPE_MASK) != 
                            LIBUSB_TRANSFER_TYPE_BULK)
                        continue;

                    if (!found_in && 
                            (config->interface[i].altsetting[a].endpoint[e].bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) ==
                            LIBUSB_ENDPOINT_IN) {
                        rt2x00dev->usb_interface_num = i;
                        rt2x00dev->usb_bulk_in_endp = config->interface[i].altsetting[a].endpoint[e].bEndpointAddress;
                        found_in = true;
                    }

                    if (!found_out && 
                            (config->interface[i].altsetting[a].endpoint[e].bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) ==
                            LIBUSB_ENDPOINT_OUT) {
                        rt2x00dev->usb_interface_num = i;
                        rt2x00dev->usb_bulk_out_endp = config->interface[i].altsetting[a].endpoint[e].bEndpointAddress;
                        found_out = true;
                    }

                    if (found_in && found_out)
                        break;
                }

                if (found_in && found_out)
                    break;
            }

            if (found_in && found_out)
                break;
        }

        libusb_free_config_descriptor(config);
    }

    /*
     * At least 1 endpoint for RX and 1 endpoint for TX must be available.
     */
    if (!found_in || !found_out) {
        rt2x00_err(rt2x00dev, "Bulk-in/Bulk-out endpoints not found\n");
        return -EPIPE;
    }

    return 0;
}

int rt2x00usb_initialize(struct rt2x00_dev *rt2x00dev) {
    int status;

	/*
	 * Allocate the driver data memory, if necessary.
	 */
	if (rt2x00dev->ops->drv_data_size > 0) {
        rt2x00dev->drv_data = malloc(rt2x00dev->ops->drv_data_size);
		if (!rt2x00dev->drv_data) {
            return -ENOMEM;
		}
        memset(rt2x00dev->drv_data, 0, rt2x00dev->ops->drv_data_size);
	}

    /*
     * Find endpoints for each queue
     */
    status = rt2x00usb_find_endpoints(rt2x00dev);
    if (status)
        return status;

    return 0;
}

int rt2x00usb_alloc_reg(struct rt2x00_dev *rt2x00dev) {
    rt2x00dev->csr.cache = malloc(CSR_CACHE_SIZE);
    if (!rt2x00dev->csr.cache) {
        return -ENOMEM;
    }

    rt2x00dev->eeprom = (___le16*) malloc(rt2x00dev->ops->eeprom_size);
    if (!rt2x00dev->eeprom) {
        free(rt2x00dev->csr.cache);
        return -ENOMEM;
    }

    rt2x00dev->rf = (uint32_t *) malloc(rt2x00dev->ops->rf_size);
    if (!rt2x00dev->rf) {
        free(rt2x00dev->csr.cache);
        free(rt2x00dev->eeprom);
        return -ENOMEM;
    }

    return 0;
}

void rt2x00usb_free(struct rt2x00_dev *rt2x00dev) {
    if (rt2x00dev == NULL)
        return;

    if (rt2x00dev->csr.cache)
        free(rt2x00dev->csr.cache);

    if (rt2x00dev->eeprom)
        free(rt2x00dev->eeprom);

    if (rt2x00dev->rf)
        free(rt2x00dev->rf);

    free(rt2x00dev);

    return;
}

