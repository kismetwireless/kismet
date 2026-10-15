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

#include <errno.h>
#include <stdlib.h>

#include "mm8108.h"
#include "mm_util.h"

/* Checks the chip anyway after this long without an interrupt */
#define MM_IRQ_FALLBACK_MS  100

/* A full window plus a split packet's overhang */
#define MM_RX_BUF_LEN   (MM_YAPS_WINDOW_SIZE + MM_YAPS_MAX_PKT_SIZE + 64)
#define MM_TX_BUF_LEN   (MM_YAPS_WINDOW_SIZE + 64)

int mm8108_init(struct mm8108_dev *dev, int verbose) {
    int r;

    memset(dev, 0, sizeof(*dev));
    dev->verbose = verbose;

    if ((r = libusb_init(&dev->ctx)) < 0)
        return mm_error(dev, -EIO, "could not initialize libusb: %s", libusb_strerror(r));

    dev->rx_buf = malloc(MM_RX_BUF_LEN);
    dev->tx_buf = malloc(MM_TX_BUF_LEN);

    if (dev->rx_buf == NULL || dev->tx_buf == NULL) {
        mm8108_free(dev);
        return mm_error(dev, -ENOMEM, "could not allocate transfer buffers");
    }

    return 0;
}

void mm8108_free(struct mm8108_dev *dev) {
    mm_usb_close(dev);

    if (dev->ctx != NULL) {
        libusb_exit(dev->ctx);
        dev->ctx = NULL;
    }

    free(dev->rx_buf);
    free(dev->tx_buf);
    dev->rx_buf = dev->tx_buf = NULL;
}

void mm8108_set_rx_cb(struct mm8108_dev *dev, mm_rx_cb_t cb, void *ctx) {
    dev->rx_cb = cb;
    dev->rx_ctx = ctx;
}

/* Waits for the chip to raise an interrupt, then drains what it has queued */
int mm8108_poll(struct mm8108_dev *dev, unsigned int timeout_ms) {
    uint32_t int_sts = 0;
    bool fallback = false;
    int r;

    if (!dev->hw_on || !dev->yaps.valid)
        return -ENODEV;

    if (!dev->irq_pending && !dev->rx_more) {
        const uint64_t now = mm_monotonic_ms();
        const uint64_t fallback_at = dev->last_service_ms + MM_IRQ_FALLBACK_MS;
        unsigned int wait = timeout_ms;

        if (fallback_at <= now)
            wait = 0;
        else if (fallback_at - now < wait)
            wait = (unsigned int) (fallback_at - now);

        if ((r = mm_usb_int_wait(dev, wait)) < 0)
            return mm_error(dev, r, "interrupt endpoint failed");

        if (r == 0) {
            if (mm_monotonic_ms() < fallback_at)
                return 0;
            fallback = true;
        }
    }

    dev->irq_pending = 0;
    dev->rx_more = false;
    dev->last_service_ms = mm_monotonic_ms();

    /* Clear what the chip raised before draining, as the driver does, so data arriving
     * meanwhile raises a new interrupt */
    if ((r = mm_reg32_read(dev, MM8108_REG_INT1_STS, &int_sts)) < 0)
        return r;
    if (int_sts != 0 && (r = mm_reg32_write(dev, MM8108_REG_INT1_CLR, int_sts)) < 0)
        return r;

    if ((r = mm_yaps_update_status(dev)) < 0)
        return r;

    if (dev->yaps.status.fc_rx_bytes_in_queue == 0)
        return 0;

    if (fallback) {
        dev->missed_irq_count++;
        mm_log(dev, 2, "found %u queued bytes without an interrupt",
                dev->yaps.status.fc_rx_bytes_in_queue);
    }

    if ((r = mm_yaps_read(dev)) > 0)
        dev->rx_more = true;

    return r;
}

int mm8108_start_monitor(struct mm8108_dev *dev) {
    return mm_cmd_add_monitor(dev);
}

/* Removes the monitor interface and resets the chip so the firmware stops */
void mm8108_stop(struct mm8108_dev *dev) {
    if (dev->handle == NULL)
        return;

    /* Responses arrive through interrupts, so stop them only after the last command */
    if (dev->hw_on && dev->mon_added)
        mm_cmd_remove_monitor(dev);

    mm_usb_int_stop(dev);

    if (dev->hw_on)
        mm_digital_reset(dev);
}
