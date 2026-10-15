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

/* Chip register and memory access, from morse_driver hw.c, mm8108.c and mem_access.c */

#include <errno.h>
#include <stdarg.h>
#include <time.h>

#include "mm8108.h"
#include "mm_util.h"

#define MEM_ACCESS_STATE_RESTRICTED     0x494E4954
#define MEM_ACCESS_REQUEST_STARTED      0xFEEDDA7A
#define MEM_ACCESS_REQUEST_GRANTED      0x00ACCE55
#define MEM_ACCESS_REQUEST_GRANTED_BURST 0x0ACCE55B
#define MEM_ACCESS_REQUEST_DENIED       0xBAADBAAD
#define MEM_ACCESS_RESPONSE_TIMEOUT_MS  5

/* Regions which never need an access request when restriction is enforced */
#define MEM_ACCESS_EXPAND_START         0x00170000
#define MEM_ACCESS_EXPAND_END           (0x00180000 - 64)

uint64_t mm_monotonic_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + (uint64_t) ts.tv_nsec / 1000000;
}

void mm_sleep_us(unsigned int us) {
    struct timespec ts;
    ts.tv_sec = us / 1000000;
    ts.tv_nsec = (long) (us % 1000000) * 1000;
    while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
        ;
}

void mm_log(const struct mm8108_dev *dev, int level, const char *fmt, ...) {
    va_list args;

    if (dev->verbose < level)
        return;

    va_start(args, fmt);
    fprintf(stderr, "mm8108: ");
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");
    va_end(args);
}

int mm_error(struct mm8108_dev *dev, int err, const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    vsnprintf(dev->errstr, sizeof(dev->errstr), fmt, args);
    va_end(args);

    mm_log(dev, 1, "error: %s", dev->errstr);

    return err;
}

static bool mm_region_contains(uint32_t start, uint32_t end, uint32_t addr, size_t len) {
    return addr >= start && (uint64_t) addr + len <= end;
}

/* The restriction state is cached once firmware is running */
bool mm_mem_restricted(struct mm8108_dev *dev) {
    uint8_t buf[4];

    if (dev->mem_overridden)
        return false;

    if (dev->hw_on)
        return dev->mem_restricted;

    if (mm_usb_mem_read(dev, MM8108_REG_MEM_ACCESS_STATE, buf, sizeof(buf)) < 0)
        return dev->mem_restricted;

    const uint32_t state = mm_get_le32(buf);

    if (state == MEM_ACCESS_STATE_RESTRICTED) {
        dev->mem_restricted = true;
    } else if (state == (uint32_t) ~MEM_ACCESS_STATE_RESTRICTED) {
        dev->mem_restricted = false;
        dev->mem_overridden = true;
    } else {
        dev->mem_restricted = false;
    }

    return dev->mem_restricted;
}

void mm_mem_access_reset_cache(struct mm8108_dev *dev) {
    dev->mem_cache_start = dev->mem_cache_end = 0;
}

static int mm_mem_access_request(struct mm8108_dev *dev, uint32_t addr, size_t len) {
    uint8_t buf[4];
    uint32_t status = MEM_ACCESS_REQUEST_STARTED;
    int r;

    if (!mm_mem_restricted(dev))
        return 0;

    if (mm_region_contains(MM8108_REG_RESET, MM8108_REG_RESET + 4, addr, len) ||
            mm_region_contains(MM8108_REG_TRGR_BASE, MM8108_REG_TRGR_END + 4, addr, len))
        return 0;

    if (dev->mem_cache_end != 0 &&
            mm_region_contains(dev->mem_cache_start, dev->mem_cache_end, addr, len))
        return 0;

    if (mm_region_contains(MEM_ACCESS_EXPAND_START, MEM_ACCESS_EXPAND_END, addr, len)) {
        addr = MEM_ACCESS_EXPAND_START;
        len = MEM_ACCESS_EXPAND_END - MEM_ACCESS_EXPAND_START;
    }

    mm_put_le32(buf, MEM_ACCESS_REQUEST_STARTED);
    if ((r = mm_usb_mem_write(dev, MM8108_REG_MEM_ACCESS_STATUS, buf, 4)) < 0)
        return r;
    mm_put_le32(buf, addr);
    if ((r = mm_usb_mem_write(dev, MM8108_REG_MEM_ACCESS_ADDR, buf, 4)) < 0)
        return r;
    mm_put_le32(buf, (uint32_t) len);
    if ((r = mm_usb_mem_write(dev, MM8108_REG_MEM_ACCESS_SIZE, buf, 4)) < 0)
        return r;
    mm_put_le32(buf, 1);
    if ((r = mm_usb_mem_write(dev, MM8108_REG_TRGR2_SET, buf, 4)) < 0)
        return r;

    const uint64_t expiry = mm_monotonic_ms() + MEM_ACCESS_RESPONSE_TIMEOUT_MS;

    while (status == MEM_ACCESS_REQUEST_STARTED && mm_monotonic_ms() <= expiry) {
        if ((r = mm_usb_mem_read(dev, MM8108_REG_MEM_ACCESS_STATUS, buf, 4)) < 0)
            return r;
        status = mm_get_le32(buf);
    }

    switch (status) {
        case MEM_ACCESS_REQUEST_GRANTED:
        case MEM_ACCESS_REQUEST_GRANTED_BURST:
            dev->mem_cache_start = addr;
            dev->mem_cache_end = addr + (uint32_t) len;
            return 0;
        case MEM_ACCESS_REQUEST_STARTED:
            return mm_error(dev, -ETIMEDOUT, "memory access request for 0x%08x timed out", addr);
        case MEM_ACCESS_REQUEST_DENIED:
            return mm_error(dev, -EACCES, "memory access request for 0x%08x denied", addr);
        default:
            return mm_error(dev, -EIO, "unknown memory access response 0x%08x", status);
    }
}

int mm_dm_read(struct mm8108_dev *dev, uint32_t addr, uint8_t *buf, size_t len) {
    int r;

    if ((r = mm_mem_access_request(dev, addr, len)) < 0)
        return r;

    return mm_usb_mem_read(dev, addr, buf, len);
}

int mm_dm_write(struct mm8108_dev *dev, uint32_t addr, const uint8_t *buf, size_t len) {
    int r;

    if ((r = mm_mem_access_request(dev, addr, len)) < 0)
        return r;

    return mm_usb_mem_write(dev, addr, buf, len);
}

int mm_reg32_read(struct mm8108_dev *dev, uint32_t addr, uint32_t *val) {
    uint8_t buf[4];
    int r;

    if ((r = mm_dm_read(dev, addr, buf, sizeof(buf))) < 0)
        return r;

    *val = mm_get_le32(buf);
    return 0;
}

int mm_reg32_write(struct mm8108_dev *dev, uint32_t addr, uint32_t val) {
    uint8_t buf[4];

    mm_put_le32(buf, val);
    return mm_dm_write(dev, addr, buf, sizeof(buf));
}

const char *mm_chip_name(uint32_t chip_id) {
    switch (chip_id) {
        case MM8108_CHIP_ID_B0:
            return "MM8108B0";
        case MM8108_CHIP_ID_B1:
            return "MM8108B1";
        case MM8108_CHIP_ID_B2:
            return "MM8108B2";
        case MM8108_CHIP_ID_B3:
            return "MM8108B3";
        default:
            return "unknown";
    }
}

const char *mm_chip_rev_string(uint32_t chip_id) {
    switch (chip_id) {
        case MM8108_CHIP_ID_B0:
            return "b0";
        case MM8108_CHIP_ID_B1:
            return "b1";
        case MM8108_CHIP_ID_B2:
            return "b2";
        case MM8108_CHIP_ID_B3:
            return "b3";
        default:
            return NULL;
    }
}

int mm_read_chip_id(struct mm8108_dev *dev) {
    int r;

    if ((r = mm_reg32_read(dev, MM8108_REG_CHIP_ID, &dev->chip_id)) < 0)
        return mm_error(dev, r, "could not read chip ID");

    /* FPGA builds aren't supported */
    if (mm_chip_rev_string(dev->chip_id) == NULL)
        return mm_error(dev, -ENODEV, "unsupported chip ID 0x%08x", dev->chip_id);

    mm_log(dev, 1, "chip ID 0x%04x (%s)", dev->chip_id, mm_chip_name(dev->chip_id));

    return 0;
}

int mm_toggle_aon_latch(struct mm8108_dev *dev) {
    uint32_t latch;
    int r;

    if ((r = mm_reg32_read(dev, MM8108_REG_AON_LATCH, &latch)) < 0)
        return r;

    if ((r = mm_reg32_write(dev, MM8108_REG_AON_LATCH, latch & ~MM8108_REG_AON_LATCH_MASK)) < 0)
        return r;
    mm_sleep_us(5000);
    if ((r = mm_reg32_write(dev, MM8108_REG_AON_LATCH, latch | MM8108_REG_AON_LATCH_MASK)) < 0)
        return r;
    mm_sleep_us(5000);
    if ((r = mm_reg32_write(dev, MM8108_REG_AON_LATCH, latch & ~MM8108_REG_AON_LATCH_MASK)) < 0)
        return r;
    mm_sleep_us(5000);

    return 0;
}

/* Read-modify-write of the AON register clearing mask, then latch it */
static int mm_aon_clear_bits(struct mm8108_dev *dev, uint32_t mask) {
    uint32_t v;
    int r;

    if ((r = mm_reg32_read(dev, MM8108_REG_AON_LATCH, &v)) < 0)
        return r;

    if ((r = mm_reg32_write(dev, MM8108_REG_AON_LATCH, v & ~mask)) < 0)
        return r;

    return mm_toggle_aon_latch(dev);
}

int mm_digital_reset(struct mm8108_dev *dev) {
    int r;

    /* Both are handled by the chip when memory access is restricted */
    if (!mm_mem_restricted(dev)) {
        /* Enable the internal slow clock first; do not reorder */
        if ((r = mm_aon_clear_bits(dev, MM8108_REG_RC_CLK_POWER_OFF_MASK)) < 0)
            return mm_error(dev, r, "could not enable slow clock");
        mm_sleep_us(2000);

        /* Remove PMU control of the CPU before reset */
        if ((r = mm_aon_clear_bits(dev, MM8108_REG_AON_PMU_CTRL_MASK)) < 0)
            return mm_error(dev, r, "could not disable PMU control");
    }

    if ((r = mm_usb_ndr_reset(dev)) < 0)
        return mm_error(dev, r, "USB digital reset failed");

    /* The driver waits after every reset, including USB */
    mm_sleep_us(400 * 1000);

    dev->hw_on = false;
    mm_mem_access_reset_cache(dev);

    return 0;
}

static int mm_otp_read_bank(struct mm8108_dev *dev, uint8_t bank, uint32_t *val) {
    uint32_t auto_rd;
    int r, i;

    if ((r = mm_reg32_write(dev, MM8108_REG_OTPCTRL_PA, bank)) < 0)
        return r;
    /* Ignore ECC */
    if ((r = mm_reg32_write(dev, MM8108_REG_OTPCTRL_PECCRDB, 1)) < 0)
        return r;

    if ((r = mm_reg32_read(dev, MM8108_REG_OTPCTRL_AUTO_RD, &auto_rd)) < 0)
        return r;
    if ((r = mm_reg32_write(dev, MM8108_REG_OTPCTRL_AUTO_RD, (auto_rd & ~1u) | 1u)) < 0)
        return r;

    auto_rd = 1;
    for (i = 0; i < 5 && (auto_rd & 1); i++) {
        mm_sleep_us(20);
        if ((r = mm_reg32_read(dev, MM8108_REG_OTPCTRL_AUTO_RD, &auto_rd)) < 0)
            return r;
    }

    if (auto_rd & 1)
        return -EIO;

    return mm_reg32_read(dev, MM8108_REG_OTPCTRL_PDOUT, val);
}

static int mm_otp_read_direct(struct mm8108_dev *dev, uint32_t *board, uint32_t *country) {
    int r, r2;

    /* Power up and enable reads */
    if ((r = mm_reg32_write(dev, MM8108_REG_OTPCTRL_PENVDD2, 1)) < 0)
        return r;
    mm_sleep_us(2);
    if ((r = mm_reg32_write(dev, MM8108_REG_OTPCTRL_PLDO, 1)) < 0)
        return r;
    mm_sleep_us(20);
    if ((r = mm_reg32_write(dev, MM8108_REG_OTPCTRL_PDSTB, 1)) < 0)
        return r;
    mm_sleep_us(3);
    if ((r = mm_reg32_write(dev, MM8108_REG_OTPCTRL_PTM, 0)) < 0)
        return r;
    if ((r = mm_reg32_write(dev, MM8108_REG_OTPCTRL_PCE, 1)) < 0)
        return r;
    mm_sleep_us(20);

    r = mm_otp_read_bank(dev, MM8108_OTP_BANK_BOARD_TYPE, board);
    if (r == 0)
        r = mm_otp_read_bank(dev, MM8108_OTP_BANK_COUNTRY, country);

    /* Always power back down */
    r2 = mm_reg32_write(dev, MM8108_REG_OTPCTRL_PCE, 0);
    mm_sleep_us(1);
    if (r2 == 0)
        r2 = mm_reg32_write(dev, MM8108_REG_OTPCTRL_PDSTB, 0);
    if (r2 == 0)
        r2 = mm_reg32_write(dev, MM8108_REG_OTPCTRL_PLDO, 0);
    if (r2 == 0)
        r2 = mm_reg32_write(dev, MM8108_REG_OTPCTRL_PENVDD2, 0);

    return r < 0 ? r : r2;
}

/* Board type selects the BCF; the country, if programmed, locks the regulatory domain */
int mm_read_otp(struct mm8108_dev *dev) {
    uint32_t board = 0, country = 0;
    int r;

    if (mm_mem_restricted(dev)) {
        if ((r = mm_reg32_read(dev, MM8108_OTP_CONFIG_BOARD_TYPE, &board)) == 0)
            r = mm_reg32_read(dev, MM8108_OTP_CONFIG_COUNTRY, &country);
    } else {
        r = mm_otp_read_direct(dev, &board, &country);
    }

    if (r < 0)
        return mm_error(dev, r, "could not read OTP");

    dev->board_type = board & 0xFFFF;

    const char c0 = (char) (country & 0xFF);
    const char c1 = (char) ((country >> 8) & 0xFF);

    if (c0 >= 0x20 && c0 <= 0x7E && c1 >= 0x20 && c1 <= 0x7E) {
        dev->otp_country[0] = c0;
        dev->otp_country[1] = c1;
        dev->otp_country[2] = 0;
    } else {
        dev->otp_country[0] = 0;
    }

    mm_log(dev, 1, "board type 0x%04x, OTP country %s", dev->board_type,
            dev->otp_country[0] ? dev->otp_country : "(none)");

    return 0;
}

int mm_irq_enable(struct mm8108_dev *dev, uint32_t mask) {
    uint32_t en;
    int r;

    if ((r = mm_reg32_read(dev, MM8108_REG_INT1_EN, &en)) < 0)
        return r;

    if ((r = mm_reg32_write(dev, MM8108_REG_INT1_CLR, mask)) < 0)
        return r;

    return mm_reg32_write(dev, MM8108_REG_INT1_EN, en | mask);
}
