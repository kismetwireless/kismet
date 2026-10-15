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

#ifndef __MM8108_H__
#define __MM8108_H__

/* Userspace driver for the Morse Micro MM8108 802.11ah (Wi-Fi HaLow) USB chipset.
 *
 * Ported from the Morse Micro Linux driver (https://github.com/MorseMicro/morse_driver,
 * GPL-2.0), reduced to what is needed to boot the chip and capture in monitor mode.
 *
 * The chip is driven entirely through reads and writes of chip memory over two bulk
 * endpoints; frames and commands move through the YAPS stream windows in chip memory.
 *
 * Firmware and board configuration (BCF) files are not included; they are distributed
 * by Morse Micro under their own license at https://github.com/MorseMicro/morse-firmware
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <libusb.h>

#define MM8108_USB_VID 0x325b
#define MM8108_USB_PID 0x8100

/* Chip IDs; chip | rev << 8 | type << 12 */
#define MM8108_CHIP_ID_B0 0x0609
#define MM8108_CHIP_ID_B1 0x0709
#define MM8108_CHIP_ID_B2 0x0809
#define MM8108_CHIP_ID_B3 0x0909

/* Registers */
#define MM8108_REG_CHIP_ID              0x00002d20
#define MM8108_REG_MANIFEST_PTR         0x00002d40
#define MM8108_REG_APPS_BOOT_ADDR       0x00002084
#define MM8108_REG_AON                  0x00002114
#define MM8108_REG_AON_COUNT            2
#define MM8108_REG_AON_RESET_USB_VALUE  0x8
#define MM8108_REG_AON_LATCH            0x00405020
#define MM8108_REG_AON_LATCH_MASK       0x1
#define MM8108_REG_AON_PMU_CTRL_MASK    0x80
#define MM8108_REG_RC_CLK_POWER_OFF_MASK 0x40
#define MM8108_REG_MSI                  0x00004100
#define MM8108_REG_RESET                0x000020AC
#define MM8108_REG_TRGR_BASE            0x00003c00
#define MM8108_REG_TRGR_END             0x00003c6c
#define MM8108_REG_TRGR2_SET            (MM8108_REG_TRGR_BASE + 0x14)
#define MM8108_REG_INT1_STS             0x00003c50
#define MM8108_REG_INT1_CLR             0x00003c58
#define MM8108_REG_INT1_EN              0x00003c5c
#define MM8108_REG_INT2_CLR             0x00003c68
#define MM8108_REG_MEM_ACCESS_BASE      0x00003c20
#define MM8108_REG_MEM_ACCESS_ADDR      (MM8108_REG_MEM_ACCESS_BASE + 0x00)
#define MM8108_REG_MEM_ACCESS_SIZE      (MM8108_REG_MEM_ACCESS_BASE + 0x0C)
#define MM8108_REG_MEM_ACCESS_STATUS    (MM8108_REG_MEM_ACCESS_BASE + 0x18)
#define MM8108_REG_MEM_ACCESS_STATE     (MM8108_REG_MEM_ACCESS_BASE + 0x24)
#define MM8108_REG_SECURE_BOOT_STATUS   0x0011fff8
#define MM8108_REG_SECURITY_MANIFEST_PTR 0x0011fffc

/* OTP */
#define MM8108_REG_OTPCTRL_PENVDD2      0x00004010
#define MM8108_REG_OTPCTRL_PLDO         0x00004014
#define MM8108_REG_OTPCTRL_PDSTB        0x00004018
#define MM8108_REG_OTPCTRL_PTM          0x0000401c
#define MM8108_REG_OTPCTRL_PCE          0x00004020
#define MM8108_REG_OTPCTRL_PA           0x00004034
#define MM8108_REG_OTPCTRL_PDOUT        0x00004040
#define MM8108_REG_OTPCTRL_PECCRDB      0x00004048
#define MM8108_REG_OTPCTRL_AUTO_RD      0x0000400c
#define MM8108_OTP_CONFIG_BASE          (0x2AC000 - 44)
#define MM8108_OTP_CONFIG_COUNTRY       (MM8108_OTP_CONFIG_BASE + 16)
#define MM8108_OTP_CONFIG_BOARD_TYPE    (MM8108_OTP_CONFIG_BASE + 20)
#define MM8108_OTP_BANK_COUNTRY         25
#define MM8108_OTP_BANK_BOARD_TYPE      26

#define MM8108_HOST_MAGIC               0xDEADBEEF
#define MM8108_FW_SEMVER_MAJOR          57
#define MM8108_FW_SEMVER_MINOR          13

#define MM8108_INT_YAPS_PKT_WAITING     (1u << 0)
#define MM8108_INT_YAPS_PKT_FREED       (1u << 1)

/* Firmware flags in the host table */
#define MM8108_FW_FLAG_FAILSAFE         (1u << 11)

/* YAPS */
#define MM_YAPS_WINDOW_SIZE             32768
#define MM_YAPS_MAX_PKT_SIZE            16128
#define MM_YAPS_PAGE_SIZE               256

enum mm_yaps_pool {
    MM_YAPS_TC_TX = 0,
    MM_YAPS_TC_CMD = 1,
    MM_YAPS_TC_BEACON = 2,
    MM_YAPS_TC_MGMT = 3,
    MM_YAPS_FC_RX = 4,
    MM_YAPS_FC_CMD_RESP = 5,
    MM_YAPS_FC_TX_STATUS = 6,
    MM_YAPS_FC_AUX = 7,
};

struct mm_yaps_status {
    uint32_t tc_tx_pool_num_pages;
    uint32_t tc_cmd_pool_num_pages;
    uint32_t tc_beacon_pool_num_pages;
    uint32_t tc_mgmt_pool_num_pages;
    uint32_t fc_rx_pool_num_pages;
    uint32_t fc_resp_pool_num_pages;
    uint32_t fc_tx_sts_pool_num_pages;
    uint32_t fc_aux_pool_num_pages;
    uint32_t tc_tx_num_pkts;
    uint32_t tc_cmd_num_pkts;
    uint32_t tc_beacon_num_pkts;
    uint32_t tc_mgmt_num_pkts;
    uint32_t fc_num_pkts;
    uint32_t fc_done_num_pkts;
    uint32_t fc_rx_bytes_in_queue;
    uint32_t tc_delim_crc_fail_detected;
    uint32_t scratch_0;
    uint32_t lock;
};

#define MM_YAPS_STATUS_LEN (18 * 4)

struct mm_yaps {
    bool valid;
    uint32_t ysl_addr;
    uint32_t yds_addr;
    uint32_t status_regs_addr;
    uint8_t tc_cmd_q_size;
    uint16_t reserved_page_size;
    struct mm_yaps_status status;
};

/* Per-frame header on everything moving through YAPS */
#define MM_SKB_HDR_LEN          40
#define MM_SKB_HDR_SYNC         0xAA

#define MM_SKB_CHAN_DATA        0x00
#define MM_SKB_CHAN_NDP_FRAMES  0x01
#define MM_SKB_CHAN_DATA_NOACK  0x02
#define MM_SKB_CHAN_BEACON      0x03
#define MM_SKB_CHAN_MGMT        0x04
#define MM_SKB_CHAN_WIPHY       0x05
#define MM_SKB_CHAN_LOOPBACK    0xEE
#define MM_SKB_CHAN_COMMAND     0xFE
#define MM_SKB_CHAN_TX_STATUS   0xFF

#define MM_RX_FLAG_ERROR        (1u << 0)
#define MM_RX_FLAG_DECRYPTED    (1u << 1)
#define MM_RX_FLAG_FCS_INCLUDED (1u << 2)
#define MM_RX_FLAG_EOF          (1u << 3)
#define MM_RX_FLAG_AMPDU        (1u << 4)
#define MM_RX_FLAG_NDP          (1u << 7)
#define MM_RX_FLAG_UPLINK       (1u << 8)
#define MM_RX_FLAG_CRC_ERROR    (1u << 14)
#define MM_RX_FLAG_RI(f)        (((f) >> 9) & 0x3)

/* Rate code fields */
#define MM_RATECODE_PREAMBLE(r) ((r) & 0xF)
#define MM_RATECODE_MCS(r)      (((r) >> 4) & 0xF)
#define MM_RATECODE_NSS(r)      ((((r) >> 8) & 0x7) + 1)
#define MM_RATECODE_BW_IDX(r)   (((r) >> 11) & 0x7)
#define MM_RATECODE_SGI(r)      (((r) >> 18) & 0x1)

#define MM_PREAMBLE_S1G_LONG    0
#define MM_PREAMBLE_S1G_SHORT   1
#define MM_PREAMBLE_S1G_1M      2

struct mm_rx_status {
    uint8_t channel;
    uint32_t flags;
    uint32_t ratecode;
    int8_t rssi;
    int8_t noise;
    uint32_t freq_khz;
    uint8_t bss_color;
    uint8_t channel_info;
    uint64_t timestamp_us;
};

/* Commands */
#define MM_CMD_HDR_LEN          12
#define MM_CMD_FLAG_REQ         (1u << 0)
#define MM_CMD_FLAG_RESP        (1u << 1)
#define MM_CMD_FLAG_EVT         (1u << 2)

#define MM_CMD_SET_CHANNEL      0x0001
#define MM_CMD_GET_VERSION      0x0002
#define MM_CMD_ADD_INTERFACE    0x0004
#define MM_CMD_REMOVE_INTERFACE 0x0005
#define MM_CMD_HEALTH_CHECK     0x0019
#define MM_CMD_GET_CHANNEL      0x001D
#define MM_CMD_GET_DISABLED_CHANNELS 0x004A

#define MM_INTERFACE_TYPE_MON   3

#define MM_CMD_TIMEOUT_MS       600
#define MM_CMD_TRIES            2

typedef void (*mm_rx_cb_t)(void *ctx, const struct mm_rx_status *status,
        const uint8_t *frame, size_t frame_len);

struct mm8108_dev {
    libusb_context *ctx;
    libusb_device_handle *handle;
    int interface;
    uint8_t ep_in;
    uint8_t ep_out;
    uint8_t ep_int;
    bool kernel_driver_detached;

    /* Interrupt endpoint transfer; each completion means the chip raised an interrupt */
    struct libusb_transfer *int_xfer;
    uint8_t int_buf[8];
    bool int_active;
    int int_error;
    /* Set by the transfer callback; an int so libusb can wait on it */
    int irq_pending;

    int verbose;

    uint32_t chip_id;
    uint16_t board_type;
    char otp_country[3];

    /* Memory access restriction state */
    bool hw_on;
    bool mem_restricted;
    bool mem_overridden;
    uint32_t mem_cache_start;
    uint32_t mem_cache_end;

    /* From the firmware image */
    uint32_t bcf_addr;
    uint32_t bcf_size;

    /* From the running firmware */
    uint32_t host_table_ptr;
    uint32_t fw_version;
    uint32_t fw_flags;
    uint8_t mac[6];
    bool validate_checksum;
    struct mm_yaps yaps;

    uint16_t cmd_seq;
    /* The single outstanding command */
    bool cmd_waiting;
    bool cmd_done;
    uint16_t cmd_wait_id;
    uint16_t cmd_wait_host_id;
    uint8_t cmd_resp[512];
    size_t cmd_resp_len;

    bool mon_added;
    uint16_t mon_vif_id;

    mm_rx_cb_t rx_cb;
    void *rx_ctx;

    /* Packets which failed validation */
    uint64_t rx_errors;

    /* Interrupts seen, and checks after a quiet period which found data anyway */
    uint64_t irq_count;
    uint64_t missed_irq_count;
    uint64_t last_service_ms;
    /* The last read may have left data queued */
    bool rx_more;

    /* Shared transfer buffers; sized for a full YAPS window */
    uint8_t *rx_buf;
    uint8_t *tx_buf;

    char errstr[256];
};

struct mm8108_boot_config {
    const char *firmware_path;
    const char *bcf_path;
    /* Two-letter regulatory section to load from the BCF */
    const char *country;
};

/* Logging */
void mm_log(const struct mm8108_dev *dev, int level, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
int mm_error(struct mm8108_dev *dev, int err, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));

/* USB transport (mm_usb.c) */
int mm_usb_open(struct mm8108_dev *dev, int bus, int address);
void mm_usb_close(struct mm8108_dev *dev);
int mm_usb_mem_read(struct mm8108_dev *dev, uint32_t addr, uint8_t *buf, size_t len);
int mm_usb_mem_write(struct mm8108_dev *dev, uint32_t addr, const uint8_t *buf, size_t len);
int mm_usb_ndr_reset(struct mm8108_dev *dev);
int mm_usb_int_start(struct mm8108_dev *dev);
void mm_usb_int_stop(struct mm8108_dev *dev);
/* Waits up to timeout_ms for an interrupt; returns 1 if one is pending, 0 on timeout */
int mm_usb_int_wait(struct mm8108_dev *dev, unsigned int timeout_ms);

/* Chip access (mm_hw.c) */
int mm_reg32_read(struct mm8108_dev *dev, uint32_t addr, uint32_t *val);
int mm_reg32_write(struct mm8108_dev *dev, uint32_t addr, uint32_t val);
int mm_dm_read(struct mm8108_dev *dev, uint32_t addr, uint8_t *buf, size_t len);
int mm_dm_write(struct mm8108_dev *dev, uint32_t addr, const uint8_t *buf, size_t len);
bool mm_mem_restricted(struct mm8108_dev *dev);
void mm_mem_access_reset_cache(struct mm8108_dev *dev);
int mm_read_chip_id(struct mm8108_dev *dev);
const char *mm_chip_name(uint32_t chip_id);
const char *mm_chip_rev_string(uint32_t chip_id);
int mm_read_otp(struct mm8108_dev *dev);
int mm_digital_reset(struct mm8108_dev *dev);
int mm_toggle_aon_latch(struct mm8108_dev *dev);
int mm_irq_enable(struct mm8108_dev *dev, uint32_t mask);

/* Firmware and boot (mm_fw.c) */
int mm_boot(struct mm8108_dev *dev, const struct mm8108_boot_config *cfg);

/* YAPS (mm_yaps.c) */
int mm_yaps_parse_table(struct mm8108_dev *dev, const uint8_t *tbl, size_t len);
int mm_yaps_update_status(struct mm8108_dev *dev);
int mm_yaps_write_cmd(struct mm8108_dev *dev, const uint8_t *pkt, size_t len);
/* Reads and dispatches pending packets; returns the number handled or a negative error */
int mm_yaps_read(struct mm8108_dev *dev);
uint8_t mm_yaps_crc7(uint32_t word);

/* Commands (mm_cmd.c) */
int mm_cmd_send(struct mm8108_dev *dev, uint16_t msg_id, uint16_t vif_id,
        const uint8_t *body, size_t body_len, uint8_t *resp, size_t resp_max,
        size_t *resp_len);
void mm_cmd_handle_packet(struct mm8108_dev *dev, const uint8_t *data, size_t len);
int mm_cmd_get_version(struct mm8108_dev *dev, char *version, size_t version_len);
int mm_cmd_add_monitor(struct mm8108_dev *dev);
int mm_cmd_remove_monitor(struct mm8108_dev *dev);
int mm_cmd_set_channel(struct mm8108_dev *dev, uint32_t freq_khz, uint8_t op_bw_mhz,
        uint8_t pri_bw_mhz, uint8_t pri_1mhz_idx);
int mm_cmd_health_check(struct mm8108_dev *dev);

/* A bw_mhz of 0 means every width at that frequency is disabled */
struct mm_disabled_channel {
    uint32_t freq_khz;
    uint8_t bw_mhz;
};

int mm_cmd_get_disabled_channels(struct mm8108_dev *dev, struct mm_disabled_channel *out,
        size_t max, size_t *num);

/* Device lifecycle (mm8108.c) */
int mm8108_init(struct mm8108_dev *dev, int verbose);
void mm8108_free(struct mm8108_dev *dev);
void mm8108_set_rx_cb(struct mm8108_dev *dev, mm_rx_cb_t cb, void *ctx);
/* Services the chip for up to timeout_ms; returns packets handled or a negative error */
int mm8108_poll(struct mm8108_dev *dev, unsigned int timeout_ms);
int mm8108_start_monitor(struct mm8108_dev *dev);
void mm8108_stop(struct mm8108_dev *dev);

#endif
