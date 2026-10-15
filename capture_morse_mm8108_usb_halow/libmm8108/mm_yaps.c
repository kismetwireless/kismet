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

/* YAPS host transport, from morse_driver yaps.c, yaps_hw.c and skbq.c.
 *
 * Packets to the chip are written to the YDS window and packets from the chip are read
 * from the YSL window, each prefixed by a 32-bit delimiter:
 *   size (14 bits) | pool (3) | padding (2) | irq (1) | reserved (5) | crc7 (7)
 * Reading the YSL window consumes the data; there is no acknowledgement.
 */

#include <errno.h>
#include <stdlib.h>

#include "mm8108.h"
#include "mm_util.h"

#define YAPS_TABLE_LEN          36
#define YAPS_STATUS_TIMEOUT_MS  100
/* Pages for metadata, plus one for a chip page-handle corruption workaround */
#define YAPS_EXTRA_PAGES        2

/* Payload length covered by the checksum on data frames */
#define MM_CSUM_DATA_LEN        (MM_SKB_HDR_LEN + 32 + 8)

#define DELIM_SIZE(d)           ((d) & 0x3FFF)
#define DELIM_POOL(d)           (((d) >> 14) & 0x7)
#define DELIM_PAD(d)            (((d) >> 17) & 0x3)
#define DELIM_CRC(d)            (((d) >> 25) & 0x7F)

/* CRC-7 (poly 0x09), MSB first, over the 25 non-CRC bits; matches Linux crc7_be */
uint8_t mm_yaps_crc7(uint32_t word) {
    uint8_t crc = 0;

    word &= 0x1FFFFFF;

    for (int i = 0; i < 4; i++) {
        crc ^= (uint8_t) (word >> 24);
        for (int b = 0; b < 8; b++)
            crc = (crc & 0x80) ? (uint8_t) ((crc << 1) ^ 0x12) : (uint8_t) (crc << 1);
        word <<= 8;
    }

    return crc >> 1;
}

static uint32_t mm_yaps_delimiter(const struct mm8108_dev *dev, size_t size, uint8_t pool, bool irq) {
    uint32_t d = 0;

    d |= (uint32_t) ((size + dev->yaps.reserved_page_size) & 0x3FFF);
    d |= (uint32_t) (MM_PAD4(size) & 0x3) << 17;
    d |= (uint32_t) (pool & 0x7) << 14;
    d |= (uint32_t) (irq ? 1 : 0) << 19;
    d |= (uint32_t) mm_yaps_crc7(d) << 25;

    return d;
}

static bool mm_yaps_delimiter_valid(uint32_t d) {
    const uint32_t size = DELIM_SIZE(d);

    if (mm_yaps_crc7(d) != DELIM_CRC(d))
        return false;

    if (size == 0 || size + DELIM_PAD(d) > MM_YAPS_MAX_PKT_SIZE)
        return false;

    return MM_PAD4(size) == DELIM_PAD(d);
}

int mm_yaps_parse_table(struct mm8108_dev *dev, const uint8_t *tbl, size_t len) {
    struct mm_yaps *y = &dev->yaps;

    if (len < YAPS_TABLE_LEN)
        return mm_error(dev, -EINVAL, "YAPS table is too short (%zu)", len);

    y->ysl_addr = mm_get_le32(tbl + 4);
    y->yds_addr = mm_get_le32(tbl + 8);
    y->status_regs_addr = mm_get_le32(tbl + 12);
    y->tc_cmd_q_size = tbl[27];
    y->reserved_page_size = mm_get_le16(tbl + 32);

    /* RX sizes subtract the reserved size from a word-padded size */
    if (y->reserved_page_size % 4 != 0 || y->reserved_page_size >= MM_YAPS_MAX_PKT_SIZE)
        return mm_error(dev, -EINVAL, "unsupported YAPS reserved page size %u",
                y->reserved_page_size);

    y->valid = true;

    mm_log(dev, 2, "YAPS ysl 0x%08x yds 0x%08x status 0x%08x cmd q %u reserved %u",
            y->ysl_addr, y->yds_addr, y->status_regs_addr, y->tc_cmd_q_size,
            y->reserved_page_size);

    return 0;
}

int mm_yaps_update_status(struct mm8108_dev *dev) {
    uint8_t buf[MM_YAPS_STATUS_LEN];
    uint32_t v[MM_YAPS_STATUS_LEN / 4];
    struct mm_yaps_status *s = &dev->yaps.status;
    const uint64_t expiry = mm_monotonic_ms() + YAPS_STATUS_TIMEOUT_MS;
    int r;

    /* The chip sets lock while it updates the block */
    do {
        if (mm_monotonic_ms() > expiry)
            return mm_error(dev, -ETIMEDOUT, "timed out reading YAPS status");

        if ((r = mm_dm_read(dev, dev->yaps.status_regs_addr, buf, sizeof(buf))) < 0)
            return r;
    } while (mm_get_le32(buf + 17 * 4) != 0);

    for (size_t i = 0; i < MM_YAPS_STATUS_LEN / 4; i++)
        v[i] = mm_get_le32(buf + i * 4);

    s->tc_tx_pool_num_pages = v[0];
    s->tc_cmd_pool_num_pages = v[1];
    s->tc_beacon_pool_num_pages = v[2];
    s->tc_mgmt_pool_num_pages = v[3];
    s->fc_rx_pool_num_pages = v[4];
    s->fc_resp_pool_num_pages = v[5];
    s->fc_tx_sts_pool_num_pages = v[6];
    s->fc_aux_pool_num_pages = v[7];
    s->tc_tx_num_pkts = v[8];
    s->tc_cmd_num_pkts = v[9];
    s->tc_beacon_num_pkts = v[10];
    s->tc_mgmt_num_pkts = v[11];
    s->fc_num_pkts = v[12];
    s->fc_done_num_pkts = v[13];
    s->fc_rx_bytes_in_queue = v[14];
    s->tc_delim_crc_fail_detected = v[15];
    s->scratch_0 = v[16];
    s->lock = v[17];

    /* Host and chip are out of sync; not recoverable without a reset */
    if (s->tc_delim_crc_fail_detected)
        return mm_error(dev, -EIO, "chip reported a YAPS delimiter CRC failure");

    return 0;
}

/* pkt is a complete skb header + command, already padded to a word */
int mm_yaps_write_cmd(struct mm8108_dev *dev, const uint8_t *pkt, size_t len) {
    const struct mm_yaps_status *s = &dev->yaps.status;
    const size_t pages = (len + dev->yaps.reserved_page_size + MM_YAPS_PAGE_SIZE - 1) /
        MM_YAPS_PAGE_SIZE + YAPS_EXTRA_PAGES;
    int r;

    if (len % 4 != 0 || len + 4 > MM_YAPS_WINDOW_SIZE ||
            len + dev->yaps.reserved_page_size > MM_YAPS_MAX_PKT_SIZE)
        return -EMSGSIZE;

    if ((r = mm_yaps_update_status(dev)) < 0)
        return r;

    if (pages > s->tc_cmd_pool_num_pages || s->tc_cmd_num_pkts >= dev->yaps.tc_cmd_q_size)
        return -EAGAIN;

    mm_put_le32(dev->tx_buf, mm_yaps_delimiter(dev, len, MM_YAPS_TC_CMD, true));
    memcpy(dev->tx_buf + 4, pkt, len);

    return mm_dm_write(dev, dev->yaps.yds_addr, dev->tx_buf, len + 4);
}

static bool mm_is_csum_data_frame(const uint8_t *frame, size_t len) {
    uint16_t fc;

    if (len < 2)
        return false;

    fc = mm_get_le16(frame);

    /* PV0 data, or PV1 QoS data */
    if ((fc & 0x000C) == 0x0008)
        return true;

    return (fc & 0x0003) == 1 && ((fc & 0x001C) == 0x0000 || (fc & 0x001C) == 0x000C);
}

/* XOR of the words of the header and payload, with the checksum fields zeroed */
static bool mm_skb_checksum_valid(const uint8_t *pkt, size_t pkt_len) {
    const uint32_t expected = ((uint32_t) mm_get_le16(pkt + 6) << 8) | pkt[5];
    const uint8_t channel = pkt[1];
    size_t len = (size_t) mm_get_le16(pkt + 2) + MM_SKB_HDR_LEN;
    uint32_t x = 0;

    if (channel == MM_SKB_CHAN_DATA && mm_is_csum_data_frame(pkt + MM_SKB_HDR_LEN + pkt[4],
                pkt_len - MM_SKB_HDR_LEN - pkt[4])) {
        if (len > MM_CSUM_DATA_LEN)
            len = MM_CSUM_DATA_LEN;
        len &= ~((size_t) 3);
    }

    /* The driver sums whole words, which may run into the YAPS padding that follows */
    if (MM_ROUND_UP4(len) > MM_ROUND_UP4(pkt_len))
        return false;

    for (size_t i = 0; i < len; i += 4) {
        uint32_t w = mm_get_le32(pkt + i);

        /* Checksum bytes 5..7 are treated as zero */
        if (i == 4)
            w &= 0x000000FF;

        x ^= w;
    }

    return (x & 0x00FFFFFF) == expected;
}

static void mm_rx_status_parse(const uint8_t *pkt, struct mm_rx_status *st) {
    st->channel = pkt[1];
    st->flags = mm_get_le32(pkt + 8);
    st->ratecode = mm_get_le32(pkt + 12);
    st->rssi = (int8_t) mm_get_le16(pkt + 16);
    st->freq_khz = (uint32_t) mm_get_le16(pkt + 18) * 100;
    st->bss_color = pkt[20];
    st->noise = (int8_t) pkt[21];
    st->channel_info = pkt[22];
    st->timestamp_us = mm_get_le64(pkt + 24);
}

/* pkt_len is the delimiter size less padding and reserved bytes */
static void mm_yaps_dispatch(struct mm8108_dev *dev, const uint8_t *pkt, size_t pkt_len) {
    struct mm_rx_status st;
    size_t payload_off, payload_len;

    if (pkt_len < MM_SKB_HDR_LEN || pkt[0] != MM_SKB_HDR_SYNC) {
        dev->rx_errors++;
        mm_log(dev, 2, "dropping YAPS packet with a bad header");
        return;
    }

    payload_off = MM_SKB_HDR_LEN + pkt[4];
    payload_len = mm_get_le16(pkt + 2);

    if (payload_off > pkt_len || payload_len > pkt_len - payload_off) {
        dev->rx_errors++;
        mm_log(dev, 2, "dropping YAPS packet with length %zu beyond %zu", payload_len, pkt_len);
        return;
    }

    if (dev->validate_checksum && !mm_skb_checksum_valid(pkt, pkt_len) &&
            pkt[1] != MM_SKB_CHAN_TX_STATUS) {
        dev->rx_errors++;
        mm_log(dev, 2, "dropping YAPS packet with a bad checksum");
        return;
    }

    switch (pkt[1]) {
        case MM_SKB_CHAN_COMMAND:
            mm_cmd_handle_packet(dev, pkt + payload_off, payload_len);
            break;

        case MM_SKB_CHAN_DATA:
        case MM_SKB_CHAN_NDP_FRAMES:
        case MM_SKB_CHAN_DATA_NOACK:
        case MM_SKB_CHAN_BEACON:
        case MM_SKB_CHAN_MGMT:
            if (dev->rx_cb != NULL) {
                mm_rx_status_parse(pkt, &st);
                dev->rx_cb(dev->rx_ctx, &st, pkt + payload_off, payload_len);
            }
            break;

        case MM_SKB_CHAN_TX_STATUS:
        case MM_SKB_CHAN_LOOPBACK:
        case MM_SKB_CHAN_WIPHY:
            break;

        default:
            dev->rx_errors++;
            mm_log(dev, 2, "dropping YAPS packet on unknown channel 0x%02x", pkt[1]);
            break;
    }
}

int mm_yaps_read(struct mm8108_dev *dev) {
    const struct mm_yaps *y = &dev->yaps;
    size_t remaining = y->status.fc_rx_bytes_in_queue;
    size_t off = 0;
    int count = 0;
    int r;

    if (remaining == 0)
        return 0;

    if (remaining > MM_YAPS_WINDOW_SIZE)
        remaining = MM_YAPS_WINDOW_SIZE;

    if ((r = mm_dm_read(dev, y->ysl_addr, dev->rx_buf, MM_ROUND_UP4(remaining))) < 0)
        return r;

    while (remaining >= 4) {
        const uint32_t d = mm_get_le32(dev->rx_buf + off);
        size_t total, size;

        off += 4;
        remaining -= 4;

        /* End of stream */
        if (d == 0)
            break;

        if (!mm_yaps_delimiter_valid(d)) {
            dev->rx_errors++;
            mm_log(dev, 1, "invalid YAPS delimiter 0x%08x, discarding %zu bytes", d, remaining);
            break;
        }

        if (DELIM_SIZE(d) < y->reserved_page_size) {
            dev->rx_errors++;
            break;
        }

        size = DELIM_SIZE(d) - y->reserved_page_size;
        total = size + DELIM_PAD(d);

        if (total <= remaining) {
            mm_yaps_dispatch(dev, dev->rx_buf + off, size);
            off += total;
            remaining -= total;
        } else {
            /* The packet runs past the window; fetch the rest.  The read is offset by 4
             * so the chip doesn't treat it as a retry of the first read. */
            const size_t overhang = total - remaining;

            memmove(dev->rx_buf, dev->rx_buf + off, remaining);

            if ((r = mm_dm_read(dev, y->ysl_addr + 4, dev->rx_buf + remaining,
                            MM_ROUND_UP4(overhang))) < 0)
                return r;

            mm_yaps_dispatch(dev, dev->rx_buf, size);
            remaining = 0;
        }

        count++;
    }

    return count;
}
