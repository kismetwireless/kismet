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

/* Firmware commands, from morse_driver command.c and morse_commands.h.
 *
 * A command is a 12-byte header (flags, message id, body length, host id, vif id, pad;
 * all le16) and a body, sent on the command channel.  Responses add a le32 status after
 * the header and are matched on the message id and the sequence part of the host id.
 */

#include <errno.h>

#include "mm8108.h"
#include "mm_util.h"

#define MM_CMD_MAX_BODY         256
#define MM_CMD_SEQ_MASK         0xFFF0

static void mm_cmd_put_header(uint8_t *p, uint16_t flags, uint16_t msg_id, uint16_t len,
        uint16_t host_id, uint16_t vif_id) {
    mm_put_le16(p, flags);
    mm_put_le16(p + 2, msg_id);
    mm_put_le16(p + 4, len);
    mm_put_le16(p + 6, host_id);
    mm_put_le16(p + 8, vif_id);
    mm_put_le16(p + 10, 0);
}

void mm_cmd_handle_packet(struct mm8108_dev *dev, const uint8_t *data, size_t len) {
    uint16_t flags, msg_id, host_id;

    if (len < MM_CMD_HDR_LEN) {
        dev->rx_errors++;
        return;
    }

    flags = mm_get_le16(data);
    msg_id = mm_get_le16(data + 2);
    host_id = mm_get_le16(data + 6);

    if (flags & MM_CMD_FLAG_RESP) {
        if (!dev->cmd_waiting || dev->cmd_done || msg_id != dev->cmd_wait_id ||
                (host_id & MM_CMD_SEQ_MASK) != (dev->cmd_wait_host_id & MM_CMD_SEQ_MASK)) {
            mm_log(dev, 2, "ignoring late response 0x%04x:%04x", msg_id, host_id);
            return;
        }

        dev->cmd_resp_len = len < sizeof(dev->cmd_resp) ? len : sizeof(dev->cmd_resp);
        memcpy(dev->cmd_resp, data, dev->cmd_resp_len);
        dev->cmd_done = true;
    } else if (flags & MM_CMD_FLAG_EVT) {
        mm_log(dev, 2, "firmware event 0x%04x (%zu bytes)", msg_id, len);
    }
}

/* Services the chip until the response arrives; received frames are delivered meanwhile */
static int mm_cmd_wait(struct mm8108_dev *dev, unsigned int timeout_ms) {
    const uint64_t expiry = mm_monotonic_ms() + timeout_ms;
    int r;

    while (!dev->cmd_done) {
        if (mm_monotonic_ms() > expiry)
            return -ETIMEDOUT;

        if ((r = mm8108_poll(dev, 1)) < 0)
            return r;
    }

    return 0;
}

/* Returns the firmware status, which is 0 on success and negative on failure */
int mm_cmd_send(struct mm8108_dev *dev, uint16_t msg_id, uint16_t vif_id,
        const uint8_t *body, size_t body_len, uint8_t *resp, size_t resp_max,
        size_t *resp_len) {
    uint8_t pkt[MM_SKB_HDR_LEN + MM_CMD_HDR_LEN + MM_CMD_MAX_BODY + 4];
    const size_t cmd_len = MM_CMD_HDR_LEN + body_len;
    const size_t pkt_len = MM_ROUND_UP4(MM_SKB_HDR_LEN + cmd_len);
    int r = -ETIMEDOUT;

    if (body_len > MM_CMD_MAX_BODY)
        return -EMSGSIZE;

    if (!dev->yaps.valid)
        return -ENODEV;

    /* Sequence numbers run 1..0xFFF */
    if (++dev->cmd_seq > 0xFFF)
        dev->cmd_seq = 1;

    for (int retry = 0; retry < MM_CMD_TRIES && r == -ETIMEDOUT; retry++) {
        const uint16_t host_id = (uint16_t) ((dev->cmd_seq << 4) | retry);
        const uint64_t expiry = mm_monotonic_ms() + MM_CMD_TIMEOUT_MS;

        memset(pkt, 0, sizeof(pkt));
        pkt[0] = MM_SKB_HDR_SYNC;
        pkt[1] = MM_SKB_CHAN_COMMAND;
        mm_put_le16(pkt + 2, (uint16_t) cmd_len);
        mm_cmd_put_header(pkt + MM_SKB_HDR_LEN, MM_CMD_FLAG_REQ, msg_id, (uint16_t) body_len,
                host_id, vif_id);
        if (body_len)
            memcpy(pkt + MM_SKB_HDR_LEN + MM_CMD_HDR_LEN, body, body_len);

        dev->cmd_waiting = true;
        dev->cmd_done = false;
        dev->cmd_wait_id = msg_id;
        dev->cmd_wait_host_id = host_id;

        /* Wait for room in the command queue */
        while ((r = mm_yaps_write_cmd(dev, pkt, pkt_len)) == -EAGAIN) {
            if (mm_monotonic_ms() > expiry) {
                r = -ETIMEDOUT;
                break;
            }
            if ((r = mm8108_poll(dev, 1)) < 0)
                break;
        }

        if (r < 0)
            break;

        r = mm_cmd_wait(dev, MM_CMD_TIMEOUT_MS);

        if (r == -ETIMEDOUT)
            mm_log(dev, 1, "command 0x%04x timed out (try %d)", msg_id, retry + 1);
    }

    dev->cmd_waiting = false;

    if (r < 0)
        return mm_error(dev, r, "command 0x%04x failed: %d", msg_id, r);

    if (dev->cmd_resp_len < MM_CMD_HDR_LEN + 4)
        return mm_error(dev, -EPROTO, "command 0x%04x response is too short", msg_id);

    if (resp != NULL) {
        const size_t n = dev->cmd_resp_len < resp_max ? dev->cmd_resp_len : resp_max;
        memcpy(resp, dev->cmd_resp, n);
        if (resp_len != NULL)
            *resp_len = n;
    }

    const int32_t status = (int32_t) mm_get_le32(dev->cmd_resp + MM_CMD_HDR_LEN);

    if (status != 0)
        return mm_error(dev, status < 0 ? status : -EIO, "command 0x%04x returned status %d",
                msg_id, status);

    return 0;
}

int mm_cmd_get_version(struct mm8108_dev *dev, char *version, size_t version_len) {
    uint8_t resp[sizeof(dev->cmd_resp)];
    size_t resp_len = 0;
    int r;

    if (version_len == 0)
        return -EINVAL;

    version[0] = 0;

    if ((r = mm_cmd_send(dev, MM_CMD_GET_VERSION, 0, NULL, 0, resp, sizeof(resp), &resp_len)) < 0)
        return r;

    /* header, status, le32 length, string */
    if (resp_len < MM_CMD_HDR_LEN + 8)
        return -EPROTO;

    int32_t slen = (int32_t) mm_get_le32(resp + MM_CMD_HDR_LEN + 4);
    const size_t avail = resp_len - (MM_CMD_HDR_LEN + 8);

    if (slen < 0)
        slen = 0;
    if ((size_t) slen > avail)
        slen = (int32_t) avail;
    if ((size_t) slen >= version_len)
        slen = (int32_t) version_len - 1;

    memcpy(version, resp + MM_CMD_HDR_LEN + 8, (size_t) slen);
    version[slen] = 0;

    /* Stop at any embedded NUL and keep it printable */
    for (int32_t i = 0; i < slen; i++) {
        if (version[i] == 0)
            break;
        if (version[i] < 0x20 || version[i] > 0x7E)
            version[i] = '?';
    }

    return 0;
}

int mm_cmd_add_monitor(struct mm8108_dev *dev) {
    uint8_t body[10];
    uint8_t resp[MM_CMD_HDR_LEN + 4];
    size_t resp_len = 0;
    int r;

    memcpy(body, dev->mac, 6);
    mm_put_le32(body + 6, MM_INTERFACE_TYPE_MON);

    if ((r = mm_cmd_send(dev, MM_CMD_ADD_INTERFACE, 0, body, sizeof(body), resp, sizeof(resp),
                    &resp_len)) < 0)
        return r;

    /* The new interface id comes back in the header */
    dev->mon_vif_id = mm_get_le16(resp + 8);
    dev->mon_added = true;

    mm_log(dev, 1, "monitor interface added (vif %u)", dev->mon_vif_id);

    return 0;
}

int mm_cmd_remove_monitor(struct mm8108_dev *dev) {
    int r;

    if (!dev->mon_added)
        return 0;

    r = mm_cmd_send(dev, MM_CMD_REMOVE_INTERFACE, dev->mon_vif_id, NULL, 0, NULL, 0, NULL);
    dev->mon_added = false;

    return r;
}

int mm_cmd_set_channel(struct mm8108_dev *dev, uint32_t freq_khz, uint8_t op_bw_mhz,
        uint8_t pri_bw_mhz, uint8_t pri_1mhz_idx) {
    uint8_t body[10];

    mm_put_le32(body, freq_khz * 1000);
    body[4] = op_bw_mhz;
    body[5] = pri_bw_mhz;
    body[6] = pri_1mhz_idx;
    /* 802.11ah */
    body[7] = 0;
    /* Deprecated, must be 1 */
    body[8] = 1;
    /* Not off-channel */
    body[9] = 0;

    return mm_cmd_send(dev, MM_CMD_SET_CHANNEL, 0, body, sizeof(body), NULL, 0, NULL);
}

/* Channels the board config disallows */
int mm_cmd_get_disabled_channels(struct mm8108_dev *dev, struct mm_disabled_channel *out,
        size_t max, size_t *num) {
    uint8_t resp[sizeof(dev->cmd_resp)];
    size_t resp_len = 0, avail;
    uint32_t count;
    int r;

    *num = 0;

    if ((r = mm_cmd_send(dev, MM_CMD_GET_DISABLED_CHANNELS, 0, NULL, 0, resp, sizeof(resp),
                    &resp_len)) < 0)
        return r;

    if (resp_len < MM_CMD_HDR_LEN + 8)
        return -EPROTO;

    count = mm_get_le32(resp + MM_CMD_HDR_LEN + 4);
    avail = (resp_len - (MM_CMD_HDR_LEN + 8)) / 3;

    if (count > avail) {
        mm_log(dev, 1, "disabled channel list truncated (%u > %zu)", count, avail);
        count = (uint32_t) avail;
    }

    for (uint32_t i = 0; i < count && *num < max; i++) {
        const uint8_t *e = resp + MM_CMD_HDR_LEN + 8 + i * 3;

        out[*num].freq_khz = (uint32_t) mm_get_le16(e) * 100;
        out[*num].bw_mhz = e[2];
        (*num)++;
    }

    return 0;
}

int mm_cmd_health_check(struct mm8108_dev *dev) {
    return mm_cmd_send(dev, MM_CMD_HEALTH_CHECK, 0, NULL, 0, NULL, 0, NULL);
}
