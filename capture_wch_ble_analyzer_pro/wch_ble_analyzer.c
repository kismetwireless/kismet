/*
 * WCH BLE Analyzer Pro – Linux libusb driver implementation
 *
 * Protocol confirmed by reverse-engineering BleAnalyzer64.exe:
 *
 *   Command format (EP 0x02, Bulk OUT):
 *     [0xAA][CMD][len_lo][len_hi][payload…]
 *
 *   Init sequence (state=3, firmware already loaded):
 *     1. AA 84 13 00 [00 00 00 00] "BLEAnalyzer&IAP"  → EP 0x82: 33 32
 *     2. AA 81 19 00 [25-byte BLE config payload]      → starts BLE streaming
 *     3. AA A1 00 00                                   → status echo + scan
 *
 *   Data frame format (received on EP 0x82, one per USB transfer):
 *     Byte 0:    0x55 (magic)
 *     Byte 1:    0x10 (data packet) | 0x01 (status echo)
 *     Byte 2-3:  payload_len (LE uint16)
 *     Payload:
 *       [0-3]  timestamp_us (LE uint32, μs from device boot)
 *       [4]    channel_index (0-39)
 *       [5]    flags (0x00 or 0x01)
 *       [6-7]  reserved (0x00 0x00)
 *       [8]    rssi (signed int8, dBm)
 *       [9]    reserved
 *       [10]   pdu_hdr0 (BLE LL PDU header byte 0)
 *       [11]   pdu_payload_len (bytes, includes AdvA, excludes CRC)
 *       [12-17] addr (AdvA, or ScanA for SCAN_REQ)
 *       [18+]  rest of PDU payload (AdvData, or AdvA for SCAN_REQ)
 */

#include "wch_ble_analyzer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ── Protocol constants ─────────────────────────────────────────────────── */

#define WCH_MAGIC        0xAA   /* command magic byte */
#define CMD_IDENTIFY     0x84   /* identify/arm */
#define CMD_BLE_CONFIG   0x81   /* BLE monitor config + start */
#define CMD_SCAN_START   0xA1   /* start scan trigger */

/* "BLEAnalyzer&IAP" – 15-byte ASCII string used in the identify command */
static const uint8_t IAP_STR[15] = {
    'B','L','E','A','n','a','l','y','z','e','r','&','I','A','P'
};

/* Device frame magic bytes */
#define FRAME_MAGIC      0x55
#define FRAME_TYPE_DATA  0x10
#define FRAME_TYPE_STS   0x01   /* status / config echo */

/* BLE advertising access address (little-endian) */
#define BLE_ADV_AA       UINT32_C(0x8E89BED6)

/* Minimum payload bytes in a data frame */
#define MIN_DATA_PAYLOAD 18   /* 12 meta + 6 addr */

/* ── Internal helpers ───────────────────────────────────────────────────── */

static int bulk_write(wch_device_t *dev, const uint8_t *buf, int len)
{
    int xfer = 0;
    return libusb_bulk_transfer(dev->handle, EP_BULK_OUT,
                                (uint8_t *)buf, len, &xfer, 1000);
}

static int bulk_read(wch_device_t *dev, uint8_t *buf, int len,
                     int *got, int timeout_ms)
{
    *got = 0;
    return libusb_bulk_transfer(dev->handle, EP_BULK_IN,
                                buf, len, got, timeout_ms);
}

/* ── wch_init ────────────────────────────────────────────────────────────── */

int wch_init(libusb_context **ctx_out)
{
    return libusb_init(ctx_out);
}

/* ── wch_exit ────────────────────────────────────────────────────────────── */

void wch_exit(libusb_context *ctx)
{
    libusb_exit(ctx);
}

/* ── wch_find_devices ────────────────────────────────────────────────────── */

int wch_find_devices(libusb_context *ctx, wch_device_t devs[MAX_MCU_DEVICES])
{
    libusb_device **list;
    ssize_t cnt = libusb_get_device_list(ctx, &list);
    if (cnt < 0)
        return (int)cnt;

    int found = 0;
    for (ssize_t i = 0; i < cnt && found < MAX_MCU_DEVICES; i++) {
        struct libusb_device_descriptor desc;
        if (libusb_get_device_descriptor(list[i], &desc) != 0)
            continue;
        if (desc.idVendor  != WCH_VID ||
            desc.idProduct != WCH_PID_BLE_MCU)
            continue;

        memset(&devs[found], 0, sizeof(wch_device_t));
        devs[found].ctx     = ctx;
        devs[found].bus     = libusb_get_bus_number(list[i]);
        devs[found].addr    = libusb_get_device_address(list[i]);
        devs[found].is_open = false;
        found++;
    }

    libusb_free_device_list(list, 1);
    return found;
}

/* ── wch_open_device ─────────────────────────────────────────────────────── */

int wch_open_device(wch_device_t *dev)
{
    libusb_device **list;
    ssize_t cnt = libusb_get_device_list(dev->ctx, &list);
    if (cnt < 0)
        return (int)cnt;

    libusb_device *target = NULL;
    for (ssize_t i = 0; i < cnt; i++) {
        if (libusb_get_bus_number(list[i])     == dev->bus &&
            libusb_get_device_address(list[i]) == dev->addr) {
            target = list[i];
            break;
        }
    }

    if (!target) {
        libusb_free_device_list(list, 1);
        return LIBUSB_ERROR_NO_DEVICE;
    }

    int r = libusb_open(target, &dev->handle);
    libusb_free_device_list(list, 1);
    if (r != 0)
        return r;

    libusb_set_auto_detach_kernel_driver(dev->handle, 1);

    r = libusb_claim_interface(dev->handle, 0);
    if (r != 0) {
        libusb_close(dev->handle);
        dev->handle = NULL;
        return r;
    }

    dev->is_open    = true;
    dev->rx_count   = 0;
    dev->err_count  = 0;
    dev->ts_prev_us = 0;
    dev->ts_hi_us   = 0;
    dev->pkt_seq    = 0;
    return 0;
}

/* ── wch_close_device ────────────────────────────────────────────────────── */

void wch_close_device(wch_device_t *dev)
{
    if (!dev->is_open)
        return;
    libusb_release_interface(dev->handle, 0);
    libusb_close(dev->handle);
    dev->handle  = NULL;
    dev->is_open = false;
}

/* ── wch_start_capture ───────────────────────────────────────────────────── */

/*
 * Confirmed init sequence for state=3 (firmware already loaded):
 *
 *   Step 1 – AA 84: identify / arm
 *     Frame: AA 84 13 00  [00 00 00 00]  "BLEAnalyzer&IAP"
 *     Response on EP 0x82: 33 32  (non-zero byte 0 → firmware present, state=3)
 *
 *   Step 2 – AA 81: BLE monitor config
 *     Frame: AA 81 19 00  [25-byte payload]
 *     Payload: [0]=0x01 (BLE mode flag)  [1]=PHY  [2-24]=zeros (no filters)
 *     Sending this makes the device start streaming captured BLE packets
 *     immediately; you may receive a BLE packet during the response read.
 *
 *   Step 3 – AA A1: start-scan trigger
 *     Frame: AA A1 00 00
 *     Device sends a 29-byte status echo, then continues streaming.
 */
int wch_start_capture(wch_device_t *dev, const wch_capture_config_t *cfg)
{
    uint8_t frame[64];
    uint8_t resp[64];
    int     got, r;

    /* ── Step 1: AA 84 identify ─────────────────────────────────── */
    memset(frame, 0, sizeof(frame));
    frame[0] = WCH_MAGIC;
    frame[1] = CMD_IDENTIFY;
    frame[2] = 0x13;            /* payload len = 19 = 4 + 15 */
    frame[3] = 0x00;
    /* bytes [4..7] = 4-byte device ID (zeros works) */
    memcpy(frame + 8, IAP_STR, sizeof(IAP_STR));

    r = bulk_write(dev, frame, 4 + 4 + 15);
    if (r != 0 && r != LIBUSB_ERROR_TIMEOUT)
        return r;

    /* Read response: expect 2 bytes (e.g. 33 32) indicating firmware present */
    r = bulk_read(dev, resp, sizeof(resp), &got, 2000);
    if (r != 0 && r != LIBUSB_ERROR_TIMEOUT) {
        /*
        fprintf(stderr, "[wch bus=%d addr=%d] AA84 read error: %s\n",
                dev->bus, dev->addr, libusb_error_name(r));
        */
        return r;
    }
    /*
    if (got >= 1)
        fprintf(stderr, "[wch bus=%d addr=%d] AA84 response[0]=0x%02X (%s)\n",
                dev->bus, dev->addr, resp[0],
                resp[0] ? "firmware present, state=3" : "no firmware?");
    */

    /* 0                       8                       16                      24
     * aa 81 19 00 ff 01 27 00 00 00 00 00 00 00 00 d6 be 89 8e 55 55 55 10 00 00 00 00 00 00
     */

    /* ── Step 2: AA 81 BLE monitor config ───────────────────────── */
    memset(frame, 0, sizeof(frame));
    frame[0] = WCH_MAGIC;
    frame[1] = CMD_BLE_CONFIG;
    frame[2] = 0x19;            /* payload len = 25 */
    frame[3] = 0x00;
    frame[4] = 0xFF;
    frame[5] = 0x01;
#if 0
    frame[4] = 0x01;            /* BLE monitor mode flag */
    if (cfg->ble_channel)
        frame[4] |= 0x02;       /* channel-nonzero flag (RE: bit set when ch != 0) */
    frame[5] = cfg->phy ? cfg->phy : 1;   /* PHY: 1=1M 2=2M 3/4=Coded */
#endif
    frame[6] = cfg->ble_channel;  /* BLE adv channel: 37/38/39 (0 = all) */

    /* frame[7..14] = 0x00; */
    frame[15] = 0xd6;
    frame[16] = 0xbe;
    frame[17] = 0x89;
    frame[18] = 0x8e;
    frame[19] = 0x55;
    frame[20] = 0x55;
    frame[21] = 0x55;
    frame[22] = 0x10;
    /* frmae[23..28] = 0x00; */

    r = bulk_write(dev, frame, 4 + 25);
    if (r != 0 && r != LIBUSB_ERROR_TIMEOUT)
        return r;

    /* Device may immediately stream a BLE packet – drain it briefly */
    r = bulk_read(dev, resp, sizeof(resp), &got, 100);
    /*
    if (r == 0 && got > 0)
        fprintf(stderr, "[wch bus=%d addr=%d] AA81 triggered %d byte(s) "
                "(BLE streaming started)\n", dev->bus, dev->addr, got);
    */

    /* ── Step 3: AA A1 start-scan trigger ───────────────────────── */
    memset(frame, 0, sizeof(frame));
    frame[0] = WCH_MAGIC;
    frame[1] = CMD_SCAN_START;
    frame[2] = 0x00;
    frame[3] = 0x00;

    r = bulk_write(dev, frame, 4);
    if (r != 0 && r != LIBUSB_ERROR_TIMEOUT)
        return r;

    /* Read the 29-byte status echo (55 01 19 00 …) */
    r = bulk_read(dev, resp, sizeof(resp), &got, 1000);
    /*
    if (r == 0 && got >= 1)
        fprintf(stderr, "[wch bus=%d addr=%d] AA A1 response: %d bytes "
                "(magic=0x%02X type=0x%02X)\n",
                dev->bus, dev->addr, got, resp[0], got > 1 ? resp[1] : 0);
    */

    return 0;
}

/* ── wch_stop_capture ────────────────────────────────────────────────────── */

int wch_stop_capture(wch_device_t *dev)
{
    /*
     * No confirmed stop command yet.  Closing the USB interface effectively
     * stops the stream.  Sending an empty AA A1 again seems harmless.
     */
    uint8_t frame[4] = { WCH_MAGIC, CMD_SCAN_START, 0x00, 0x00 };
    int r = bulk_write(dev, frame, sizeof(frame));
    return (r == LIBUSB_ERROR_TIMEOUT) ? 0 : r;
}

/* ── wch_read_packets ────────────────────────────────────────────────────── */

/*
 * Reads one USB bulk transfer from EP 0x82 and decodes all device frames
 * found in the buffer.
 *
 * Device frame format:
 *   [0x55][type][len_lo][len_hi][payload…]
 *
 * type=0x10: BLE data packet – decoded and reported via callback.
 * type=0x01: status echo     – silently skipped.
 * other:     resync one byte.
 *
 * Returns number of decoded packets (≥0) or negative libusb error.
 * LIBUSB_ERROR_TIMEOUT is treated as 0 (normal when no packets arrive).
 */
int wch_read_packets(wch_device_t    *dev,
                     uint8_t         *buf,
                     wch_packet_cb_t  cb,
                     void            *user_ctx,
                     int              timeout_ms)
{
    int xfer = 0;
    int r = libusb_bulk_transfer(dev->handle, EP_BULK_IN,
                                 buf, BULK_TRANSFER_SIZE,
                                 &xfer, timeout_ms);
    if (r == LIBUSB_ERROR_TIMEOUT)
        return 0;
    if (r != 0)
        return r;
    if (xfer < 4)
        return 0;

    int decoded = 0;
    int offset  = 0;

    while (offset + 4 <= xfer) {
        if (buf[offset] != FRAME_MAGIC) {
            offset++;
            continue;
        }

        uint8_t  ftype      = buf[offset + 1];
        uint16_t plen       = (uint16_t)buf[offset + 2]
                            | ((uint16_t)buf[offset + 3] << 8);
        int      frame_size = 4 + (int)plen;

        if (offset + frame_size > xfer)
            break;   /* truncated frame – wait for more data */

        /* appears to indicate a junk packet - process the length of the packet but don't send it */
        if (buf[offset + 9] != 0) {
            offset += frame_size;
            continue;
        }

        /* Status echo: skip silently */
        if (ftype == FRAME_TYPE_STS) {
            offset += frame_size;
            dev->err_count++;
            continue;
        }

        /* Unknown type: skip */
        if (ftype != FRAME_TYPE_DATA) {
            offset++;
            continue;
        }

        /* Data frame: need at least MIN_DATA_PAYLOAD bytes of payload */
        if (plen < MIN_DATA_PAYLOAD) {
            offset += frame_size;
            continue;
        }

        const uint8_t *p = buf + offset + 4;  /* payload start */

        uint8_t  channel      = p[4];
        if (channel > 39) {
            offset += frame_size;
            continue;
        }

        uint32_t ts32         = (uint32_t)p[0] | ((uint32_t)p[1] << 8)
                              | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
        uint8_t  flags        = p[5];
        int8_t   rssi         = (int8_t)p[8];
        uint8_t  pdu_hdr0     = p[10];
        uint8_t  pdu_plen     = p[11];
        uint8_t  pkt_type_ble = pdu_hdr0 & 0x0F;  /* BLE LL PDU type */

        /* Extend 32-bit device timestamp to 64-bit */
        if (ts32 < dev->ts_prev_us)
            dev->ts_hi_us += UINT64_C(0x100000000);
        uint64_t ts64 = dev->ts_hi_us | ts32;
        uint64_t dt   = ts64 - (dev->ts_hi_us | dev->ts_prev_us);
        dev->ts_prev_us = ts32;

        /* Build wch_pkt_hdr_t */
        wch_pkt_hdr_t hdr;
        memset(&hdr, 0, sizeof(hdr));
        hdr.rssi         = rssi;
        hdr.pkt_type     = pkt_type_ble;
        hdr.direction    = flags & 0x01;   /* 0=M→S, 1=S→M */
        hdr.access_addr  = BLE_ADV_AA;     /* advertising channels */
        hdr.channel_index = channel;
        hdr.timestamp_us = ts64;
        hdr.interval_us  = dt;
        hdr.pkt_index    = dev->pkt_seq++;

        /* src_addr = first address in PDU payload (AdvA or ScanA) */
        memcpy(hdr.src_addr, p + 12, 6);

        /* dst_addr = second address (AdvA for SCAN_REQ / CONNECT_IND) */
        if ((pkt_type_ble == PKT_SCAN_REQ || pkt_type_ble == PKT_CONNECT_REQ)
                && pdu_plen >= 12 && plen >= 18 + 6)
            memcpy(hdr.dst_addr, p + 18, 6);

        /*
         * BLE LL PDU for callback: [pdu_hdr0][pdu_plen][PDU payload…]
         * Total = 2 + pdu_plen bytes.
         */
        const uint8_t *pdu = p + 10;
        int pdu_len = 2 + (int)pdu_plen;

        /* Clamp to what's actually in the buffer */
        int avail = (int)plen - 10;
        if (pdu_len > avail)
            pdu_len = avail;

        dev->rx_count++;
        if (cb)
            cb(&hdr, pdu, pdu_len, user_ctx);

        decoded++;
        offset += frame_size;
    }

    return decoded;
}

/* ── Utility ──────────────────────────────────────────────────────────────── */

const char *wch_pkt_type_name(uint8_t pkt_type)
{
    switch (pkt_type) {
    case PKT_ADV_IND:                 return "ADV_IND";
    case PKT_ADV_DIRECT_IND:          return "ADV_DIRECT_IND";
    case PKT_ADV_NONCONN_IND:         return "ADV_NONCONN_IND";
    case PKT_SCAN_REQ:                return "SCAN_REQ";
    case PKT_SCAN_RSP:                return "SCAN_RSP";
    case PKT_CONNECT_REQ:             return "CONNECT_REQ";
    case PKT_ADV_SCAN_IND:            return "ADV_SCAN_IND";
    case PKT_AUX_SCAN_REQ:            return "AUX_SCAN_REQ";
    case PKT_AUX_CONNECT_REQ:         return "AUX_CONNECT_REQ";
    case PKT_AUX_COMMON:              return "AUX_COMMON";
    case PKT_AUX_ADV_IND:             return "AUX_ADV_IND";
    case PKT_AUX_SCAN_RSP:            return "AUX_SCAN_RSP";
    case PKT_AUX_SYNC_IND:            return "AUX_SYNC_IND";
    case PKT_AUX_CONNECT_RSP:         return "AUX_CONNECT_RSP";
    case PKT_AUX_CHAIN_IND:           return "AUX_CHAIN_IND";
    case PKT_DATA_PDU_RESERVED:       return "DATA_PDU_RESERVED";
    case PKT_DATA_PDU_EMPORCON:       return "DATA_PDU_CONT";
    case PKT_DATA_PDU_DATA:           return "DATA_PDU_DATA";
    case PKT_DATA_PDU_CONTROL:        return "DATA_PDU_CTRL";
    case PKT_LL_CTRL_CONN_UPDATE_IND: return "LL_CONN_UPDATE_IND";
    case PKT_LL_CTRL_TERMINATE_IND:   return "LL_TERMINATE_IND";
    case PKT_CRC_ERR:                 return "CRC_ERR";
    case PKT_MISS:                    return "PKT_MISS";
    case PKT_LL_EMPTY:                return "LL_EMPTY";
    default: {
        static char buf[8];
        snprintf(buf, sizeof(buf), "0x%02X", pkt_type);
        return buf;
    }
    }
}

void wch_mac_to_str(const uint8_t mac[6], char out[18])
{
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[5], mac[4], mac[3], mac[2], mac[1], mac[0]);
}

void wch_print_packet(const wch_pkt_hdr_t *hdr,
                      const uint8_t       *pdu,
                      int                  pdu_len)
{
    char src[18], dst[18];
    wch_mac_to_str(hdr->src_addr, src);
    wch_mac_to_str(hdr->dst_addr, dst);

    printf("[%12llu us] ch%02u  %-22s  rssi %4d dBm  AA %08X  %s",
           (unsigned long long)hdr->timestamp_us,
           hdr->channel_index,
           wch_pkt_type_name(hdr->pkt_type),
           (int)hdr->rssi,
           hdr->access_addr,
           src);

    if (hdr->pkt_type == PKT_SCAN_REQ || hdr->pkt_type == PKT_CONNECT_REQ)
        printf("→%s", dst);

    if (pdu && pdu_len > 0) {
        int show = (pdu_len < 24) ? pdu_len : 24;
        printf("  PDU[%d]:", pdu_len);
        for (int i = 0; i < show; i++)
            printf(" %02x", pdu[i]);
        if (pdu_len > show)
            printf(" ...");
    }
    putchar('\n');
}
