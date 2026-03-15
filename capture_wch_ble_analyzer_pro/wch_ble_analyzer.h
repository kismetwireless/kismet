/*
 * WCH BLE Analyzer Pro - Linux libusb driver
 *
 * Hardware: 3x CH582F BLE 5.1 RISC-V MCUs + CH334 USB 2.0 hub
 * USB IDs:  VID 0x1A86 / PID 0x8009 (WinChipHead / wch.cn)
 *           VID 0x1A86 / PID 0x8091 (CH334 hub, handled by kernel hub driver)
 *
 * USB descriptor (per CH582F MCU):
 *   Interface 0: Class 0xFF (Vendor Specific), SubClass 0x80, Protocol 0x55
 *   EP 0x81: Interrupt IN,  64 bytes  – (not used; I/O error in practice)
 *   EP 0x82: Bulk IN,       64 bytes  – captured BLE packet stream
 *   EP 0x02: Bulk OUT,      64 bytes  – host → device commands
 *
 * Three CH582F devices appear as three independent USB devices through the
 * CH334 hub.  All three MCUs receive the same init sequence and stream
 * BLE advertising packets from channel 37 (and/or 38, 39 when hopping).
 *
 * ── CONFIRMED command protocol (EP 0x02, Bulk OUT) ──────────────────────────
 *   Frame format: [0xAA][CMD][len_lo][len_hi][payload…]
 *
 *   AA 84 13 00  [4-byte device-ID, use zeros]  "BLEAnalyzer&IAP"
 *       Identify / arm.  Response on EP 0x82: 0x33 0x32 means firmware
 *       already loaded (state=3).  State machine does NOT send AA 86 in
 *       this case.
 *
 *   AA 81 19 00  [25-byte payload]
 *       BLE monitor config.  Payload:
 *         [0] = 0x01 (BLE monitor mode flag)
 *         [1] = PHY  (1 = 1M, 2 = 2M, 3 = CodedS8, 4 = CodedS2)
 *         [2-24] = zeros (no MAC filters, no LTK)
 *       Sending this starts packet streaming on EP 0x82 immediately.
 *
 *   AA A1 00 00
 *       Start-scan trigger.  Device sends a 29-byte status echo then
 *       continues streaming BLE packets on EP 0x82.
 *
 *   AA 85  [firmware upload chunks – only needed when device has no firmware]
 *   AA 86  [configure after firmware upload – NOT sent in normal operation]
 *
 * ── Packet format received on EP 0x82 ───────────────────────────────────────
 *   Each USB transfer carries one device frame:
 *
 *   Byte  Size  Field
 *   ────  ────  ─────
 *      0     1  0x55  (frame magic)
 *      1     1  0x10  (data packet type; 0x01 = status echo, others: skip)
 *      2     2  payload_len  (LE uint16, number of bytes that follow)
 *   --- payload (payload_len bytes) ---
 *      4     4  timestamp_us  (LE uint32, microseconds from device boot)
 *      8     1  channel_index (BLE RF channel 0-39)
 *      9     1  flags         (0x00 or 0x01; appears to indicate original checksum was valid)
 *     10     2  reserved      (0x00 0x00)
 *     12     1  rssi          (signed int8, dBm)
 *     13     1  reserved      (0x00)
 *     14     1  pdu_hdr0      (BLE LL PDU header byte 0:
 *                              bits[3:0] = PDU type, bit[5] = TxAdd,
 *                              bit[6] = RxAdd)
 *     15     1  pdu_payload_len (BLE PDU payload length in bytes,
 *                              includes AdvA but NOT 3-byte CRC)
 *     16     6  addr          (AdvA for ADV* / SCAN_RSP / CONNECT_IND;
 *                              ScanA for SCAN_REQ)
 *     22     N  rest_of_pdu   (AdvData; or AdvA for SCAN_REQ;
 *                              N = pdu_payload_len - 6)
 *
 *   The full reconstructed BLE LL PDU for pcap output:
 *     [pdu_hdr0][pdu_payload_len][payload_16+…]   (2 + pdu_payload_len bytes)
 *
 * Command protocol (EP 0x02, Bulk OUT) – CONFIRMED via RE of BleAnalyzer64.exe
 */

#ifndef WCH_BLE_ANALYZER_H
#define WCH_BLE_ANALYZER_H

#include <stdint.h>
#include <stdbool.h>
#include <libusb-1.0/libusb.h>

/* ── USB IDs ─────────────────────────────────────────────────────────────── */
#define WCH_VID              0x1A86
#define WCH_PID_BLE_MCU      0x8009   /* CH582F BLE MCU */
#define WCH_PID_HUB          0x8091   /* CH334 USB hub  */

/* ── Endpoints ───────────────────────────────────────────────────────────── */
#define EP_INTERRUPT_IN      0x81   /* EP1 IN  – interrupt, 64 B, status/events */
#define EP_BULK_IN           0x82   /* EP2 IN  – bulk,      64 B, BLE packets   */
#define EP_BULK_OUT          0x02   /* EP2 OUT – bulk,      64 B, commands       */
#define EP_MAX_PACKET_SIZE   64

/* Bulk transfer sizes (from Windows driver analysis) */
#define BULK_TRANSFER_SIZE   0x2800   /* 10240 bytes – driver's default read size */
#define BULK_READ_TIMEOUT_MS 1000
#define INT_READ_TIMEOUT_MS  200

/* Maximum CH582F devices in the product (hub has 4 ports, 3 used) */
/* allow up to 10 products connected to the same host PC in basic indexing */
#define MAX_MCU_DEVICES      3*10

/* ── Packet type codes (pkt_type field) ─────────────────────────────────── */
/* Advertisement / Scan */
#define PKT_ADV_IND                      0x00
#define PKT_ADV_DIRECT_IND               0x01
#define PKT_ADV_NONCONN_IND              0x02
#define PKT_SCAN_REQ                     0x03
#define PKT_SCAN_RSP                     0x04
#define PKT_CONNECT_REQ                  0x05
#define PKT_ADV_SCAN_IND                 0x06
/* Extended advertising (BLE 5.0+) */
#define PKT_AUX_SCAN_REQ                 0x07
#define PKT_AUX_CONNECT_REQ              0x08
#define PKT_AUX_COMMON                   0x09
#define PKT_AUX_ADV_IND                  0x0A
#define PKT_AUX_SCAN_RSP                 0x0B
#define PKT_AUX_SYNC_IND                 0x0C
#define PKT_AUX_CONNECT_RSP              0x0D
#define PKT_AUX_CHAIN_IND                0x0E
/* Data PDU LLID types */
#define PKT_DATA_PDU_RESERVED            0x0F
#define PKT_DATA_PDU_EMPORCON            0x10
#define PKT_DATA_PDU_DATA                0x11
#define PKT_DATA_PDU_CONTROL             0x12
/* LL Control */
#define PKT_LL_CTRL_CONN_UPDATE_IND      0x13
#define PKT_LL_CTRL_TERMINATE_IND        0x15
/* … see Lua mDefine.lua for the full list … */
/* Error / status */
#define PKT_CRC_ERR                      0xFE
#define PKT_MISS                         0xFD
#define PKT_LL_EMPTY                     0xFC

/* ── Direction field ─────────────────────────────────────────────────────── */
#define DIR_MASTER_TO_SLAVE  0
#define DIR_SLAVE_TO_MASTER  1

/* ── PHY modes (used in start command) ──────────────────────────────────── */
#define PHY_1M       1
#define PHY_2M       2
#define PHY_CODED_S8 3   /* Long range, 125 kbps */
#define PHY_CODED_S2 4   /* Long range, 500 kbps */

/* ── Capture modes ───────────────────────────────────────────────────────── */
#define MODE_BLE_MONITOR  0   /* Standard BLE sniffer mode        */
#define MODE_CUSTOM_2G4   1   /* Custom 2.4 GHz (raw PHY) mode    */

/*
 * Decoded per-packet metadata header (internal representation, NOT the
 * on-wire device format).  wch_read_packets() fills this from the actual
 * device frame and passes it to the user callback together with the raw
 * BLE LL PDU bytes.
 */
typedef struct {
    int8_t   rssi;            /* Signed RSSI in dBm            */
    uint8_t  pkt_type;        /* PKT_* constant (BLE LL type)  */
    uint8_t  direction;       /* DIR_* constant                */
    uint8_t  reserved0;
    uint32_t access_addr;     /* BLE Access Address (LE)       */
    uint8_t  src_addr[6];     /* AdvA or ScanA (wire order)    */
    uint8_t  dst_addr[6];     /* AdvA target for SCAN_REQ      */
    uint64_t pkt_index;       /* Per-device sequence number    */
    uint64_t timestamp_us;    /* Timestamp in μs               */
    uint64_t interval_us;     /* Δt since previous packet (μs) */
    uint8_t  reserved1;
    uint8_t  channel_index;   /* BLE channel 0-39              */
} __attribute((packed)) wch_pkt_hdr_t;

/* ── Configuration for start command ────────────────────────────────────── */
typedef struct {
    uint8_t  mode;              /* MODE_BLE_MONITOR or MODE_CUSTOM_2G4 */
    uint8_t  phy;               /* PHY_1M / PHY_2M / PHY_CODED_S8 / _S2 */
    /* BLE Monitor mode params */
    uint8_t  ble_channel;       /* BLE adv channel: 37/38/39 (0 = all)  */
    uint8_t  initiator_addr[6]; /* BLE Initiator MAC filter              */
    uint8_t  adv_addr[6];       /* BLE Advertiser MAC filter             */
    uint8_t  ltk[16];           /* Long-Term Key for decryption          */
    uint32_t pass_key;          /* BLE Pass Key (6 digits, 0 = none)     */
    /* Custom 2.4G mode params */
    uint8_t  channel;           /* Channel index 0-39                    */
    uint32_t access_addr_24g;   /* Access Address for 2.4G mode          */
    uint8_t  crc_init[3];       /* CRC init value for 2.4G mode          */
    uint8_t  whitening;         /* Whitening init value for 2.4G mode    */
} wch_capture_config_t;

/* ── Per-device handle ───────────────────────────────────────────────────── */
typedef struct {
    libusb_context       *ctx;        /* libusb context (set by wch_find_devices) */
    libusb_device_handle *handle;
    int                   bus;
    int                   addr;
    bool                  is_open;
    uint64_t              rx_count;   /* Good packets received   */
    uint64_t              err_count;  /* Status/unknown frames   */
    /* Timestamp extension (device provides 32-bit μs; we extend to 64-bit) */
    uint32_t              ts_prev_us; /* Previous 32-bit timestamp */
    uint64_t              ts_hi_us;   /* High 32 bits accumulated  */
    uint64_t              pkt_seq;    /* Monotonic sequence number */
} wch_device_t;

/* ── Callback prototype ───────────────────────────────────────────────────── */
/*
 * Called for every complete packet received from the device.
 *   hdr      – pointer to the decoded 46-byte metadata header
 *   pdu      – pointer to the raw BLE PDU bytes (after the header)
 *   pdu_len  – length of pdu in bytes
 *   user_ctx – opaque pointer passed to wch_start_capture()
 */
typedef void (*wch_packet_cb_t)(const wch_pkt_hdr_t *hdr,
                                const uint8_t       *pdu,
                                int                  pdu_len,
                                void                *user_ctx);

/* ── Public API ──────────────────────────────────────────────────────────── */

/**
 * Initialise libusb context.  Must be called once before any other function.
 * Returns 0 on success, negative libusb error code on failure.
 */
int  wch_init(libusb_context **ctx_out);

/**
 * Scan the bus for connected WCH BLE Analyzer MCUs.
 * Fills @devs[0..MAX_MCU_DEVICES-1] and returns the number found (0–3).
 */
int  wch_find_devices(libusb_context *ctx, wch_device_t devs[MAX_MCU_DEVICES]);

/**
 * Open a single MCU device, detach any kernel driver, claim interface 0.
 * Returns 0 on success.
 */
int  wch_open_device(wch_device_t *dev);

/**
 * Send the capture start sequence to one MCU.
 * Sequence: AA84 (identify) → AA81 (BLE config) → AA A1 (start scan).
 * Returns 0 on success, negative libusb error on failure.
 */
int  wch_start_capture(wch_device_t *dev, const wch_capture_config_t *cfg);

/**
 * Send the capture stop command to one MCU.
 * Returns 0 on success.
 */
int  wch_stop_capture(wch_device_t *dev);

/**
 * Read and decode one bulk-IN transfer from EP 0x82.
 * Parses device frames: [0x55][0x10][len16][payload…]
 * Calls @cb for each BLE data frame (type 0x10).  Status frames (type 0x01)
 * and unknown frames are silently discarded.
 * buf must be caller-allocated with at least BULK_TRANSFER_SIZE bytes.
 *
 * @timeout_ms: libusb transfer timeout in milliseconds.
 *   Use BULK_READ_TIMEOUT_MS (1000) for normal blocking reads.
 *   Use 0 for a non-blocking poll (returns immediately if no data).
 *
 * Returns the number of packets decoded (≥0), or a negative libusb error.
 * LIBUSB_ERROR_TIMEOUT (returned as 0) is normal when no packets arrive.
 */
int  wch_read_packets(wch_device_t    *dev,
                      uint8_t         *buf,      /* caller-allocated, ≥BULK_TRANSFER_SIZE */
                      wch_packet_cb_t  cb,
                      void            *user_ctx,
                      int              timeout_ms);

/**
 * Release interface and close the device handle.
 */
void wch_close_device(wch_device_t *dev);

/**
 * Tear down libusb context.
 */
void wch_exit(libusb_context *ctx);

/* ── Utility ──────────────────────────────────────────────────────────────── */
const char *wch_pkt_type_name(uint8_t pkt_type);
void        wch_print_packet(const wch_pkt_hdr_t *hdr,
                              const uint8_t       *pdu,
                              int                  pdu_len);
void        wch_mac_to_str(const uint8_t mac[6], char out[18]);

#endif /* WCH_BLE_ANALYZER_H */
