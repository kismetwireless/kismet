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

#ifndef __RT2800USB_H__
#define __RT2800USB_H__ 

#include "rt2x00.h"

/*
 * 8051 firmware image.
 */
#define FIRMWARE_RT2870			"rt2870.bin"
#define FIRMWARE_IMAGE_BASE		0x3000

/*
 * DMA descriptor defines.
 */
#define TXINFO_DESC_SIZE		(1 * sizeof(__le32))
#define RXINFO_DESC_SIZE		(1 * sizeof(__le32))

/*
 * TX Info structure
 */

/*
 * Word0
 * WIV: Wireless Info Valid. 1: Driver filled WI,  0: DMA needs to copy WI
 * QSEL: Select on-chip FIFO ID for 2nd-stage output scheduler.
 *       0:MGMT, 1:HCCA 2:EDCA
 * USB_DMA_NEXT_VALID: Used ONLY in USB bulk Aggregation, NextValid
 * DMA_TX_BURST: used ONLY in USB bulk Aggregation.
 *               Force USB DMA transmit frame from current selected endpoint
 */
#define TXINFO_W0_USB_DMA_TX_PKT_LEN	FIELD32(0x0000ffff)
#define TXINFO_W0_WIV			FIELD32(0x01000000)
#define TXINFO_W0_QSEL			FIELD32(0x06000000)
#define TXINFO_W0_SW_USE_LAST_ROUND	FIELD32(0x08000000)
#define TXINFO_W0_USB_DMA_NEXT_VALID	FIELD32(0x40000000)
#define TXINFO_W0_USB_DMA_TX_BURST	FIELD32(0x80000000)

/*
 * RX Info structure
 */

/*
 * Word 0
 */

#define RXINFO_W0_USB_DMA_RX_PKT_LEN	FIELD32(0x0000ffff)

/*
 * RX descriptor format for RX Ring.
 */

/*
 * Word0
 * UNICAST_TO_ME: This RX frame is unicast to me.
 * MULTICAST: This is a multicast frame.
 * BROADCAST: This is a broadcast frame.
 * MY_BSS: this frame belongs to the same BSSID.
 * CRC_ERROR: CRC error.
 * CIPHER_ERROR: 0: decryption okay, 1:ICV error, 2:MIC error, 3:KEY not valid.
 * AMSDU: rx with 802.3 header, not 802.11 header.
 */

#define RXD_W0_BA			FIELD32(0x00000001)
#define RXD_W0_DATA			FIELD32(0x00000002)
#define RXD_W0_NULLDATA			FIELD32(0x00000004)
#define RXD_W0_FRAG			FIELD32(0x00000008)
#define RXD_W0_UNICAST_TO_ME		FIELD32(0x00000010)
#define RXD_W0_MULTICAST		FIELD32(0x00000020)
#define RXD_W0_BROADCAST		FIELD32(0x00000040)
#define RXD_W0_MY_BSS			FIELD32(0x00000080)
#define RXD_W0_CRC_ERROR		FIELD32(0x00000100)
#define RXD_W0_CIPHER_ERROR		FIELD32(0x00000600)
#define RXD_W0_AMSDU			FIELD32(0x00000800)
#define RXD_W0_HTC			FIELD32(0x00001000)
#define RXD_W0_RSSI			FIELD32(0x00002000)
#define RXD_W0_L2PAD			FIELD32(0x00004000)
#define RXD_W0_AMPDU			FIELD32(0x00008000)
#define RXD_W0_DECRYPTED		FIELD32(0x00010000)
#define RXD_W0_PLCP_RSSI		FIELD32(0x00020000)
#define RXD_W0_CIPHER_ALG		FIELD32(0x00040000)
#define RXD_W0_LAST_AMSDU		FIELD32(0x00080000)
#define RXD_W0_PLCP_SIGNAL		FIELD32(0xfff00000)

/*
 * Firmware functions
 */
int rt2800usb_autorun_detect(struct rt2x00_dev *rt2x00dev);
/*
 * Probe a usb device to determine if it's a viable rt2800 device;
 * returns 1 on success and populates **probe_dev,
 * returns 0 on no match
 * returns negative on error
 */
int rt2800usb_probe_device(struct libusb_device_descriptor *desc, 
        struct userspace_wifi_probe_dev **probe_dev);


#endif /* ifndef RT2800USB_H */
