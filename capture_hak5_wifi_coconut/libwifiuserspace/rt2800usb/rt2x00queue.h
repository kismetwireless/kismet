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

#ifndef __RT2X00QUEUE_H__
#define __RT2X00QUEUE_H__ 

#include "kernel/bits.h"
#include "kernel/mac80211.h"
#include "kernel/types.h"

/**
 * DOC: Entry frame size
 *
 * Ralink PCI devices demand the Frame size to be a multiple of 128 bytes,
 * for USB devices this restriction does not apply, but the value of
 * 2432 makes sense since it is big enough to contain the maximum fragment
 * size according to the ieee802.11 specs.
 * The aggregation size depends on support from the driver, but should
 * be something around 3840 bytes.
 */
#define DATA_FRAME_SIZE		2432
#define MGMT_FRAME_SIZE		256
#define AGGREGATION_SIZE	3840

/**
 * enum rxdone_entry_desc_flags: Flags for &struct rxdone_entry_desc
 *
 * @RXDONE_SIGNAL_PLCP: Signal field contains the plcp value.
 * @RXDONE_SIGNAL_BITRATE: Signal field contains the bitrate value.
 * @RXDONE_SIGNAL_MCS: Signal field contains the mcs value.
 * @RXDONE_MY_BSS: Does this frame originate from device's BSS.
 * @RXDONE_CRYPTO_IV: Driver provided IV/EIV data.
 * @RXDONE_CRYPTO_ICV: Driver provided ICV data.
 * @RXDONE_L2PAD: 802.11 payload has been padded to 4-byte boundary.
 */
enum rxdone_entry_desc_flags {
	RXDONE_SIGNAL_PLCP = BIT(0),
	RXDONE_SIGNAL_BITRATE = BIT(1),
	RXDONE_SIGNAL_MCS = BIT(2),
	RXDONE_MY_BSS = BIT(3),
	RXDONE_CRYPTO_IV = BIT(4),
	RXDONE_CRYPTO_ICV = BIT(5),
	RXDONE_L2PAD = BIT(6),
};

/**
 * RXDONE_SIGNAL_MASK - Define to mask off all &rxdone_entry_desc_flags flags
 * except for the RXDONE_SIGNAL_* flags. This is useful to convert the dev_flags
 * from &rxdone_entry_desc to a signal value type.
 */
#define RXDONE_SIGNAL_MASK \
	( RXDONE_SIGNAL_PLCP | RXDONE_SIGNAL_BITRATE | RXDONE_SIGNAL_MCS )

/**
 * struct rxdone_entry_desc: RX Entry descriptor
 *
 * Summary of information that has been read from the RX frame descriptor.
 *
 * @timestamp: RX Timestamp
 * @signal: Signal of the received frame.
 * @rssi: RSSI of the received frame.
 * @size: Data size of the received frame.
 * @flags: MAC80211 receive flags (See &enum mac80211_rx_flags).
 * @dev_flags: Ralink receive flags (See &enum rxdone_entry_desc_flags).
 * @rate_mode: Rate mode (See @enum rate_modulation).
 * @cipher: Cipher type used during decryption.
 * @cipher_status: Decryption status.
 * @iv: IV/EIV data used during decryption.
 * @icv: ICV data used during decryption.
 */
struct rxdone_entry_desc {
	u64 timestamp;
	int signal;
	int rssi;
	int size;
	int flags;
	int dev_flags;
	u16 rate_mode;
	u16 enc_flags;
	enum mac80211_rx_encoding encoding;
	enum rate_info_bw bw;
	u8 cipher;
	u8 cipher_status;

	__le32 iv[2];
	__le32 icv;
};

#endif /* ifndef RT2X00QUEUE_H */

