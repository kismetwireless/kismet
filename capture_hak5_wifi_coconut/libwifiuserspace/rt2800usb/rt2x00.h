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

#ifndef __RT2X00_H__
#define __RT2X00_H__ 

#include <pthread.h>
#include <stdio.h>

#include <libusb-1.0/libusb.h>

#include "kernel/average.h"
#include "kernel/types.h"
#include "kernel/kernel.h"
#include "kernel/mac80211.h"
#include "kernel/usb.h"

#include "rt2800usb/rt2x00queue.h"
#include "rt2800usb/rt2x00reg.h"

#include "userspace/userspace.h"

#define rt2x00_err(dev, fmt, ...)					\
    userspace_wifi_error(dev->userspace_context, dev->userspace_dev, \
            0, fmt, ##__VA_ARGS__)

#ifdef RT2800_USERSPACE_DEBUG
#define rt2x00_warn(dev, fmt, ...)					\
	fprintf(stderr, "%s: Warning - " fmt,	\
		   __func__, ##__VA_ARGS__)
#define rt2x00_info(dev, fmt, ...)					\
	fprintf(stderr, "%s: Info - " fmt,			\
		   __func__, ##__VA_ARGS__)

/* Various debug levels */
#define rt2x00_dbg(dev, fmt, ...)					\
	fprintf(stderr, "%s: Debug - " fmt,			\
		  __func__, ##__VA_ARGS__)
#define rt2x00_eeprom_dbg(dev, fmt, ...)				\
	fprintf(stderr, "%s: EEPROM recovery - " fmt,	\
		  __func__, ##__VA_ARGS__)
#else
#define rt2x00_warn(dev, fmt, ...)
#define rt2x00_info(dev, fmt, ...)
#define rt2x00_dbg(dev, fmt, ...)
#define rt2x00_eeprom_dbg(dev, fmt, ...)
#endif

/*
 * rt2x00 state flags
 */
enum rt2x00_state_flags {
	/*
	 * Device flags
	 */
	DEVICE_STATE_PRESENT,
	DEVICE_STATE_REGISTERED_HW,
	DEVICE_STATE_INITIALIZED,
	DEVICE_STATE_STARTED,
	DEVICE_STATE_ENABLED_RADIO,
	DEVICE_STATE_SCANNING,
	DEVICE_STATE_FLUSHING,

	/*
	 * Driver configuration
	 */
	CONFIG_CHANNEL_HT40,
	CONFIG_POWERSAVING,
	CONFIG_HT_DISABLED,
	CONFIG_MONITORING,

	/*
	 * Mark we currently are sequentially reading TX_STA_FIFO register
	 * FIXME: this is for only rt2800usb, should go to private data
	 */
	TX_STATUS_READING,
};

/*
 * rt2x00 capability flags
 */
enum rt2x00_capability_flags {
	/*
	 * Requirements
	 */
	REQUIRE_FIRMWARE,
	REQUIRE_BEACON_GUARD,
	REQUIRE_ATIM_QUEUE,
	REQUIRE_DMA,
	REQUIRE_COPY_IV,
	REQUIRE_L2PAD,
	REQUIRE_TXSTATUS_FIFO,
	REQUIRE_TASKLET_CONTEXT,
	REQUIRE_SW_SEQNO,
	REQUIRE_HT_TX_DESC,
	REQUIRE_PS_AUTOWAKE,
	REQUIRE_DELAYED_RFKILL,

	/*
	 * Capabilities
	 */
	CAPABILITY_HW_BUTTON,
	CAPABILITY_HW_CRYPTO,
	CAPABILITY_POWER_LIMIT,
	CAPABILITY_CONTROL_FILTERS,
	CAPABILITY_CONTROL_FILTER_PSPOLL,
	CAPABILITY_PRE_TBTT_INTERRUPT,
	CAPABILITY_LINK_TUNING,
	CAPABILITY_FRAME_TYPE,
	CAPABILITY_RF_SEQUENCE,
	CAPABILITY_EXTERNAL_LNA_A,
	CAPABILITY_EXTERNAL_LNA_BG,
	CAPABILITY_DOUBLE_ANTENNA,
	CAPABILITY_BT_COEXIST,
	CAPABILITY_VCO_RECALIBRATION,
	CAPABILITY_EXTERNAL_PA_TX0,
	CAPABILITY_EXTERNAL_PA_TX1,
};

/*
 * For USB vendor requests we need to pass a timeout time in ms, for this we
 * use the REGISTER_TIMEOUT, however when loading firmware or read EEPROM
 * a higher value is required. In that case we use the REGISTER_TIMEOUT_FIRMWARE
 * and EEPROM_TIMEOUT.
 */
#define REGISTER_TIMEOUT		100
#define REGISTER_TIMEOUT_FIRMWARE	1000
#define EEPROM_TIMEOUT			2000

/*
 * Cache size
 */
#define CSR_CACHE_SIZE			64

/*
 * USB request types.
 */
#define USB_VENDOR_REQUEST	( USB_TYPE_VENDOR | USB_RECIP_DEVICE )
#define USB_VENDOR_REQUEST_IN	( USB_DIR_IN | USB_VENDOR_REQUEST )
#define USB_VENDOR_REQUEST_OUT	( USB_DIR_OUT | USB_VENDOR_REQUEST )

enum rt2x00_chip_intf {
	RT2X00_CHIP_INTF_PCI,
	RT2X00_CHIP_INTF_PCIE,
	RT2X00_CHIP_INTF_USB,
	RT2X00_CHIP_INTF_SOC,
};

/*
 * Chipset identification
 * The chipset on the device is composed of a RT and RF chip.
 * The chipset combination is important for determining device capabilities.
 */
struct rt2x00_chip {
	uint16_t rt;
#define RT2460		0x2460
#define RT2560		0x2560
#define RT2570		0x2570
#define RT2661		0x2661
#define RT2573		0x2573
#define RT2860		0x2860	/* 2.4GHz */
#define RT2872		0x2872	/* WSOC */
#define RT2883		0x2883	/* WSOC */
#define RT3070		0x3070
#define RT3071		0x3071
#define RT3090		0x3090	/* 2.4GHz PCIe */
#define RT3290		0x3290
#define RT3352		0x3352  /* WSOC */
#define RT3390		0x3390
#define RT3572		0x3572
#define RT3593		0x3593
#define RT3883		0x3883	/* WSOC */
#define RT5350		0x5350  /* WSOC 2.4GHz */
#define RT5390		0x5390  /* 2.4GHz */
#define RT5392		0x5392  /* 2.4GHz */
#define RT5592		0x5592
#define RT6352		0x6352  /* WSOC 2.4GHz */

	uint16_t rf;
	uint16_t rev;

	enum rt2x00_chip_intf intf;
};

/*
 * RF register values that belong to a particular channel.
 */
struct rf_channel {
	int channel;
	uint32_t rf1;
	uint32_t rf2;
	uint32_t rf3;
	uint32_t rf4;
};

/*
 * Channel information structure
 */
struct channel_info {
	unsigned int flags;
#define GEOGRAPHY_ALLOWED	0x00000001

	short max_power;
	short default_power1;
	short default_power2;
	short default_power3;
};

/*
 * Antenna setup values.
 */
struct antenna_setup {
	enum antenna rx;
	enum antenna tx;
	uint8_t rx_chain_num;
	uint8_t tx_chain_num;
};

/*
 * Quality statistics about the currently active link.
 */
struct link_qual {
	/*
	 * Statistics required for Link tuning by driver
	 * The rssi value is provided by rt2x00lib during the
	 * link_tuner() callback function.
	 * The false_cca field is filled during the link_stats()
	 * callback function and could be used during the
	 * link_tuner() callback function.
	 */
	int rssi;
	int false_cca;

	/*
	 * VGC levels
	 * Hardware driver will tune the VGC level during each call
	 * to the link_tuner() callback function. This vgc_level is
	 * is determined based on the link quality statistics like
	 * average RSSI and the false CCA count.
	 *
	 * In some cases the drivers need to differentiate between
	 * the currently "desired" VGC level and the level configured
	 * in the hardware. The latter is important to reduce the
	 * number of BBP register reads to reduce register access
	 * overhead. For this reason we store both values here.
	 */
	uint8_t vgc_level;
	uint8_t vgc_level_reg;

	/*
	 * Statistics required for Signal quality calculation.
	 * These fields might be changed during the link_stats()
	 * callback function.
	 */
	int rx_success;
	int rx_failed;
	int tx_success;
	int tx_failed;
};

enum rt2x00_delayed_flags {
	DELAYED_UPDATE_BEACON,
};

/*
 * Interface structure
 * Per interface configuration details, this structure
 * is allocated as the private data for ieee80211_vif.
 */
struct rt2x00_intf {
	/*
	 * Entry in the beacon queue which belongs to
	 * this interface. Each interface has its own
	 * dedicated beacon entry.
	 */
	struct queue_entry *beacon;
	bool enable_beacon;

	/*
	 * Actions that needed rescheduling.
	 */
	unsigned long delayed_flags;

	/*
	 * Software sequence counter, this is only required
	 * for hardware which doesn't support hardware
	 * sequence counting.
	 */
	atomic_t seqno;

};

static inline struct rt2x00_intf* vif_to_intf(struct ieee80211_vif *vif)
{
	return (struct rt2x00_intf *)vif->drv_priv;
}

/**
 * struct hw_mode_spec: Hardware specifications structure
 *
 * Details about the supported modes, rates and channels
 * of a particular chipset. This is used by rt2x00lib
 * to build the ieee80211_hw_mode array for mac80211.
 *
 * @supported_bands: Bitmask contained the supported bands (2.4GHz, 5.2GHz).
 * @supported_rates: Rate types which are supported (CCK, OFDM).
 * @num_channels: Number of supported channels. This is used as array size
 *	for @tx_power_a, @tx_power_bg and @channels.
 * @channels: Device/chipset specific channel values (See &struct rf_channel).
 * @channels_info: Additional information for channels (See &struct channel_info).
 * @ht: Driver HT Capabilities (See &ieee80211_sta_ht_cap).
 */
struct hw_mode_spec {
	unsigned int supported_bands;
#define SUPPORT_BAND_2GHZ	0x00000001
#define SUPPORT_BAND_5GHZ	0x00000002

	unsigned int supported_rates;
#define SUPPORT_RATE_CCK	0x00000001
#define SUPPORT_RATE_OFDM	0x00000002

	unsigned int num_channels;
	const struct rf_channel *channels;
	const struct channel_info *channels_info;

	struct ieee80211_sta_ht_cap ht;
};

/*
 * Configuration structure wrapper around the
 * mac80211 configuration structure.
 * When mac80211 configures the driver, rt2x00lib
 * can precalculate values which are equal for all
 * rt2x00 drivers. Those values can be stored in here.
 */
struct rt2x00lib_conf {
	struct ieee80211_conf *conf;

	struct rf_channel rf;
	struct channel_info channel;
};

/*
 * Configuration structure for hardware encryption.
 */
struct rt2x00lib_crypto {
	enum cipher cipher;

	enum set_key_cmd cmd;
	const uint8_t *address;

	uint32_t bssidx;

	uint8_t key[16];
	uint8_t tx_mic[8];
	uint8_t rx_mic[8];

	int wcid;
};

/*
 * Configuration structure wrapper around the
 * rt2x00 interface configuration handler.
 */
struct rt2x00intf_conf {
	/*
	 * Interface type
	 */
	enum nl80211_iftype type;

	/*
	 * TSF sync value, this is dependent on the operation type.
	 */
	enum tsf_sync sync;

	/*
	 * The MAC and BSSID addresses are simple array of bytes,
	 * these arrays are little endian, so when sending the addresses
	 * to the drivers, copy the it into a endian-signed variable.
	 *
	 * Note that all devices (except rt2500usb) have 32 bits
	 * register word sizes. This means that whatever variable we
	 * pass _must_ be a multiple of 32 bits. Otherwise the device
	 * might not accept what we are sending to it.
	 * This will also make it easier for the driver to write
	 * the data to the device.
	 */
	___le32 mac[2];
	___le32 bssid[2];
};

/*
 * Configuration structure for erp settings.
 */
struct rt2x00lib_erp {
	int short_preamble;
	int cts_protection;

	uint32_t basic_rates;

	int slot_time;

	short sifs;
	short pifs;
	short difs;
	short eifs;

	uint16_t beacon_int;
	uint16_t ht_opmode;
};

DECLARE_EWMA(rssi, 10, 8)

/*
 * Antenna settings about the currently active link.
 */
struct link_ant {
	/*
	 * Antenna flags
	 */
	unsigned int flags;
#define ANTENNA_RX_DIVERSITY	0x00000001
#define ANTENNA_TX_DIVERSITY	0x00000002
#define ANTENNA_MODE_SAMPLE	0x00000004

	/*
	 * Currently active TX/RX antenna setup.
	 * When software diversity is used, this will indicate
	 * which antenna is actually used at this time.
	 */
	struct antenna_setup active;

	/*
	 * RSSI history information for the antenna.
	 * Used to determine when to switch antenna
	 * when using software diversity.
	 */
	int rssi_history;

	/*
	 * Current RSSI average of the currently active antenna.
	 * Similar to the avg_rssi in the link_qual structure
	 * this value is updated by using the walking average.
	 */
	struct ewma_rssi rssi_ant;
};

/*
 * To optimize the quality of the link we need to store
 * the quality of received frames and periodically
 * optimize the link.
 */
struct link {
	/*
	 * Link tuner counter
	 * The number of times the link has been tuned
	 * since the radio has been switched on.
	 */
	uint32_t count;

	/*
	 * Quality measurement values.
	 */
	struct link_qual qual;

	/*
	 * TX/RX antenna setup.
	 */
	struct link_ant ant;

	/*
	 * Currently active average RSSI value
	 */
	struct ewma_rssi avg_rssi;
};


struct rt2x00_dev {
    /*
     * Libusb device handle; this replaces the kernel pci/usb/etc combo
     * device structure
     */
    struct libusb_device_handle *dev;

    /*
     * Base libusb device, used to open the handle and query the endpoints, 
     * etc.
     */
    struct libusb_device *base_dev;

	/*
	 * Libusb context
	 */
	struct libusb_context *libusb_context;

	/*
	 * control synchronizer
	 */
	pthread_mutex_t usb_control_mutex;
	pthread_cond_t usb_control_cond;
    bool usb_command_complete;

	/*
	 * userspace usb context
	 */
	void *userspace_context;

    /*
     * Reverse map to userspace wifi device
     */
    void *userspace_dev;

    /*
     * USB interface and endpoints
     */
    unsigned int usb_interface_num;
    unsigned int usb_bulk_in_endp;
    unsigned int usb_bulk_out_endp;

	/*
	 * Device state flags.
	 * In these flags the current status is stored.
	 * Access to these flags should occur atomically.
	 */
	unsigned long flags;

	/*
	 * Device capabiltiy flags.
	 * In these flags the device/driver capabilities are stored.
	 * Access to these flags should occur non-atomically.
	 */
	unsigned long cap_flags;

    unsigned int num_proto_errs;

    /*
     * Options pointer
     */
    const struct rt2x00_ops *ops;

	/*
	 * Chipset identification.
	 */
	struct rt2x00_chip chip;

	/*
	 * hw capability specifications.
	 */
	struct hw_mode_spec spec;

	/*
	 * This is the default TX/RX antenna setup as indicated
	 * by the device's EEPROM.
	 */
	struct antenna_setup default_ant;

	/*
	 * Register pointers
	 * csr.cache: CSR cache for usb_control_msg. (USB)
	 */
	union csr {
		void *cache;
	} csr;

    pthread_mutex_t csr_mutex;

	/*
	 * EEPROM data.
	 */
	___le16 *eeprom;

	/*
	 * Active RF register values.
	 * These are stored here so we don't need
	 * to read the rf registers and can directly
	 * use this value instead.
	 * This field should be accessed by using
	 * rt2x00_rf_read() and rt2x00_rf_write().
	 */
	uint32_t *rf;

	/*
     * Last set channel data
	 */
	int rf_channel;
    enum nl80211_band rf_band;

	/*
	 * Driver data.
	 */
	void *drv_data;

	/*
	 * IEEE80211 control structure.
	 */
	struct ieee80211_supported_band bands[NUM_NL80211_BANDS];
	enum nl80211_band curr_band;
	int curr_freq;

	/*
	 * LNA gain
	 */
	short lna_gain;

	/*
	 * Current TX power value.
	 */
	uint16_t tx_power;

	/*
	 * Rssi <-> Dbm offset
	 */
	uint8_t rssi_offset;

	/*
	 * Frequency offset.
	 */
	uint8_t freq_offset;

    /*
     * LED reg cache
     */
	uint16_t led_mcu_reg;

    /* 
     * MAC address
     */
    uint8_t *mac;

    /*
     * station count (should just be 1)
     */
    int intf_sta_count;

	/*
	 * Link quality
	 */
	struct link link;

	/*
	 * Rehomed from the queue definition, the tx and rx header sizes
	 */
	short unsigned int rxwi_size;
	short unsigned int txwi_size;

    /*
     * Control transfer and buffer cache
     */
    struct libusb_transfer *control_transfer;
    unsigned char *control_transfer_buffer;
    size_t control_transfer_buffer_sz;
};

static inline void rt2x00dev_control_cb(struct libusb_transfer *transfer) {
	struct rt2x00_dev *rt2x00dev = (struct rt2x00_dev *) transfer->user_data;

    pthread_mutex_lock(&rt2x00dev->usb_control_mutex);
    rt2x00dev->usb_command_complete = true;
	pthread_cond_signal(&rt2x00dev->usb_control_cond);
    pthread_mutex_unlock(&rt2x00dev->usb_control_mutex);
}

/*
 * rt2x00lib callback functions.
 */
struct rt2x00lib_ops {
	/*
	 * TX status tasklet handler.
	 */
	void (*txstatus_tasklet) (unsigned long data);
	void (*pretbtt_tasklet) (unsigned long data);
	void (*tbtt_tasklet) (unsigned long data);
	void (*rxdone_tasklet) (unsigned long data);
	void (*autowake_tasklet) (unsigned long data);

	/*
	 * Device init handlers.
	 */
	int (*probe_hw) (struct rt2x00_dev *rt2x00dev);
	char *(*get_firmware_name) (struct rt2x00_dev *rt2x00dev);
	int (*check_firmware) (struct rt2x00_dev *rt2x00dev,
			       const uint8_t *data, const size_t len);
	int (*load_firmware) (struct rt2x00_dev *rt2x00dev,
			      const uint8_t *data, const size_t len);

	/*
	 * Device initialization/deinitialization handlers.
	 */
	int (*initialize) (struct rt2x00_dev *rt2x00dev);
	void (*uninitialize) (struct rt2x00_dev *rt2x00dev);

    /*
     * Modified queue commands for userspace; take a device
     * not a queue and only set the rx registers
     */
    void (*start_queue) (struct rt2x00_dev *rt2x00dev);
    void (*stop_queue) (struct rt2x00_dev *rt2x00dev);

	/*
	 * Radio control handlers.
	 */
	int (*set_device_state) (struct rt2x00_dev *rt2x00dev,
				 enum dev_state state);
	int (*rfkill_poll) (struct rt2x00_dev *rt2x00dev);
	void (*link_stats) (struct rt2x00_dev *rt2x00dev,
			    struct link_qual *qual);
	void (*reset_tuner) (struct rt2x00_dev *rt2x00dev,
			     struct link_qual *qual);
	void (*link_tuner) (struct rt2x00_dev *rt2x00dev,
			    struct link_qual *qual, const uint32_t count);
	void (*gain_calibration) (struct rt2x00_dev *rt2x00dev);
	void (*vco_calibration) (struct rt2x00_dev *rt2x00dev);

	/*
	 * RX control handlers
	 */
	void (*fill_rxdone) (struct queue_entry *entry,
			     struct rxdone_entry_desc *rxdesc);

	/*
	 * Configuration handlers.
	 */
	int (*config_shared_key) (struct rt2x00_dev *rt2x00dev,
				  struct rt2x00lib_crypto *crypto,
				  struct ieee80211_key_conf *key);
	int (*config_pairwise_key) (struct rt2x00_dev *rt2x00dev,
				    struct rt2x00lib_crypto *crypto,
				    struct ieee80211_key_conf *key);
	void (*config_filter) (struct rt2x00_dev *rt2x00dev,
			       const unsigned int filter_flags);
	void (*config_intf) (struct rt2x00_dev *rt2x00dev,
			     struct rt2x00_intf *intf,
			     struct rt2x00intf_conf *conf,
			     const unsigned int flags);
#define CONFIG_UPDATE_TYPE		( 1 << 1 )
#define CONFIG_UPDATE_MAC		( 1 << 2 )
#define CONFIG_UPDATE_BSSID		( 1 << 3 )

	void (*config_erp) (struct rt2x00_dev *rt2x00dev,
			    struct rt2x00lib_erp *erp,
			    uint32_t changed);
	void (*config_ant) (struct rt2x00_dev *rt2x00dev,
			    struct antenna_setup *ant);
	void (*config) (struct rt2x00_dev *rt2x00dev,
			struct rt2x00lib_conf *libconf,
			const unsigned int changed_flags);
	int (*sta_add) (struct rt2x00_dev *rt2x00dev,
			struct ieee80211_vif *vif,
			struct ieee80211_sta *sta);
	int (*sta_remove) (struct rt2x00_dev *rt2x00dev,
			   struct ieee80211_sta *sta);
};

/*
 * rt2x00 driver callback operation structure.
 */
/*
 * Modified to remove 80211 ops and queues since we don't use them
 * in the userspace implementation
 */
struct rt2x00_ops {
	const char *name;
	const unsigned int drv_data_size;
	const unsigned int max_ap_intf;
	const unsigned int eeprom_size;
	const unsigned int rf_size;
	const unsigned int tx_queues;
	const struct rt2x00lib_ops *lib;
	const void *drv;
#ifdef CONFIG_RT2X00_LIB_DEBUGFS
	const struct rt2x00debug *debugfs;
#endif /* CONFIG_RT2X00_LIB_DEBUGFS */
};

/*
 * Register defines.
 * Some registers require multiple attempts before success,
 * in those cases REGISTER_BUSY_COUNT attempts should be
 * taken with a REGISTER_BUSY_DELAY interval. Due to USB
 * bus delays, we do not have to loop so many times to wait
 * for valid register value on that bus.
 */
#define REGISTER_BUSY_COUNT	100
#define REGISTER_USB_BUSY_COUNT 20
#define REGISTER_BUSY_DELAY	100

/*
 * Chipset handlers
 */
static inline void rt2x00_set_chip(struct rt2x00_dev *rt2x00dev,
        const uint16_t rt, const uint16_t rf, const uint16_t rev) {
    rt2x00dev->chip.rt = rt;
    rt2x00dev->chip.rf = rf;
    rt2x00dev->chip.rev = rev;

    rt2x00_info(rt2x00dev, "Chipset detected - rt: %04x, rf: %04x, rev: %04x\n",
            rt2x00dev->chip.rt, rt2x00dev->chip.rf,
            rt2x00dev->chip.rev);
}

static inline void rt2x00_set_rt(struct rt2x00_dev *rt2x00dev,
        const uint16_t rt, const uint16_t rev) {
    rt2x00dev->chip.rt = rt;
    rt2x00dev->chip.rev = rev;

    rt2x00_info(rt2x00dev, "RT chipset %04x, rev %04x detected\n",
            rt2x00dev->chip.rt, rt2x00dev->chip.rev);
}

static inline void rt2x00_set_rf(struct rt2x00_dev *rt2x00dev, const uint16_t rf) {
    rt2x00dev->chip.rf = rf;

    rt2x00_info(rt2x00dev, "RF chipset %04x detected\n",
            rt2x00dev->chip.rf);
}

static inline bool rt2x00_rt(struct rt2x00_dev *rt2x00dev, const uint16_t rt) {
    return (rt2x00dev->chip.rt == rt);
}

static inline bool rt2x00_rf(struct rt2x00_dev *rt2x00dev, const uint16_t rf) {
    return (rt2x00dev->chip.rf == rf);
}

static inline uint16_t rt2x00_rev(struct rt2x00_dev *rt2x00dev) {
    return rt2x00dev->chip.rev;
}

static inline bool rt2x00_rt_rev(struct rt2x00_dev *rt2x00dev,
        const uint16_t rt, const uint16_t rev) {
    return (rt2x00_rt(rt2x00dev, rt) && rt2x00_rev(rt2x00dev) == rev);
}

static inline bool rt2x00_rt_rev_lt(struct rt2x00_dev *rt2x00dev,
        const uint16_t rt, const uint16_t rev) {
    return (rt2x00_rt(rt2x00dev, rt) && rt2x00_rev(rt2x00dev) < rev);
}

static inline bool rt2x00_rt_rev_gte(struct rt2x00_dev *rt2x00dev,
        const uint16_t rt, const uint16_t rev) {
    return (rt2x00_rt(rt2x00dev, rt) && rt2x00_rev(rt2x00dev) >= rev);
}

static inline void rt2x00_set_chip_intf(struct rt2x00_dev *rt2x00dev,
        enum rt2x00_chip_intf intf) {
    rt2x00dev->chip.intf = intf;
}

static inline bool rt2x00_intf(struct rt2x00_dev *rt2x00dev,
        enum rt2x00_chip_intf intf) {
    return (rt2x00dev->chip.intf == intf);
}

static inline bool rt2x00_is_pci(struct rt2x00_dev *rt2x00dev) {
    return rt2x00_intf(rt2x00dev, RT2X00_CHIP_INTF_PCI) ||
        rt2x00_intf(rt2x00dev, RT2X00_CHIP_INTF_PCIE);
}

static inline bool rt2x00_is_pcie(struct rt2x00_dev *rt2x00dev) {
    return rt2x00_intf(rt2x00dev, RT2X00_CHIP_INTF_PCIE);
}

static inline bool rt2x00_is_usb(struct rt2x00_dev *rt2x00dev) {
    return rt2x00_intf(rt2x00dev, RT2X00_CHIP_INTF_USB);
}

static inline bool rt2x00_is_soc(struct rt2x00_dev *rt2x00dev) {
    return rt2x00_intf(rt2x00dev, RT2X00_CHIP_INTF_SOC);
}

/* Helpers for capability flags */

static inline bool
rt2x00_has_cap_flag(struct rt2x00_dev *rt2x00dev,
		    enum rt2x00_capability_flags cap_flag)
{
	return test_bit(cap_flag, &rt2x00dev->cap_flags);
}

static inline bool
rt2x00_has_cap_hw_crypto(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_HW_CRYPTO);
}

static inline bool
rt2x00_has_cap_power_limit(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_POWER_LIMIT);
}

static inline bool
rt2x00_has_cap_control_filters(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_CONTROL_FILTERS);
}

static inline bool
rt2x00_has_cap_control_filter_pspoll(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_CONTROL_FILTER_PSPOLL);
}

static inline bool
rt2x00_has_cap_pre_tbtt_interrupt(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_PRE_TBTT_INTERRUPT);
}

static inline bool
rt2x00_has_cap_link_tuning(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_LINK_TUNING);
}

static inline bool
rt2x00_has_cap_frame_type(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_FRAME_TYPE);
}

static inline bool
rt2x00_has_cap_rf_sequence(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_RF_SEQUENCE);
}

static inline bool
rt2x00_has_cap_external_lna_a(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_EXTERNAL_LNA_A);
}

static inline bool
rt2x00_has_cap_external_lna_bg(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_EXTERNAL_LNA_BG);
}

static inline bool
rt2x00_has_cap_double_antenna(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_DOUBLE_ANTENNA);
}

static inline bool
rt2x00_has_cap_bt_coexist(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_BT_COEXIST);
}

static inline bool
rt2x00_has_cap_vco_recalibration(struct rt2x00_dev *rt2x00dev)
{
	return rt2x00_has_cap_flag(rt2x00dev, CAPABILITY_VCO_RECALIBRATION);
}

/*
 * Generic EEPROM access. The EEPROM is being accessed by word or byte index.
 */
static inline void *rt2x00_eeprom_addr(struct rt2x00_dev *rt2x00dev,
        const unsigned int word) {
    return (void *)&rt2x00dev->eeprom[word];
}

static inline uint16_t rt2x00_eeprom_read(struct rt2x00_dev *rt2x00dev,
        const unsigned int word) {
    return le16_to_cpu(rt2x00dev->eeprom[word]);
}

static inline void rt2x00_eeprom_write(struct rt2x00_dev *rt2x00dev,
        const unsigned int word, uint16_t data) {
    rt2x00dev->eeprom[word] = cpu_to_le16(data);
}

static inline uint8_t rt2x00_eeprom_byte(struct rt2x00_dev *rt2x00dev,
        const unsigned int byte) {
    return *(((uint8_t *)rt2x00dev->eeprom) + byte);
}

/*
 * Generic RF access.
 * The RF is being accessed by word index.
 */
static inline uint32_t rt2x00_rf_read(struct rt2x00_dev *rt2x00dev,
				 const unsigned int word)
{
	BUG_ON(word < 1 || word > rt2x00dev->ops->rf_size / sizeof(uint32_t));
	return rt2x00dev->rf[word - 1];
}

static inline void rt2x00_rf_write(struct rt2x00_dev *rt2x00dev,
				   const unsigned int word, uint32_t data)
{
	BUG_ON(word < 1 || word > rt2x00dev->ops->rf_size / sizeof(uint32_t));
	rt2x00dev->rf[word - 1] = data;
}

#define DATA_FRAME_SIZE     2432

#define RT2X00_L2PAD_SIZE   8
#define L2PAD_SIZE(__hdrlen)	(-(__hdrlen) & 3)

#endif /* ifndef RT2X00_H */

