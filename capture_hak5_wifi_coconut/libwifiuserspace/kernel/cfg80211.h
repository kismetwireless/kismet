/*
 * 802.11 device and configuration interface
 *
 * Copyright 2006-2010	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2013-2014 Intel Mobile Communications GmbH
 * Copyright 2015-2017	Intel Deutschland GmbH
 * Copyright (C) 2018-2019 Intel Corporation
 */

/*
 * Userspace port (c) 2019 Hak5
 */

#ifndef __USERSPACE_CFG80211_H__
#define __USERSPACE_CFG80211_H__ 

#include <stdbool.h>

#include "kernel/bits.h"
#include "kernel/types.h"
#include "kernel/nl80211.h"
#include "kernel/ieee80211.h"

/**
 * struct ieee80211_channel - channel definition
 *
 * This structure describes a single channel for use
 * with cfg80211.
 *
 * @center_freq: center frequency in MHz
 * @hw_value: hardware-specific value for the channel
 * @flags: channel flags from &enum ieee80211_channel_flags.
 * @orig_flags: channel flags at registration time, used by regulatory
 *	code to support devices with additional restrictions
 * @band: band this channel belongs to.
 * @max_antenna_gain: maximum antenna gain in dBi
 * @max_power: maximum transmission power (in dBm)
 * @max_reg_power: maximum regulatory transmission power (in dBm)
 * @beacon_found: helper to regulatory code to indicate when a beacon
 *	has been found on this channel. Use regulatory_hint_found_beacon()
 *	to enable this, this is useful only on 5 GHz band.
 * @orig_mag: internal use
 * @orig_mpwr: internal use
 * @dfs_state: current state of this channel. Only relevant if radar is required
 *	on this channel.
 * @dfs_state_entered: timestamp (jiffies) when the dfs state was entered.
 * @dfs_cac_ms: DFS CAC time in milliseconds, this is valid for DFS channels.
 */
struct ieee80211_channel {
	enum nl80211_band band;
	u32 center_freq;
	u16 hw_value;
	u32 flags;
	int max_antenna_gain;
	int max_power;
	int max_reg_power;
	bool beacon_found;
	u32 orig_flags;
	int orig_mag, orig_mpwr;
	enum nl80211_dfs_state dfs_state;
	unsigned long dfs_state_entered;
	unsigned int dfs_cac_ms;
};

/**
 * struct cfg80211_chan_def - channel definition
 * @chan: the (control) channel
 * @width: channel width
 * @center_freq1: center frequency of first segment
 * @center_freq2: center frequency of second segment
 *	(only with 80+80 MHz)
 */
struct cfg80211_chan_def {
	struct ieee80211_channel *chan;
	enum nl80211_chan_width width;
	u32 center_freq1;
	u32 center_freq2;
}
;
/**
 * struct ieee80211_rate - bitrate definition
 *
 * This structure describes a bitrate that an 802.11 PHY can
 * operate with. The two values @hw_value and @hw_value_short
 * are only for driver use when pointers to this structure are
 * passed around.
 *
 * @flags: rate-specific flags
 * @bitrate: bitrate in units of 100 Kbps
 * @hw_value: driver/hardware value for this rate
 * @hw_value_short: driver/hardware value for this rate when
 *	short preamble is used
 */
struct ieee80211_rate {
	u32 flags;
	u16 bitrate;
	u16 hw_value, hw_value_short;
};

/**
 * struct ieee80211_sta_ht_cap - STA's HT capabilities
 *
 * This structure describes most essential parameters needed
 * to describe 802.11n HT capabilities for an STA.
 *
 * @ht_supported: is HT supported by the STA
 * @cap: HT capabilities map as described in 802.11n spec
 * @ampdu_factor: Maximum A-MPDU length factor
 * @ampdu_density: Minimum A-MPDU spacing
 * @mcs: Supported MCS rates
 */
struct ieee80211_sta_ht_cap {
	u16 cap; /* use IEEE80211_HT_CAP_ */
	bool ht_supported;
	u8 ampdu_factor;
	u8 ampdu_density;
	struct ieee80211_mcs_info mcs;
};

/**
 * struct ieee80211_sta_vht_cap - STA's VHT capabilities
 *
 * This structure describes most essential parameters needed
 * to describe 802.11ac VHT capabilities for an STA.
 *
 * @vht_supported: is VHT supported by the STA
 * @cap: VHT capabilities map as described in 802.11ac spec
 * @vht_mcs: Supported VHT MCS rates
 */
struct ieee80211_sta_vht_cap {
	bool vht_supported;
	u32 cap; /* use IEEE80211_VHT_CAP_ */
	struct ieee80211_vht_mcs_info vht_mcs;
};

#define IEEE80211_HE_PPE_THRES_MAX_LEN		25

/**
 * struct ieee80211_sta_he_cap - STA's HE capabilities
 *
 * This structure describes most essential parameters needed
 * to describe 802.11ax HE capabilities for a STA.
 *
 * @has_he: true iff HE data is valid.
 * @he_cap_elem: Fixed portion of the HE capabilities element.
 * @he_mcs_nss_supp: The supported NSS/MCS combinations.
 * @ppe_thres: Holds the PPE Thresholds data.
 */
struct ieee80211_sta_he_cap {
	bool has_he;
	struct ieee80211_he_cap_elem he_cap_elem;
	struct ieee80211_he_mcs_nss_supp he_mcs_nss_supp;
	u8 ppe_thres[IEEE80211_HE_PPE_THRES_MAX_LEN];
};

#define IEEE80211_MAX_CHAINS            4

/**
 * enum station_info_rate_flags - bitrate info flags
 *
 * Used by the driver to indicate the specific rate transmission
 * type for 802.11n transmissions.
 *
 * @RATE_INFO_FLAGS_MCS: mcs field filled with HT MCS
 * @RATE_INFO_FLAGS_VHT_MCS: mcs field filled with VHT MCS
 * @RATE_INFO_FLAGS_SHORT_GI: 400ns guard interval
 * @RATE_INFO_FLAGS_60G: 60GHz MCS
 * @RATE_INFO_FLAGS_HE_MCS: HE MCS information
 */
enum rate_info_flags {
	RATE_INFO_FLAGS_MCS			= BIT(0),
	RATE_INFO_FLAGS_VHT_MCS			= BIT(1),
	RATE_INFO_FLAGS_SHORT_GI		= BIT(2),
	RATE_INFO_FLAGS_60G			= BIT(3),
	RATE_INFO_FLAGS_HE_MCS			= BIT(4),
};

/**
 * enum rate_info_bw - rate bandwidth information
 *
 * Used by the driver to indicate the rate bandwidth.
 *
 * @RATE_INFO_BW_5: 5 MHz bandwidth
 * @RATE_INFO_BW_10: 10 MHz bandwidth
 * @RATE_INFO_BW_20: 20 MHz bandwidth
 * @RATE_INFO_BW_40: 40 MHz bandwidth
 * @RATE_INFO_BW_80: 80 MHz bandwidth
 * @RATE_INFO_BW_160: 160 MHz bandwidth
 * @RATE_INFO_BW_HE_RU: bandwidth determined by HE RU allocation
 */
enum rate_info_bw {
	RATE_INFO_BW_20 = 0,
	RATE_INFO_BW_5,
	RATE_INFO_BW_10,
	RATE_INFO_BW_40,
	RATE_INFO_BW_80,
	RATE_INFO_BW_160,
	RATE_INFO_BW_HE_RU,
};

/**
 * struct rate_info - bitrate information
 *
 * Information about a receiving or transmitting bitrate
 *
 * @flags: bitflag of flags from &enum rate_info_flags
 * @mcs: mcs index if struct describes an HT/VHT/HE rate
 * @legacy: bitrate in 100kbit/s for 802.11abg
 * @nss: number of streams (VHT & HE only)
 * @bw: bandwidth (from &enum rate_info_bw)
 * @he_gi: HE guard interval (from &enum nl80211_he_gi)
 * @he_dcm: HE DCM value
 * @he_ru_alloc: HE RU allocation (from &enum nl80211_he_ru_alloc,
 *	only valid if bw is %RATE_INFO_BW_HE_RU)
 */
struct rate_info {
	u8 flags;
	u8 mcs;
	u16 legacy;
	u8 nss;
	u8 bw;
	u8 he_gi;
	u8 he_dcm;
	u8 he_ru_alloc;
};

/**
 * ieee80211_channel_to_frequency - convert channel number to frequency
 * @chan: channel number
 * @band: band, necessary due to channel number overlap
 * Return: The corresponding frequency (in MHz), or 0 if the conversion failed.
 */
int ieee80211_channel_to_frequency(int chan, enum nl80211_band band);

/**
 * ieee80211_frequency_to_channel - convert frequency to channel number
 * @freq: center frequency
 * Return: The corresponding channel, or 0 if the conversion failed.
 */
int ieee80211_frequency_to_channel(int freq);

/** 
 * Extract header length from raw packet 
 */
unsigned int ieee80211_get_hdrlen_from_buf(const uint8_t *buf, size_t len);

/**
 * enum ieee80211_rate_flags - rate flags
 *
 * Hardware/specification flags for rates. These are structured
 * in a way that allows using the same bitrate structure for
 * different bands/PHY modes.
 *
 * @IEEE80211_RATE_SHORT_PREAMBLE: Hardware can send with short
 *	preamble on this bitrate; only relevant in 2.4GHz band and
 *	with CCK rates.
 * @IEEE80211_RATE_MANDATORY_A: This bitrate is a mandatory rate
 *	when used with 802.11a (on the 5 GHz band); filled by the
 *	core code when registering the wiphy.
 * @IEEE80211_RATE_MANDATORY_B: This bitrate is a mandatory rate
 *	when used with 802.11b (on the 2.4 GHz band); filled by the
 *	core code when registering the wiphy.
 * @IEEE80211_RATE_MANDATORY_G: This bitrate is a mandatory rate
 *	when used with 802.11g (on the 2.4 GHz band); filled by the
 *	core code when registering the wiphy.
 * @IEEE80211_RATE_ERP_G: This is an ERP rate in 802.11g mode.
 * @IEEE80211_RATE_SUPPORTS_5MHZ: Rate can be used in 5 MHz mode
 * @IEEE80211_RATE_SUPPORTS_10MHZ: Rate can be used in 10 MHz mode
 */
enum ieee80211_rate_flags {
	IEEE80211_RATE_SHORT_PREAMBLE	= 1<<0,
	IEEE80211_RATE_MANDATORY_A	= 1<<1,
	IEEE80211_RATE_MANDATORY_B	= 1<<2,
	IEEE80211_RATE_MANDATORY_G	= 1<<3,
	IEEE80211_RATE_ERP_G		= 1<<4,
	IEEE80211_RATE_SUPPORTS_5MHZ	= 1<<5,
	IEEE80211_RATE_SUPPORTS_10MHZ	= 1<<6,
};

/**
 * struct ieee80211_supported_band - frequency band definition
 *
 * This structure describes a frequency band a wiphy
 * is able to operate in.
 *
 * @channels: Array of channels the hardware can operate in
 *	in this band.
 * @band: the band this structure represents
 * @n_channels: Number of channels in @channels
 * @bitrates: Array of bitrates the hardware can operate with
 *	in this band. Must be sorted to give a valid "supported
 *	rates" IE, i.e. CCK rates first, then OFDM.
 * @n_bitrates: Number of bitrates in @bitrates
 * @ht_cap: HT capabilities in this band
 * @vht_cap: VHT capabilities in this band
 * @n_iftype_data: number of iftype data entries
 * @iftype_data: interface type data entries.  Note that the bits in
 *	@types_mask inside this structure cannot overlap (i.e. only
 *	one occurrence of each type is allowed across all instances of
 *	iftype_data).
 */
struct ieee80211_supported_band {
	struct ieee80211_channel *channels;
	struct ieee80211_rate *bitrates;
	enum nl80211_band band;
	int n_channels;
	int n_bitrates;
	struct ieee80211_sta_ht_cap ht_cap;
	struct ieee80211_sta_vht_cap vht_cap;
	u16 n_iftype_data;
	const struct ieee80211_sband_iftype_data *iftype_data;
};

#endif /* ifndef USERSPACE_CFG80211_H */
