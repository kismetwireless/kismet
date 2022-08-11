/* SPDX-License-Identifier: GPL-2.0-only */

/*
 * mac80211 <-> driver interface
 *
 * Copyright 2002-2005, Devicescape Software, Inc.
 * Copyright 2006-2007	Jiri Benc <jbenc@suse.cz>
 * Copyright 2007-2010	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2013-2014  Intel Mobile Communications GmbH
 * Copyright (C) 2015 - 2017 Intel Deutschland GmbH
 * Copyright (C) 2018 - 2019 Intel Corporation
 */

/*
 * Userspace port (C) 2019 Hak5 Inc
 */

#ifndef __USERSPACE_MAC80211_H__
#define __USERSPACE_MAC80211_H__ 

#include <stdlib.h>

#include "bitops.h"
#include "bits.h"
#include "cfg80211.h"
#include "ieee80211.h"
#include "if_ether.h"
#include "kernel.h"
#include "nl80211.h"
#include "types.h"

/**
 * enum ieee80211_filter_flags - hardware filter flags
 *
 * These flags determine what the filter in hardware should be
 * programmed to let through and what should not be passed to the
 * stack. It is always safe to pass more frames than requested,
 * but this has negative impact on power consumption.
 *
 * @FIF_ALLMULTI: pass all multicast frames, this is used if requested
 *	by the user or if the hardware is not capable of filtering by
 *	multicast address.
 *
 * @FIF_FCSFAIL: pass frames with failed FCS (but you need to set the
 *	%RX_FLAG_FAILED_FCS_CRC for them)
 *
 * @FIF_PLCPFAIL: pass frames with failed PLCP CRC (but you need to set
 *	the %RX_FLAG_FAILED_PLCP_CRC for them
 *
 * @FIF_BCN_PRBRESP_PROMISC: This flag is set during scanning to indicate
 *	to the hardware that it should not filter beacons or probe responses
 *	by BSSID. Filtering them can greatly reduce the amount of processing
 *	mac80211 needs to do and the amount of CPU wakeups, so you should
 *	honour this flag if possible.
 *
 * @FIF_CONTROL: pass control frames (except for PS Poll) addressed to this
 *	station
 *
 * @FIF_OTHER_BSS: pass frames destined to other BSSes
 *
 * @FIF_PSPOLL: pass PS Poll frames
 *
 * @FIF_PROBE_REQ: pass probe request frames
 */
enum ieee80211_filter_flags {
	FIF_ALLMULTI		= 1<<1,
	FIF_FCSFAIL		= 1<<2,
	FIF_PLCPFAIL		= 1<<3,
	FIF_BCN_PRBRESP_PROMISC	= 1<<4,
	FIF_CONTROL		= 1<<5,
	FIF_OTHER_BSS		= 1<<6,
	FIF_PSPOLL		= 1<<7,
	FIF_PROBE_REQ		= 1<<8,
};

/**
 * struct ieee80211_key_conf - key information
 *
 * This key information is given by mac80211 to the driver by
 * the set_key() callback in &struct ieee80211_ops.
 *
 * @hw_key_idx: To be set by the driver, this is the key index the driver
 *	wants to be given when a frame is transmitted and needs to be
 *	encrypted in hardware.
 * @cipher: The key's cipher suite selector.
 * @tx_pn: PN used for TX keys, may be used by the driver as well if it
 *	needs to do software PN assignment by itself (e.g. due to TSO)
 * @flags: key flags, see &enum ieee80211_key_flags.
 * @keyidx: the key index (0-3)
 * @keylen: key material length
 * @key: key material. For ALG_TKIP the key is encoded as a 256-bit (32 byte)
 * 	data block:
 * 	- Temporal Encryption Key (128 bits)
 * 	- Temporal Authenticator Tx MIC Key (64 bits)
 * 	- Temporal Authenticator Rx MIC Key (64 bits)
 * @icv_len: The ICV length for this key type
 * @iv_len: The IV length for this key type
 */
struct ieee80211_key_conf {
	atomic64_t tx_pn;
	u32 cipher;
	u8 icv_len;
	u8 iv_len;
	u8 hw_key_idx;
	s8 keyidx;
	u16 flags;
	u8 keylen;
	u8 key[0];
};

/**
 * enum set_key_cmd - key command
 *
 * Used with the set_key() callback in &struct ieee80211_ops, this
 * indicates whether a key is being removed or added.
 *
 * @SET_KEY: a key is set
 * @DISABLE_KEY: a key must be disabled
 */
enum set_key_cmd {
	SET_KEY, DISABLE_KEY,
};

/**
 * enum ieee80211_smps_mode - spatial multiplexing power save mode
 *
 * @IEEE80211_SMPS_AUTOMATIC: automatic
 * @IEEE80211_SMPS_OFF: off
 * @IEEE80211_SMPS_STATIC: static
 * @IEEE80211_SMPS_DYNAMIC: dynamic
 * @IEEE80211_SMPS_NUM_MODES: internal, don't use
 */
enum ieee80211_smps_mode {
	IEEE80211_SMPS_AUTOMATIC,
	IEEE80211_SMPS_OFF,
	IEEE80211_SMPS_STATIC,
	IEEE80211_SMPS_DYNAMIC,

	/* keep last */
	IEEE80211_SMPS_NUM_MODES,
};


/**
 * struct ieee80211_conf - configuration of the device
 *
 * This struct indicates how the driver shall configure the hardware.
 *
 * @flags: configuration flags defined above
 *
 * @listen_interval: listen interval in units of beacon interval
 * @ps_dtim_period: The DTIM period of the AP we're connected to, for use
 *	in power saving. Power saving will not be enabled until a beacon
 *	has been received and the DTIM period is known.
 * @dynamic_ps_timeout: The dynamic powersave timeout (in ms), see the
 *	powersave documentation below. This variable is valid only when
 *	the CONF_PS flag is set.
 *
 * @power_level: requested transmit power (in dBm), backward compatibility
 *	value only that is set to the minimum of all interfaces
 *
 * @chandef: the channel definition to tune to
 * @radar_enabled: whether radar detection is enabled
 *
 * @long_frame_max_tx_count: Maximum number of transmissions for a "long" frame
 *	(a frame not RTS protected), called "dot11LongRetryLimit" in 802.11,
 *	but actually means the number of transmissions not the number of retries
 * @short_frame_max_tx_count: Maximum number of transmissions for a "short"
 *	frame, called "dot11ShortRetryLimit" in 802.11, but actually means the
 *	number of transmissions not the number of retries
 *
 * @smps_mode: spatial multiplexing powersave mode; note that
 *	%IEEE80211_SMPS_STATIC is used when the device is not
 *	configured for an HT channel.
 *	Note that this is only valid if channel contexts are not used,
 *	otherwise each channel context has the number of chains listed.
 */
struct ieee80211_conf {
	u32 flags;
	int power_level, dynamic_ps_timeout;

	u16 listen_interval;
	u8 ps_dtim_period;

	u8 long_frame_max_tx_count, short_frame_max_tx_count;

	struct cfg80211_chan_def chandef;
	bool radar_enabled;
	enum ieee80211_smps_mode smps_mode;
};

/**
 * enum ieee80211_hw_flags - hardware flags
 *
 * These flags are used to indicate hardware capabilities to
 * the stack. Generally, flags here should have their meaning
 * done in a way that the simplest hardware doesn't need setting
 * any particular flags. There are some exceptions to this rule,
 * however, so you are advised to review these flags carefully.
 *
 * @IEEE80211_HW_HAS_RATE_CONTROL:
 *	The hardware or firmware includes rate control, and cannot be
 *	controlled by the stack. As such, no rate control algorithm
 *	should be instantiated, and the TX rate reported to userspace
 *	will be taken from the TX status instead of the rate control
 *	algorithm.
 *	Note that this requires that the driver implement a number of
 *	callbacks so it has the correct information, it needs to have
 *	the @set_rts_threshold callback and must look at the BSS config
 *	@use_cts_prot for G/N protection, @use_short_slot for slot
 *	timing in 2.4 GHz and @use_short_preamble for preambles for
 *	CCK frames.
 *
 * @IEEE80211_HW_RX_INCLUDES_FCS:
 *	Indicates that received frames passed to the stack include
 *	the FCS at the end.
 *
 * @IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING:
 *	Some wireless LAN chipsets buffer broadcast/multicast frames
 *	for power saving stations in the hardware/firmware and others
 *	rely on the host system for such buffering. This option is used
 *	to configure the IEEE 802.11 upper layer to buffer broadcast and
 *	multicast frames when there are power saving stations so that
 *	the driver can fetch them with ieee80211_get_buffered_bc().
 *
 * @IEEE80211_HW_SIGNAL_UNSPEC:
 *	Hardware can provide signal values but we don't know its units. We
 *	expect values between 0 and @max_signal.
 *	If possible please provide dB or dBm instead.
 *
 * @IEEE80211_HW_SIGNAL_DBM:
 *	Hardware gives signal values in dBm, decibel difference from
 *	one milliwatt. This is the preferred method since it is standardized
 *	between different devices. @max_signal does not need to be set.
 *
 * @IEEE80211_HW_SPECTRUM_MGMT:
 * 	Hardware supports spectrum management defined in 802.11h
 * 	Measurement, Channel Switch, Quieting, TPC
 *
 * @IEEE80211_HW_AMPDU_AGGREGATION:
 *	Hardware supports 11n A-MPDU aggregation.
 *
 * @IEEE80211_HW_SUPPORTS_PS:
 *	Hardware has power save support (i.e. can go to sleep).
 *
 * @IEEE80211_HW_PS_NULLFUNC_STACK:
 *	Hardware requires nullfunc frame handling in stack, implies
 *	stack support for dynamic PS.
 *
 * @IEEE80211_HW_SUPPORTS_DYNAMIC_PS:
 *	Hardware has support for dynamic PS.
 *
 * @IEEE80211_HW_MFP_CAPABLE:
 *	Hardware supports management frame protection (MFP, IEEE 802.11w).
 *
 * @IEEE80211_HW_REPORTS_TX_ACK_STATUS:
 *	Hardware can provide ack status reports of Tx frames to
 *	the stack.
 *
 * @IEEE80211_HW_CONNECTION_MONITOR:
 *	The hardware performs its own connection monitoring, including
 *	periodic keep-alives to the AP and probing the AP on beacon loss.
 *
 * @IEEE80211_HW_NEED_DTIM_BEFORE_ASSOC:
 *	This device needs to get data from beacon before association (i.e.
 *	dtim_period).
 *
 * @IEEE80211_HW_SUPPORTS_PER_STA_GTK: The device's crypto engine supports
 *	per-station GTKs as used by IBSS RSN or during fast transition. If
 *	the device doesn't support per-station GTKs, but can be asked not
 *	to decrypt group addressed frames, then IBSS RSN support is still
 *	possible but software crypto will be used. Advertise the wiphy flag
 *	only in that case.
 *
 * @IEEE80211_HW_AP_LINK_PS: When operating in AP mode the device
 *	autonomously manages the PS status of connected stations. When
 *	this flag is set mac80211 will not trigger PS mode for connected
 *	stations based on the PM bit of incoming frames.
 *	Use ieee80211_start_ps()/ieee8021_end_ps() to manually configure
 *	the PS mode of connected stations.
 *
 * @IEEE80211_HW_TX_AMPDU_SETUP_IN_HW: The device handles TX A-MPDU session
 *	setup strictly in HW. mac80211 should not attempt to do this in
 *	software.
 *
 * @IEEE80211_HW_WANT_MONITOR_VIF: The driver would like to be informed of
 *	a virtual monitor interface when monitor interfaces are the only
 *	active interfaces.
 *
 * @IEEE80211_HW_NO_AUTO_VIF: The driver would like for no wlanX to
 *	be created.  It is expected user-space will create vifs as
 *	desired (and thus have them named as desired).
 *
 * @IEEE80211_HW_SW_CRYPTO_CONTROL: The driver wants to control which of the
 *	crypto algorithms can be done in software - so don't automatically
 *	try to fall back to it if hardware crypto fails, but do so only if
 *	the driver returns 1. This also forces the driver to advertise its
 *	supported cipher suites.
 *
 * @IEEE80211_HW_SUPPORT_FAST_XMIT: The driver/hardware supports fast-xmit,
 *	this currently requires only the ability to calculate the duration
 *	for frames.
 *
 * @IEEE80211_HW_QUEUE_CONTROL: The driver wants to control per-interface
 *	queue mapping in order to use different queues (not just one per AC)
 *	for different virtual interfaces. See the doc section on HW queue
 *	control for more details.
 *
 * @IEEE80211_HW_SUPPORTS_RC_TABLE: The driver supports using a rate
 *	selection table provided by the rate control algorithm.
 *
 * @IEEE80211_HW_P2P_DEV_ADDR_FOR_INTF: Use the P2P Device address for any
 *	P2P Interface. This will be honoured even if more than one interface
 *	is supported.
 *
 * @IEEE80211_HW_TIMING_BEACON_ONLY: Use sync timing from beacon frames
 *	only, to allow getting TBTT of a DTIM beacon.
 *
 * @IEEE80211_HW_SUPPORTS_HT_CCK_RATES: Hardware supports mixing HT/CCK rates
 *	and can cope with CCK rates in an aggregation session (e.g. by not
 *	using aggregation for such frames.)
 *
 * @IEEE80211_HW_CHANCTX_STA_CSA: Support 802.11h based channel-switch (CSA)
 *	for a single active channel while using channel contexts. When support
 *	is not enabled the default action is to disconnect when getting the
 *	CSA frame.
 *
 * @IEEE80211_HW_SUPPORTS_CLONED_SKBS: The driver will never modify the payload
 *	or tailroom of TX skbs without copying them first.
 *
 * @IEEE80211_HW_SINGLE_SCAN_ON_ALL_BANDS: The HW supports scanning on all bands
 *	in one command, mac80211 doesn't have to run separate scans per band.
 *
 * @IEEE80211_HW_TDLS_WIDER_BW: The device/driver supports wider bandwidth
 *	than then BSS bandwidth for a TDLS link on the base channel.
 *
 * @IEEE80211_HW_SUPPORTS_AMSDU_IN_AMPDU: The driver supports receiving A-MSDUs
 *	within A-MPDU.
 *
 * @IEEE80211_HW_BEACON_TX_STATUS: The device/driver provides TX status
 *	for sent beacons.
 *
 * @IEEE80211_HW_NEEDS_UNIQUE_STA_ADDR: Hardware (or driver) requires that each
 *	station has a unique address, i.e. each station entry can be identified
 *	by just its MAC address; this prevents, for example, the same station
 *	from connecting to two virtual AP interfaces at the same time.
 *
 * @IEEE80211_HW_SUPPORTS_REORDERING_BUFFER: Hardware (or driver) manages the
 *	reordering buffer internally, guaranteeing mac80211 receives frames in
 *	order and does not need to manage its own reorder buffer or BA session
 *	timeout.
 *
 * @IEEE80211_HW_USES_RSS: The device uses RSS and thus requires parallel RX,
 *	which implies using per-CPU station statistics.
 *
 * @IEEE80211_HW_TX_AMSDU: Hardware (or driver) supports software aggregated
 *	A-MSDU frames. Requires software tx queueing and fast-xmit support.
 *	When not using minstrel/minstrel_ht rate control, the driver must
 *	limit the maximum A-MSDU size based on the current tx rate by setting
 *	max_rc_amsdu_len in struct ieee80211_sta.
 *
 * @IEEE80211_HW_TX_FRAG_LIST: Hardware (or driver) supports sending frag_list
 *	skbs, needed for zero-copy software A-MSDU.
 *
 * @IEEE80211_HW_REPORTS_LOW_ACK: The driver (or firmware) reports low ack event
 *	by ieee80211_report_low_ack() based on its own algorithm. For such
 *	drivers, mac80211 packet loss mechanism will not be triggered and driver
 *	is completely depending on firmware event for station kickout.
 *
 * @IEEE80211_HW_SUPPORTS_TX_FRAG: Hardware does fragmentation by itself.
 *	The stack will not do fragmentation.
 *	The callback for @set_frag_threshold should be set as well.
 *
 * @IEEE80211_HW_SUPPORTS_TDLS_BUFFER_STA: Hardware supports buffer STA on
 *	TDLS links.
 *
 * @IEEE80211_HW_DEAUTH_NEED_MGD_TX_PREP: The driver requires the
 *	mgd_prepare_tx() callback to be called before transmission of a
 *	deauthentication frame in case the association was completed but no
 *	beacon was heard. This is required in multi-channel scenarios, where the
 *	virtual interface might not be given air time for the transmission of
 *	the frame, as it is not synced with the AP/P2P GO yet, and thus the
 *	deauthentication frame might not be transmitted.
 *
 * @IEEE80211_HW_DOESNT_SUPPORT_QOS_NDP: The driver (or firmware) doesn't
 *	support QoS NDP for AP probing - that's most likely a driver bug.
 *
 * @IEEE80211_HW_BUFF_MMPDU_TXQ: use the TXQ for bufferable MMPDUs, this of
 *	course requires the driver to use TXQs to start with.
 *
 * @IEEE80211_HW_SUPPORTS_VHT_EXT_NSS_BW: (Hardware) rate control supports VHT
 *	extended NSS BW (dot11VHTExtendedNSSBWCapable). This flag will be set if
 *	the selected rate control algorithm sets %RATE_CTRL_CAPA_VHT_EXT_NSS_BW
 *	but if the rate control is built-in then it must be set by the driver.
 *	See also the documentation for that flag.
 *
 * @IEEE80211_HW_STA_MMPDU_TXQ: use the extra non-TID per-station TXQ for all
 *	MMPDUs on station interfaces. This of course requires the driver to use
 *	TXQs to start with.
 *
 * @IEEE80211_HW_TX_STATUS_NO_AMPDU_LEN: Driver does not report accurate A-MPDU
 *	length in tx status information
 *
 * @IEEE80211_HW_SUPPORTS_MULTI_BSSID: Hardware supports multi BSSID
 *
 * @IEEE80211_HW_SUPPORTS_ONLY_HE_MULTI_BSSID: Hardware supports multi BSSID
 *	only for HE APs. Applies if @IEEE80211_HW_SUPPORTS_MULTI_BSSID is set.
 *
 * @IEEE80211_HW_EXT_KEY_ID_NATIVE: Driver and hardware are supporting Extended
 *	Key ID and can handle two unicast keys per station for Rx and Tx.
 *
 * @NUM_IEEE80211_HW_FLAGS: number of hardware flags, used for sizing arrays
 */
enum ieee80211_hw_flags {
	IEEE80211_HW_HAS_RATE_CONTROL,
	IEEE80211_HW_RX_INCLUDES_FCS,
	IEEE80211_HW_HOST_BROADCAST_PS_BUFFERING,
	IEEE80211_HW_SIGNAL_UNSPEC,
	IEEE80211_HW_SIGNAL_DBM,
	IEEE80211_HW_NEED_DTIM_BEFORE_ASSOC,
	IEEE80211_HW_SPECTRUM_MGMT,
	IEEE80211_HW_AMPDU_AGGREGATION,
	IEEE80211_HW_SUPPORTS_PS,
	IEEE80211_HW_PS_NULLFUNC_STACK,
	IEEE80211_HW_SUPPORTS_DYNAMIC_PS,
	IEEE80211_HW_MFP_CAPABLE,
	IEEE80211_HW_WANT_MONITOR_VIF,
	IEEE80211_HW_NO_AUTO_VIF,
	IEEE80211_HW_SW_CRYPTO_CONTROL,
	IEEE80211_HW_SUPPORT_FAST_XMIT,
	IEEE80211_HW_REPORTS_TX_ACK_STATUS,
	IEEE80211_HW_CONNECTION_MONITOR,
	IEEE80211_HW_QUEUE_CONTROL,
	IEEE80211_HW_SUPPORTS_PER_STA_GTK,
	IEEE80211_HW_AP_LINK_PS,
	IEEE80211_HW_TX_AMPDU_SETUP_IN_HW,
	IEEE80211_HW_SUPPORTS_RC_TABLE,
	IEEE80211_HW_P2P_DEV_ADDR_FOR_INTF,
	IEEE80211_HW_TIMING_BEACON_ONLY,
	IEEE80211_HW_SUPPORTS_HT_CCK_RATES,
	IEEE80211_HW_CHANCTX_STA_CSA,
	IEEE80211_HW_SUPPORTS_CLONED_SKBS,
	IEEE80211_HW_SINGLE_SCAN_ON_ALL_BANDS,
	IEEE80211_HW_TDLS_WIDER_BW,
	IEEE80211_HW_SUPPORTS_AMSDU_IN_AMPDU,
	IEEE80211_HW_BEACON_TX_STATUS,
	IEEE80211_HW_NEEDS_UNIQUE_STA_ADDR,
	IEEE80211_HW_SUPPORTS_REORDERING_BUFFER,
	IEEE80211_HW_USES_RSS,
	IEEE80211_HW_TX_AMSDU,
	IEEE80211_HW_TX_FRAG_LIST,
	IEEE80211_HW_REPORTS_LOW_ACK,
	IEEE80211_HW_SUPPORTS_TX_FRAG,
	IEEE80211_HW_SUPPORTS_TDLS_BUFFER_STA,
	IEEE80211_HW_DEAUTH_NEED_MGD_TX_PREP,
	IEEE80211_HW_DOESNT_SUPPORT_QOS_NDP,
	IEEE80211_HW_BUFF_MMPDU_TXQ,
	IEEE80211_HW_SUPPORTS_VHT_EXT_NSS_BW,
	IEEE80211_HW_STA_MMPDU_TXQ,
	IEEE80211_HW_TX_STATUS_NO_AMPDU_LEN,
	IEEE80211_HW_SUPPORTS_MULTI_BSSID,
	IEEE80211_HW_SUPPORTS_ONLY_HE_MULTI_BSSID,
	IEEE80211_HW_EXT_KEY_ID_NATIVE,

	/* keep last, obviously */
	NUM_IEEE80211_HW_FLAGS
};

/**
 * struct ieee80211_hw - hardware information and state
 *
 * This structure contains the configuration and hardware
 * information for an 802.11 PHY.
 *
 * @wiphy: This points to the &struct wiphy allocated for this
 *	802.11 PHY. You must fill in the @perm_addr and @dev
 *	members of this structure using SET_IEEE80211_DEV()
 *	and SET_IEEE80211_PERM_ADDR(). Additionally, all supported
 *	bands (with channels, bitrates) are registered here.
 *
 * @conf: &struct ieee80211_conf, device configuration, don't use.
 *
 * @priv: pointer to private area that was allocated for driver use
 *	along with this structure.
 *
 * @flags: hardware flags, see &enum ieee80211_hw_flags.
 *
 * @extra_tx_headroom: headroom to reserve in each transmit skb
 *	for use by the driver (e.g. for transmit headers.)
 *
 * @extra_beacon_tailroom: tailroom to reserve in each beacon tx skb.
 *	Can be used by drivers to add extra IEs.
 *
 * @max_signal: Maximum value for signal (rssi) in RX information, used
 *	only when @IEEE80211_HW_SIGNAL_UNSPEC or @IEEE80211_HW_SIGNAL_DB
 *
 * @max_listen_interval: max listen interval in units of beacon interval
 *	that HW supports
 *
 * @queues: number of available hardware transmit queues for
 *	data packets. WMM/QoS requires at least four, these
 *	queues need to have configurable access parameters.
 *
 * @rate_control_algorithm: rate control algorithm for this hardware.
 *	If unset (NULL), the default algorithm will be used. Must be
 *	set before calling ieee80211_register_hw().
 *
 * @vif_data_size: size (in bytes) of the drv_priv data area
 *	within &struct ieee80211_vif.
 * @sta_data_size: size (in bytes) of the drv_priv data area
 *	within &struct ieee80211_sta.
 * @chanctx_data_size: size (in bytes) of the drv_priv data area
 *	within &struct ieee80211_chanctx_conf.
 * @txq_data_size: size (in bytes) of the drv_priv data area
 *	within @struct ieee80211_txq.
 *
 * @max_rates: maximum number of alternate rate retry stages the hw
 *	can handle.
 * @max_report_rates: maximum number of alternate rate retry stages
 *	the hw can report back.
 * @max_rate_tries: maximum number of tries for each stage
 *
 * @max_rx_aggregation_subframes: maximum buffer size (number of
 *	sub-frames) to be used for A-MPDU block ack receiver
 *	aggregation.
 *	This is only relevant if the device has restrictions on the
 *	number of subframes, if it relies on mac80211 to do reordering
 *	it shouldn't be set.
 *
 * @max_tx_aggregation_subframes: maximum number of subframes in an
 *	aggregate an HT/HE device will transmit. In HT AddBA we'll
 *	advertise a constant value of 64 as some older APs crash if
 *	the window size is smaller (an example is LinkSys WRT120N
 *	with FW v1.0.07 build 002 Jun 18 2012).
 *	For AddBA to HE capable peers this value will be used.
 *
 * @max_tx_fragments: maximum number of tx buffers per (A)-MSDU, sum
 *	of 1 + skb_shinfo(skb)->nr_frags for each skb in the frag_list.
 *
 * @offchannel_tx_hw_queue: HW queue ID to use for offchannel TX
 *	(if %IEEE80211_HW_QUEUE_CONTROL is set)
 *
 * @radiotap_mcs_details: lists which MCS information can the HW
 *	reports, by default it is set to _MCS, _GI and _BW but doesn't
 *	include _FMT. Use %IEEE80211_RADIOTAP_MCS_HAVE_\* values, only
 *	adding _BW is supported today.
 *
 * @radiotap_vht_details: lists which VHT MCS information the HW reports,
 *	the default is _GI | _BANDWIDTH.
 *	Use the %IEEE80211_RADIOTAP_VHT_KNOWN_\* values.
 *
 * @radiotap_he: HE radiotap validity flags
 *
 * @radiotap_timestamp: Information for the radiotap timestamp field; if the
 *	@units_pos member is set to a non-negative value then the timestamp
 *	field will be added and populated from the &struct ieee80211_rx_status
 *	device_timestamp.
 * @radiotap_timestamp.units_pos: Must be set to a combination of a
 *	IEEE80211_RADIOTAP_TIMESTAMP_UNIT_* and a
 *	IEEE80211_RADIOTAP_TIMESTAMP_SPOS_* value.
 * @radiotap_timestamp.accuracy: If non-negative, fills the accuracy in the
 *	radiotap field and the accuracy known flag will be set.
 *
 * @netdev_features: netdev features to be set in each netdev created
 *	from this HW. Note that not all features are usable with mac80211,
 *	other features will be rejected during HW registration.
 *
 * @uapsd_queues: This bitmap is included in (re)association frame to indicate
 *	for each access category if it is uAPSD trigger-enabled and delivery-
 *	enabled. Use IEEE80211_WMM_IE_STA_QOSINFO_AC_* to set this bitmap.
 *	Each bit corresponds to different AC. Value '1' in specific bit means
 *	that corresponding AC is both trigger- and delivery-enabled. '0' means
 *	neither enabled.
 *
 * @uapsd_max_sp_len: maximum number of total buffered frames the WMM AP may
 *	deliver to a WMM STA during any Service Period triggered by the WMM STA.
 *	Use IEEE80211_WMM_IE_STA_QOSINFO_SP_* for correct values.
 *
 * @n_cipher_schemes: a size of an array of cipher schemes definitions.
 * @cipher_schemes: a pointer to an array of cipher scheme definitions
 *	supported by HW.
 * @max_nan_de_entries: maximum number of NAN DE functions supported by the
 *	device.
 *
 * @tx_sk_pacing_shift: Pacing shift to set on TCP sockets when frames from
 *	them are encountered. The default should typically not be changed,
 *	unless the driver has good reasons for needing more buffers.
 *
 * @weight_multiplier: Driver specific airtime weight multiplier used while
 *	refilling deficit of each TXQ.
 */
struct ieee80211_hw {
	struct ieee80211_conf conf;
	struct wiphy *wiphy;
	const char *rate_control_algorithm;
	void *priv;
	unsigned long flags[BITS_TO_LONGS(NUM_IEEE80211_HW_FLAGS)];
	unsigned int extra_tx_headroom;
	unsigned int extra_beacon_tailroom;
	int vif_data_size;
	int sta_data_size;
	int chanctx_data_size;
	int txq_data_size;
	u16 queues;
	u16 max_listen_interval;
	s8 max_signal;
	u8 max_rates;
	u8 max_report_rates;
	u8 max_rate_tries;
	u16 max_rx_aggregation_subframes;
	u16 max_tx_aggregation_subframes;
	u8 max_tx_fragments;
	u8 offchannel_tx_hw_queue;
	u8 radiotap_mcs_details;
	u16 radiotap_vht_details;
	struct {
		int units_pos;
		s16 accuracy;
	} radiotap_timestamp;
	netdev_features_t netdev_features;
	u8 uapsd_queues;
	u8 uapsd_max_sp_len;
	u8 n_cipher_schemes;
	const struct ieee80211_cipher_scheme *cipher_schemes;
	u8 max_nan_de_entries;
	u8 tx_sk_pacing_shift;
	u8 weight_multiplier;
};

/**
 * enum ieee80211_bss_change - BSS change notification flags
 *
 * These flags are used with the bss_info_changed() callback
 * to indicate which BSS parameter changed.
 *
 * @BSS_CHANGED_ASSOC: association status changed (associated/disassociated),
 *	also implies a change in the AID.
 * @BSS_CHANGED_ERP_CTS_PROT: CTS protection changed
 * @BSS_CHANGED_ERP_PREAMBLE: preamble changed
 * @BSS_CHANGED_ERP_SLOT: slot timing changed
 * @BSS_CHANGED_HT: 802.11n parameters changed
 * @BSS_CHANGED_BASIC_RATES: Basic rateset changed
 * @BSS_CHANGED_BEACON_INT: Beacon interval changed
 * @BSS_CHANGED_BSSID: BSSID changed, for whatever
 *	reason (IBSS and managed mode)
 * @BSS_CHANGED_BEACON: Beacon data changed, retrieve
 *	new beacon (beaconing modes)
 * @BSS_CHANGED_BEACON_ENABLED: Beaconing should be
 *	enabled/disabled (beaconing modes)
 * @BSS_CHANGED_CQM: Connection quality monitor config changed
 * @BSS_CHANGED_IBSS: IBSS join status changed
 * @BSS_CHANGED_ARP_FILTER: Hardware ARP filter address list or state changed.
 * @BSS_CHANGED_QOS: QoS for this association was enabled/disabled. Note
 *	that it is only ever disabled for station mode.
 * @BSS_CHANGED_IDLE: Idle changed for this BSS/interface.
 * @BSS_CHANGED_SSID: SSID changed for this BSS (AP and IBSS mode)
 * @BSS_CHANGED_AP_PROBE_RESP: Probe Response changed for this BSS (AP mode)
 * @BSS_CHANGED_PS: PS changed for this BSS (STA mode)
 * @BSS_CHANGED_TXPOWER: TX power setting changed for this interface
 * @BSS_CHANGED_P2P_PS: P2P powersave settings (CTWindow, opportunistic PS)
 *	changed
 * @BSS_CHANGED_BEACON_INFO: Data from the AP's beacon became available:
 *	currently dtim_period only is under consideration.
 * @BSS_CHANGED_BANDWIDTH: The bandwidth used by this interface changed,
 *	note that this is only called when it changes after the channel
 *	context had been assigned.
 * @BSS_CHANGED_OCB: OCB join status changed
 * @BSS_CHANGED_MU_GROUPS: VHT MU-MIMO group id or user position changed
 * @BSS_CHANGED_KEEP_ALIVE: keep alive options (idle period or protected
 *	keep alive) changed.
 * @BSS_CHANGED_MCAST_RATE: Multicast Rate setting changed for this interface
 * @BSS_CHANGED_FTM_RESPONDER: fime timing reasurement request responder
 *	functionality changed for this BSS (AP mode).
 *
 */
enum ieee80211_bss_change {
	BSS_CHANGED_ASSOC		= 1<<0,
	BSS_CHANGED_ERP_CTS_PROT	= 1<<1,
	BSS_CHANGED_ERP_PREAMBLE	= 1<<2,
	BSS_CHANGED_ERP_SLOT		= 1<<3,
	BSS_CHANGED_HT			= 1<<4,
	BSS_CHANGED_BASIC_RATES		= 1<<5,
	BSS_CHANGED_BEACON_INT		= 1<<6,
	BSS_CHANGED_BSSID		= 1<<7,
	BSS_CHANGED_BEACON		= 1<<8,
	BSS_CHANGED_BEACON_ENABLED	= 1<<9,
	BSS_CHANGED_CQM			= 1<<10,
	BSS_CHANGED_IBSS		= 1<<11,
	BSS_CHANGED_ARP_FILTER		= 1<<12,
	BSS_CHANGED_QOS			= 1<<13,
	BSS_CHANGED_IDLE		= 1<<14,
	BSS_CHANGED_SSID		= 1<<15,
	BSS_CHANGED_AP_PROBE_RESP	= 1<<16,
	BSS_CHANGED_PS			= 1<<17,
	BSS_CHANGED_TXPOWER		= 1<<18,
	BSS_CHANGED_P2P_PS		= 1<<19,
	BSS_CHANGED_BEACON_INFO		= 1<<20,
	BSS_CHANGED_BANDWIDTH		= 1<<21,
	BSS_CHANGED_OCB                 = 1<<22,
	BSS_CHANGED_MU_GROUPS		= 1<<23,
	BSS_CHANGED_KEEP_ALIVE		= 1<<24,
	BSS_CHANGED_MCAST_RATE		= 1<<25,
	BSS_CHANGED_FTM_RESPONDER	= 1<<26,

	/* when adding here, make sure to change ieee80211_reconfig */
};

/*
 * The maximum number of IPv4 addresses listed for ARP filtering. If the number
 * of addresses for an interface increase beyond this value, hardware ARP
 * filtering will be disabled.
 */
#define IEEE80211_BSS_ARP_ADDR_LIST_LEN 4

/**
 * struct ieee80211_mu_group_data - STA's VHT MU-MIMO group data
 *
 * This structure describes the group id data of VHT MU-MIMO
 *
 * @membership: 64 bits array - a bit is set if station is member of the group
 * @position: 2 bits per group id indicating the position in the group
 */
struct ieee80211_mu_group_data {
	u8 membership[WLAN_MEMBERSHIP_LEN];
	u8 position[WLAN_USER_POSITION_LEN];
};

/**
 * struct ieee80211_bss_conf - holds the BSS's changing parameters
 *
 * This structure keeps information about a BSS (and an association
 * to that BSS) that can change during the lifetime of the BSS.
 *
 * @bss_color: 6-bit value to mark inter-BSS frame, if BSS supports HE
 * @htc_trig_based_pkt_ext: default PE in 4us units, if BSS supports HE
 * @multi_sta_back_32bit: supports BA bitmap of 32-bits in Multi-STA BACK
 * @uora_exists: is the UORA element advertised by AP
 * @ack_enabled: indicates support to receive a multi-TID that solicits either
 *	ACK, BACK or both
 * @uora_ocw_range: UORA element's OCW Range field
 * @frame_time_rts_th: HE duration RTS threshold, in units of 32us
 * @he_support: does this BSS support HE
 * @twt_requester: does this BSS support TWT requester (relevant for managed
 *	mode only, set if the AP advertises TWT responder role)
 * @assoc: association status
 * @ibss_joined: indicates whether this station is part of an IBSS
 *	or not
 * @ibss_creator: indicates if a new IBSS network is being created
 * @aid: association ID number, valid only when @assoc is true
 * @use_cts_prot: use CTS protection
 * @use_short_preamble: use 802.11b short preamble
 * @use_short_slot: use short slot time (only relevant for ERP)
 * @dtim_period: num of beacons before the next DTIM, for beaconing,
 *	valid in station mode only if after the driver was notified
 *	with the %BSS_CHANGED_BEACON_INFO flag, will be non-zero then.
 * @sync_tsf: last beacon's/probe response's TSF timestamp (could be old
 *	as it may have been received during scanning long ago). If the
 *	HW flag %IEEE80211_HW_TIMING_BEACON_ONLY is set, then this can
 *	only come from a beacon, but might not become valid until after
 *	association when a beacon is received (which is notified with the
 *	%BSS_CHANGED_DTIM flag.). See also sync_dtim_count important notice.
 * @sync_device_ts: the device timestamp corresponding to the sync_tsf,
 *	the driver/device can use this to calculate synchronisation
 *	(see @sync_tsf). See also sync_dtim_count important notice.
 * @sync_dtim_count: Only valid when %IEEE80211_HW_TIMING_BEACON_ONLY
 *	is requested, see @sync_tsf/@sync_device_ts.
 *	IMPORTANT: These three sync_* parameters would possibly be out of sync
 *	by the time the driver will use them. The synchronized view is currently
 *	guaranteed only in certain callbacks.
 * @beacon_int: beacon interval
 * @assoc_capability: capabilities taken from assoc resp
 * @basic_rates: bitmap of basic rates, each bit stands for an
 *	index into the rate table configured by the driver in
 *	the current band.
 * @beacon_rate: associated AP's beacon TX rate
 * @mcast_rate: per-band multicast rate index + 1 (0: disabled)
 * @bssid: The BSSID for this BSS
 * @enable_beacon: whether beaconing should be enabled or not
 * @chandef: Channel definition for this BSS -- the hardware might be
 *	configured a higher bandwidth than this BSS uses, for example.
 * @mu_group: VHT MU-MIMO group membership data
 * @ht_operation_mode: HT operation mode like in &struct ieee80211_ht_operation.
 *	This field is only valid when the channel is a wide HT/VHT channel.
 *	Note that with TDLS this can be the case (channel is HT, protection must
 *	be used from this field) even when the BSS association isn't using HT.
 * @cqm_rssi_thold: Connection quality monitor RSSI threshold, a zero value
 *	implies disabled. As with the cfg80211 callback, a change here should
 *	cause an event to be sent indicating where the current value is in
 *	relation to the newly configured threshold.
 * @cqm_rssi_low: Connection quality monitor RSSI lower threshold, a zero value
 *	implies disabled.  This is an alternative mechanism to the single
 *	threshold event and can't be enabled simultaneously with it.
 * @cqm_rssi_high: Connection quality monitor RSSI upper threshold.
 * @cqm_rssi_hyst: Connection quality monitor RSSI hysteresis
 * @arp_addr_list: List of IPv4 addresses for hardware ARP filtering. The
 *	may filter ARP queries targeted for other addresses than listed here.
 *	The driver must allow ARP queries targeted for all address listed here
 *	to pass through. An empty list implies no ARP queries need to pass.
 * @arp_addr_cnt: Number of addresses currently on the list. Note that this
 *	may be larger than %IEEE80211_BSS_ARP_ADDR_LIST_LEN (the arp_addr_list
 *	array size), it's up to the driver what to do in that case.
 * @qos: This is a QoS-enabled BSS.
 * @idle: This interface is idle. There's also a global idle flag in the
 *	hardware config which may be more appropriate depending on what
 *	your driver/device needs to do.
 * @ps: power-save mode (STA only). This flag is NOT affected by
 *	offchannel/dynamic_ps operations.
 * @ssid: The SSID of the current vif. Valid in AP and IBSS mode.
 * @ssid_len: Length of SSID given in @ssid.
 * @hidden_ssid: The SSID of the current vif is hidden. Only valid in AP-mode.
 * @txpower: TX power in dBm
 * @txpower_type: TX power adjustment used to control per packet Transmit
 *	Power Control (TPC) in lower driver for the current vif. In particular
 *	TPC is enabled if value passed in %txpower_type is
 *	NL80211_TX_POWER_LIMITED (allow using less than specified from
 *	userspace), whereas TPC is disabled if %txpower_type is set to
 *	NL80211_TX_POWER_FIXED (use value configured from userspace)
 * @p2p_noa_attr: P2P NoA attribute for P2P powersave
 * @allow_p2p_go_ps: indication for AP or P2P GO interface, whether it's allowed
 *	to use P2P PS mechanism or not. AP/P2P GO is not allowed to use P2P PS
 *	if it has associated clients without P2P PS support.
 * @max_idle_period: the time period during which the station can refrain from
 *	transmitting frames to its associated AP without being disassociated.
 *	In units of 1000 TUs. Zero value indicates that the AP did not include
 *	a (valid) BSS Max Idle Period Element.
 * @protected_keep_alive: if set, indicates that the station should send an RSN
 *	protected frame to the AP to reset the idle timer at the AP for the
 *	station.
 * @ftm_responder: whether to enable or disable fine timing measurement FTM
 *	responder functionality.
 * @ftmr_params: configurable lci/civic parameter when enabling FTM responder.
 * @nontransmitted: this BSS is a nontransmitted BSS profile
 * @transmitter_bssid: the address of transmitter AP
 * @bssid_index: index inside the multiple BSSID set
 * @bssid_indicator: 2^bssid_indicator is the maximum number of APs in set
 * @ema_ap: AP supports enhancements of discovery and advertisement of
 *	nontransmitted BSSIDs
 * @profile_periodicity: the least number of beacon frames need to be received
 *	in order to discover all the nontransmitted BSSIDs in the set.
 */
struct ieee80211_bss_conf {
	const u8 *bssid;
	u8 bss_color;
	u8 htc_trig_based_pkt_ext;
	bool multi_sta_back_32bit;
	bool uora_exists;
	bool ack_enabled;
	u8 uora_ocw_range;
	u16 frame_time_rts_th;
	bool he_support;
	bool twt_requester;
	/* association related data */
	bool assoc, ibss_joined;
	bool ibss_creator;
	u16 aid;
	/* erp related data */
	bool use_cts_prot;
	bool use_short_preamble;
	bool use_short_slot;
	bool enable_beacon;
	u8 dtim_period;
	u16 beacon_int;
	u16 assoc_capability;
	u64 sync_tsf;
	u32 sync_device_ts;
	u8 sync_dtim_count;
	u32 basic_rates;
	struct ieee80211_rate *beacon_rate;
	int mcast_rate[NUM_NL80211_BANDS];
	u16 ht_operation_mode;
	s32 cqm_rssi_thold;
	u32 cqm_rssi_hyst;
	s32 cqm_rssi_low;
	s32 cqm_rssi_high;
	struct cfg80211_chan_def chandef;
	struct ieee80211_mu_group_data mu_group;
	__be32 arp_addr_list[IEEE80211_BSS_ARP_ADDR_LIST_LEN];
	int arp_addr_cnt;
	bool qos;
	bool idle;
	bool ps;
	u8 ssid[IEEE80211_MAX_SSID_LEN];
	size_t ssid_len;
	bool hidden_ssid;
	int txpower;
	enum nl80211_tx_power_setting txpower_type;
	struct ieee80211_p2p_noa_attr p2p_noa_attr;
	bool allow_p2p_go_ps;
	u16 max_idle_period;
	bool protected_keep_alive;
	bool ftm_responder;
	struct ieee80211_ftm_responder_params *ftmr_params;
	/* Multiple BSSID data */
	bool nontransmitted;
	u8 transmitter_bssid[ETH_ALEN];
	u8 bssid_index;
	u8 bssid_indicator;
	bool ema_ap;
	u8 profile_periodicity;
};

/**
 * struct ieee80211_chanctx_conf - channel context that vifs may be tuned to
 *
 * This is the driver-visible part. The ieee80211_chanctx
 * that contains it is visible in mac80211 only.
 *
 * @def: the channel definition
 * @min_def: the minimum channel definition currently required.
 * @rx_chains_static: The number of RX chains that must always be
 *	active on the channel to receive MIMO transmissions
 * @rx_chains_dynamic: The number of RX chains that must be enabled
 *	after RTS/CTS handshake to receive SMPS MIMO transmissions;
 *	this will always be >= @rx_chains_static.
 * @radar_enabled: whether radar detection is enabled on this channel.
 * @drv_priv: data area for driver use, will always be aligned to
 *	sizeof(void *), size is determined in hw information.
 */
struct ieee80211_chanctx_conf {
	struct cfg80211_chan_def def;
	struct cfg80211_chan_def min_def;

	u8 rx_chains_static, rx_chains_dynamic;

	bool radar_enabled;

	u8 drv_priv[0] __aligned(sizeof(void *));
};

/**
 * enum ieee80211_vif_flags - virtual interface flags
 *
 * @IEEE80211_VIF_BEACON_FILTER: the device performs beacon filtering
 *	on this virtual interface to avoid unnecessary CPU wakeups
 * @IEEE80211_VIF_SUPPORTS_CQM_RSSI: the device can do connection quality
 *	monitoring on this virtual interface -- i.e. it can monitor
 *	connection quality related parameters, such as the RSSI level and
 *	provide notifications if configured trigger levels are reached.
 * @IEEE80211_VIF_SUPPORTS_UAPSD: The device can do U-APSD for this
 *	interface. This flag should be set during interface addition,
 *	but may be set/cleared as late as authentication to an AP. It is
 *	only valid for managed/station mode interfaces.
 * @IEEE80211_VIF_GET_NOA_UPDATE: request to handle NOA attributes
 *	and send P2P_PS notification to the driver if NOA changed, even
 *	this is not pure P2P vif.
 */
enum ieee80211_vif_flags {
	IEEE80211_VIF_BEACON_FILTER		= BIT(0),
	IEEE80211_VIF_SUPPORTS_CQM_RSSI		= BIT(1),
	IEEE80211_VIF_SUPPORTS_UAPSD		= BIT(2),
	IEEE80211_VIF_GET_NOA_UPDATE		= BIT(3),
};

/**
 * struct ieee80211_vif - per-interface data
 *
 * Data in this structure is continually present for driver
 * use during the life of a virtual interface.
 *
 * @type: type of this virtual interface
 * @bss_conf: BSS configuration for this interface, either our own
 *	or the BSS we're associated to
 * @addr: address of this interface
 * @p2p: indicates whether this AP or STA interface is a p2p
 *	interface, i.e. a GO or p2p-sta respectively
 * @csa_active: marks whether a channel switch is going on. Internally it is
 *	write-protected by sdata_lock and local->mtx so holding either is fine
 *	for read access.
 * @mu_mimo_owner: indicates interface owns MU-MIMO capability
 * @driver_flags: flags/capabilities the driver has for this interface,
 *	these need to be set (or cleared) when the interface is added
 *	or, if supported by the driver, the interface type is changed
 *	at runtime, mac80211 will never touch this field
 * @hw_queue: hardware queue for each AC
 * @cab_queue: content-after-beacon (DTIM beacon really) queue, AP mode only
 * @chanctx_conf: The channel context this interface is assigned to, or %NULL
 *	when it is not assigned. This pointer is RCU-protected due to the TX
 *	path needing to access it; even though the netdev carrier will always
 *	be off when it is %NULL there can still be races and packets could be
 *	processed after it switches back to %NULL.
 * @debugfs_dir: debugfs dentry, can be used by drivers to create own per
 *	interface debug files. Note that it will be NULL for the virtual
 *	monitor interface (if that is requested.)
 * @probe_req_reg: probe requests should be reported to mac80211 for this
 *	interface.
 * @drv_priv: data area for driver use, will always be aligned to
 *	sizeof(void \*).
 * @txq: the multicast data TX queue (if driver uses the TXQ abstraction)
 * @txqs_stopped: per AC flag to indicate that intermediate TXQs are stopped,
 *	protected by fq->lock.
 */
struct ieee80211_vif {
	enum nl80211_iftype type;
	struct ieee80211_bss_conf bss_conf;
	u8 addr[ETH_ALEN] __aligned(2);
	bool p2p;
	bool csa_active;
	bool mu_mimo_owner;

	u8 cab_queue;
	u8 hw_queue[IEEE80211_NUM_ACS];

	struct ieee80211_txq *txq;

	struct ieee80211_chanctx_conf __rcu *chanctx_conf;

	u32 driver_flags;

#ifdef CONFIG_MAC80211_DEBUGFS
	struct dentry *debugfs_dir;
#endif

	unsigned int probe_req_reg;

	bool txqs_stopped[IEEE80211_NUM_ACS];

	/* must be last */
	u8 drv_priv[0] __aligned(sizeof(void *));
};

/**
 * enum ieee80211_sta_state - station state
 *
 * @IEEE80211_STA_NOTEXIST: station doesn't exist at all,
 *	this is a special state for add/remove transitions
 * @IEEE80211_STA_NONE: station exists without special state
 * @IEEE80211_STA_AUTH: station is authenticated
 * @IEEE80211_STA_ASSOC: station is associated
 * @IEEE80211_STA_AUTHORIZED: station is authorized (802.1X)
 */
enum ieee80211_sta_state {
	/* NOTE: These need to be ordered correctly! */
	IEEE80211_STA_NOTEXIST,
	IEEE80211_STA_NONE,
	IEEE80211_STA_AUTH,
	IEEE80211_STA_ASSOC,
	IEEE80211_STA_AUTHORIZED,
};

/**
 * enum ieee80211_sta_rx_bandwidth - station RX bandwidth
 * @IEEE80211_STA_RX_BW_20: station can only receive 20 MHz
 * @IEEE80211_STA_RX_BW_40: station can receive up to 40 MHz
 * @IEEE80211_STA_RX_BW_80: station can receive up to 80 MHz
 * @IEEE80211_STA_RX_BW_160: station can receive up to 160 MHz
 *	(including 80+80 MHz)
 *
 * Implementation note: 20 must be zero to be initialized
 *	correctly, the values must be sorted.
 */
enum ieee80211_sta_rx_bandwidth {
	IEEE80211_STA_RX_BW_20 = 0,
	IEEE80211_STA_RX_BW_40,
	IEEE80211_STA_RX_BW_80,
	IEEE80211_STA_RX_BW_160,
};

/* there are 40 bytes if you don't need the rateset to be kept */
#define IEEE80211_TX_INFO_DRIVER_DATA_SIZE 40

/* if you do need the rateset, then you have less space */
#define IEEE80211_TX_INFO_RATE_DRIVER_DATA_SIZE 24

/* maximum number of rate stages */
#define IEEE80211_TX_MAX_RATES	4

/* maximum number of rate table entries */
#define IEEE80211_TX_RATE_TABLE_SIZE	4

/*
 * We shouldn't need this in userspace
 */
struct rcu_head { 
	/* MSVC doesn't like empty structs, so give it some junk here */
	u8 junk;
};

/**
 * struct ieee80211_sta_rates - station rate selection table
 *
 * @rcu_head: RCU head used for freeing the table on update
 * @rate: transmit rates/flags to be used by default.
 *	Overriding entries per-packet is possible by using cb tx control.
 */
struct ieee80211_sta_rates {
	struct rcu_head rcu_head;
	struct {
		s8 idx;
		u8 count;
		u8 count_cts;
		u8 count_rts;
		u16 flags;
	} rate[IEEE80211_TX_RATE_TABLE_SIZE];
};

/**
 * struct ieee80211_sta_txpwr - station txpower configuration
 *
 * Used to configure txpower for station.
 *
 * @power: indicates the tx power, in dBm, to be used when sending data frames
 *	to the STA.
 * @type: In particular if TPC %type is NL80211_TX_POWER_LIMITED then tx power
 *	will be less than or equal to specified from userspace, whereas if TPC
 *	%type is NL80211_TX_POWER_AUTOMATIC then it indicates default tx power.
 *	NL80211_TX_POWER_FIXED is not a valid configuration option for
 *	per peer TPC.
 */
struct ieee80211_sta_txpwr {
	s16 power;
	enum nl80211_tx_power_setting type;
};

/**
 * struct ieee80211_sta - station table entry
 *
 * A station table entry represents a station we are possibly
 * communicating with. Since stations are RCU-managed in
 * mac80211, any ieee80211_sta pointer you get access to must
 * either be protected by rcu_read_lock() explicitly or implicitly,
 * or you must take good care to not use such a pointer after a
 * call to your sta_remove callback that removed it.
 *
 * @addr: MAC address
 * @aid: AID we assigned to the station if we're an AP
 * @supp_rates: Bitmap of supported rates (per band)
 * @ht_cap: HT capabilities of this STA; restricted to our own capabilities
 * @vht_cap: VHT capabilities of this STA; restricted to our own capabilities
 * @he_cap: HE capabilities of this STA
 * @max_rx_aggregation_subframes: maximal amount of frames in a single AMPDU
 *	that this station is allowed to transmit to us.
 *	Can be modified by driver.
 * @wme: indicates whether the STA supports QoS/WME (if local devices does,
 *	otherwise always false)
 * @drv_priv: data area for driver use, will always be aligned to
 *	sizeof(void \*), size is determined in hw information.
 * @uapsd_queues: bitmap of queues configured for uapsd. Only valid
 *	if wme is supported. The bits order is like in
 *	IEEE80211_WMM_IE_STA_QOSINFO_AC_*.
 * @max_sp: max Service Period. Only valid if wme is supported.
 * @bandwidth: current bandwidth the station can receive with
 * @rx_nss: in HT/VHT, the maximum number of spatial streams the
 *	station can receive at the moment, changed by operating mode
 *	notifications and capabilities. The value is only valid after
 *	the station moves to associated state.
 * @smps_mode: current SMPS mode (off, static or dynamic)
 * @rates: rate control selection table
 * @tdls: indicates whether the STA is a TDLS peer
 * @tdls_initiator: indicates the STA is an initiator of the TDLS link. Only
 *	valid if the STA is a TDLS peer in the first place.
 * @mfp: indicates whether the STA uses management frame protection or not.
 * @max_amsdu_subframes: indicates the maximal number of MSDUs in a single
 *	A-MSDU. Taken from the Extended Capabilities element. 0 means
 *	unlimited.
 * @support_p2p_ps: indicates whether the STA supports P2P PS mechanism or not.
 * @max_rc_amsdu_len: Maximum A-MSDU size in bytes recommended by rate control.
 * @max_tid_amsdu_len: Maximum A-MSDU size in bytes for this TID
 * @txq: per-TID data TX queues (if driver uses the TXQ abstraction); note that
 *	the last entry (%IEEE80211_NUM_TIDS) is used for non-data frames
 */
struct ieee80211_sta {
	u32 supp_rates[NUM_NL80211_BANDS];
	u8 addr[ETH_ALEN];
	u16 aid;
	struct ieee80211_sta_ht_cap ht_cap;
	struct ieee80211_sta_vht_cap vht_cap;
	struct ieee80211_sta_he_cap he_cap;
	u16 max_rx_aggregation_subframes;
	bool wme;
	u8 uapsd_queues;
	u8 max_sp;
	u8 rx_nss;
	enum ieee80211_sta_rx_bandwidth bandwidth;
	enum ieee80211_smps_mode smps_mode;
	struct ieee80211_sta_rates __rcu *rates;
	bool tdls;
	bool tdls_initiator;
	bool mfp;
	u8 max_amsdu_subframes;

	/**
	 * @max_amsdu_len:
	 * indicates the maximal length of an A-MSDU in bytes.
	 * This field is always valid for packets with a VHT preamble.
	 * For packets with a HT preamble, additional limits apply:
	 *
	 * * If the skb is transmitted as part of a BA agreement, the
	 *   A-MSDU maximal size is min(max_amsdu_len, 4065) bytes.
	 * * If the skb is not part of a BA aggreement, the A-MSDU maximal
	 *   size is min(max_amsdu_len, 7935) bytes.
	 *
	 * Both additional HT limits must be enforced by the low level
	 * driver. This is defined by the spec (IEEE 802.11-2012 section
	 * 8.3.2.2 NOTE 2).
	 */
	u16 max_amsdu_len;
	bool support_p2p_ps;
	u16 max_rc_amsdu_len;
	u16 max_tid_amsdu_len[IEEE80211_NUM_TIDS];
	struct ieee80211_sta_txpwr txpwr;

	struct ieee80211_txq *txq[IEEE80211_NUM_TIDS + 1];

	/* must be last */
	u8 drv_priv[0] __aligned(sizeof(void *));
};

static inline bool
conf_is_ht20(struct ieee80211_conf *conf)
{
	return conf->chandef.width == NL80211_CHAN_WIDTH_20;
}

static inline bool
conf_is_ht40_minus(struct ieee80211_conf *conf)
{
	return conf->chandef.width == NL80211_CHAN_WIDTH_40 &&
	       conf->chandef.center_freq1 < conf->chandef.chan->center_freq;
}

static inline bool
conf_is_ht40_plus(struct ieee80211_conf *conf)
{
	return conf->chandef.width == NL80211_CHAN_WIDTH_40 &&
	       conf->chandef.center_freq1 > conf->chandef.chan->center_freq;
}

static inline bool
conf_is_ht40(struct ieee80211_conf *conf)
{
	return conf->chandef.width == NL80211_CHAN_WIDTH_40;
}

static inline bool
conf_is_ht(struct ieee80211_conf *conf)
{
	return (conf->chandef.width != NL80211_CHAN_WIDTH_5) &&
		(conf->chandef.width != NL80211_CHAN_WIDTH_10) &&
		(conf->chandef.width != NL80211_CHAN_WIDTH_20_NOHT);
}

/**
 * enum mac80211_rx_encoding_flags - MCS & bandwidth flags
 *
 * @RX_ENC_FLAG_SHORTPRE: Short preamble was used for this frame
 * @RX_ENC_FLAG_SHORT_GI: Short guard interval was used
 * @RX_ENC_FLAG_HT_GF: This frame was received in a HT-greenfield transmission,
 *	if the driver fills this value it should add
 *	%IEEE80211_RADIOTAP_MCS_HAVE_FMT
 *	to @hw.radiotap_mcs_details to advertise that fact.
 * @RX_ENC_FLAG_LDPC: LDPC was used
 * @RX_ENC_FLAG_STBC_MASK: STBC 2 bit bitmask. 1 - Nss=1, 2 - Nss=2, 3 - Nss=3
 * @RX_ENC_FLAG_BF: packet was beamformed
 */
enum mac80211_rx_encoding_flags {
	RX_ENC_FLAG_SHORTPRE		= BIT(0),
	RX_ENC_FLAG_SHORT_GI		= BIT(2),
	RX_ENC_FLAG_HT_GF		= BIT(3),
	RX_ENC_FLAG_STBC_MASK		= BIT(4) | BIT(5),
	RX_ENC_FLAG_LDPC		= BIT(6),
	RX_ENC_FLAG_BF			= BIT(7),
};

#define RX_ENC_FLAG_STBC_SHIFT		4

enum mac80211_rx_encoding {
	RX_ENC_LEGACY = 0,
	RX_ENC_HT,
	RX_ENC_VHT,
	RX_ENC_HE,
};

/**
 * struct ieee80211_rx_status - receive status
 *
 * The low-level driver should provide this information (the subset
 * supported by hardware) to the 802.11 code with each received
 * frame, in the skb's control buffer (cb).
 *
 * @mactime: value in microseconds of the 64-bit Time Synchronization Function
 * 	(TSF) timer when the first data symbol (MPDU) arrived at the hardware.
 * @boottime_ns: CLOCK_BOOTTIME timestamp the frame was received at, this is
 *	needed only for beacons and probe responses that update the scan cache.
 * @device_timestamp: arbitrary timestamp for the device, mac80211 doesn't use
 *	it but can store it and pass it back to the driver for synchronisation
 * @band: the active band when this frame was received
 * @freq: frequency the radio was tuned to when receiving this frame, in MHz
 *	This field must be set for management frames, but isn't strictly needed
 *	for data (other) frames - for those it only affects radiotap reporting.
 * @signal: signal strength when receiving this frame, either in dBm, in dB or
 *	unspecified depending on the hardware capabilities flags
 *	@IEEE80211_HW_SIGNAL_*
 * @chains: bitmask of receive chains for which separate signal strength
 *	values were filled.
 * @chain_signal: per-chain signal strength, in dBm (unlike @signal, doesn't
 *	support dB or unspecified units)
 * @antenna: antenna used
 * @rate_idx: index of data rate into band's supported rates or MCS index if
 *	HT or VHT is used (%RX_FLAG_HT/%RX_FLAG_VHT)
 * @nss: number of streams (VHT and HE only)
 * @flag: %RX_FLAG_\*
 * @encoding: &enum mac80211_rx_encoding
 * @bw: &enum rate_info_bw
 * @enc_flags: uses bits from &enum mac80211_rx_encoding_flags
 * @he_ru: HE RU, from &enum nl80211_he_ru_alloc
 * @he_gi: HE GI, from &enum nl80211_he_gi
 * @he_dcm: HE DCM value
 * @rx_flags: internal RX flags for mac80211
 * @ampdu_reference: A-MPDU reference number, must be a different value for
 *	each A-MPDU but the same for each subframe within one A-MPDU
 * @ampdu_delimiter_crc: A-MPDU delimiter CRC
 * @zero_length_psdu_type: radiotap type of the 0-length PSDU
 */
struct ieee80211_rx_status {
	u64 mactime;
	u64 boottime_ns;
	u32 device_timestamp;
	u32 ampdu_reference;
	u32 flag;
	u16 freq;
	u8 enc_flags;
	u8 encoding:2, bw:3, he_ru:3;
	u8 he_gi:2, he_dcm:1;
	u8 rate_idx;
	u8 nss;
	u8 rx_flags;
	u8 band;
	u8 antenna;
	s8 signal;
	u8 chains;
	s8 chain_signal[IEEE80211_MAX_CHAINS];
	u8 ampdu_delimiter_crc;
	u8 zero_length_psdu_type;
};

/**
 * enum ieee80211_conf_flags - configuration flags
 *
 * Flags to define PHY configuration options
 *
 * @IEEE80211_CONF_MONITOR: there's a monitor interface present -- use this
 *	to determine for example whether to calculate timestamps for packets
 *	or not, do not use instead of filter flags!
 * @IEEE80211_CONF_PS: Enable 802.11 power save mode (managed mode only).
 *	This is the power save mode defined by IEEE 802.11-2007 section 11.2,
 *	meaning that the hardware still wakes up for beacons, is able to
 *	transmit frames and receive the possible acknowledgment frames.
 *	Not to be confused with hardware specific wakeup/sleep states,
 *	driver is responsible for that. See the section "Powersave support"
 *	for more.
 * @IEEE80211_CONF_IDLE: The device is running, but idle; if the flag is set
 *	the driver should be prepared to handle configuration requests but
 *	may turn the device off as much as possible. Typically, this flag will
 *	be set when an interface is set UP but not associated or scanning, but
 *	it can also be unset in that case when monitor interfaces are active.
 * @IEEE80211_CONF_OFFCHANNEL: The device is currently not on its main
 *	operating channel.
 */
enum ieee80211_conf_flags {
	IEEE80211_CONF_MONITOR		= (1<<0),
	IEEE80211_CONF_PS		= (1<<1),
	IEEE80211_CONF_IDLE		= (1<<2),
	IEEE80211_CONF_OFFCHANNEL	= (1<<3),
};

/**
 * enum ieee80211_conf_changed - denotes which configuration changed
 *
 * @IEEE80211_CONF_CHANGE_LISTEN_INTERVAL: the listen interval changed
 * @IEEE80211_CONF_CHANGE_MONITOR: the monitor flag changed
 * @IEEE80211_CONF_CHANGE_PS: the PS flag or dynamic PS timeout changed
 * @IEEE80211_CONF_CHANGE_POWER: the TX power changed
 * @IEEE80211_CONF_CHANGE_CHANNEL: the channel/channel_type changed
 * @IEEE80211_CONF_CHANGE_RETRY_LIMITS: retry limits changed
 * @IEEE80211_CONF_CHANGE_IDLE: Idle flag changed
 * @IEEE80211_CONF_CHANGE_SMPS: Spatial multiplexing powersave mode changed
 *	Note that this is only valid if channel contexts are not used,
 *	otherwise each channel context has the number of chains listed.
 */
enum ieee80211_conf_changed {
	IEEE80211_CONF_CHANGE_SMPS		= BIT(1),
	IEEE80211_CONF_CHANGE_LISTEN_INTERVAL	= BIT(2),
	IEEE80211_CONF_CHANGE_MONITOR		= BIT(3),
	IEEE80211_CONF_CHANGE_PS		= BIT(4),
	IEEE80211_CONF_CHANGE_POWER		= BIT(5),
	IEEE80211_CONF_CHANGE_CHANNEL		= BIT(6),
	IEEE80211_CONF_CHANGE_RETRY_LIMITS	= BIT(7),
	IEEE80211_CONF_CHANGE_IDLE		= BIT(8),
};

#endif /* ifndef USERSPACE_MAC80211_H */
