/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
	Copyright (C) 2004 - 2009 Ivo van Doorn <IvDoorn@gmail.com>
	Copyright (C) 2004 - 2009 Gertjan van Wingerde <gwingerde@gmail.com>
	<http://rt2x00.serialmonkey.com>

 */

/*
 * Userspace port (c) 2019 Hak5
 */

/*
	Module: rt2x00lib
	Abstract: Data structures and definitions for the rt2x00lib module.
 */

#ifndef __RT2x00LIB_H__
#define __RT2x00LIB_H__ 

#include "kernel/nl80211.h"
#include "kernel/types.h"

/*
 * rt2x00_rate: Per rate device information
 */
struct rt2x00_rate {
	unsigned short flags;
#define DEV_RATE_CCK			0x0001
#define DEV_RATE_OFDM			0x0002
#define DEV_RATE_SHORT_PREAMBLE		0x0004

	unsigned short bitrate; /* In 100kbit/s */
	unsigned short ratemask;

	unsigned short plcp;
	unsigned short mcs;
};

extern const struct rt2x00_rate rt2x00_supported_rates[12];

static inline const struct rt2x00_rate *rt2x00_get_rate(const u16 hw_value)
{
	return &rt2x00_supported_rates[hw_value & 0xff];
}

#define RATE_MCS(__mode, __mcs) \
	((((__mode) & 0x00ff) << 8) | ((__mcs) & 0x00ff))

static inline int rt2x00_get_rate_mcs(const u16 mcs_value)
{
	return (mcs_value & 0x00ff);
}

/*
 * Initialization handlers.
 */
int rt2x00lib_start(struct rt2x00_dev *rt2x00dev);
void rt2x00lib_stop(struct rt2x00_dev *rt2x00dev);

/*
 * Configuration handlers.
 */
int rt2x00mac_add_interface(struct ieee80211_hw *hw,
			    struct ieee80211_vif *vif);
void rt2x00lib_config_intf(struct rt2x00_dev *rt2x00dev,
			   struct rt2x00_intf *intf,
			   enum nl80211_iftype type,
			   const u8 *mac, const u8 *bssid);
void rt2x00lib_config_erp(struct rt2x00_dev *rt2x00dev,
			  struct rt2x00_intf *intf,
			  struct ieee80211_bss_conf *conf,
			  u32 changed);
void rt2x00lib_config_antenna(struct rt2x00_dev *rt2x00dev,
			      struct antenna_setup ant);
void rt2x00lib_config(struct rt2x00_dev *rt2x00dev,
		      struct ieee80211_conf *conf,
		      const unsigned int changed_flags);

#endif /* ifndef RT2x00LIB_H */
