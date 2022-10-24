// SPDX-License-Identifier: GPL-2.0
/*
 * Wireless utility functions
 *
 * Copyright 2007-2009	Johannes Berg <johannes@sipsolutions.net>
 * Copyright 2013-2014  Intel Mobile Communications GmbH
 * Copyright 2017	Intel Deutschland GmbH
 * Copyright (C) 2018-2019 Intel Corporation
 */

/*
 * Userspace port (c) 2019 Hak5
 */

#include <stddef.h>
#include "cfg80211.h"
#include "kernel.h"

int ieee80211_channel_to_frequency(int chan, enum nl80211_band band)
{
	/* see 802.11 17.3.8.3.2 and Annex J
	 * there are overlapping channel numbers in 5GHz and 2GHz bands */
	if (chan <= 0)
		return 0; /* not supported */
	switch (band) {
	case NL80211_BAND_2GHZ:
		if (chan == 14)
			return 2484;
		else if (chan < 14)
			return 2407 + chan * 5;
		break;
	case NL80211_BAND_5GHZ:
		if (chan >= 182 && chan <= 196)
			return 4000 + chan * 5;
		else
			return 5000 + chan * 5;
		break;
	case NL80211_BAND_60GHZ:
		if (chan < 7)
			return 56160 + chan * 2160;
		break;
	default:
		;
	}
	return 0; /* not supported */
}
EXPORT_SYMBOL(ieee80211_channel_to_frequency);

int ieee80211_frequency_to_channel(int freq)
{
	/* see 802.11 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq <= 45000) /* DMG band lower limit */
		return (freq - 5000) / 5;
	else if (freq >= 58320 && freq <= 70200)
		return (freq - 56160) / 2160;
	else
		return 0;
}
EXPORT_SYMBOL(ieee80211_frequency_to_channel);

unsigned int __attribute_const__ ieee80211_hdrlen(__le16 fc)
{
	unsigned int hdrlen = 24;

	if (ieee80211_is_ext(fc)) {
		hdrlen = 4;
		goto out;
	}

	if (ieee80211_is_data(fc)) {
		if (ieee80211_has_a4(fc))
			hdrlen = 30;
		if (ieee80211_is_data_qos(fc)) {
			hdrlen += IEEE80211_QOS_CTL_LEN;
			if (ieee80211_has_order(fc))
				hdrlen += IEEE80211_HT_CTL_LEN;
		}
		goto out;
	}

	if (ieee80211_is_mgmt(fc)) {
		if (ieee80211_has_order(fc))
			hdrlen += IEEE80211_HT_CTL_LEN;
		goto out;
	}

	if (ieee80211_is_ctl(fc)) {
		/*
		 * ACK and CTS are 10 bytes, all others 16. To see how
		 * to get this condition consider
		 *   subtype mask:   0b0000000011110000 (0x00F0)
		 *   ACK subtype:    0b0000000011010000 (0x00D0)
		 *   CTS subtype:    0b0000000011000000 (0x00C0)
		 *   bits that matter:         ^^^      (0x00E0)
		 *   value of those: 0b0000000011000000 (0x00C0)
		 */
		if ((fc & cpu_to_le16(0x00E0)) == cpu_to_le16(0x00C0))
			hdrlen = 10;
		else
			hdrlen = 16;
	}
out:
	return hdrlen;
}
EXPORT_SYMBOL(ieee80211_hdrlen);

unsigned int ieee80211_get_hdrlen_from_buf(const uint8_t *buf, size_t len)
{
	const struct ieee80211_hdr *hdr =
			(const struct ieee80211_hdr *) buf;
	unsigned int hdrlen;

	if (unlikely(len < 10))
		return 0;
	hdrlen = ieee80211_hdrlen(hdr->frame_control);
	if (unlikely(hdrlen > len))
		return 0;
	return hdrlen;
}
EXPORT_SYMBOL(ieee80211_get_hdrlen_from_buf);

