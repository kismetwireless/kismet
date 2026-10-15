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

/* cfg80211 utilities and regulatory hooks.
 *
 * Frequency conversion and header length are from Linux net/wireless/util.c (GPL-2.0,
 * Copyright 2007-2009 Johannes Berg, 2013 Intel Mobile Communications GmbH, 2017 Intel
 * Deutschland GmbH, 2018-2023 Intel Corporation).  There is no regulatory database: the
 * firmware enforces its own limits and every channel the driver lists is usable. */

#include "local.h"

const unsigned char rfc1042_header[] __aligned(2) =
	{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00 };

const unsigned char bridge_tunnel_header[] __aligned(2) =
	{ 0xaa, 0xaa, 0x03, 0x00, 0x00, 0xf8 };

u32 ieee80211_channel_to_freq_khz(int chan, enum nl80211_band band)
{
	/* see 802.11 17.3.8.3.2 and Annex J
	 * there are overlapping channel numbers in 5GHz and 2GHz bands */
	if (chan <= 0)
		return 0; /* not supported */
	switch (band) {
	case NL80211_BAND_2GHZ:
	case NL80211_BAND_LC:
		if (chan == 14)
			return MHZ_TO_KHZ(2484);
		else if (chan < 14)
			return MHZ_TO_KHZ(2407 + chan * 5);
		break;
	case NL80211_BAND_5GHZ:
		if (chan >= 182 && chan <= 196)
			return MHZ_TO_KHZ(4000 + chan * 5);
		else
			return MHZ_TO_KHZ(5000 + chan * 5);
		break;
	case NL80211_BAND_6GHZ:
		/* see 802.11ax D6.1 27.3.23.2 */
		if (chan == 2)
			return MHZ_TO_KHZ(5935);
		if (chan <= 253)
			return MHZ_TO_KHZ(5950 + chan * 5);
		break;
	case NL80211_BAND_60GHZ:
		if (chan < 7)
			return MHZ_TO_KHZ(56160 + chan * 2160);
		break;
	case NL80211_BAND_S1GHZ:
		return 902000 + chan * 500;
	default:
		;
	}
	return 0; /* not supported */
}

int ieee80211_freq_khz_to_channel(u32 freq)
{
	/* TODO: just handle MHz for now */
	freq = KHZ_TO_MHZ(freq);

	/* see 802.11 17.3.8.3.2 and Annex J */
	if (freq == 2484)
		return 14;
	else if (freq < 2484)
		return (freq - 2407) / 5;
	else if (freq >= 4910 && freq <= 4980)
		return (freq - 4000) / 5;
	else if (freq < 5925)
		return (freq - 5000) / 5;
	else if (freq == 5935)
		return 2;
	else if (freq <= 45000) /* DMG band lower limit */
		/* see 802.11ax D6.1 27.3.22.2 */
		return (freq - 5950) / 5;
	else if (freq >= 58320 && freq <= 70200)
		return (freq - 56160) / 2160;
	else
		return 0;
}

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
		if ((fc & cpu_to_le16(0x00E0)) == cpu_to_le16(0x00C0))
			hdrlen = 10;
		else
			hdrlen = 16;
	}
out:
	return hdrlen;
}

unsigned int ieee80211_get_hdrlen_from_skb(const struct sk_buff *skb)
{
	const struct ieee80211_hdr *hdr =
			(const struct ieee80211_hdr *)skb->data;
	unsigned int hdrlen;

	if (unlikely(skb->len < 10))
		return 0;
	hdrlen = ieee80211_hdrlen(hdr->frame_control);
	if (unlikely(hdrlen > skb->len))
		return 0;
	return hdrlen;
}

/* As net/wireless/chan.c */
void cfg80211_chandef_create(struct cfg80211_chan_def *chandef, struct ieee80211_channel *chan,
        enum nl80211_channel_type chan_type) {
    if (WARN_ON(!chan))
        return;

    memset(chandef, 0, sizeof(*chandef));
    chandef->chan = chan;
    chandef->freq1_offset = chan->freq_offset;

    switch (chan_type) {
        case NL80211_CHAN_NO_HT:
            chandef->width = NL80211_CHAN_WIDTH_20_NOHT;
            chandef->center_freq1 = chan->center_freq;
            break;
        case NL80211_CHAN_HT20:
            chandef->width = NL80211_CHAN_WIDTH_20;
            chandef->center_freq1 = chan->center_freq;
            break;
        case NL80211_CHAN_HT40PLUS:
            chandef->width = NL80211_CHAN_WIDTH_40;
            chandef->center_freq1 = chan->center_freq + 10;
            break;
        case NL80211_CHAN_HT40MINUS:
            chandef->width = NL80211_CHAN_WIDTH_40;
            chandef->center_freq1 = chan->center_freq - 10;
            break;
        default:
            WARN_ON(1);
    }
}

bool cfg80211_chandef_usable(struct wiphy *wiphy, const struct cfg80211_chan_def *chandef,
        u32 prohibited_flags) {
    (void) wiphy;
    return chandef->chan && !(chandef->chan->flags & prohibited_flags & IEEE80211_CHAN_DISABLED);
}

/* Monitor interfaces never beacon; reporting beaconing as allowed keeps channel switches
 * from being treated as radar-detection switches */
bool cfg80211_reg_check_beaconing(struct wiphy *wiphy, struct cfg80211_chan_def *chandef,
        struct cfg80211_beaconing_check_config *cfg) {
    (void) wiphy; (void) chandef; (void) cfg;
    return true;
}

int regulatory_hint(struct wiphy *wiphy, const char *alpha2) {
    return kc_mac80211_set_regdomain(wiphy_to_ieee80211_hw(wiphy), alpha2);
}

int regulatory_set_wiphy_regd(struct wiphy *wiphy, struct ieee80211_regdomain *rd) {
    rcu_assign_pointer(wiphy->regd, rd);
    return 0;
}

void wiphy_rfkill_set_hw_state_reason(struct wiphy *wiphy, bool blocked,
        enum rfkill_hard_block_reasons reason) {
    (void) reason;
    if (blocked)
        dev_warn(&wiphy->dev, "radio is blocked by a hardware switch");
}

void wiphy_rfkill_start_polling(struct wiphy *wiphy) {
    (void) wiphy;
}
