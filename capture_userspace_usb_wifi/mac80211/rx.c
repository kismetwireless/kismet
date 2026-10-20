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

/* Receive path: every frame goes to the monitor callback with a radiotap header.
 *
 * ieee80211_rx_radiotap_hdrlen() and ieee80211_add_rx_radiotap_header() are from Linux
 * net/mac80211/rx.c (GPL-2.0, Copyright 2002-2005 Instant802 Networks, 2005-2006 Devicescape
 * Software, 2006-2007 Jiri Benc, 2007-2010 Johannes Berg, 2013-2014 Intel Mobile
 * Communications GmbH, 2015-2017 Intel Deutschland GmbH, 2018-2026 Intel Corporation),
 * adapted only where they reach into mac80211 internals. */

#include "local.h"

#define FCS_LEN 4

/* The kernel converts start-of-frame times to the radiotap convention; the drivers here
 * report the start of frame, so it's passed through */
u64 ieee80211_calculate_rx_timestamp(struct ieee80211_hw *hw, struct ieee80211_rx_status *status,
        unsigned int mpdu_len, unsigned int mpdu_offset) {
    (void) hw;
    (void) mpdu_len;
    (void) mpdu_offset;
    return status->mactime;
}

static int
ieee80211_rx_radiotap_hdrlen(struct ieee80211_local *local,
			     struct ieee80211_rx_status *status,
			     struct sk_buff *skb)
{
	int len;

	/* always present fields */
	len = sizeof(struct ieee80211_radiotap_header) + 8;

	/* allocate extra bitmaps */
	if (status->chains)
		len += 4 * hweight8(status->chains);

	if (ieee80211_have_rx_timestamp(status)) {
		len = ALIGN(len, 8);
		len += 8;
	}
	if (ieee80211_hw_check(&local->hw, SIGNAL_DBM))
		len += 1;

	/* antenna field, if we don't have per-chain info */
	if (!status->chains)
		len += 1;

	/* padding for RX_FLAGS if necessary */
	len = ALIGN(len, 2);

	if (status->encoding == RX_ENC_HT) /* HT info */
		len += 3;

	if (status->flag & RX_FLAG_AMPDU_DETAILS) {
		len = ALIGN(len, 4);
		len += 8;
	}

	if (status->encoding == RX_ENC_VHT) {
		/* Included even if RX_FLAG_RADIOTAP_VHT is not set */
		len = ALIGN(len, 2);
		len += 12;
		BUILD_BUG_ON(sizeof(struct ieee80211_radiotap_vht) != 12);
	}

	if (local->hw.radiotap_timestamp.units_pos >= 0) {
		len = ALIGN(len, 8);
		len += 12;
	}

	if (status->encoding == RX_ENC_HE &&
	    status->flag & RX_FLAG_RADIOTAP_HE) {
		len = ALIGN(len, 2);
		len += 12;
		BUILD_BUG_ON(sizeof(struct ieee80211_radiotap_he) != 12);
	}

	if (status->encoding == RX_ENC_HE &&
	    status->flag & RX_FLAG_RADIOTAP_HE_MU) {
		len = ALIGN(len, 2);
		len += 12;
		BUILD_BUG_ON(sizeof(struct ieee80211_radiotap_he_mu) != 12);
	}

	if (status->flag & RX_FLAG_NO_PSDU)
		len += 1;

	if (status->flag & RX_FLAG_RADIOTAP_LSIG) {
		len = ALIGN(len, 2);
		len += 4;
		BUILD_BUG_ON(sizeof(struct ieee80211_radiotap_lsig) != 4);
	}

	if (status->chains) {
		/* antenna and antenna signal fields */
		len += 2 * hweight8(status->chains);
	}

	(void) skb;
	return len;
}

static void
ieee80211_add_rx_radiotap_header(struct ieee80211_local *local,
				 struct sk_buff *skb,
				 struct ieee80211_rate *rate,
				 int rtap_len, bool has_fcs)
{
	struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
	struct ieee80211_radiotap_header *rthdr;
	unsigned char *pos;
	__le32 *it_present;
	u32 it_present_val;
	u16 rx_flags = 0;
	u16 channel_flags = 0;
	int mpdulen;
	unsigned long chain;
	unsigned long chains = status->chains;
	struct ieee80211_radiotap_vht vht = {};
	struct ieee80211_radiotap_he he = {};
	struct ieee80211_radiotap_he_mu he_mu = {};
	struct ieee80211_radiotap_lsig lsig = {};

	if (status->flag & RX_FLAG_RADIOTAP_VHT) {
		vht = *(struct ieee80211_radiotap_vht *)skb->data;
		skb_pull(skb, sizeof(vht));
		WARN_ON_ONCE(status->encoding != RX_ENC_VHT);
	}

	if (status->flag & RX_FLAG_RADIOTAP_HE) {
		he = *(struct ieee80211_radiotap_he *)skb->data;
		skb_pull(skb, sizeof(he));
		WARN_ON_ONCE(status->encoding != RX_ENC_HE);
	}

	if (status->flag & RX_FLAG_RADIOTAP_HE_MU) {
		he_mu = *(struct ieee80211_radiotap_he_mu *)skb->data;
		skb_pull(skb, sizeof(he_mu));
	}

	if (status->flag & RX_FLAG_RADIOTAP_LSIG) {
		lsig = *(struct ieee80211_radiotap_lsig *)skb->data;
		skb_pull(skb, sizeof(lsig));
	}

	mpdulen = skb->len;
	if (!(has_fcs && ieee80211_hw_check(&local->hw, RX_INCLUDES_FCS)))
		mpdulen += FCS_LEN;

	rthdr = skb_push(skb, rtap_len);
	memset(rthdr, 0, rtap_len);
	it_present = &rthdr->it_present;

	/* radiotap header, set always present flags */
	rthdr->it_len = cpu_to_le16(rtap_len);
	it_present_val = BIT(IEEE80211_RADIOTAP_FLAGS) |
			 BIT(IEEE80211_RADIOTAP_CHANNEL) |
			 BIT(IEEE80211_RADIOTAP_RX_FLAGS);

	if (!status->chains)
		it_present_val |= BIT(IEEE80211_RADIOTAP_ANTENNA);

	for_each_set_bit(chain, &chains, IEEE80211_MAX_CHAINS) {
		it_present_val |=
			BIT(IEEE80211_RADIOTAP_EXT) |
			BIT(IEEE80211_RADIOTAP_RADIOTAP_NAMESPACE);
		put_unaligned_le32(it_present_val, it_present);
		it_present++;
		it_present_val = BIT(IEEE80211_RADIOTAP_ANTENNA) |
				 BIT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL);
	}

	put_unaligned_le32(it_present_val, it_present);

	pos = (void *)(it_present + 1);

	/* the order of the following fields is important */

	/* IEEE80211_RADIOTAP_TSFT */
	if (ieee80211_have_rx_timestamp(status)) {
		/* padding */
		while ((pos - (u8 *)rthdr) & 7)
			*pos++ = 0;
		put_unaligned_le64(
			ieee80211_calculate_rx_timestamp(&local->hw, status,
							 mpdulen, 0),
			pos);
		rthdr->it_present |= cpu_to_le32(BIT(IEEE80211_RADIOTAP_TSFT));
		pos += 8;
	}

	/* IEEE80211_RADIOTAP_FLAGS */
	if (has_fcs && ieee80211_hw_check(&local->hw, RX_INCLUDES_FCS))
		*pos |= IEEE80211_RADIOTAP_F_FCS;
	if (status->flag & (RX_FLAG_FAILED_FCS_CRC | RX_FLAG_FAILED_PLCP_CRC))
		*pos |= IEEE80211_RADIOTAP_F_BADFCS;
	if (status->enc_flags & RX_ENC_FLAG_SHORTPRE)
		*pos |= IEEE80211_RADIOTAP_F_SHORTPRE;
	pos++;

	/* IEEE80211_RADIOTAP_RATE */
	if (!rate || status->encoding != RX_ENC_LEGACY) {
		*pos = 0;
	} else {
		int shift = 0;
		rthdr->it_present |= cpu_to_le32(BIT(IEEE80211_RADIOTAP_RATE));
		if (status->bw == RATE_INFO_BW_10)
			shift = 1;
		else if (status->bw == RATE_INFO_BW_5)
			shift = 2;
		*pos = DIV_ROUND_UP(rate->bitrate, 5 * (1 << shift));
	}
	pos++;

	/* IEEE80211_RADIOTAP_CHANNEL */
	put_unaligned_le16(status->freq, pos);
	pos += 2;
	if (status->bw == RATE_INFO_BW_10)
		channel_flags |= IEEE80211_CHAN_HALF;
	else if (status->bw == RATE_INFO_BW_5)
		channel_flags |= IEEE80211_CHAN_QUARTER;

	if (status->band == NL80211_BAND_5GHZ ||
	    status->band == NL80211_BAND_6GHZ)
		channel_flags |= IEEE80211_CHAN_OFDM | IEEE80211_CHAN_5GHZ;
	else if (status->encoding != RX_ENC_LEGACY)
		channel_flags |= IEEE80211_CHAN_DYN | IEEE80211_CHAN_2GHZ;
	else if (rate && rate->flags & IEEE80211_RATE_ERP_G)
		channel_flags |= IEEE80211_CHAN_OFDM | IEEE80211_CHAN_2GHZ;
	else if (rate)
		channel_flags |= IEEE80211_CHAN_CCK | IEEE80211_CHAN_2GHZ;
	else
		channel_flags |= IEEE80211_CHAN_2GHZ;
	put_unaligned_le16(channel_flags, pos);
	pos += 2;

	/* IEEE80211_RADIOTAP_DBM_ANTSIGNAL */
	if (ieee80211_hw_check(&local->hw, SIGNAL_DBM) &&
	    !(status->flag & RX_FLAG_NO_SIGNAL_VAL)) {
		*pos = status->signal;
		rthdr->it_present |=
			cpu_to_le32(BIT(IEEE80211_RADIOTAP_DBM_ANTSIGNAL));
		pos++;
	}

	if (!status->chains) {
		/* IEEE80211_RADIOTAP_ANTENNA */
		*pos = status->antenna;
		pos++;
	}

	/* IEEE80211_RADIOTAP_RX_FLAGS */
	/* ensure 2 byte alignment for the 2 byte field as required */
	if ((pos - (u8 *)rthdr) & 1)
		*pos++ = 0;
	if (status->flag & RX_FLAG_FAILED_PLCP_CRC)
		rx_flags |= IEEE80211_RADIOTAP_F_RX_BADPLCP;
	put_unaligned_le16(rx_flags, pos);
	pos += 2;

	if (status->encoding == RX_ENC_HT) {
		unsigned int stbc;

		rthdr->it_present |= cpu_to_le32(BIT(IEEE80211_RADIOTAP_MCS));
		*pos = local->hw.radiotap_mcs_details;
		if (status->enc_flags & RX_ENC_FLAG_HT_GF)
			*pos |= IEEE80211_RADIOTAP_MCS_HAVE_FMT;
		if (status->enc_flags & RX_ENC_FLAG_LDPC)
			*pos |= IEEE80211_RADIOTAP_MCS_HAVE_FEC;
		pos++;
		*pos = 0;
		if (status->enc_flags & RX_ENC_FLAG_SHORT_GI)
			*pos |= IEEE80211_RADIOTAP_MCS_SGI;
		if (status->bw == RATE_INFO_BW_40)
			*pos |= IEEE80211_RADIOTAP_MCS_BW_40;
		if (status->enc_flags & RX_ENC_FLAG_HT_GF)
			*pos |= IEEE80211_RADIOTAP_MCS_FMT_GF;
		if (status->enc_flags & RX_ENC_FLAG_LDPC)
			*pos |= IEEE80211_RADIOTAP_MCS_FEC_LDPC;
		stbc = (status->enc_flags & RX_ENC_FLAG_STBC_MASK) >> RX_ENC_FLAG_STBC_SHIFT;
		*pos |= stbc << IEEE80211_RADIOTAP_MCS_STBC_SHIFT;
		pos++;
		*pos++ = status->rate_idx;
	}

	if (status->flag & RX_FLAG_AMPDU_DETAILS) {
		u16 flags = 0;

		/* ensure 4 byte alignment */
		while ((pos - (u8 *)rthdr) & 3)
			pos++;
		rthdr->it_present |=
			cpu_to_le32(BIT(IEEE80211_RADIOTAP_AMPDU_STATUS));
		put_unaligned_le32(status->ampdu_reference, pos);
		pos += 4;
		if (status->flag & RX_FLAG_AMPDU_LAST_KNOWN)
			flags |= IEEE80211_RADIOTAP_AMPDU_LAST_KNOWN;
		if (status->flag & RX_FLAG_AMPDU_IS_LAST)
			flags |= IEEE80211_RADIOTAP_AMPDU_IS_LAST;
		if (status->flag & RX_FLAG_AMPDU_DELIM_CRC_ERROR)
			flags |= IEEE80211_RADIOTAP_AMPDU_DELIM_CRC_ERR;
		if (status->flag & RX_FLAG_AMPDU_EOF_BIT_KNOWN)
			flags |= IEEE80211_RADIOTAP_AMPDU_EOF_KNOWN;
		if (status->flag & RX_FLAG_AMPDU_EOF_BIT)
			flags |= IEEE80211_RADIOTAP_AMPDU_EOF;
		put_unaligned_le16(flags, pos);
		pos += 2;
		*pos++ = 0;
		*pos++ = 0;
	}

	if (status->encoding == RX_ENC_VHT) {
		u16 fill = local->hw.radiotap_vht_details;

		/* Leave driver filled fields alone */
		fill &= ~le16_to_cpu(vht.known);
		vht.known |= cpu_to_le16(fill);

		if (fill & IEEE80211_RADIOTAP_VHT_KNOWN_GI &&
		    status->enc_flags & RX_ENC_FLAG_SHORT_GI)
			vht.flags |= IEEE80211_RADIOTAP_VHT_FLAG_SGI;
		/* in VHT, STBC is binary */
		if (fill & IEEE80211_RADIOTAP_VHT_KNOWN_STBC &&
		    status->enc_flags & RX_ENC_FLAG_STBC_MASK)
			vht.flags |= IEEE80211_RADIOTAP_VHT_FLAG_STBC;
		if (fill & IEEE80211_RADIOTAP_VHT_KNOWN_BEAMFORMED &&
		    status->enc_flags & RX_ENC_FLAG_BF)
			*pos |= IEEE80211_RADIOTAP_VHT_FLAG_BEAMFORMED;

		if (fill & IEEE80211_RADIOTAP_VHT_KNOWN_BANDWIDTH) {
			switch (status->bw) {
			case RATE_INFO_BW_40:
				vht.bandwidth = IEEE80211_RADIOTAP_VHT_BW_40;
				break;
			case RATE_INFO_BW_80:
				vht.bandwidth = IEEE80211_RADIOTAP_VHT_BW_80;
				break;
			case RATE_INFO_BW_160:
				vht.bandwidth = IEEE80211_RADIOTAP_VHT_BW_160;
				break;
			default:
				vht.bandwidth = IEEE80211_RADIOTAP_VHT_BW_20;
				break;
			}
		}

		if (!vht.mcs_nss[0]) {
			vht.mcs_nss[0] = (status->rate_idx << 4) | status->nss;

			/* coding field */
			if (status->enc_flags & RX_ENC_FLAG_LDPC)
				vht.coding |= IEEE80211_RADIOTAP_CODING_LDPC_USER0;
		}

		/* ensure 2 byte alignment */
		while ((pos - (u8 *)rthdr) & 1)
			pos++;
		rthdr->it_present |= cpu_to_le32(BIT(IEEE80211_RADIOTAP_VHT));
		memcpy(pos, &vht, sizeof(vht));
		pos += sizeof(vht);
	}

	if (local->hw.radiotap_timestamp.units_pos >= 0) {
		u16 accuracy = 0;
		u8 flags;
		u64 ts;

		rthdr->it_present |=
			cpu_to_le32(BIT(IEEE80211_RADIOTAP_TIMESTAMP));

		/* ensure 8 byte alignment */
		while ((pos - (u8 *)rthdr) & 7)
			pos++;

		if (status->flag & RX_FLAG_MACTIME_IS_RTAP_TS64) {
			flags = IEEE80211_RADIOTAP_TIMESTAMP_FLAG_64BIT;
			ts = status->mactime;
		} else {
			flags = IEEE80211_RADIOTAP_TIMESTAMP_FLAG_32BIT;
			ts = status->device_timestamp;
		}

		put_unaligned_le64(ts, pos);
		pos += sizeof(u64);

		if (local->hw.radiotap_timestamp.accuracy >= 0) {
			accuracy = local->hw.radiotap_timestamp.accuracy;
			flags |= IEEE80211_RADIOTAP_TIMESTAMP_FLAG_ACCURACY;
		}
		put_unaligned_le16(accuracy, pos);
		pos += sizeof(u16);

		*pos++ = local->hw.radiotap_timestamp.units_pos;
		*pos++ = flags;
	}

	if (status->encoding == RX_ENC_HE &&
	    status->flag & RX_FLAG_RADIOTAP_HE) {
#define HE_PREP(f, val)	le16_encode_bits(val, IEEE80211_RADIOTAP_HE_##f)

		if (status->enc_flags & RX_ENC_FLAG_STBC_MASK) {
			he.data6 |= HE_PREP(DATA6_NSTS,
					    FIELD_GET(RX_ENC_FLAG_STBC_MASK,
						      status->enc_flags));
			he.data3 |= HE_PREP(DATA3_STBC, 1);
		} else {
			he.data6 |= HE_PREP(DATA6_NSTS, status->nss);
		}

		he.data3 |= HE_PREP(DATA3_DATA_MCS, status->rate_idx);
		he.data3 |= HE_PREP(DATA3_DATA_DCM, status->he_dcm);
		he.data3 |= HE_PREP(DATA3_CODING,
				    !!(status->enc_flags & RX_ENC_FLAG_LDPC));

		he.data5 |= HE_PREP(DATA5_GI, status->he_gi);

		switch (status->bw) {
		case RATE_INFO_BW_20:
			he.data5 |= HE_PREP(DATA5_DATA_BW_RU_ALLOC,
					    IEEE80211_RADIOTAP_HE_DATA5_DATA_BW_RU_ALLOC_20MHZ);
			break;
		case RATE_INFO_BW_40:
			he.data5 |= HE_PREP(DATA5_DATA_BW_RU_ALLOC,
					    IEEE80211_RADIOTAP_HE_DATA5_DATA_BW_RU_ALLOC_40MHZ);
			break;
		case RATE_INFO_BW_80:
			he.data5 |= HE_PREP(DATA5_DATA_BW_RU_ALLOC,
					    IEEE80211_RADIOTAP_HE_DATA5_DATA_BW_RU_ALLOC_80MHZ);
			break;
		case RATE_INFO_BW_160:
			he.data5 |= HE_PREP(DATA5_DATA_BW_RU_ALLOC,
					    IEEE80211_RADIOTAP_HE_DATA5_DATA_BW_RU_ALLOC_160MHZ);
			break;
		case RATE_INFO_BW_HE_RU:
			he.data5 |= HE_PREP(DATA5_DATA_BW_RU_ALLOC,
					    status->he_ru + 4);
			break;
		default:
			WARN_ONCE(1, "Invalid SU BW %d\n", status->bw);
		}

		/* ensure 2 byte alignment */
		while ((pos - (u8 *)rthdr) & 1)
			pos++;
		rthdr->it_present |= cpu_to_le32(BIT(IEEE80211_RADIOTAP_HE));
		memcpy(pos, &he, sizeof(he));
		pos += sizeof(he);
	}

	if (status->encoding == RX_ENC_HE &&
	    status->flag & RX_FLAG_RADIOTAP_HE_MU) {
		/* ensure 2 byte alignment */
		while ((pos - (u8 *)rthdr) & 1)
			pos++;
		rthdr->it_present |= cpu_to_le32(BIT(IEEE80211_RADIOTAP_HE_MU));
		memcpy(pos, &he_mu, sizeof(he_mu));
		pos += sizeof(he_mu);
	}

	if (status->flag & RX_FLAG_NO_PSDU) {
		rthdr->it_present |=
			cpu_to_le32(BIT(IEEE80211_RADIOTAP_ZERO_LEN_PSDU));
		*pos++ = status->zero_length_psdu_type;
	}

	if (status->flag & RX_FLAG_RADIOTAP_LSIG) {
		/* ensure 2 byte alignment */
		while ((pos - (u8 *)rthdr) & 1)
			pos++;
		rthdr->it_present |= cpu_to_le32(BIT(IEEE80211_RADIOTAP_LSIG));
		memcpy(pos, &lsig, sizeof(lsig));
		pos += sizeof(lsig);
	}

	for_each_set_bit(chain, &chains, IEEE80211_MAX_CHAINS) {
		*pos++ = status->chain_signal[chain];
		*pos++ = chain;
	}
}

/* Builds radiotap in front of the frame and hands it to the monitor callback */
void kc_mac80211_deliver(struct ieee80211_local *local, struct sk_buff *skb) {
    struct ieee80211_rx_status *status = IEEE80211_SKB_RXCB(skb);
    struct ieee80211_supported_band *sband;
    struct ieee80211_rate *rate = NULL;
    int rtap_len;

    if (local->rx_cb == NULL)
        goto out;

    if (status->band >= NUM_NL80211_BANDS || (sband = local->hw.wiphy->bands[status->band]) == NULL)
        goto out;

    if (status->encoding == RX_ENC_LEGACY && status->rate_idx < sband->n_bitrates)
        rate = &sband->bitrates[status->rate_idx];

    if (skb_is_nonlinear(skb) && skb_linearize(skb) < 0)
        goto out;

    rtap_len = ieee80211_rx_radiotap_hdrlen(local, status, skb);

    /* Driver-supplied radiotap fields sit in front of the frame and are pulled first */
    int driver_rtap = 0;
    if (status->flag & RX_FLAG_RADIOTAP_VHT)
        driver_rtap += sizeof(struct ieee80211_radiotap_vht);
    if (status->flag & RX_FLAG_RADIOTAP_HE)
        driver_rtap += sizeof(struct ieee80211_radiotap_he);
    if (status->flag & RX_FLAG_RADIOTAP_HE_MU)
        driver_rtap += sizeof(struct ieee80211_radiotap_he_mu);
    if (status->flag & RX_FLAG_RADIOTAP_LSIG)
        driver_rtap += sizeof(struct ieee80211_radiotap_lsig);

    if ((unsigned int) driver_rtap > skb->len)
        goto out;

    int need = rtap_len - driver_rtap;
    if (need > 0 && (int) skb_headroom(skb) < need &&
            pskb_expand_head(skb, need - (int) skb_headroom(skb), 0, GFP_ATOMIC) < 0)
        goto out;

    ieee80211_add_rx_radiotap_header(local, skb, rate, rtap_len, false);

    local->rx_cb(local->rx_ctx, &local->hw, status, skb->data, skb->len);

out:
    kfree_skb(skb);
}

/* Delivered from the driver's RX work rather than a tasklet */
void ieee80211_rx_irqsafe(struct ieee80211_hw *hw, struct sk_buff *skb) {
    kc_mac80211_deliver(hw_to_local(hw), skb);
}

void ieee80211_rx_list(struct ieee80211_hw *hw, struct ieee80211_sta *sta, struct sk_buff *skb,
        struct list_head *list) {
    (void) sta;
    (void) list;
    kc_mac80211_deliver(hw_to_local(hw), skb);
}
