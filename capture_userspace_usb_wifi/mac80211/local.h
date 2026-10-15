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

#ifndef __KC_MAC80211_LOCAL_H__
#define __KC_MAC80211_LOCAL_H__

/* mac80211 internal state, named as in net/mac80211 so ported code reads the same */

#include "kc_mac80211.h"

struct ieee80211_local {
    struct ieee80211_hw hw;
    const struct ieee80211_ops *ops;
    struct workqueue_struct *workqueue;

    bool registered;
    bool started;
    int open_count;
    /* Driver supplied the emulate_* chanctx helpers */
    bool emulate_chanctx;

    /* The single monitor interface and its channel context */
    struct ieee80211_vif *monitor_vif;
    struct ieee80211_chanctx_conf *chanctx;
    struct cfg80211_chan_def default_chandef;

    char alpha2[3];

    kc_mac80211_rx_cb_t rx_cb;
    void *rx_ctx;

    struct list_head list;
};

static inline struct ieee80211_local *hw_to_local(struct ieee80211_hw *hw) {
    return container_of(hw, struct ieee80211_local, hw);
}

/* From net/mac80211/ieee80211_i.h */
#define IEEE80211_DEFAULT_UAPSD_QUEUES 0
#define IEEE80211_DEFAULT_MAX_SP_LEN IEEE80211_WMM_IE_STA_QOSINFO_SP_ALL

static inline bool
ieee80211_have_rx_timestamp(struct ieee80211_rx_status *status)
{
	return status->flag & RX_FLAG_MACTIME;
}

/* rx.c */
void kc_mac80211_deliver(struct ieee80211_local *local, struct sk_buff *skb);

#endif
