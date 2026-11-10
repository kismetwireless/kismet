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

#ifndef __KC_MAC80211_H__
#define __KC_MAC80211_H__

/* Minimal mac80211 for unmodified Linux Wi-Fi drivers, for monitor-mode capture and
 * injection.
 *
 * Drivers allocate and register an ieee80211_hw as usual.  The host program finds the
 * registered hw for a probed device, then brings up a monitor interface and changes
 * channels; the calls into the driver follow mac80211's order for a monitor interface.
 * Received frames are delivered with a radiotap header built as mac80211 builds it, and
 * frames are injected with one, as on a Linux monitor interface. */

#include <stdio.h>

#include <net/mac80211.h>

/* data holds a radiotap header followed by the 802.11 frame; valid only during the call */
typedef void (*kc_mac80211_rx_cb_t)(void *ctx, struct ieee80211_hw *hw,
        const struct ieee80211_rx_status *status, const u8 *data, size_t len);

/* Waits for the driver bound to parent to register its hw; NULL on timeout */
struct ieee80211_hw *kc_mac80211_wait_hw(struct device *parent, unsigned int timeout_ms);

/* Sets the regulatory country the driver is notified of; "00" is the world domain */
int kc_mac80211_set_regdomain(struct ieee80211_hw *hw, const char *alpha2);
/* The regulatory country last set; NULL if none was */
const char *kc_mac80211_get_regdomain(struct ieee80211_hw *hw);

/* Status of an injected frame: data is the 802.11 frame, valid only during the call */
typedef void (*kc_mac80211_tx_status_cb_t)(void *ctx, struct ieee80211_hw *hw, const u8 *data, size_t len,
        bool acked);

int kc_mac80211_start_monitor(struct ieee80211_hw *hw, kc_mac80211_rx_cb_t cb, void *ctx);
int kc_mac80211_set_chandef(struct ieee80211_hw *hw, const struct cfg80211_chan_def *def);
void kc_mac80211_stop(struct ieee80211_hw *hw);

/* Adds a station interface with addr beside the monitor, joined to no BSS, so the hardware
 * acknowledges frames sent to addr, as an active monitor does; it's removed on stop */
int kc_mac80211_add_station_vif(struct ieee80211_hw *hw, const u8 *addr);

/* Injects a frame on the current channel: a radiotap header followed by the 802.11 frame,
 * as written to a Linux monitor interface.  Radiotap flags, TX flags, rate, MCS, VHT, data
 * retries and antenna are honoured as mac80211 honours them.  Returns 0 once queued,
 * -EBUSY while the driver's queues are full, -EPERM where the channel forbids transmit
 * (no-IR or radar), -EINVAL for a malformed frame. */
int kc_mac80211_tx(struct ieee80211_hw *hw, const u8 *data, size_t len);
void kc_mac80211_set_tx_status_cb(struct ieee80211_hw *hw, kc_mac80211_tx_status_cb_t cb, void *ctx);

/* For chips which DMA the FCS after some frames but report a length without it; a valid
 * FCS found there is kept on the frame and flagged in radiotap */
void kc_mac80211_set_rx_fcs_past_end(struct ieee80211_hw *hw);

/* For drivers which present their channels as other channels, such as 802.11ah as 5GHz:
 * writes how the registered channels map to the real ones */
typedef void (*kc_mac80211_chanmap_cb_t)(struct ieee80211_hw *hw, FILE *out);
void kc_mac80211_set_chanmap_cb(struct ieee80211_hw *hw, kc_mac80211_chanmap_cb_t cb);
/* Writes nothing for a driver whose channels are real */
void kc_mac80211_print_chanmap(struct ieee80211_hw *hw, FILE *out);

/* Builds a chandef for a control channel, width and centre frequency (0 for 20 MHz) */
int kc_mac80211_chandef(struct ieee80211_hw *hw, enum nl80211_band band, int channel,
        enum nl80211_chan_width width, u32 center_freq1, struct cfg80211_chan_def *def);

#endif
