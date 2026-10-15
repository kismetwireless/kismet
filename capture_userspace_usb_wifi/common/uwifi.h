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

#ifndef __UWIFI_H__
#define __UWIFI_H__

/* Userspace USB Wi-Fi: the interface tools and capture code use, independent of driver.
 *
 * Devices are found by matching every registered driver's USB ID table.  Opening a
 * device runs the driver's probe; once it registers with mac80211 its bands describe
 * the supported channels, rates and widths. */

#include <kc_mac80211.h>

struct uwifi_dev;

struct uwifi_dev_info {
    /* Synthetic interface name: the driver without its USB suffix and a per-driver index,
     * in USB path order, such as "mt7921-0" */
    char ifname[40];
    char driver[32];
    u16 vid;
    u16 pid;
    int bus;
    int address;
    char path[32];
    const char *speed;
};

/* Firmware directories are searched in order for driver firmware paths */
int uwifi_init(const char *const *fw_paths, size_t n_paths, int log_level);

/* Sends driver log messages to cb instead of stderr */
void uwifi_set_log_cb(void (*cb)(void *ctx, int level, const char *msg), void *ctx);

/* Error-level messages logged by drivers so far, such as rejected firmware commands */
unsigned long uwifi_error_count(void);

/* Lists supported adapters without opening them; free with free() */
int uwifi_list(struct uwifi_dev_info **list, size_t *n);

/* Opens the index-th supported adapter, loading firmware; NULL on failure */
struct uwifi_dev *uwifi_open(size_t index, unsigned int timeout_ms);
/* Finds an adapter by synthetic interface name; returns its index or -ENODEV */
int uwifi_find_ifname(const char *ifname, struct uwifi_dev_info *info);
struct uwifi_dev *uwifi_open_ifname(const char *ifname, unsigned int timeout_ms);
void uwifi_close(struct uwifi_dev *dev);

struct ieee80211_hw *uwifi_hw(struct uwifi_dev *dev);
const u8 *uwifi_mac(struct uwifi_dev *dev);
/* False once the adapter has been unplugged or stopped responding */
bool uwifi_alive(struct uwifi_dev *dev);
/* The band exists and supports the width */
bool uwifi_band_width_ok(struct uwifi_dev *dev, enum nl80211_band band, enum nl80211_chan_width width);
const struct uwifi_dev_info *uwifi_info(struct uwifi_dev *dev);
const char *uwifi_product(struct uwifi_dev *dev);

/* Writes bands, channels, rates, HT/VHT/HE capabilities and widths */
void uwifi_print_caps(struct uwifi_dev *dev, FILE *out);

/* A channel and width to tune, in Kismet's notation: "6", "6HT40+", "36VHT80", "6g:37HE80" */
struct uwifi_chan {
    enum nl80211_band band;
    int channel;
    enum nl80211_chan_width width;
    u32 center_freq1;
    char name[24];
};

int uwifi_parse_chan(struct uwifi_dev *dev, const char *spec, struct uwifi_chan *chan);
/* Every supported channel at the given widths (bitmask of 1 << NL80211_CHAN_WIDTH_*) and bands */
int uwifi_hop_list(struct uwifi_dev *dev, unsigned int bands, unsigned int widths,
        struct uwifi_chan **list, size_t *n);

int uwifi_start_monitor(struct uwifi_dev *dev, kc_mac80211_rx_cb_t cb, void *ctx);
int uwifi_set_chan(struct uwifi_dev *dev, const struct uwifi_chan *chan);

static inline const char *uwifi_band_name(enum nl80211_band b) {
    return b == NL80211_BAND_2GHZ ? "2.4GHz" : b == NL80211_BAND_5GHZ ? "5GHz" :
        b == NL80211_BAND_6GHZ ? "6GHz" : "other";
}

#endif
