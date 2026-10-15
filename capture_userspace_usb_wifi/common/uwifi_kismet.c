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

/* Kismet channel names and the capture binary's view of an adapter */

#include <kcompat/host.h>

#include "uwifi.h"
#include "uwifi_kismet.h"
#include "../../wifi_ht_channels.h"

#define UWIFI_KIS_OPEN_TIMEOUT_MS 20000

static uwifi_kis_log_t kis_log;
static void *kis_log_ctx;

static void uwifi_kis_log(void *ctx, int level, const char *msg) {
    (void) ctx;
    if (kis_log)
        kis_log(kis_log_ctx, level, msg);
}

int uwifi_kis_init(const char *const *fw_paths, size_t n_paths, uwifi_kis_log_t log, void *ctx,
        int max_level) {
    static bool inited;
    int r;

    kis_log = log;
    kis_log_ctx = ctx;

    /* Paths may differ between calls, from source options */
    if (inited) {
        kc_firmware_set_paths(fw_paths, n_paths);
        return 0;
    }

    if ((r = uwifi_init(fw_paths, n_paths, max_level)) < 0)
        return r;

    /* Driver messages go to the capture binary rather than stderr */
    uwifi_set_log_cb(uwifi_kis_log, NULL);
    inited = true;
    return 0;
}

int uwifi_kis_list(struct uwifi_kis_iface **list, size_t *n) {
    struct uwifi_dev_info *info;
    int r;

    *list = NULL;

    if ((r = uwifi_list(&info, n)) < 0 || *n == 0)
        return r;

    if ((*list = calloc(*n, sizeof(**list))) == NULL) {
        free(info);
        return -ENOMEM;
    }

    for (size_t i = 0; i < *n; i++) {
        snprintf((*list)[i].ifname, sizeof((*list)[i].ifname), "%s", info[i].ifname);
        snprintf((*list)[i].hardware, sizeof((*list)[i].hardware), "%s (%04x:%04x)", info[i].driver,
                info[i].vid, info[i].pid);
    }

    free(info);
    return 0;
}

struct uwifi_dev *uwifi_kis_open(const char *ifname, char *error, size_t error_len) {
    struct uwifi_dev *dev;

    if (uwifi_find_ifname(ifname, NULL) < 0) {
        snprintf(error, error_len, "no supported USB Wi-Fi adapter named %s", ifname);
        return NULL;
    }

    if ((dev = uwifi_open_ifname(ifname, UWIFI_KIS_OPEN_TIMEOUT_MS)) == NULL) {
        snprintf(error, error_len, "could not open %s; check that it isn't in use, that there is "
                "permission to access the USB device, and that the firmware is installed", ifname);
        return NULL;
    }

    return dev;
}

void uwifi_kis_close(struct uwifi_dev *dev) {
    uwifi_close(dev);
}

bool uwifi_kis_alive(struct uwifi_dev *dev) {
    return uwifi_alive(dev);
}

const uint8_t *uwifi_kis_mac(struct uwifi_dev *dev) {
    return uwifi_mac(dev);
}

void uwifi_kis_hardware(struct uwifi_dev *dev, char *out, size_t len) {
    const struct uwifi_dev_info *info = uwifi_info(dev);
    snprintf(out, len, "%s (%04x:%04x) %s", info->driver, info->vid, info->pid, uwifi_product(dev));
}

/* Channels */
struct uwifi_kis_chan {
    struct uwifi_chan chan;
};

static const struct ieee80211_channel *kis_find_chan(struct uwifi_dev *dev, enum nl80211_band band, int ch) {
    const struct ieee80211_supported_band *sband;

    if (band >= NUM_NL80211_BANDS || (sband = uwifi_hw(dev)->wiphy->bands[band]) == NULL)
        return NULL;

    for (int c = 0; c < sband->n_channels; c++)
        if (sband->channels[c].hw_value == ch && !(sband->channels[c].flags & IEEE80211_CHAN_DISABLED))
            return &sband->channels[c];

    return NULL;
}

/* Every 20MHz channel in a block centred on center_mhz must be usable */
static bool kis_block_ok(struct uwifi_dev *dev, enum nl80211_band band, u32 center_mhz, int width_mhz) {
    for (u32 f = center_mhz - width_mhz / 2 + 10; f < center_mhz + width_mhz / 2; f += 20) {
        int ch = ieee80211_frequency_to_channel(f);
        if (ch <= 0 || kis_find_chan(dev, band, ch) == NULL)
            return false;
    }
    return true;
}

static bool kis_make(struct uwifi_dev *dev, enum nl80211_band band, int ch, enum nl80211_chan_width width,
        u32 center, struct uwifi_chan *out) {
    if (kis_find_chan(dev, band, ch) == NULL || !uwifi_band_width_ok(dev, band, width))
        return false;

    if (width != NL80211_CHAN_WIDTH_20) {
        int mhz = width == NL80211_CHAN_WIDTH_40 ? 40 : width == NL80211_CHAN_WIDTH_80 ? 80 : 160;
        if (!kis_block_ok(dev, band, center, mhz))
            return false;
    }

    memset(out, 0, sizeof(*out));
    out->band = band;
    out->channel = ch;
    out->width = width;
    out->center_freq1 = center;
    return true;
}

static enum nl80211_band kis_band_for(unsigned int ch) {
    return ch <= 14 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ;
}

void *uwifi_kis_parse_channel(struct uwifi_dev *dev, const char *chanstr, char *error, size_t error_len) {
    struct uwifi_kis_chan *kc;
    unsigned int ch = 0, extra = 0;
    char suffix[16] = { 0 };
    enum nl80211_band band;
    enum nl80211_chan_width width = NL80211_CHAN_WIDTH_20;
    u32 freq, center;
    int n;

    if ((kc = calloc(1, sizeof(*kc))) == NULL)
        return NULL;

    /* Channel number, then an optional width suffix */
    if (sscanf(chanstr, "%u%15s", &ch, suffix) < 1 || ch == 0 || ch > 255)
        goto bad;

    if (strcasecmp(suffix, "W6e") == 0 || strcasecmp(suffix, "-W6e") == 0) {
        band = NL80211_BAND_6GHZ;
    } else {
        band = kis_band_for(ch);
    }

    freq = ieee80211_channel_to_frequency((int) ch, band);
    center = freq;

    if (band == NL80211_BAND_6GHZ || suffix[0] == 0 || strcasecmp(suffix, "HT20") == 0) {
        width = NL80211_CHAN_WIDTH_20;
    } else if (strcasecmp(suffix, "HT40+") == 0 || strcasecmp(suffix, "HT40-") == 0) {
        bool plus = suffix[4] == '+';
        unsigned int need = plus ? WIFI_HT_HT40PLUS : WIFI_HT_HT40MINUS;

        if (ch > MAX_WIFI_HT_CHANNEL || !(wifi_ht_channels[ch].flags & need))
            goto bad;

        width = NL80211_CHAN_WIDTH_40;
        center = plus ? freq + 10 : freq - 10;
    } else if (strncasecmp(suffix, "VHT80", 5) == 0 || strncasecmp(suffix, "VHT160", 6) == 0) {
        bool w160 = strncasecmp(suffix, "VHT160", 6) == 0;
        const char *rest = suffix + (w160 ? 6 : 5);

        width = w160 ? NL80211_CHAN_WIDTH_160 : NL80211_CHAN_WIDTH_80;

        if (*rest == '-') {
            /* Explicit centre, as MHz or a channel number */
            if (sscanf(rest + 1, "%u%n", &extra, &n) != 1 || rest[1 + n] != 0)
                goto bad;
            center = extra > 1000 ? extra : ieee80211_channel_to_frequency((int) extra, band);
        } else if (*rest == 0) {
            if (ch > MAX_WIFI_HT_CHANNEL || !(wifi_ht_channels[ch].flags & (w160 ? WIFI_HT_HT160 : WIFI_HT_HT80)))
                goto bad;
            center = (u32) (w160 ? wifi_ht_channels[ch].freq160 : wifi_ht_channels[ch].freq80);
        } else {
            goto bad;
        }
    } else {
        goto bad;
    }

    if (!kis_make(dev, band, (int) ch, width, center, &kc->chan)) {
        snprintf(error, error_len, "channel %s is not supported by this adapter", chanstr);
        free(kc);
        return NULL;
    }

    snprintf(kc->chan.name, sizeof(kc->chan.name), "%s", chanstr);
    return kc;

bad:
    snprintf(error, error_len, "could not parse channel %s", chanstr);
    free(kc);
    return NULL;
}

const char *uwifi_kis_channel_name(const void *chan) {
    return ((const struct uwifi_kis_chan *) chan)->chan.name;
}

int uwifi_kis_set_channel(struct uwifi_dev *dev, const void *chan) {
    const struct uwifi_kis_chan *kc = chan;
    unsigned long errs = uwifi_error_count();

    if (uwifi_set_chan(dev, &kc->chan) < 0)
        return 0;

    /* The driver logs firmware rejections rather than returning them */
    return uwifi_error_count() == errs ? 1 : 0;
}

static int kis_add(char ***list, size_t *n, size_t *cap, const char *name) {
    if (*n == *cap) {
        size_t ncap = *cap ? *cap * 2 : 64;
        char **nl = realloc(*list, ncap * sizeof(char *));
        if (nl == NULL)
            return -ENOMEM;
        *list = nl;
        *cap = ncap;
    }

    if (((*list)[*n] = strdup(name)) == NULL)
        return -ENOMEM;

    (*n)++;
    return 0;
}

int uwifi_kis_channels(struct uwifi_dev *dev, bool ht, bool vht, char ***list, size_t *n) {
    struct wiphy *wiphy = uwifi_hw(dev)->wiphy;
    size_t cap = 0;
    char name[32];
    struct uwifi_chan tmp;

    *list = NULL;
    *n = 0;

    for (int b = 0; b < NUM_NL80211_BANDS; b++) {
        const struct ieee80211_supported_band *sband = wiphy->bands[b];

        if (sband == NULL)
            continue;

        for (int c = 0; c < sband->n_channels; c++) {
            const struct ieee80211_channel *chan = &sband->channels[c];
            const unsigned int ch = chan->hw_value;
            const u32 freq = chan->center_freq;

            if (chan->flags & IEEE80211_CHAN_DISABLED)
                continue;

            if (b == NL80211_BAND_6GHZ) {
                snprintf(name, sizeof(name), "%uW6e", ch);
                if (kis_add(list, n, &cap, name) < 0)
                    return -ENOMEM;
                continue;
            }

            if (b != NL80211_BAND_2GHZ && b != NL80211_BAND_5GHZ)
                continue;

            snprintf(name, sizeof(name), "%u", ch);
            if (kis_add(list, n, &cap, name) < 0)
                return -ENOMEM;

            if (ch > MAX_WIFI_HT_CHANNEL)
                continue;

            const unsigned int flags = wifi_ht_channels[ch].flags;

            if (ht && (flags & WIFI_HT_HT40MINUS) &&
                    kis_make(dev, b, (int) ch, NL80211_CHAN_WIDTH_40, freq - 10, &tmp)) {
                snprintf(name, sizeof(name), "%uHT40-", ch);
                if (kis_add(list, n, &cap, name) < 0)
                    return -ENOMEM;
            }

            if (ht && (flags & WIFI_HT_HT40PLUS) &&
                    kis_make(dev, b, (int) ch, NL80211_CHAN_WIDTH_40, freq + 10, &tmp)) {
                snprintf(name, sizeof(name), "%uHT40+", ch);
                if (kis_add(list, n, &cap, name) < 0)
                    return -ENOMEM;
            }

            if (vht && (flags & WIFI_HT_HT80) &&
                    kis_make(dev, b, (int) ch, NL80211_CHAN_WIDTH_80, (u32) wifi_ht_channels[ch].freq80, &tmp)) {
                snprintf(name, sizeof(name), "%uVHT80", ch);
                if (kis_add(list, n, &cap, name) < 0)
                    return -ENOMEM;
            }

            if (vht && (flags & WIFI_HT_HT160) &&
                    kis_make(dev, b, (int) ch, NL80211_CHAN_WIDTH_160, (u32) wifi_ht_channels[ch].freq160, &tmp)) {
                snprintf(name, sizeof(name), "%uVHT160", ch);
                if (kis_add(list, n, &cap, name) < 0)
                    return -ENOMEM;
            }
        }
    }

    return 0;
}

int uwifi_kis_set_country(struct uwifi_dev *dev, const char *alpha2) {
    return kc_mac80211_set_regdomain(uwifi_hw(dev), alpha2);
}

/* Adapts the mac80211 receive callback to the capture binary's */
struct kis_rx_ctx {
    uwifi_kis_rx_t rx;
    void *ctx;
};

static struct kis_rx_ctx kis_rx;

static void kis_rx_frame(void *ctx, struct ieee80211_hw *hw, const struct ieee80211_rx_status *status,
        const u8 *data, size_t len) {
    struct kis_rx_ctx *k = ctx;
    (void) hw;
    (void) status;
    k->rx(k->ctx, data, len);
}

int uwifi_kis_start(struct uwifi_dev *dev, uwifi_kis_rx_t rx, void *ctx) {
    kis_rx.rx = rx;
    kis_rx.ctx = ctx;
    return uwifi_start_monitor(dev, kis_rx_frame, &kis_rx);
}
