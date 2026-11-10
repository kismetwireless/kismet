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

/* Kismet's 802.11ah view of the MM8108 that userspace-wifi presents as a 5GHz radio */

#include <kcompat/host.h>

#include "common/uwifi.h"
#include "mm8108/mm_channels.h"
#include "mm8108/mm_s1g.h"
#include "mm8108_kismet.h"

#define MM_KIS_DRIVER "mm8108"
#define MM_KIS_OPEN_TIMEOUT_MS 30000

/* The driver's TLVs end the radiotap header: the S1G TLV (12 bytes) and Morse Micro's
 * frequency TLV (16 bytes) */
#define MM_KIS_TLVS_LEN 28
#define MM_KIS_RT_TLV_BIT 28

/* Header (8), TSFT (8), flags (1), pad (1), channel (4), signal (1), pad (1), then the TLVs */
#define MM_KIS_RT_FIXED_LEN 24
#define MM_KIS_RT_LEN (MM_KIS_RT_FIXED_LEN + MM_KIS_TLVS_LEN)

#define RT_PRESENT_TSFT         (1u << 0)
#define RT_PRESENT_FLAGS        (1u << 1)
#define RT_PRESENT_CHANNEL      (1u << 3)
#define RT_PRESENT_ANTSIGNAL    (1u << 5)

#define RT_FLAG_BADFCS          0x40

#define RT_CHAN_700MHZ          0x0001
#define RT_CHAN_800MHZ          0x0002
#define RT_CHAN_900MHZ          0x0004

static const uint8_t mm_kis_morse_oui[3] = { 0x0C, 0xBF, 0x74 };

static mm_kis_log_t kis_log;
static void *kis_log_ctx;

/* The last driver error, to explain a failed open */
static pthread_mutex_t kis_err_lock = PTHREAD_MUTEX_INITIALIZER;
static char kis_last_err[256];

static void mm_kis_log_cb(void *ctx, int level, const char *msg) {
    (void) ctx;

    if (level <= 3) {
        pthread_mutex_lock(&kis_err_lock);
        snprintf(kis_last_err, sizeof(kis_last_err), "%s", msg);
        pthread_mutex_unlock(&kis_err_lock);
    }

    if (kis_log)
        kis_log(kis_log_ctx, level, msg);
}

int mm_kis_init(const char *const *fw_paths, size_t n_paths, mm_kis_log_t log, void *ctx,
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

    uwifi_set_log_cb(mm_kis_log_cb, NULL);
    inited = true;
    return 0;
}

int mm_kis_list(struct mm_kis_iface **list, size_t *n) {
    struct uwifi_dev_info *info;
    size_t num, k = 0;
    int r;

    *list = NULL;
    *n = 0;

    if ((r = uwifi_list(&info, &num)) < 0 || num == 0)
        return r;

    if ((*list = calloc(num, sizeof(**list))) == NULL) {
        free(info);
        return -ENOMEM;
    }

    for (size_t i = 0; i < num; i++) {
        if (strcmp(info[i].driver, MM_KIS_DRIVER) != 0)
            continue;
        snprintf((*list)[k].ifname, sizeof((*list)[k].ifname), "%s", info[i].ifname);
        snprintf((*list)[k].hardware, sizeof((*list)[k].hardware),
                "Morse Micro MM8108 HaLow (%04x:%04x)", info[i].vid, info[i].pid);
        k++;
    }

    free(info);

    if (k == 0) {
        free(*list);
        *list = NULL;
    }

    *n = k;
    return 0;
}

bool mm_kis_find(const char *ifname, char *hardware, size_t hw_len) {
    struct uwifi_dev_info info;

    if (uwifi_find_ifname(ifname, &info) < 0 || strcmp(info.driver, MM_KIS_DRIVER) != 0)
        return false;

    snprintf(hardware, hw_len, "Morse Micro MM8108 HaLow (%04x:%04x)", info.vid, info.pid);
    return true;
}

struct uwifi_dev *mm_kis_open(const char *ifname, const char *firmware, const char *boardfile,
        const char *country, char *error, size_t error_len) {
    struct uwifi_dev *dev;
    char hw[96];

    if (!mm_kis_find(ifname, hw, sizeof(hw))) {
        snprintf(error, error_len, "%s is not an attached MM8108 HaLow adapter", ifname);
        return NULL;
    }

    pthread_mutex_lock(&kis_err_lock);
    kis_last_err[0] = 0;
    pthread_mutex_unlock(&kis_err_lock);

    uwifi_set_firmware_choice(firmware, boardfile);
    uwifi_set_country_choice(country);

    if ((dev = uwifi_open_ifname(ifname, MM_KIS_OPEN_TIMEOUT_MS)) == NULL) {
        pthread_mutex_lock(&kis_err_lock);
        if (kis_last_err[0])
            snprintf(error, error_len, "could not open %s: %s", ifname, kis_last_err);
        else
            snprintf(error, error_len, "could not open %s; check that it isn't in use and that "
                    "there is permission to access the USB device", ifname);
        pthread_mutex_unlock(&kis_err_lock);
        return NULL;
    }

    return dev;
}

void mm_kis_close(struct uwifi_dev *dev) {
    uwifi_close(dev);
}

void mm_kis_exit(void) {
    uwifi_exit();
}

bool mm_kis_alive(struct uwifi_dev *dev) {
    return uwifi_alive(dev);
}

const uint8_t *mm_kis_mac(struct uwifi_dev *dev) {
    return uwifi_mac(dev);
}

const char *mm_kis_country(struct uwifi_dev *dev) {
    return uwifi_country(dev);
}

void mm_kis_hardware(struct uwifi_dev *dev, char *out, size_t len) {
    const struct uwifi_dev_info *info = uwifi_info(dev);
    const char *fw = uwifi_hw(dev)->wiphy->fw_version;

    snprintf(out, len, "Morse Micro MM8108 HaLow (%04x:%04x)%s%s", info->vid, info->pid,
            fw[0] ? ", firmware " : "", fw);
}

void mm_kis_countries(char *buf, size_t len) {
    mm_s1g_countries(buf, len);
}

bool mm_kis_country_known(const char *country) {
    return mm_s1g_region(country) != NULL;
}

/* Channels */
struct mm_kis_chan {
    struct uwifi_chan chan;
    unsigned int s1g;
};

static const struct mm_s1g_region *mm_kis_region(struct uwifi_dev *dev) {
    return mm_s1g_region(uwifi_country(dev));
}

static enum nl80211_chan_width mm_kis_width(unsigned int bw_mhz) {
    switch (bw_mhz) {
        case 1:
            return NL80211_CHAN_WIDTH_20;
        case 2:
            return NL80211_CHAN_WIDTH_40;
        case 4:
            return NL80211_CHAN_WIDTH_80;
        case 8:
            return NL80211_CHAN_WIDTH_160;
        default:
            return NL80211_CHAN_WIDTH_20_NOHT;
    }
}

static u32 mm_kis_5g_freq(unsigned int chan_5g) {
    return 5000 + 5 * chan_5g;
}

/* The tuning primary of ch: itself at 1MHz, else its lowest 1MHz channel the adapter has, and
 * whether the driver allows ch at all, which it flags on its 1MHz channels by width */
static const struct ieee80211_channel *mm_kis_primary(struct uwifi_dev *dev,
        const struct mm_s1g_region *region, const struct mm_s1g_channel *ch) {
    const struct ieee80211_channel *best = NULL;
    u32 best_khz = 0;

    for (size_t i = 0; i < region->num_channels; i++) {
        const struct mm_s1g_channel *c = &region->channels[i];
        const struct ieee80211_channel *bc;

        if (c->bw_mhz != 1)
            continue;
        if (ch->bw_mhz == 1 ? c != ch : mm_s1g_containing(region, c, ch->bw_mhz, NULL) != ch)
            continue;
        if ((bc = uwifi_find_chan(dev, NL80211_BAND_5GHZ, c->chan_5g)) == NULL)
            continue;

        if (best == NULL || c->freq_khz < best_khz) {
            best = bc;
            best_khz = c->freq_khz;
        }
    }

    if (best == NULL)
        return NULL;

    switch (ch->bw_mhz) {
        case 1:
            return best;
        case 2:
            return (best->flags & IEEE80211_CHAN_NO_HT40PLUS) &&
                (best->flags & IEEE80211_CHAN_NO_HT40MINUS) ? NULL : best;
        case 4:
            return (best->flags & IEEE80211_CHAN_NO_80MHZ) ? NULL : best;
        case 8:
            return (best->flags & IEEE80211_CHAN_NO_160MHZ) ? NULL : best;
        default:
            return NULL;
    }
}

static bool mm_kis_width_listed(const char *widths, unsigned int bw) {
    char buf[64], *save = NULL;

    if (widths == NULL)
        return true;

    snprintf(buf, sizeof(buf), "%s", widths);

    for (char *t = strtok_r(buf, ",", &save); t != NULL; t = strtok_r(NULL, ",", &save))
        if ((unsigned int) strtoul(t, NULL, 10) == bw)
            return true;

    return false;
}

int mm_kis_channels(struct uwifi_dev *dev, const char *widths, char ***list, size_t *n) {
    const struct mm_s1g_region *region = mm_kis_region(dev);
    char name[16];

    *list = NULL;
    *n = 0;

    if (region == NULL)
        return -EINVAL;

    if ((*list = calloc(region->num_channels, sizeof(char *))) == NULL)
        return -ENOMEM;

    for (size_t i = 0; i < region->num_channels; i++) {
        const struct mm_s1g_channel *c = &region->channels[i];

        if (!mm_kis_width_listed(widths, c->bw_mhz) || mm_kis_primary(dev, region, c) == NULL)
            continue;

        snprintf(name, sizeof(name), "%uah", c->channel);
        if (((*list)[*n] = strdup(name)) == NULL) {
            for (size_t j = 0; j < *n; j++)
                free((*list)[j]);
            free(*list);
            *list = NULL;
            *n = 0;
            return -ENOMEM;
        }
        (*n)++;
    }

    return 0;
}

void *mm_kis_parse_channel(struct uwifi_dev *dev, const char *chanstr) {
    const struct mm_s1g_region *region = mm_kis_region(dev);
    const struct mm_s1g_channel *ch;
    const struct ieee80211_channel *pri;
    struct mm_kis_chan *kc;
    unsigned long c;
    char *end;

    if (region == NULL || chanstr == NULL)
        return NULL;

    errno = 0;
    c = strtoul(chanstr, &end, 10);

    if (errno != 0 || end == chanstr || (*end != 0 && strcasecmp(end, "ah") != 0) || c > UINT16_MAX)
        return NULL;

    if ((ch = mm_s1g_channel_lookup(region, (unsigned int) c)) == NULL ||
            (pri = mm_kis_primary(dev, region, ch)) == NULL)
        return NULL;

    if ((kc = calloc(1, sizeof(*kc))) == NULL)
        return NULL;

    kc->s1g = ch->channel;
    kc->chan.band = NL80211_BAND_5GHZ;
    kc->chan.channel = pri->hw_value;
    kc->chan.width = mm_kis_width(ch->bw_mhz);
    kc->chan.center_freq1 = mm_kis_5g_freq(ch->chan_5g);
    snprintf(kc->chan.name, sizeof(kc->chan.name), "%uah", ch->channel);

    return kc;
}

const char *mm_kis_channel_name(const void *chan) {
    return ((const struct mm_kis_chan *) chan)->chan.name;
}

int mm_kis_set_channel(struct uwifi_dev *dev, const void *chan) {
    const struct mm_kis_chan *kc = chan;
    unsigned long errs = uwifi_error_count();
    int r;

    if ((r = uwifi_set_chan(dev, &kc->chan)) < 0)
        return r;

    /* The driver logs firmware rejections rather than returning them */
    return uwifi_error_count() == errs ? 0 : -EIO;
}

/* Receive: rebuilds the radiotap mac80211 made for the 5GHz view as S1G radiotap */
struct mm_kis_rx_ctx {
    mm_kis_rx_t rx;
    void *ctx;
};

static struct mm_kis_rx_ctx kis_rx;

static void mm_kis_rx_frame(void *ctx, struct ieee80211_hw *hw, const struct ieee80211_rx_status *status,
        const u8 *data, size_t len) {
    struct mm_kis_rx_ctx *k = ctx;
    uint8_t rt[MM_KIS_RT_LEN];
    const u8 *tlv;
    unsigned int it_len;
    u32 khz, mhz;
    u16 chan_flags;
    (void) hw;

    if (len < 8)
        return;

    it_len = get_unaligned_le16(data + 2);

    if (it_len < 8 + MM_KIS_TLVS_LEN || it_len > len ||
            !(get_unaligned_le32(data + 4) & BIT(MM_KIS_RT_TLV_BIT)))
        return;

    /* The S1G TLV then Morse Micro's frequency TLV, as the driver puts them */
    tlv = data + it_len - MM_KIS_TLVS_LEN;

    if (get_unaligned_le16(tlv) != 32 || get_unaligned_le16(tlv + 2) != 6 ||
            get_unaligned_le16(tlv + 12) != 30 || get_unaligned_le16(tlv + 14) != 12 ||
            memcmp(tlv + 16, mm_kis_morse_oui, sizeof(mm_kis_morse_oui)) != 0 ||
            get_unaligned_le16(tlv + 20) != 35)
        return;

    if ((khz = get_unaligned_le32(tlv + 24)) == 0)
        return;

    mhz = khz / 1000;
    chan_flags = mhz <= 700 ? RT_CHAN_700MHZ : mhz <= 800 ? RT_CHAN_800MHZ : RT_CHAN_900MHZ;

    memset(rt, 0, MM_KIS_RT_FIXED_LEN);
    put_unaligned_le16(MM_KIS_RT_LEN, rt + 2);
    put_unaligned_le32(RT_PRESENT_TSFT | RT_PRESENT_FLAGS | RT_PRESENT_CHANNEL |
            RT_PRESENT_ANTSIGNAL | BIT(MM_KIS_RT_TLV_BIT), rt + 4);

    /* The chip's local timer at frame detection */
    if (status->flag & RX_FLAG_MACTIME)
        put_unaligned_le64(status->mactime, rt + 8);

    if (status->flag & (RX_FLAG_FAILED_FCS_CRC | RX_FLAG_FAILED_PLCP_CRC))
        rt[16] = RT_FLAG_BADFCS;

    put_unaligned_le16((u16) mhz, rt + 18);
    put_unaligned_le16(chan_flags, rt + 20);
    rt[22] = (u8) status->signal;

    memcpy(rt + MM_KIS_RT_FIXED_LEN, tlv, MM_KIS_TLVS_LEN);

    k->rx(k->ctx, rt, sizeof(rt), data + it_len, len - it_len);
}

int mm_kis_start(struct uwifi_dev *dev, mm_kis_rx_t rx, void *ctx) {
    kis_rx.rx = rx;
    kis_rx.ctx = ctx;
    return uwifi_start_monitor(dev, mm_kis_rx_frame, &kis_rx);
}
