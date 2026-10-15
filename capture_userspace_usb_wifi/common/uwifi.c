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

#include <kcompat/host.h>

#include "uwifi.h"

struct uwifi_dev {
    struct usb_interface *intf;
    struct ieee80211_hw *hw;
    struct uwifi_dev_info info;
};

static int uwifi_log_level = 4;
static unsigned long uwifi_errors;
static void (*uwifi_log_cb)(void *ctx, int level, const char *msg);
static void *uwifi_log_ctx;

void uwifi_set_log_cb(void (*cb)(void *ctx, int level, const char *msg), void *ctx) {
    uwifi_log_ctx = ctx;
    uwifi_log_cb = cb;
}

static void uwifi_log(void *ctx, int level, const char *msg) {
    size_t len = strlen(msg);
    (void) ctx;

    if (level <= 3)
        __atomic_add_fetch(&uwifi_errors, 1, __ATOMIC_RELAXED);

    if (level > uwifi_log_level)
        return;

    if (uwifi_log_cb) {
        uwifi_log_cb(uwifi_log_ctx, level, msg);
        return;
    }

    fprintf(stderr, "%s%s", msg, (len && msg[len - 1] == '\n') ? "" : "\n");
}

unsigned long uwifi_error_count(void) {
    return __atomic_load_n(&uwifi_errors, __ATOMIC_RELAXED);
}

int uwifi_init(const char *const *fw_paths, size_t n_paths, int log_level) {
    uwifi_log_level = log_level;
    kc_set_log_cb(uwifi_log, NULL, 7);
    kc_firmware_set_paths(fw_paths, n_paths);
    return kc_usb_init();
}

static const char *uwifi_speed_name(int speed) {
    switch (speed) {
        case USB_SPEED_LOW:
            return "1.5Mbps";
        case USB_SPEED_FULL:
            return "12Mbps";
        case USB_SPEED_HIGH:
            return "480Mbps";
        case USB_SPEED_SUPER:
            return "5Gbps";
        case USB_SPEED_SUPER_PLUS:
            return "10Gbps";
        default:
            return "unknown";
    }
}

/* USB drivers are named for their bus; the interface name drops that */
static void uwifi_ifname_prefix(const char *driver, char *out, size_t len) {
    size_t n = strlen(driver);

    if (n > 3 && strcmp(driver + n - 3, "usb") == 0)
        n -= 3;
    else if (n > 1 && driver[n - 1] == 'u')
        n -= 1;

    snprintf(out, len, "%.*s", (int) n, driver);
}

static void uwifi_fill_info(const struct kc_usb_probe_entry *e, struct uwifi_dev_info *info) {
    memset(info, 0, sizeof(*info));
    snprintf(info->driver, sizeof(info->driver), "%s", e->driver->name);
    info->vid = e->vid;
    info->pid = e->pid;
    info->bus = e->bus;
    info->address = e->address;
    snprintf(info->path, sizeof(info->path), "%s", e->path);
    info->speed = uwifi_speed_name(e->speed);
}

/* Devices in bus order, so indexes are stable between calls */
static int uwifi_find(struct kc_usb_probe_entry ***arr, size_t *n, struct kc_usb_probe_entry **list) {
    struct kc_usb_probe_entry *e;
    int r;

    *arr = NULL;
    *n = 0;

    if ((r = kc_usb_find_devices(list)) < 0)
        return r;

    if (r == 0)
        return 0;

    if ((*arr = calloc((size_t) r, sizeof(**arr))) == NULL) {
        kc_usb_free_probe(*list);
        return -ENOMEM;
    }

    for (e = *list; e != NULL; e = e->next)
        (*arr)[(*n)++] = e;

    for (size_t i = 1; i < *n; i++) {
        for (size_t j = i; j > 0 && strcmp((*arr)[j - 1]->path, (*arr)[j]->path) > 0; j--) {
            struct kc_usb_probe_entry *t = (*arr)[j - 1];
            (*arr)[j - 1] = (*arr)[j];
            (*arr)[j] = t;
        }
    }

    return 0;
}

int uwifi_list(struct uwifi_dev_info **list, size_t *n) {
    struct kc_usb_probe_entry **arr, *probe = NULL;
    int r;

    *list = NULL;
    *n = 0;

    if ((r = uwifi_find(&arr, n, &probe)) < 0)
        return r;

    if (*n == 0)
        return 0;

    if ((*list = calloc(*n, sizeof(**list))) == NULL) {
        free(arr);
        kc_usb_free_probe(probe);
        return -ENOMEM;
    }

    for (size_t i = 0; i < *n; i++)
        uwifi_fill_info(arr[i], &(*list)[i]);

    /* Index adapters per driver, in path order */
    for (size_t i = 0; i < *n; i++) {
        char prefix[32];
        int idx = 0;

        uwifi_ifname_prefix((*list)[i].driver, prefix, sizeof(prefix));
        for (size_t j = 0; j < i; j++)
            if (strcmp((*list)[j].driver, (*list)[i].driver) == 0)
                idx++;

        snprintf((*list)[i].ifname, sizeof((*list)[i].ifname), "%s-%d", prefix, idx);
    }

    free(arr);
    kc_usb_free_probe(probe);
    return 0;
}

struct uwifi_dev *uwifi_open(size_t index, unsigned int timeout_ms) {
    struct kc_usb_probe_entry **arr, *probe = NULL;
    struct uwifi_dev *dev;
    size_t n;
    int r;

    if (uwifi_find(&arr, &n, &probe) < 0)
        return NULL;

    if (index >= n) {
        pr_err("no supported adapter at index %zu (%zu found)\n", index, n);
        free(arr);
        kc_usb_free_probe(probe);
        return NULL;
    }

    if ((dev = calloc(1, sizeof(*dev))) == NULL) {
        free(arr);
        kc_usb_free_probe(probe);
        return NULL;
    }

    uwifi_fill_info(arr[index], &dev->info);
    r = kc_usb_probe_device(arr[index], &dev->intf);
    free(arr);
    kc_usb_free_probe(probe);

    if (r < 0) {
        pr_err("%s probe failed: %d\n", dev->info.driver, r);
        free(dev);
        return NULL;
    }

    /* Drivers register from asynchronous init work after loading firmware */
    if ((dev->hw = kc_mac80211_wait_hw(&dev->intf->dev, timeout_ms)) == NULL) {
        pr_err("%s did not finish initializing\n", dev->info.driver);
        kc_usb_disconnect(dev->intf);
        free(dev);
        return NULL;
    }

    /* Let the init work finish everything after registration */
    flush_workqueue(system_wq);

    return dev;
}

int uwifi_find_ifname(const char *ifname, struct uwifi_dev_info *info) {
    struct uwifi_dev_info *list;
    size_t n;
    int r;

    if ((r = uwifi_list(&list, &n)) < 0)
        return r;

    r = -ENODEV;
    for (size_t i = 0; i < n; i++) {
        if (strcmp(list[i].ifname, ifname) == 0) {
            if (info)
                *info = list[i];
            r = (int) i;
            break;
        }
    }

    free(list);
    return r;
}

struct uwifi_dev *uwifi_open_ifname(const char *ifname, unsigned int timeout_ms) {
    struct uwifi_dev_info info;
    struct uwifi_dev *dev;
    int idx;

    if ((idx = uwifi_find_ifname(ifname, &info)) < 0)
        return NULL;

    if ((dev = uwifi_open((size_t) idx, timeout_ms)) != NULL)
        snprintf(dev->info.ifname, sizeof(dev->info.ifname), "%s", info.ifname);

    return dev;
}

void uwifi_close(struct uwifi_dev *dev) {
    if (dev == NULL)
        return;

    if (dev->hw)
        kc_mac80211_stop(dev->hw);

    kc_usb_disconnect(dev->intf);
    free(dev);
}

struct ieee80211_hw *uwifi_hw(struct uwifi_dev *dev) {
    return dev->hw;
}

const u8 *uwifi_mac(struct uwifi_dev *dev) {
    return dev->hw->wiphy->perm_addr;
}

bool uwifi_alive(struct uwifi_dev *dev) {
    return !interface_to_usbdev(dev->intf)->kc_gone;
}

const struct uwifi_dev_info *uwifi_info(struct uwifi_dev *dev) {
    return &dev->info;
}

const char *uwifi_product(struct uwifi_dev *dev) {
    struct usb_device *udev = interface_to_usbdev(dev->intf);
    return udev->product ? udev->product : "unknown";
}

/* Capabilities */
static const struct ieee80211_sta_he_cap *uwifi_he_cap(const struct ieee80211_supported_band *sband) {
    const struct ieee80211_sta_he_cap *he = ieee80211_get_he_iftype_cap(sband, NL80211_IFTYPE_STATION);
    return (he && he->has_he) ? he : NULL;
}

static bool uwifi_width_ok(const struct ieee80211_supported_band *sband, enum nl80211_chan_width w) {
    const struct ieee80211_sta_he_cap *he = uwifi_he_cap(sband);
    const u8 he_w = he ? he->he_cap_elem.phy_cap_info[0] : 0;
    const u32 vht_w = sband->vht_cap.vht_supported ? sband->vht_cap.cap & IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK : 0;

    switch (w) {
        case NL80211_CHAN_WIDTH_20:
            return true;
        case NL80211_CHAN_WIDTH_40:
            if (sband->band == NL80211_BAND_2GHZ)
                return (sband->ht_cap.ht_supported && (sband->ht_cap.cap & IEEE80211_HT_CAP_SUP_WIDTH_20_40)) ||
                    (he_w & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_IN_2G);
            if (sband->band == NL80211_BAND_5GHZ)
                return sband->ht_cap.ht_supported && (sband->ht_cap.cap & IEEE80211_HT_CAP_SUP_WIDTH_20_40);
            return he_w & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G;
        case NL80211_CHAN_WIDTH_80:
            if (sband->band == NL80211_BAND_5GHZ)
                return sband->vht_cap.vht_supported;
            if (sband->band == NL80211_BAND_6GHZ)
                return he_w & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_40MHZ_80MHZ_IN_5G;
            return false;
        case NL80211_CHAN_WIDTH_160:
            if (sband->band == NL80211_BAND_5GHZ)
                return vht_w != 0 || (he_w & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G);
            if (sband->band == NL80211_BAND_6GHZ)
                return he_w & IEEE80211_HE_PHY_CAP0_CHANNEL_WIDTH_SET_160MHZ_IN_5G;
            return false;
        default:
            return false;
    }
}

static int uwifi_ht_streams(const struct ieee80211_sta_ht_cap *ht) {
    int s = 0;
    for (int i = 0; i < 4; i++)
        if (ht->mcs.rx_mask[i])
            s = i + 1;
    return s;
}

/* Streams and highest MCS from a VHT/HE 2-bit-per-stream MCS map */
static void uwifi_mcs_map(u16 map, int *streams, int *max_mcs, const int *mcs_for) {
    *streams = 0;
    *max_mcs = -1;
    for (int i = 0; i < 8; i++) {
        int v = (map >> (2 * i)) & 3;
        if (v == 3)
            continue;
        *streams = i + 1;
        if (mcs_for[v] > *max_mcs)
            *max_mcs = mcs_for[v];
    }
}

void uwifi_print_caps(struct uwifi_dev *dev, FILE *out) {
    struct wiphy *wiphy = dev->hw->wiphy;
    static const int vht_mcs[] = { 7, 8, 9 };
    static const int he_mcs[] = { 7, 9, 11 };
    static const enum nl80211_chan_width widths[] = {
        NL80211_CHAN_WIDTH_20, NL80211_CHAN_WIDTH_40, NL80211_CHAN_WIDTH_80, NL80211_CHAN_WIDTH_160,
    };
    static const char *wnames[] = { "20", "40", "80", "160" };

    fprintf(out, "Adapter:   %s (%04x:%04x) on USB %s at %s, driver %s\n", uwifi_product(dev),
            dev->info.vid, dev->info.pid, dev->info.path, dev->info.speed, dev->info.driver);
    fprintf(out, "MAC:       %02x:%02x:%02x:%02x:%02x:%02x\n", wiphy->perm_addr[0], wiphy->perm_addr[1],
            wiphy->perm_addr[2], wiphy->perm_addr[3], wiphy->perm_addr[4], wiphy->perm_addr[5]);
    if (wiphy->fw_version[0])
        fprintf(out, "Firmware:  %s\n", wiphy->fw_version);
    fprintf(out, "Antennas:  tx 0x%x rx 0x%x\n", wiphy->available_antennas_tx, wiphy->available_antennas_rx);

    for (int b = 0; b < NUM_NL80211_BANDS; b++) {
        const struct ieee80211_supported_band *sband = wiphy->bands[b];
        const struct ieee80211_sta_he_cap *he;
        int streams, mcs, enabled = 0;

        if (sband == NULL)
            continue;

        for (int c = 0; c < sband->n_channels; c++)
            if (!(sband->channels[c].flags & IEEE80211_CHAN_DISABLED))
                enabled++;

        fprintf(out, "\n%s band: %d channels (%d enabled)\n", uwifi_band_name(sband->band), sband->n_channels,
                enabled);

        fprintf(out, "  Channels:");
        for (int c = 0; c < sband->n_channels; c++) {
            const struct ieee80211_channel *ch = &sband->channels[c];
            if (c % 12 == 0)
                fprintf(out, "\n   ");
            fprintf(out, " %3d%s", ch->hw_value, (ch->flags & IEEE80211_CHAN_DISABLED) ? "(x)" :
                    (ch->flags & IEEE80211_CHAN_RADAR) ? "(r)" : "   ");
        }
        fprintf(out, "\n");

        if (sband->n_bitrates) {
            fprintf(out, "  Legacy rates:");
            for (int r = 0; r < sband->n_bitrates; r++)
                fprintf(out, " %g", sband->bitrates[r].bitrate / 10.0);
            fprintf(out, " Mbps\n");
        }

        if (sband->ht_cap.ht_supported)
            fprintf(out, "  HT:        %d streams, MCS 0-%d%s%s%s%s\n", uwifi_ht_streams(&sband->ht_cap),
                    uwifi_ht_streams(&sband->ht_cap) * 8 - 1,
                    (sband->ht_cap.cap & IEEE80211_HT_CAP_SUP_WIDTH_20_40) ? ", 40MHz" : "",
                    (sband->ht_cap.cap & IEEE80211_HT_CAP_SGI_40) ? ", SGI40" :
                    (sband->ht_cap.cap & IEEE80211_HT_CAP_SGI_20) ? ", SGI20" : "",
                    (sband->ht_cap.cap & IEEE80211_HT_CAP_LDPC_CODING) ? ", LDPC" : "",
                    (sband->ht_cap.cap & IEEE80211_HT_CAP_RX_STBC) ? ", RX STBC" : "");

        if (sband->vht_cap.vht_supported) {
            uwifi_mcs_map(le16_to_cpu(sband->vht_cap.vht_mcs.rx_mcs_map), &streams, &mcs, vht_mcs);
            fprintf(out, "  VHT:       %d streams, MCS 0-%d%s%s%s\n", streams, mcs,
                    (sband->vht_cap.cap & IEEE80211_VHT_CAP_SUPP_CHAN_WIDTH_MASK) ? ", 160MHz" : ", 80MHz",
                    (sband->vht_cap.cap & IEEE80211_VHT_CAP_SHORT_GI_80) ? ", SGI80" : "",
                    (sband->vht_cap.cap & IEEE80211_VHT_CAP_RXLDPC) ? ", LDPC" : "");
        }

        if ((he = uwifi_he_cap(sband)) != NULL) {
            uwifi_mcs_map(le16_to_cpu(he->he_mcs_nss_supp.rx_mcs_80), &streams, &mcs, he_mcs);
            fprintf(out, "  HE:        %d streams, MCS 0-%d\n", streams, mcs);
        }

        fprintf(out, "  Widths:   ");
        for (size_t w = 0; w < ARRAY_SIZE(widths); w++)
            if (uwifi_width_ok(sband, widths[w]))
                fprintf(out, " %sMHz", wnames[w]);
        fprintf(out, "\n");
    }
}

/* Channel specs */
static const struct ieee80211_channel *uwifi_find_chan(struct uwifi_dev *dev, enum nl80211_band band,
        int channel) {
    const struct ieee80211_supported_band *sband;

    if (band >= NUM_NL80211_BANDS || (sband = dev->hw->wiphy->bands[band]) == NULL)
        return NULL;

    for (int c = 0; c < sband->n_channels; c++)
        if (sband->channels[c].hw_value == channel && !(sband->channels[c].flags & IEEE80211_CHAN_DISABLED))
            return &sband->channels[c];

    return NULL;
}

/* Centre channel of the block containing a 5GHz or 6GHz control channel */
static int uwifi_center_chan(enum nl80211_band band, int ch, int width_mhz) {
    static const int c5_40[] = { 38, 46, 54, 62, 102, 110, 118, 126, 134, 142, 151, 159, 167, 175 };
    static const int c5_80[] = { 42, 58, 106, 122, 138, 155, 171 };
    static const int c5_160[] = { 50, 114, 163 };
    const int half = width_mhz / 10;

    if (band == NL80211_BAND_6GHZ) {
        /* Blocks start at channel 1 */
        int span = width_mhz / 5;
        return ((ch - 1) / span) * span + 1 + (span / 2) - 2;
    }

    const int *tbl = width_mhz == 40 ? c5_40 : width_mhz == 80 ? c5_80 : c5_160;
    size_t n = width_mhz == 40 ? ARRAY_SIZE(c5_40) : width_mhz == 80 ? ARRAY_SIZE(c5_80) : ARRAY_SIZE(c5_160);

    for (size_t i = 0; i < n; i++)
        if (ch > tbl[i] - half && ch < tbl[i] + half)
            return tbl[i];

    return -1;
}

static int uwifi_make_chan(struct uwifi_dev *dev, enum nl80211_band band, int ch, int width_mhz, int ht40dir,
        struct uwifi_chan *out) {
    const struct ieee80211_supported_band *sband = dev->hw->wiphy->bands[band];
    enum nl80211_chan_width w;
    int center = ch;

    if (sband == NULL || uwifi_find_chan(dev, band, ch) == NULL)
        return -ENOENT;

    switch (width_mhz) {
        case 20: w = NL80211_CHAN_WIDTH_20; break;
        case 40: w = NL80211_CHAN_WIDTH_40; break;
        case 80: w = NL80211_CHAN_WIDTH_80; break;
        case 160: w = NL80211_CHAN_WIDTH_160; break;
        default: return -EINVAL;
    }

    if (!uwifi_width_ok(sband, w))
        return -EOPNOTSUPP;

    if (width_mhz > 20) {
        if (band == NL80211_BAND_2GHZ) {
            if (width_mhz != 40)
                return -EINVAL;
            if (ht40dir == 0)
                ht40dir = ch <= 7 ? 1 : -1;
            center = ch + 2 * ht40dir;
            /* The secondary channel must exist too */
            if (uwifi_find_chan(dev, band, ch + 4 * ht40dir) == NULL)
                return -ENOENT;
        } else {
            if ((center = uwifi_center_chan(band, ch, width_mhz)) < 0)
                return -ENOENT;
            /* Every 20MHz channel in the block must be usable */
            for (int s = center - width_mhz / 10 + 2; s < center + width_mhz / 10; s += 4)
                if (uwifi_find_chan(dev, band, s) == NULL)
                    return -ENOENT;
        }
    }

    memset(out, 0, sizeof(*out));
    out->band = band;
    out->channel = ch;
    out->width = w;
    out->center_freq1 = ieee80211_channel_to_frequency(center, band);

    const char *pfx = band == NL80211_BAND_6GHZ ? "6g:" : "";
    if (width_mhz == 20)
        snprintf(out->name, sizeof(out->name), "%s%d", pfx, ch);
    else if (width_mhz == 40 && band == NL80211_BAND_2GHZ)
        snprintf(out->name, sizeof(out->name), "%dHT40%c", ch, center > ch ? '+' : '-');
    else if (width_mhz == 40)
        snprintf(out->name, sizeof(out->name), "%s%dHT40%c", pfx, ch, center > ch ? '+' : '-');
    else
        snprintf(out->name, sizeof(out->name), "%s%d%s%d", pfx, ch, band == NL80211_BAND_6GHZ ? "HE" : "VHT",
                width_mhz);

    return 0;
}

int uwifi_parse_chan(struct uwifi_dev *dev, const char *spec, struct uwifi_chan *chan) {
    enum nl80211_band band;
    const char *p = spec;
    char *end;
    int width = 20, dir = 0;
    bool explicit_band = true;

    if (strncasecmp(p, "2g:", 3) == 0) {
        band = NL80211_BAND_2GHZ;
        p += 3;
    } else if (strncasecmp(p, "5g:", 3) == 0) {
        band = NL80211_BAND_5GHZ;
        p += 3;
    } else if (strncasecmp(p, "6g:", 3) == 0) {
        band = NL80211_BAND_6GHZ;
        p += 3;
    } else {
        band = NL80211_BAND_2GHZ;
        explicit_band = false;
    }

    long ch = strtol(p, &end, 10);
    if (end == p || ch <= 0 || ch > 255)
        return -EINVAL;

    if (!explicit_band)
        band = ch <= 14 ? NL80211_BAND_2GHZ : NL80211_BAND_5GHZ;

    if (*end == 0) {
        width = 20;
    } else if (strcasecmp(end, "HT20") == 0) {
        width = 20;
    } else if (strcasecmp(end, "HT40+") == 0) {
        width = 40;
        dir = 1;
    } else if (strcasecmp(end, "HT40-") == 0) {
        width = 40;
        dir = -1;
    } else if (strcasecmp(end, "HT40") == 0) {
        width = 40;
    } else if (strcasecmp(end, "VHT80") == 0 || strcasecmp(end, "HE80") == 0) {
        width = 80;
    } else if (strcasecmp(end, "VHT160") == 0 || strcasecmp(end, "HE160") == 0) {
        width = 160;
    } else {
        return -EINVAL;
    }

    return uwifi_make_chan(dev, band, (int) ch, width, dir, chan);
}

int uwifi_hop_list(struct uwifi_dev *dev, unsigned int bands, unsigned int widths, struct uwifi_chan **list,
        size_t *n) {
    static const int wmhz[] = { 20, 40, 80, 160 };
    static const enum nl80211_chan_width wenum[] = {
        NL80211_CHAN_WIDTH_20, NL80211_CHAN_WIDTH_40, NL80211_CHAN_WIDTH_80, NL80211_CHAN_WIDTH_160,
    };
    size_t cap = 64;

    *n = 0;
    if ((*list = calloc(cap, sizeof(**list))) == NULL)
        return -ENOMEM;

    for (int b = 0; b < NUM_NL80211_BANDS; b++) {
        const struct ieee80211_supported_band *sband = dev->hw->wiphy->bands[b];

        if (sband == NULL || !(bands & (1u << b)))
            continue;

        for (size_t w = 0; w < ARRAY_SIZE(wmhz); w++) {
            int last_center = -1;

            if (!(widths & (1u << wenum[w])))
                continue;

            for (int c = 0; c < sband->n_channels; c++) {
                struct uwifi_chan uc;

                if (uwifi_make_chan(dev, b, sband->channels[c].hw_value, wmhz[w], 0, &uc) < 0)
                    continue;

                /* One entry per wide block outside 2.4GHz */
                if (wmhz[w] > 20 && b != NL80211_BAND_2GHZ) {
                    if ((int) uc.center_freq1 == last_center)
                        continue;
                    last_center = (int) uc.center_freq1;
                }

                if (*n == cap) {
                    struct uwifi_chan *nl = realloc(*list, cap * 2 * sizeof(**list));
                    if (nl == NULL)
                        return -ENOMEM;
                    *list = nl;
                    cap *= 2;
                }
                (*list)[(*n)++] = uc;
            }
        }
    }

    return 0;
}

bool uwifi_band_width_ok(struct uwifi_dev *dev, enum nl80211_band band, enum nl80211_chan_width width) {
    const struct ieee80211_supported_band *sband;

    if (band >= NUM_NL80211_BANDS || (sband = dev->hw->wiphy->bands[band]) == NULL)
        return false;

    return uwifi_width_ok(sband, width);
}

int uwifi_start_monitor(struct uwifi_dev *dev, kc_mac80211_rx_cb_t cb, void *ctx) {
    return kc_mac80211_start_monitor(dev->hw, cb, ctx);
}

int uwifi_set_chan(struct uwifi_dev *dev, const struct uwifi_chan *chan) {
    struct cfg80211_chan_def def;
    int r;

    if ((r = kc_mac80211_chandef(dev->hw, chan->band, chan->channel, chan->width, chan->center_freq1, &def)) < 0)
        return r;

    return kc_mac80211_set_chandef(dev->hw, &def);
}
