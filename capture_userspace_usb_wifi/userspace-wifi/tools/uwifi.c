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

/* Userspace USB Wi-Fi tool: list adapters, show capabilities, capture in monitor mode
 * while hopping channels, with packet counts and a pcap, and inject frames. */

#include <getopt.h>
#include <signal.h>

#include "common/pcap.h"
#include "common/uwifi.h"
#ifdef UWIFI_HWSIM
#include "hwsim/hwsim.h"
#endif

#ifndef FIRMWAREDIR
#define FIRMWAREDIR "/usr/local/share/uwifi/firmware"
#endif

#define OPEN_TIMEOUT_MS 20000
#define DEFAULT_DWELL_MS 500
#define PROBE_DWELL_MS 200

/* Long options without a short form */
#define OPT_FIRMWARE 256
#define OPT_BOARDFILE 257

struct hop_stats {
    struct uwifi_chan chan;
    unsigned long frames;
    unsigned long bad_fcs;
    unsigned long by_enc[4];
    unsigned long bytes;
    bool rejected;
};

struct capture {
    struct hop_stats *hops;
    size_t n_hops;
    volatile size_t cur;
    struct uwifi_pcap *pcap;
    unsigned long pcap_errors;
};

struct inject {
    unsigned long sent;
    unsigned long busy;
    unsigned long status;
    unsigned long acked;
    unsigned long rx_frames;
    struct uwifi_pcap *pcap;
};

static volatile sig_atomic_t stop_requested;

/* Status output; stderr when the pcap is written to stdout */
static FILE *out;

static void handle_signal(int sig) {
    (void) sig;
    stop_requested = 1;
}

static u64 now_ms(void) {
    return kc_jiffies_now();
}

static void usage(const char *argv0) {
    fprintf(stderr,
#ifdef UWIFI_HWSIM
            "Usage: %s [options] list|info|capture|inject|hwsim\n"
#else
            "Usage: %s [options] list|info|capture|inject\n"
#endif
            "  list                  list supported USB Wi-Fi adapters\n"
            "  info                  load firmware and show bands, channels, rates and widths\n"
            "  capture               monitor mode with channel hopping\n"
            "  inject                transmit frames on one channel (-c), counting ACKs\n"
#ifdef UWIFI_HWSIM
            "  hwsim                 run the adapter as a Linux Wi-Fi device through mac80211_hwsim\n"
#endif
            "Options:\n"
            "  -d, --device N        adapter index from 'list' (default 0)\n"
            "  -F, --fw-dir DIR      firmware directory (searched first)\n"
            "      --firmware NAME   mm8108: firmware file to load instead of the chip's own\n"
            "      --boardfile NAME  mm8108: board config file to load instead of the board type's\n"
            "  -p, --probe-channels  with info: tune every channel and width and report results\n"
            "  -c, --channels LIST   channels to hop, e.g. 1,6,11,36VHT80,6g:37HE80\n"
            "  -b, --bands LIST      bands to hop, from 2,5,6 (default all)\n"
            "  -W, --widths LIST     widths to hop, from 20,40,80,160 (default 20)\n"
            "  -t, --dwell MS        time per channel (default %d)\n"
            "  -T, --duration S      stop after S seconds\n"
            "  -w, --pcap FILE       write radiotap pcap; '-' for stdout\n"
            "  -C, --country CC      regulatory country to report to the driver; mm8108: the\n"
            "                        region to boot with, unless the adapter locks its own\n"
            "  -v, --verbose         driver debug logging\n"
            "Inject options:\n"
            "  -n, --count N         frames to send (default 10; 0 to send until stopped)\n"
            "  -i, --interval MS     time between frames (default 100)\n"
            "  -a, --dest MAC        address probe requests to MAC, which ACKs them (default broadcast)\n"
            "  -R, --rate RATE       legacy rate in Mbps (1, 6, 54...) or HT MCS as mcsN\n"
            "  -r, --replay FILE     send the frames in an 802.11 or radiotap pcap instead\n"
#ifdef UWIFI_HWSIM
            "hwsim options:\n"
            "  -N, --name NAME       wiphy name for the radio (default the adapter's interface name)\n"
            "  -C, --country CC      also sets the radio's regulatory hint\n"
            "  -T, --duration S      status line interval (default 10; 0 for none)\n"
#endif
            ,
            argv0, DEFAULT_DWELL_MS);
}

static int cmd_list(void) {
    struct uwifi_dev_info *list;
    size_t n;
    int r;

    if ((r = uwifi_list(&list, &n)) < 0) {
        fprintf(stderr, "could not list USB devices: %d\n", r);
        return 1;
    }

    if (n == 0) {
        fprintf(out, "No supported USB Wi-Fi adapters found\n");
    } else {
        fprintf(out, "%-5s %-12s %-10s %-10s %-12s %-10s\n", "index", "interface", "driver", "usb id",
                "usb path", "speed");
        for (size_t i = 0; i < n; i++)
            fprintf(out, "%-5zu %-12s %-10s %04x:%04x  %-12s %-10s\n", i, list[i].ifname, list[i].driver,
                    list[i].vid, list[i].pid, list[i].path, list[i].speed);
    }

    free(list);

    if (uwifi_list_unconfigured(&list, &n) == 0) {
        for (size_t i = 0; i < n; i++)
            fprintf(stderr, "warning: %s adapter %04x:%04x at USB %s failed USB setup and can't be used; "
                    "check the kernel log, and replug it or use a powered hub\n", list[i].driver,
                    list[i].vid, list[i].pid, list[i].path);
        free(list);
    }

    return 0;
}

static void rx_frame(void *ctx, struct ieee80211_hw *hw, const struct ieee80211_rx_status *status,
        const u8 *data, size_t len) {
    struct capture *cap = ctx;
    struct hop_stats *h = &cap->hops[cap->cur];
    (void) hw;

    __atomic_add_fetch(&h->frames, 1, __ATOMIC_RELAXED);
    __atomic_add_fetch(&h->bytes, len, __ATOMIC_RELAXED);
    if (status->flag & RX_FLAG_FAILED_FCS_CRC)
        __atomic_add_fetch(&h->bad_fcs, 1, __ATOMIC_RELAXED);
    if (status->encoding <= RX_ENC_HE)
        __atomic_add_fetch(&h->by_enc[status->encoding <= RX_ENC_HE ? status->encoding : 0], 1,
                __ATOMIC_RELAXED);

    if (cap->pcap && uwifi_pcap_write(cap->pcap, data, len) < 0) {
        __atomic_add_fetch(&cap->pcap_errors, 1, __ATOMIC_RELAXED);
        stop_requested = 1;
    }
}

static unsigned int parse_widths(const char *s) {
    unsigned int m = 0;
    char buf[64], *save = NULL;

    snprintf(buf, sizeof(buf), "%s", s);
    for (char *t = strtok_r(buf, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        int w = atoi(t);
        if (w == 20) m |= 1u << NL80211_CHAN_WIDTH_20;
        else if (w == 40) m |= 1u << NL80211_CHAN_WIDTH_40;
        else if (w == 80) m |= 1u << NL80211_CHAN_WIDTH_80;
        else if (w == 160) m |= 1u << NL80211_CHAN_WIDTH_160;
    }
    return m;
}

static unsigned int parse_bands(const char *s) {
    unsigned int m = 0;
    char buf[64], *save = NULL;

    snprintf(buf, sizeof(buf), "%s", s);
    for (char *t = strtok_r(buf, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
        int b = atoi(t);
        if (b == 2) m |= 1u << NL80211_BAND_2GHZ;
        else if (b == 5) m |= 1u << NL80211_BAND_5GHZ;
        else if (b == 6) m |= 1u << NL80211_BAND_6GHZ;
    }
    return m;
}

static int build_hops(struct uwifi_dev *dev, struct capture *cap, const char *channels, unsigned int bands,
        unsigned int widths) {
    struct uwifi_chan *list = NULL;
    size_t n = 0;

    if (channels) {
        char buf[1024], *save = NULL;
        size_t cnt = 1;

        for (const char *p = channels; *p; p++)
            cnt += *p == ',';
        if ((list = calloc(cnt, sizeof(*list))) == NULL)
            return -1;

        snprintf(buf, sizeof(buf), "%s", channels);
        for (char *t = strtok_r(buf, ",", &save); t; t = strtok_r(NULL, ",", &save)) {
            if (uwifi_parse_chan(dev, t, &list[n]) < 0) {
                fprintf(stderr, "channel '%s' is not supported by this adapter\n", t);
                free(list);
                return -1;
            }
            n++;
        }
    } else if (uwifi_hop_list(dev, bands, widths, &list, &n) < 0) {
        return -1;
    }

    if (n == 0) {
        fprintf(stderr, "no channels to hop\n");
        free(list);
        return -1;
    }

    if ((cap->hops = calloc(n, sizeof(*cap->hops))) == NULL) {
        free(list);
        return -1;
    }

    for (size_t i = 0; i < n; i++)
        cap->hops[i].chan = list[i];
    cap->n_hops = n;
    free(list);
    return 0;
}

/* Tunes, counting driver errors logged while tuning as a rejection */
static int tune(struct uwifi_dev *dev, struct hop_stats *h) {
    unsigned long errs = uwifi_error_count();
    int r = uwifi_set_chan(dev, &h->chan);

    if (r < 0 || uwifi_error_count() != errs)
        h->rejected = true;

    return r;
}

static void print_table(const struct capture *cap, u64 elapsed) {
    unsigned long total = 0, bad = 0;

    fprintf(out, "\n%-14s %-7s %9s %8s %8s %8s %8s %8s %10s\n", "channel", "freq", "frames", "bad FCS", "legacy", "HT",
            "VHT", "HE", "bytes");
    for (size_t i = 0; i < cap->n_hops; i++) {
        const struct hop_stats *h = &cap->hops[i];
        fprintf(out, "%-14s %-7u %9lu %8lu %8lu %8lu %8lu %8lu %10lu%s\n", h->chan.name,
                ieee80211_channel_to_frequency(h->chan.channel, h->chan.band), h->frames, h->bad_fcs,
                h->by_enc[RX_ENC_LEGACY], h->by_enc[RX_ENC_HT], h->by_enc[RX_ENC_VHT], h->by_enc[RX_ENC_HE],
                h->bytes, h->rejected ? "  (tune error)" : "");
        total += h->frames;
        bad += h->bad_fcs;
    }
    fprintf(out, "total: %lu frames, %lu bad FCS in %.1fs\n", total, bad, elapsed / 1000.0);
    if (cap->pcap_errors)
        fprintf(out, "%lu frames could not be written to the pcap\n", cap->pcap_errors);
}

static int run_hops(struct uwifi_dev *dev, struct capture *cap, unsigned long dwell_ms, unsigned long duration_s,
        bool quiet) {
    const u64 start = now_ms();
    u64 next_print = start + 1000;
    unsigned long last_total = 0;

    while (!stop_requested) {
        for (size_t i = 0; i < cap->n_hops && !stop_requested; i++) {
            cap->cur = i;
            tune(dev, &cap->hops[i]);

            const u64 until = now_ms() + dwell_ms;
            while (!stop_requested && now_ms() < until) {
                msleep(20);

                if (!quiet && now_ms() >= next_print) {
                    unsigned long total = 0;
                    for (size_t j = 0; j < cap->n_hops; j++)
                        total += cap->hops[j].frames;
                    fprintf(out, "[%6.1fs] %-14s %6lu frames on channel | %8lu total, %5lu/s\n",
                            (now_ms() - start) / 1000.0, cap->hops[i].chan.name, cap->hops[i].frames, total,
                            total - last_total);
                    fflush(out);
                    last_total = total;
                    next_print += 1000;
                }

                if (duration_s && now_ms() - start >= duration_s * 1000)
                    stop_requested = 1;
            }
        }

        /* Probing makes one pass */
        if (quiet)
            break;
    }

    print_table(cap, now_ms() - start);
    return 0;
}

static void inject_rx(void *ctx, struct ieee80211_hw *hw, const struct ieee80211_rx_status *status,
        const u8 *data, size_t len) {
    struct inject *inj = ctx;
    (void) hw;
    (void) status;

    __atomic_add_fetch(&inj->rx_frames, 1, __ATOMIC_RELAXED);
    if (inj->pcap)
        uwifi_pcap_write(inj->pcap, data, len);
}

static void inject_status(void *ctx, struct ieee80211_hw *hw, const u8 *data, size_t len, bool acked) {
    struct inject *inj = ctx;
    (void) hw;
    (void) data;
    (void) len;

    __atomic_add_fetch(&inj->status, 1, __ATOMIC_RELAXED);
    if (acked)
        __atomic_add_fetch(&inj->acked, 1, __ATOMIC_RELAXED);
}

static int parse_mac(const char *s, u8 *mac) {
    unsigned int b[ETH_ALEN];

    if (sscanf(s, "%x:%x:%x:%x:%x:%x", &b[0], &b[1], &b[2], &b[3], &b[4], &b[5]) != ETH_ALEN)
        return -1;
    for (int i = 0; i < ETH_ALEN; i++)
        mac[i] = (u8) b[i];
    return 0;
}

/* Radiotap for injection: a rate or HT MCS when given, and no ACK expected for broadcast */
static size_t inject_radiotap(u8 *buf, const char *rate, bool noack) {
    u32 present = BIT(IEEE80211_RADIOTAP_TX_FLAGS);
    size_t len = 8;

    if (rate && strncmp(rate, "mcs", 3) == 0) {
        present |= BIT(IEEE80211_RADIOTAP_MCS);
    } else if (rate) {
        present |= BIT(IEEE80211_RADIOTAP_RATE);
        buf[len++] = (u8) (atof(rate) * 2);
    }

    len = ALIGN(len, 2);
    put_unaligned_le16(noack ? IEEE80211_RADIOTAP_F_TX_NOACK : 0, buf + len);
    len += 2;

    if (present & BIT(IEEE80211_RADIOTAP_MCS)) {
        buf[len++] = IEEE80211_RADIOTAP_MCS_HAVE_MCS | IEEE80211_RADIOTAP_MCS_HAVE_BW;
        buf[len++] = IEEE80211_RADIOTAP_MCS_BW_20;
        buf[len++] = (u8) atoi(rate + 3);
    }

    buf[0] = 0;
    buf[1] = 0;
    put_unaligned_le16((u16) len, buf + 2);
    put_unaligned_le32(present, buf + 4);
    return len;
}

/* A probe request with the wildcard SSID */
static size_t inject_probe_req(u8 *buf, const u8 *sa, const u8 *da, u16 seq) {
    static const u8 rates[] = { WLAN_EID_SUPP_RATES, 8, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24 };
    struct ieee80211_hdr_3addr *hdr = (struct ieee80211_hdr_3addr *) buf;
    size_t len = sizeof(*hdr);

    memset(hdr, 0, sizeof(*hdr));
    hdr->frame_control = cpu_to_le16(IEEE80211_FTYPE_MGMT | IEEE80211_STYPE_PROBE_REQ);
    memcpy(hdr->addr1, da, ETH_ALEN);
    memcpy(hdr->addr2, sa, ETH_ALEN);
    memcpy(hdr->addr3, da, ETH_ALEN);
    hdr->seq_ctrl = cpu_to_le16(seq << 4);

    buf[len++] = WLAN_EID_SSID;
    buf[len++] = 0;
    memcpy(buf + len, rates, sizeof(rates));
    return len + sizeof(rates);
}

/* Sends one frame, waiting while the driver's queues are full */
static int inject_send(struct uwifi_dev *dev, struct inject *inj, const u8 *frame, size_t len) {
    int r;

    while ((r = uwifi_tx(dev, frame, len)) == -EBUSY && !stop_requested) {
        inj->busy++;
        msleep(2);
    }

    if (r == 0)
        inj->sent++;
    return r;
}

static int run_inject(struct uwifi_dev *dev, struct inject *inj, const char *replay, const char *dest,
        const char *rate, unsigned long count, unsigned long interval_ms) {
    const u64 start = now_ms();
    u8 frame[4096];
    u8 da[ETH_ALEN];
    int r = 0;

    eth_broadcast_addr(da);
    if (dest && parse_mac(dest, da) < 0) {
        fprintf(stderr, "invalid address '%s'\n", dest);
        return 1;
    }

    if (replay) {
        struct uwifi_pcap_reader *rd;
        const u8 *pkt;
        uint32_t linktype;
        int len;

        if ((rd = uwifi_pcap_read_open(replay, &linktype)) == NULL) {
            fprintf(stderr, "could not read %s\n", replay);
            return 1;
        }
        if (linktype != UWIFI_DLT_IEEE802_11 && linktype != UWIFI_DLT_IEEE802_11_RADIO) {
            fprintf(stderr, "%s is not an 802.11 or radiotap pcap (link type %u)\n", replay, linktype);
            uwifi_pcap_read_close(rd);
            return 1;
        }

        while (!stop_requested && (count == 0 || inj->sent < count) && (len = uwifi_pcap_read_next(rd, &pkt)) > 0) {
            size_t flen = 0;

            if (linktype == UWIFI_DLT_IEEE802_11) {
                flen = inject_radiotap(frame, rate, false);
                if ((size_t) len > sizeof(frame) - flen)
                    continue;
            } else if ((size_t) len > sizeof(frame)) {
                continue;
            }
            memcpy(frame + flen, pkt, (size_t) len);

            if ((r = inject_send(dev, inj, frame, flen + (size_t) len)) < 0 && r != -EINVAL)
                break;
            if (interval_ms)
                msleep(interval_ms);
        }
        uwifi_pcap_read_close(rd);
    } else {
        for (u16 seq = 0; !stop_requested && (count == 0 || inj->sent < count); seq = (seq + 1) & 0xfff) {
            size_t rt = inject_radiotap(frame, rate, is_broadcast_ether_addr(da));
            size_t len = rt + inject_probe_req(frame + rt, uwifi_mac(dev), da, seq);

            if ((r = inject_send(dev, inj, frame, len)) < 0)
                break;
            if (interval_ms)
                msleep(interval_ms);
        }
    }

    /* Give the last frames time to be sent and reported */
    msleep(500);

    if (r < 0 && r != -EINVAL)
        fprintf(stderr, "transmit failed: %s\n", r == -EPERM ? "channel does not permit transmit" :
                strerror(-r));

    fprintf(out, "sent %lu frames in %.1fs, %lu status reports, %lu acked, %lu waits for queue space; "
            "received %lu frames\n", inj->sent, (now_ms() - start) / 1000.0, inj->status, inj->acked,
            inj->busy, inj->rx_frames);
    return r < 0 && r != -EINVAL ? 1 : 0;
}

/* A bare file name, so a chosen file can't come from outside the firmware directories */
static bool firmware_name_valid(const char *name) {
    return name[0] != 0 && strchr(name, '/') == NULL && strchr(name, '\\') == NULL &&
        strcmp(name, ".") != 0 && strcmp(name, "..") != 0;
}

int main(int argc, char *argv[]) {
    static const struct option longopts[] = {
        { "device", required_argument, NULL, 'd' },
        { "fw-dir", required_argument, NULL, 'F' },
        { "probe-channels", no_argument, NULL, 'p' },
        { "channels", required_argument, NULL, 'c' },
        { "bands", required_argument, NULL, 'b' },
        { "widths", required_argument, NULL, 'W' },
        { "dwell", required_argument, NULL, 't' },
        { "duration", required_argument, NULL, 'T' },
        { "pcap", required_argument, NULL, 'w' },
        { "country", required_argument, NULL, 'C' },
        { "verbose", no_argument, NULL, 'v' },
        { "count", required_argument, NULL, 'n' },
        { "interval", required_argument, NULL, 'i' },
        { "dest", required_argument, NULL, 'a' },
        { "rate", required_argument, NULL, 'R' },
        { "replay", required_argument, NULL, 'r' },
        { "name", required_argument, NULL, 'N' },
        { "firmware", required_argument, NULL, OPT_FIRMWARE },
        { "boardfile", required_argument, NULL, OPT_BOARDFILE },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    const char *fw_dir = NULL, *channels = NULL, *pcap_path = NULL, *country = NULL;
    const char *dest = NULL, *rate = NULL, *replay = NULL, *name = NULL;
    const char *fw_name = NULL, *bcf_name = NULL;
    unsigned long count = 10, interval_ms = 100;
    struct inject inj = { 0 };
    unsigned int bands = (1u << NL80211_BAND_2GHZ) | (1u << NL80211_BAND_5GHZ) | (1u << NL80211_BAND_6GHZ);
    unsigned int widths = 1u << NL80211_CHAN_WIDTH_20;
    unsigned long dwell_ms = DEFAULT_DWELL_MS, duration_s = 0;
    size_t index = 0;
    bool probe = false;
    int verbose = 0, opt, ret = 1;
    struct capture cap = { 0 };
    struct uwifi_dev *dev;

    while ((opt = getopt_long(argc, argv, "d:F:pc:b:W:t:T:w:C:vn:i:a:R:r:N:h", longopts, NULL)) != -1) {
        switch (opt) {
            case 'd': index = strtoul(optarg, NULL, 10); break;
            case 'F': fw_dir = optarg; break;
            case 'p': probe = true; break;
            case 'c': channels = optarg; break;
            case 'b': bands = parse_bands(optarg); break;
            case 'W': widths = parse_widths(optarg); break;
            case 't': dwell_ms = strtoul(optarg, NULL, 10); break;
            case 'T': duration_s = strtoul(optarg, NULL, 10); break;
            case 'w': pcap_path = optarg; break;
            case 'C': country = optarg; break;
            case 'v': verbose++; break;
            case 'n': count = strtoul(optarg, NULL, 10); break;
            case 'i': interval_ms = strtoul(optarg, NULL, 10); break;
            case 'a': dest = optarg; break;
            case 'R': rate = optarg; break;
            case 'r': replay = optarg; break;
            case 'N': name = optarg; break;
            case OPT_FIRMWARE: fw_name = optarg; break;
            case OPT_BOARDFILE: bcf_name = optarg; break;
            default:
                usage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

#ifndef UWIFI_HWSIM
    (void) name;
#endif

    const char *cmd = argv[optind];

    out = (pcap_path && strcmp(pcap_path, "-") == 0) ? stderr : stdout;
    /* A closed pipe ends the capture instead of killing the process */
    signal(SIGPIPE, SIG_IGN);
    const char *fw_paths[] = { fw_dir, "firmware", FIRMWAREDIR, "/usr/local/share/kismet/firmware",
        "/usr/share/kismet/firmware" };
    const char *const *paths = fw_dir ? fw_paths : fw_paths + 1;
    size_t n_paths = fw_dir ? ARRAY_SIZE(fw_paths) : ARRAY_SIZE(fw_paths) - 1;

    if ((fw_name && !firmware_name_valid(fw_name)) || (bcf_name && !firmware_name_valid(bcf_name))) {
        fprintf(stderr, "--firmware and --boardfile take a file name in the firmware directories, "
                "not a path\n");
        return 1;
    }
    uwifi_set_firmware_choice(fw_name, bcf_name);
    uwifi_set_country_choice(country);

    if (uwifi_init(paths, n_paths, verbose ? 7 : 4) < 0) {
        fprintf(stderr, "could not initialize USB\n");
        return 1;
    }

    if (strcmp(cmd, "list") == 0)
        return cmd_list();

    if (strcmp(cmd, "info") != 0 && strcmp(cmd, "capture") != 0 && strcmp(cmd, "inject") != 0
#ifdef UWIFI_HWSIM
            && strcmp(cmd, "hwsim") != 0
#endif
            ) {
        usage(argv[0]);
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    fprintf(out, "Opening adapter %zu and loading firmware...\n", index);
    if ((dev = uwifi_open(index, OPEN_TIMEOUT_MS)) == NULL) {
        fprintf(stderr, "could not open adapter %zu\n", index);
        return 1;
    }

    uwifi_print_caps(dev, out);

    if (strcmp(cmd, "info") == 0 && !probe) {
        ret = 0;
        goto out;
    }

#ifdef UWIFI_HWSIM
    if (strcmp(cmd, "hwsim") == 0) {
        struct uwifi_hwsim_opts opts = {
            .name = name,
            .country = country,
            .stats_interval_s = duration_s ? (unsigned int) duration_s : 10,
        };

        if (country && kc_mac80211_set_regdomain(uwifi_hw(dev), country) < 0)
            fprintf(stderr, "invalid country '%s'\n", country);
        ret = uwifi_hwsim_run(dev, &opts, &stop_requested, out) < 0;
        goto out;
    }
#endif

    if (strcmp(cmd, "inject") == 0) {
        struct uwifi_chan chan;

        if (channels == NULL || strchr(channels, ',') || uwifi_parse_chan(dev, channels, &chan) < 0) {
            fprintf(stderr, "inject needs one channel supported by this adapter (-c)\n");
            goto out;
        }
        if (pcap_path && (inj.pcap = uwifi_pcap_open(pcap_path)) == NULL) {
            fprintf(stderr, "could not open %s\n", pcap_path);
            goto out;
        }

        uwifi_set_tx_status_cb(dev, inject_status, &inj);
        if (uwifi_start_monitor(dev, inject_rx, &inj) < 0) {
            fprintf(stderr, "could not enter monitor mode\n");
            goto out;
        }
        if (country && kc_mac80211_set_regdomain(uwifi_hw(dev), country) < 0)
            fprintf(stderr, "invalid country '%s'\n", country);
        if (uwifi_set_chan(dev, &chan) < 0) {
            fprintf(stderr, "could not tune %s\n", chan.name);
            goto out;
        }

        fprintf(out, "\nInjecting on %s\n", chan.name);
        ret = run_inject(dev, &inj, replay, dest, rate, count, interval_ms);
        goto out;
    }

    if (probe) {
        widths = (1u << NL80211_CHAN_WIDTH_20) | (1u << NL80211_CHAN_WIDTH_40) | (1u << NL80211_CHAN_WIDTH_80) |
            (1u << NL80211_CHAN_WIDTH_160);
        dwell_ms = PROBE_DWELL_MS;
        channels = NULL;
    }

    if (build_hops(dev, &cap, channels, bands, widths) < 0)
        goto out;

    if (pcap_path && !probe && (cap.pcap = uwifi_pcap_open(pcap_path)) == NULL) {
        fprintf(stderr, "could not open %s\n", pcap_path);
        goto out;
    }

    if (uwifi_start_monitor(dev, rx_frame, &cap) < 0) {
        fprintf(stderr, "could not enter monitor mode\n");
        goto out;
    }

    if (country && kc_mac80211_set_regdomain(uwifi_hw(dev), country) < 0)
        fprintf(stderr, "invalid country '%s'\n", country);

    fprintf(out, "\n%s %zu channel%s, %lu ms each%s%s\n", probe ? "Probing" : "Hopping", cap.n_hops,
            cap.n_hops == 1 ? "" : "s", dwell_ms, pcap_path && !probe ? ", writing " : "",
            pcap_path && !probe ? pcap_path : "");

    ret = run_hops(dev, &cap, dwell_ms, duration_s, probe);

out:
    uwifi_close(dev);
    uwifi_exit();
    uwifi_pcap_close(cap.pcap);
    uwifi_pcap_close(inj.pcap);
    free(cap.hops);
    return ret;
}
