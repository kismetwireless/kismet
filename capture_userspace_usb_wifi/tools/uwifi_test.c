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

/* Test tool for userspace USB Wi-Fi drivers: list adapters, show capabilities, and
 * capture in monitor mode while hopping channels, with packet counts and a pcap. */

#include <getopt.h>
#include <signal.h>

#include "common/pcap.h"
#include "common/uwifi.h"

#ifndef FIRMWAREDIR
#define FIRMWAREDIR "/usr/local/share/kismet/firmware"
#endif

#define OPEN_TIMEOUT_MS 20000
#define DEFAULT_DWELL_MS 500
#define PROBE_DWELL_MS 200

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
            "Usage: %s [options] list|info|capture\n"
            "  list                  list supported USB Wi-Fi adapters\n"
            "  info                  load firmware and show bands, channels, rates and widths\n"
            "  capture               monitor mode with channel hopping\n"
            "Options:\n"
            "  -d, --device N        adapter index from 'list' (default 0)\n"
            "  -F, --fw-dir DIR      firmware directory (searched first)\n"
            "  -p, --probe-channels  with info: tune every channel and width and report results\n"
            "  -c, --channels LIST   channels to hop, e.g. 1,6,11,36VHT80,6g:37HE80\n"
            "  -b, --bands LIST      bands to hop, from 2,5,6 (default all)\n"
            "  -W, --widths LIST     widths to hop, from 20,40,80,160 (default 20)\n"
            "  -t, --dwell MS        time per channel (default %d)\n"
            "  -T, --duration S      stop after S seconds\n"
            "  -w, --pcap FILE       write radiotap pcap; '-' for stdout\n"
            "  -C, --country CC      regulatory country to report to the driver\n"
            "  -v, --verbose         driver debug logging\n",
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
        return 0;
    }

    fprintf(out, "%-5s %-12s %-10s %-10s %-12s %-10s\n", "index", "interface", "driver", "usb id", "usb path",
            "speed");
    for (size_t i = 0; i < n; i++)
        fprintf(out, "%-5zu %-12s %-10s %04x:%04x  %-12s %-10s\n", i, list[i].ifname, list[i].driver,
                list[i].vid, list[i].pid, list[i].path, list[i].speed);

    free(list);
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
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };
    const char *fw_dir = NULL, *channels = NULL, *pcap_path = NULL, *country = NULL;
    unsigned int bands = (1u << NL80211_BAND_2GHZ) | (1u << NL80211_BAND_5GHZ) | (1u << NL80211_BAND_6GHZ);
    unsigned int widths = 1u << NL80211_CHAN_WIDTH_20;
    unsigned long dwell_ms = DEFAULT_DWELL_MS, duration_s = 0;
    size_t index = 0;
    bool probe = false;
    int verbose = 0, opt, ret = 1;
    struct capture cap = { 0 };
    struct uwifi_dev *dev;

    while ((opt = getopt_long(argc, argv, "d:F:pc:b:W:t:T:w:C:vh", longopts, NULL)) != -1) {
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
            default:
                usage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }

    if (optind >= argc) {
        usage(argv[0]);
        return 1;
    }

    const char *cmd = argv[optind];

    out = (pcap_path && strcmp(pcap_path, "-") == 0) ? stderr : stdout;
    /* A closed pipe ends the capture instead of killing the process */
    signal(SIGPIPE, SIG_IGN);
    const char *fw_paths[] = { fw_dir, "firmware", FIRMWAREDIR, "/usr/share/kismet/firmware", "/lib/firmware" };
    const char *const *paths = fw_dir ? fw_paths : fw_paths + 1;
    size_t n_paths = fw_dir ? ARRAY_SIZE(fw_paths) : ARRAY_SIZE(fw_paths) - 1;

    if (uwifi_init(paths, n_paths, verbose ? 7 : 4) < 0) {
        fprintf(stderr, "could not initialize USB\n");
        return 1;
    }

    if (strcmp(cmd, "list") == 0)
        return cmd_list();

    if (strcmp(cmd, "info") != 0 && strcmp(cmd, "capture") != 0) {
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
    uwifi_pcap_close(cap.pcap);
    free(cap.hops);
    return ret;
}
