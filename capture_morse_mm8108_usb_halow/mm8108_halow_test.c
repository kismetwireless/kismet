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

/* Standalone test for the userspace MM8108 driver: boot the chip, enter monitor mode, hop
 * 802.11ah channels, write a radiotap pcap and print packet counts.
 */

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>

#include "libmm8108/mm8108.h"
#include "../firmware_file.h"
#include "libmm8108/mm_channels.h"
#include "libmm8108/mm_radiotap.h"
#include "libmm8108/mm_util.h"

#define DEFAULT_FW_DIR      "/lib/firmware/morse"
#define DEFAULT_DWELL_MS    1000
#define MAX_HOP_CHANNELS    64
#define PCAP_SNAPLEN        65535
#define PCAP_DLT_RADIOTAP   127

struct chan_stats {
    const struct mm_s1g_channel *chan;
    uint64_t frames;
    uint64_t bad_fcs;
    uint64_t ndp;
    uint64_t bytes;
};

struct test_state {
    FILE *pcap;
    uint64_t pcap_errors;
    struct chan_stats chans[MAX_HOP_CHANNELS];
    size_t num_chans;
    size_t cur_chan;
    /* Frames reported on a frequency we aren't tuned to */
    uint64_t other_freq;
};

static volatile sig_atomic_t stop_requested = 0;

static void handle_signal(int sig) {
    (void) sig;
    stop_requested = 1;
}

static void usage(const char *argv0) {
    fprintf(stderr,
            "Usage: %s [options]\n"
            "  -d, --fw-dir DIR      firmware directory (default " DEFAULT_FW_DIR ");\n"
            "                        a morse-firmware checkout also works\n"
            "  -f, --firmware FILE   firmware image (default: by chip revision)\n"
            "  -b, --bcf FILE        board config path, or a name in the firmware directory\n"
            "                        (default: by board type in OTP, else bcf_default.bin,\n"
            "                        else bcf_mf15457.bin)\n"
            "  -c, --country CC      regulatory domain (default: OTP, else US)\n"
            "  -C, --channels LIST   comma-separated 802.11ah channels (default: all)\n"
            "  -W, --widths LIST     only hop channels of these widths in MHz, e.g. 1,2\n"
            "  -t, --dwell MS        time per channel (default %d)\n"
            "  -w, --pcap FILE       write a radiotap pcap\n"
            "  -T, --duration SEC    stop after SEC seconds\n"
            "  -D, --device N        adapter N in USB port order, as the Kismet source's mm8108-N\n"
            "  -i, --info            boot, print device information and exit\n"
            "  -v, --verbose         more logging; repeat for USB-level detail\n"
            "Countries: %s\n"
            "Firmware and BCF files: https://github.com/MorseMicro/morse-firmware\n",
            argv0, DEFAULT_DWELL_MS, mm_s1g_countries());
}

static bool file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0 && S_ISREG(st.st_mode);
}

/* Finds name in dir or in a morse-firmware checkout layout under dir, as named or compressed */
static bool find_file(const char *dir, const char *name, char *out, size_t out_len) {
    static const char *subdirs[] = { "", "/firmware", "/bcf/morsemicro" };
    const char *suffixes[FW_FILE_MAX_SUFFIXES];
    size_t num_suffixes = fw_file_suffixes(suffixes);

    for (size_t i = 0; i < sizeof(subdirs) / sizeof(subdirs[0]); i++) {
        for (size_t x = 0; x < num_suffixes; x++) {
            int n = snprintf(out, out_len, "%s%s/%s%s", dir, subdirs[i], name, suffixes[x]);
            if (n > 0 && (size_t) n < out_len && file_exists(out))
                return true;
        }
    }

    return false;
}

static int pcap_open(struct test_state *ts, const char *path) {
    uint8_t hdr[24];

    if ((ts->pcap = fopen(path, "wb")) == NULL) {
        fprintf(stderr, "could not open %s: %s\n", path, strerror(errno));
        return -1;
    }

    mm_put_le32(hdr, 0xa1b2c3d4);
    mm_put_le16(hdr + 4, 2);
    mm_put_le16(hdr + 6, 4);
    mm_put_le32(hdr + 8, 0);
    mm_put_le32(hdr + 12, 0);
    mm_put_le32(hdr + 16, PCAP_SNAPLEN);
    mm_put_le32(hdr + 20, PCAP_DLT_RADIOTAP);

    if (fwrite(hdr, sizeof(hdr), 1, ts->pcap) != 1) {
        fprintf(stderr, "could not write %s\n", path);
        fclose(ts->pcap);
        ts->pcap = NULL;
        return -1;
    }

    return 0;
}

static void pcap_write(struct test_state *ts, const uint8_t *rt, size_t rt_len,
        const uint8_t *frame, size_t frame_len) {
    uint8_t rec[16];
    struct timeval tv;
    size_t caplen = rt_len + frame_len;

    if (caplen > PCAP_SNAPLEN)
        caplen = PCAP_SNAPLEN;

    gettimeofday(&tv, NULL);
    mm_put_le32(rec, (uint32_t) tv.tv_sec);
    mm_put_le32(rec + 4, (uint32_t) tv.tv_usec);
    mm_put_le32(rec + 8, (uint32_t) caplen);
    mm_put_le32(rec + 12, (uint32_t) (rt_len + frame_len));

    if (fwrite(rec, sizeof(rec), 1, ts->pcap) != 1 ||
            fwrite(rt, rt_len, 1, ts->pcap) != 1 ||
            (caplen > rt_len && fwrite(frame, caplen - rt_len, 1, ts->pcap) != 1))
        ts->pcap_errors++;
}

static void rx_frame(void *ctx, const struct mm_rx_status *st, const uint8_t *frame,
        size_t frame_len) {
    struct test_state *ts = ctx;
    struct chan_stats *cs = &ts->chans[ts->cur_chan];
    uint8_t rt[MM_RADIOTAP_MAX_LEN];
    size_t rt_len;

    /* Attribute to the channel we're tuned to; note frames reported elsewhere */
    if (st->freq_khz != 0 && cs->chan != NULL) {
        const uint32_t half = cs->chan->bw_mhz * 500;
        if (st->freq_khz + half < cs->chan->freq_khz || st->freq_khz > cs->chan->freq_khz + half)
            ts->other_freq++;
    }

    /* NDP frames carry SIG bits, not an 802.11 frame */
    if (st->flags & MM_RX_FLAG_NDP) {
        cs->ndp++;
        return;
    }

    cs->frames++;
    cs->bytes += frame_len;

    if (st->flags & MM_RX_FLAG_CRC_ERROR)
        cs->bad_fcs++;

    if (ts->pcap != NULL && (rt_len = mm_radiotap_build(st, rt, sizeof(rt))) > 0)
        pcap_write(ts, rt, rt_len, frame, frame_len);
}

static void print_stats(const struct test_state *ts, uint64_t elapsed_ms, bool final) {
    uint64_t frames = 0, bad = 0, ndp = 0;

    for (size_t i = 0; i < ts->num_chans; i++) {
        frames += ts->chans[i].frames;
        bad += ts->chans[i].bad_fcs;
        ndp += ts->chans[i].ndp;
    }

    if (!final) {
        const struct chan_stats *cs = &ts->chans[ts->cur_chan];
        printf("[%6.1fs] ch %3u (%u MHz %7.1f MHz): %8llu frames | total %llu frames, %llu bad FCS, %llu NDP\n",
                elapsed_ms / 1000.0, cs->chan->channel, cs->chan->bw_mhz,
                cs->chan->freq_khz / 1000.0, (unsigned long long) cs->frames,
                (unsigned long long) frames, (unsigned long long) bad, (unsigned long long) ndp);
        fflush(stdout);
        return;
    }

    printf("\n%-8s %-6s %-10s %10s %10s %8s %12s\n", "channel", "width", "freq", "frames",
            "bad FCS", "NDP", "bytes");
    for (size_t i = 0; i < ts->num_chans; i++) {
        const struct chan_stats *cs = &ts->chans[i];
        printf("%-8u %-6u %-10.1f %10llu %10llu %8llu %12llu\n", cs->chan->channel,
                cs->chan->bw_mhz, cs->chan->freq_khz / 1000.0,
                (unsigned long long) cs->frames, (unsigned long long) cs->bad_fcs,
                (unsigned long long) cs->ndp, (unsigned long long) cs->bytes);
    }
    printf("total: %llu frames, %llu bad FCS, %llu NDP in %.1fs; %llu on another frequency\n",
            (unsigned long long) frames, (unsigned long long) bad, (unsigned long long) ndp,
            elapsed_ms / 1000.0, (unsigned long long) ts->other_freq);
}

static bool width_allowed(const char *widths, unsigned int bw) {
    char buf[64], *save = NULL;

    if (widths == NULL)
        return true;

    snprintf(buf, sizeof(buf), "%s", widths);

    for (char *t = strtok_r(buf, ",", &save); t != NULL; t = strtok_r(NULL, ",", &save))
        if ((unsigned int) strtoul(t, NULL, 10) == bw)
            return true;

    return false;
}

static int build_hop_list(struct test_state *ts, const struct mm_s1g_region *region,
        const char *channels, const char *widths) {
    ts->num_chans = 0;

    if (channels == NULL) {
        for (size_t i = 0; i < region->num_channels && ts->num_chans < MAX_HOP_CHANNELS; i++)
            if (width_allowed(widths, region->channels[i].bw_mhz))
                ts->chans[ts->num_chans++].chan = &region->channels[i];
    } else {
        char buf[512], *save = NULL;

        snprintf(buf, sizeof(buf), "%s", channels);

        for (char *t = strtok_r(buf, ",", &save); t != NULL; t = strtok_r(NULL, ",", &save)) {
            char *end;
            const unsigned long c = strtoul(t, &end, 10);
            const struct mm_s1g_channel *ch;

            if (*end != 0 || (ch = mm_s1g_channel_lookup(region, (unsigned int) c)) == NULL) {
                fprintf(stderr, "channel '%s' is not valid in %s\n", t, region->country);
                return -1;
            }

            if (ts->num_chans >= MAX_HOP_CHANNELS) {
                fprintf(stderr, "too many channels\n");
                return -1;
            }

            ts->chans[ts->num_chans++].chan = ch;
        }
    }

    if (ts->num_chans == 0) {
        fprintf(stderr, "no channels to capture on\n");
        return -1;
    }

    return 0;
}

static bool channel_disabled(const struct mm_s1g_channel *ch,
        const struct mm_disabled_channel *dis, size_t num_dis) {
    for (size_t i = 0; i < num_dis; i++)
        if (dis[i].freq_khz == ch->freq_khz && (dis[i].bw_mhz == 0 || dis[i].bw_mhz == ch->bw_mhz))
            return true;

    return false;
}

/* Drops channels the board config disables, reporting each */
static int prune_disabled(struct test_state *ts, struct mm8108_dev *dev) {
    struct mm_disabled_channel dis[256];
    size_t num_dis = 0, kept = 0;

    if (mm_cmd_get_disabled_channels(dev, dis, sizeof(dis) / sizeof(dis[0]), &num_dis) < 0) {
        fprintf(stderr, "could not get the disabled channel list: %s\n", dev->errstr);
        return -1;
    }

    for (size_t i = 0; i < ts->num_chans; i++) {
        if (channel_disabled(ts->chans[i].chan, dis, num_dis)) {
            printf("skipping channel %u (%u MHz at %.1f MHz), disabled by the board config\n",
                    ts->chans[i].chan->channel, ts->chans[i].chan->bw_mhz,
                    ts->chans[i].chan->freq_khz / 1000.0);
            continue;
        }

        ts->chans[kept++] = ts->chans[i];
    }

    ts->num_chans = kept;

    if (kept == 0) {
        fprintf(stderr, "every requested channel is disabled by the board config\n");
        return -1;
    }

    return 0;
}

/* The primary is the lowest 1 MHz (or 2 MHz) sub-channel, as the driver defaults */
static int tune(struct mm8108_dev *dev, const struct mm_s1g_channel *ch) {
    const uint8_t pri_bw = ch->bw_mhz == 1 ? 1 : 2;
    return mm_cmd_set_channel(dev, ch->freq_khz, ch->bw_mhz, pri_bw, 0);
}

int main(int argc, char *argv[]) {
    static const struct option longopts[] = {
        { "fw-dir", required_argument, NULL, 'd' },
        { "firmware", required_argument, NULL, 'f' },
        { "bcf", required_argument, NULL, 'b' },
        { "country", required_argument, NULL, 'c' },
        { "channels", required_argument, NULL, 'C' },
        { "widths", required_argument, NULL, 'W' },
        { "dwell", required_argument, NULL, 't' },
        { "pcap", required_argument, NULL, 'w' },
        { "duration", required_argument, NULL, 'T' },
        { "info", no_argument, NULL, 'i' },
        { "device", required_argument, NULL, 'D' },
        { "verbose", no_argument, NULL, 'v' },
        { "help", no_argument, NULL, 'h' },
        { NULL, 0, NULL, 0 },
    };

    const char *fw_dir = DEFAULT_FW_DIR;
    const char *fw_path = NULL, *bcf_path = NULL, *country = NULL;
    const char *channels = NULL, *widths = NULL, *pcap_path = NULL;
    unsigned long dwell_ms = DEFAULT_DWELL_MS, duration_s = 0;
    bool info_only = false;
    int verbose = 0, opt, ret = 1, dev_index = -1, bus = -1, address = -1;
    char fw_buf[1024], bcf_buf[1024], name[64], version[129];
    struct mm8108_dev dev;
    struct mm8108_boot_config boot;
    struct test_state ts;
    const struct mm_s1g_region *region;

    memset(&ts, 0, sizeof(ts));

    while ((opt = getopt_long(argc, argv, "d:f:b:c:C:W:t:w:T:iD:vh", longopts, NULL)) != -1) {
        switch (opt) {
            case 'd': fw_dir = optarg; break;
            case 'f': fw_path = optarg; break;
            case 'b': bcf_path = optarg; break;
            case 'c': country = optarg; break;
            case 'C': channels = optarg; break;
            case 'W': widths = optarg; break;
            case 't': dwell_ms = strtoul(optarg, NULL, 10); break;
            case 'w': pcap_path = optarg; break;
            case 'T': duration_s = strtoul(optarg, NULL, 10); break;
            case 'i': info_only = true; break;
            case 'D': dev_index = (int) strtol(optarg, NULL, 10); break;
            case 'v': verbose++; break;
            default:
                usage(argv[0]);
                return opt == 'h' ? 0 : 1;
        }
    }

    if (dwell_ms < 50) {
        fprintf(stderr, "dwell must be at least 50ms\n");
        return 1;
    }

    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    if (mm8108_init(&dev, verbose + 1) < 0) {
        fprintf(stderr, "%s\n", dev.errstr);
        return 1;
    }

    mm8108_set_rx_cb(&dev, rx_frame, &ts);

    /* Adapters are numbered in port order, as the Kismet source names them mm8108-N */
    if (dev_index >= 0) {
        struct mm_usb_devinfo devs[16];
        libusb_context *ctx;
        int n;

        if (libusb_init(&ctx) < 0) {
            fprintf(stderr, "could not initialize libusb\n");
            goto out;
        }
        n = mm_usb_list(ctx, devs, sizeof(devs) / sizeof(devs[0]));
        libusb_exit(ctx);

        if (n <= dev_index) {
            fprintf(stderr, "no MM8108 adapter %d (%d found)\n", dev_index, n < 0 ? 0 : n);
            goto out;
        }
        bus = devs[dev_index].bus;
        address = devs[dev_index].address;
    }

    if (mm_usb_open(&dev, bus, address) < 0 || mm_read_chip_id(&dev) < 0 || mm_read_otp(&dev) < 0) {
        fprintf(stderr, "%s\n", dev.errstr);
        goto out;
    }

    /* The OTP country locks the regulatory domain */
    if (dev.otp_country[0] != 0) {
        if (country != NULL && strncmp(country, dev.otp_country, 2) != 0)
            fprintf(stderr, "warning: the device is locked to %s; ignoring %s\n",
                    dev.otp_country, country);
        country = dev.otp_country;
    } else if (country == NULL) {
        country = "US";
    }

    if ((region = mm_s1g_region(country)) == NULL) {
        fprintf(stderr, "unknown country %s; supported: %s\n", country, mm_s1g_countries());
        goto out;
    }

    if (!info_only && build_hop_list(&ts, region, channels, widths) < 0)
        goto out;

    if (fw_path == NULL) {
        snprintf(name, sizeof(name), "mm8108%s-rl.bin", mm_chip_rev_string(dev.chip_id));
        if (!find_file(fw_dir, name, fw_buf, sizeof(fw_buf))) {
            fprintf(stderr, "could not find %s in %s; use --fw-dir or --firmware\n", name, fw_dir);
            goto out;
        }
        fw_path = fw_buf;
    }

    if (bcf_path != NULL && strchr(bcf_path, '/') == NULL) {
        if (!find_file(fw_dir, bcf_path, bcf_buf, sizeof(bcf_buf))) {
            fprintf(stderr, "could not find %s in %s\n", bcf_path, fw_dir);
            goto out;
        }
        bcf_path = bcf_buf;
    } else if (bcf_path == NULL) {
        char names[MM_BCF_MAX_NAMES][MM_BCF_NAME_LEN];
        size_t num_names = mm_bcf_default_names(&dev, names), i;

        for (i = 0; i < num_names; i++)
            if (find_file(fw_dir, names[i], bcf_buf, sizeof(bcf_buf)))
                break;

        if (i == num_names) {
            fprintf(stderr, "could not find a board config for board type 0x%04x in %s; use "
                    "--bcf to choose one\n", dev.board_type, fw_dir);
            goto out;
        }

        /* Only the board type's own config is known to match the adapter */
        if (dev.board_type == 0 || i > 0)
            fprintf(stderr, "warning: %s; using board config %s, use --bcf if the adapter "
                    "needs a different one\n", dev.board_type == 0 ?
                    "no board type in OTP" : "no board config for this board type", names[i]);

        bcf_path = bcf_buf;
    }

    printf("%s, board type 0x%04x, regulatory domain %s\n", mm_chip_name(dev.chip_id),
            dev.board_type, country);
    printf("firmware %s\nBCF      %s\n", fw_path, bcf_path);

    boot.firmware_path = fw_path;
    boot.bcf_path = bcf_path;
    boot.country = country;

    if (mm_boot(&dev, &boot) < 0) {
        fprintf(stderr, "boot failed: %s\n", dev.errstr);
        goto out;
    }

    if (mm_cmd_get_version(&dev, version, sizeof(version)) < 0) {
        fprintf(stderr, "could not get the firmware version: %s\n", dev.errstr);
        goto out;
    }

    printf("firmware version %s, MAC %02x:%02x:%02x:%02x:%02x:%02x\n", version,
            dev.mac[0], dev.mac[1], dev.mac[2], dev.mac[3], dev.mac[4], dev.mac[5]);

    if (dev.bcf_module[0] != 0)
        printf("board config module %s\n", dev.bcf_module);

    if (info_only) {
        ret = 0;
        goto out;
    }

    if (pcap_path != NULL && pcap_open(&ts, pcap_path) < 0)
        goto out;

    if (prune_disabled(&ts, &dev) < 0)
        goto out;

    if (mm8108_start_monitor(&dev) < 0) {
        fprintf(stderr, "could not enter monitor mode: %s\n", dev.errstr);
        goto out;
    }

    printf("capturing on %zu channel%s, %lu ms per channel%s%s\n", ts.num_chans,
            ts.num_chans == 1 ? "" : "s", dwell_ms, pcap_path ? ", writing " : "",
            pcap_path ? pcap_path : "");

    const uint64_t start = mm_monotonic_ms();
    uint64_t next_hop = 0, next_print = start + 1000;
    bool tuned = false;

    while (!stop_requested) {
        const uint64_t now = mm_monotonic_ms();
        int r;

        if (duration_s > 0 && now - start >= duration_s * 1000)
            break;

        /* Retune when the dwell expires, or once when not hopping */
        if (!tuned || (ts.num_chans > 1 && now >= next_hop)) {
            if (tuned)
                ts.cur_chan = (ts.cur_chan + 1) % ts.num_chans;

            if (tune(&dev, ts.chans[ts.cur_chan].chan) < 0) {
                fprintf(stderr, "could not set channel %u: %s\n",
                        ts.chans[ts.cur_chan].chan->channel, dev.errstr);
                goto out;
            }

            tuned = true;
            next_hop = mm_monotonic_ms() + dwell_ms;
        }

        if ((r = mm8108_poll(&dev, 1)) < 0) {
            fprintf(stderr, "capture failed: %s\n", dev.errstr);
            goto out;
        }

        if (now >= next_print) {
            print_stats(&ts, now - start, false);
            next_print += 1000;
        }
    }

    print_stats(&ts, mm_monotonic_ms() - start, true);

    printf("%llu interrupts; data found without an interrupt %llu times\n",
            (unsigned long long) dev.irq_count, (unsigned long long) dev.missed_irq_count);

    if (dev.rx_errors)
        printf("%llu packets from the chip failed validation\n", (unsigned long long) dev.rx_errors);
    if (ts.pcap_errors)
        printf("%llu packets could not be written to the pcap\n", (unsigned long long) ts.pcap_errors);

    ret = 0;

out:
    mm8108_stop(&dev);
    mm8108_free(&dev);

    if (ts.pcap != NULL)
        fclose(ts.pcap);

    return ret;
}
