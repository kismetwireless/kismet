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

/* capture_linux_wifi
 *
 * Capture binary, written in pure c, which interfaces via the Kismet capture
 * protocol and feeds packets from, and is able to control, a wireless card on
 * Linux, using either the old iwconfig IOCTL interface (deprecated) or the
 * modern nl80211 netlink interface.
 *
 * The communications channel is a file descriptor pair, passed via command
 * line arguments, --in-fd= and --out-fd=
 *
 * We parse additional options from the source definition itself, such as a DLT
 * override, once we open the protocol
 *
 * The packets undergo as little processing as possible and are passed to Kismet
 * to process the DLT.
 *
 * This binary needs to run as root to be able to control and capture from
 * the interface - and it needs to continue running as root to be able to control
 * the channels.
 *
 */

#define _GNU_SOURCE

#include <pcap.h>
#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>

#include <sched.h>

#include <string.h>

/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <dirent.h>

#include <unistd.h>
#include <errno.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <ifaddrs.h>

#include <stdbool.h>

#include <time.h>

#include <fcntl.h>
#include <sys/stat.h>

#include "../config.h"

#include "nl80211.h"

#ifdef HAVE_LIBNM
#include <libnm/NetworkManager.h>
#include <glib.h>
#endif

#include "../capture_framework.h"

#include "../interface_control.h"
#include "linux_wireless_control.h"
#include "linux_netlink_control.h"
#include "linux_wireless_rfkill.h"
#include "linux_nexmon_control.h"

#include "../wifi_ht_channels.h"

#define MAX_PACKET_LEN  8192

// pass management+eapol, all other data is filtered
#if 0
; prep length memory at max
ld #-1
st m[1]

; parse radiotap length
ldb [3]
lsh #8
tax
ldb [2]
add x

st m[0]         ; store rtap length in M0
tax             ; store total length in index(x)

; get frame type
ldb [x + 0]
and #0xC        ; 00001100

; management
jeq #0x0, full

; data
jeq #0x8, datasub
ja drop

datasub:
; load subtype
ldb [x + 0]
and #0xF0

; normal data packets have a 24 byte header, qos have a 26 byte
; header, and anything else we don't care about

jeq #0x80, qos
jeq #0x00, basic
ja drop                 ; drop anything else

basic:
ld #24
ja data

qos:
ld #26

data:
add %x
st m[1]                 ; store rtap+data offset to m[1]

ldx m[0]                ; load the rtap offset again and compare 80211 flags
ldb [x + 1]
jset #0x40, drop        ; skip protected data packets

# load the data offset back into the index
ldx m[1]

; check LLC SNAP header
ldh [x + 0]
jne #0xAAAA, drop

; check eapol signature
ldb [x + 6]
jne #0x88, drop

ldb [x + 7]
jne #0x8E, drop

full:
ret #0xFFFF

drop:
ret #0
#endif
struct bpf_insn rt_pgm[] = {
    { 0000,  0,  0, 0xffffffff },
    { 0x02,  0,  0, 0x00000001 },
    { 0x30,  0,  0, 0x00000003 },
    { 0x64,  0,  0, 0x00000008 },
    { 0x07,  0,  0, 0000000000 },
    { 0x30,  0,  0, 0x00000002 },
    { 0x0c,  0,  0, 0000000000 },
    { 0x02,  0,  0, 0000000000 },
    { 0x07,  0,  0, 0000000000 },
    { 0x50,  0,  0, 0000000000 },
    { 0x54,  0,  0, 0x0000000c },
    { 0x15, 22,  0, 0000000000 },
    { 0x15,  1,  0, 0x00000008 },
    { 0x05,  0,  0, 0x00000015 },
    { 0x50,  0,  0, 0000000000 },
    { 0x54,  0,  0, 0x000000f0 },
    { 0x15,  4,  0, 0x00000080 },
    { 0x15,  1,  0, 0000000000 },
    { 0x05,  0,  0, 0x00000010 },
    { 0000,  0,  0, 0x00000018 },
    { 0x05,  0,  0, 0x00000001 },
    { 0000,  0,  0, 0x0000001a },
    { 0x0c,  0,  0, 0000000000 },
    { 0x02,  0,  0, 0x00000001 },
    { 0x61,  0,  0, 0000000000 },
    { 0x50,  0,  0, 0x00000001 },
    { 0x45,  8,  0, 0x00000040 },
    { 0x61,  0,  0, 0x00000001 },
    { 0x48,  0,  0, 0000000000 },
    { 0x15,  0,  5, 0x0000aaaa },
    { 0x50,  0,  0, 0x00000006 },
    { 0x15,  0,  3, 0x00000088 },
    { 0x50,  0,  0, 0x00000007 },
    { 0x15,  0,  1, 0x0000008e },
    { 0x06,  0,  0, 0x0000ffff },
    { 0x06,  0,  0, 0000000000 },
};

// Pass management and EAPOL, crop other data to rtap+dot11 headers
#if 0
; prep length memory at max
ld #-1
st m[1]

; parse radiotap length
ldb [3]
lsh #8
tax
ldb [2]
add x

st m[0]         ; store rtap length in M0
tax             ; store total length in index(x)

; get frame type
ldb [x + 0]
and #0xC        ; 00001100

; management
jeq #0x0, full

; data
jeq #0x8, datasub
ja drop

datasub:
; load subtype
ldb [x + 0]
and #0xF0

; normal data packets have a 24 byte header, qos have a 26 byte
; header, and anything else we don't care about

jeq #0x80, qos
jeq #0x00, basic
ja drop                 ; drop anything else

basic:
ld #24
ja data

qos:
ld #26

data:
add %x
st m[1]                 ; store rtap+data offset to m[1]

ldx m[0]                ; load the rtap offset again and compare 80211 flags
ldb [x + 1]
jset #0x40, trunc       ; skip protected data packets and truncate them

# load the data offset back into the index
ldx m[1]

; check LLC SNAP header
ldh [x + 0]
jne #0xAAAA, trunc

; check eapol signature
ldb [x + 6]
jne #0x88, trunc

ldb [x + 7]
jne #0x8E, trunc

full:
ret #0xFFFF

drop:
ret #0

trunc:
ldx m[1]
txa
ret %a
#endif
struct bpf_insn rt_pgm_crop_data[] = {
    { 0000,  0,  0, 0xffffffff },
    { 0x02,  0,  0, 0x00000001 },
    { 0x30,  0,  0, 0x00000003 },
    { 0x64,  0,  0, 0x00000008 },
    { 0x07,  0,  0, 0000000000 },
    { 0x30,  0,  0, 0x00000002 },
    { 0x0c,  0,  0, 0000000000 },
    { 0x02,  0,  0, 0000000000 },
    { 0x07,  0,  0, 0000000000 },
    { 0x50,  0,  0, 0000000000 },
    { 0x54,  0,  0, 0x0000000c },
    { 0x15, 22,  0, 0000000000 },
    { 0x15,  1,  0, 0x00000008 },
    { 0x05,  0,  0, 0x00000015 },
    { 0x50,  0,  0, 0000000000 },
    { 0x54,  0,  0, 0x000000f0 },
    { 0x15,  4,  0, 0x00000080 },
    { 0x15,  1,  0, 0000000000 },
    { 0x05,  0,  0, 0x00000010 },
    { 0000,  0,  0, 0x00000018 },
    { 0x05,  0,  0, 0x00000001 },
    { 0000,  0,  0, 0x0000001a },
    { 0x0c,  0,  0, 0000000000 },
    { 0x02,  0,  0, 0x00000001 },
    { 0x61,  0,  0, 0000000000 },
    { 0x50,  0,  0, 0x00000001 },
    { 0x45,  9,  0, 0x00000040 },
    { 0x61,  0,  0, 0x00000001 },
    { 0x48,  0,  0, 0000000000 },
    { 0x15,  0,  6, 0x0000aaaa },
    { 0x50,  0,  0, 0x00000006 },
    { 0x15,  0,  4, 0x00000088 },
    { 0x50,  0,  0, 0x00000007 },
    { 0x15,  0,  2, 0x0000008e },
    { 0x06,  0,  0, 0x0000ffff },
    { 0x06,  0,  0, 0000000000 },
    { 0x61,  0,  0, 0x00000001 },
    { 0x87,  0,  0, 0000000000 },
    { 0x16,  0,  0, 0000000000 },
};

/* State tracking, put in userdata */
typedef struct {
    pcap_t *pd;

    char *interface;
    char *cap_interface;
    char *base_phy;
    char *name;

    /* inter-process semaphore for computing interfaces during open */
    int lock_fd;

    int datalink_type;
    int override_dlt;

    /* Do we use mac80211 controls or basic ioctls?  We have to split this for
     * broken interfaces */
    int use_mac80211_vif;
    int use_mac80211_channels;
    int use_mac80211_mode;

    /* Cached mac80211 controls */
    void *mac80211_socket;
    int mac80211_id;
    int mac80211_ifidx;

    /* Interface must be up to set mode */
    bool up_before_mode;

    /* Do we process extended channels?  Controlled by chipset and by source
     * options */
    int use_ht_channels;
    int use_vht_channels;

    /* Do we filter traffic? */
    bool wardrive_filter;
    bool data_filter;

    /* Are we restricted to specific bands? */
    bool band_any;
    bool band_2_4;
    bool band_5;
    bool band_6;

    /* Number of sequential errors setting channel */
    unsigned int seq_channel_failure;

    /* Do we try to reset networkmanager when we're done? */
    int reset_nm_management;

    /* Do we hold a link to nexmon? */
    struct nexmon_t *nexmon;

    /* Do we spam verbose errors, like long channel set intervals? */
    int verbose_diagnostics;

    /* Do we spam statistics? */
    int verbose_statistics;

    /* Last 100 ns channel set timings */
    unsigned long channel_set_ns_avg;
    unsigned int channel_set_ns_count;

} local_wifi_t;

/* Linux Wi-Fi Channels:
 *
 * Wi-Fi can use multiple channel widths and encodings which need to be
 * accounted for.
 *
 * Channel formats:
 *
 * XXW5         Channel/frequency XX, custom 5MHz channel
 * XXW10        Channel/frequency XX, custom 10MHz channel
 * XX           Channel/frequency XX, non-HT standard 20MHz channel
 * XXHT20       Channel/frequency XX, explicitly HT20 20MHz channel
 * XXHT40+      Channel/frequency XX, HT40+ channel
 * XXHT40-      Channel/frequency XX, HT40- channel
 * XXVHT80      Channel/frequency XX, VHT 80MHz channel.  Upper pair automatically
 *              derived from channel definition table
 * XXVHT160     Channel/frequency XX, VHT 160MHz channel.  Upper pair automatically
 *              derived from channel definition table
 *
 * XXVHT80-YY   Channel/frequency XX, VHT 80MHz channel, upper pair specified
 * XXVHT160-YY  Channel/frequency XX, VHT 160MHz channel, upper pair specified
 *
 * XXW6e 	    Channel XX, WiFi 6e 6GHz band
 *
 * 5, 10, HT and VHT, and 6e channels require mac80211 drivers; the old wireless IOCTLs do
 * not support the needed attributes.
 */

enum wifi_chan_band {
    wifi_band_raw,
    wifi_band_2ghz,
    wifi_band_5ghz,
    wifi_band_6ghz,
};

/* Local interpretation of a channel; this lets us parse the string definitions
 * into a faster non-parsed version, once. */
typedef struct {
    /* For stock 20mhz channels, center freq is set to channel and
     * chan_type is set to 0/NL80211_CHAN_NO_HT
     *
     * For ht40 channels we set only the center freq/chan and the type
     * is set to NL80211_CHAN_HT40MINUS/HT40PLUS
     *
     * For vht80 and vht160, center freq is set, chan_type is set to 0,
     * chan_width is set accordingly to one of NL80211_CHAN_WIDTH_, and
     * center_freq1 is set to the corresponding vht center frequency.
     *
     * If 'unusual_center1' is true, the center_freq1 was not derived
     * automatically; this is relevant only when printing
     *
     * For sub-20mhz channels, chan_type is set to 0, chan_width is set
     * accordingly from NL80211_CHAN_WIDTH_5/10, and center_freq1 is 0.
     */
    unsigned int control_freq;
    unsigned int chan_type;
    unsigned int chan_width;
    unsigned int unusual_center1;
    unsigned int center_freq1;
    unsigned int center_freq2;
    enum wifi_chan_band chan_band;
} local_channel_t;

int acquire_interface_lock(local_wifi_t *local_wifi) {
    local_wifi->lock_fd = open("/tmp/.kismet_cap_linux_wifi_interface_lock", O_CREAT | O_NOFOLLOW | O_WRONLY, S_IWUSR | S_IWGRP);

    if (local_wifi->lock_fd < 0) {
        if (unlink("/tmp/.kismet_cap_linux_wifi_interface_lock") < 0)
            return errno;

        local_wifi->lock_fd = open("/tmp/.kismet_cap_linux_wifi_interface_lock", O_CREAT | O_NOFOLLOW | O_WRONLY, S_IWUSR | S_IWGRP);

        if (local_wifi->lock_fd < 0)
            return errno;
    }

    return 0;
}

int try_flock(local_wifi_t *local_wifi, unsigned int tries) {
    unsigned int attempt = 0;
    int r = 0;

    if (local_wifi->lock_fd < 0) {
        return EINVAL;
    }

    /* Spin looking for an exclusive system-wide lock */
    for (attempt = 0; attempt < tries; attempt++) {
        if ((r = flock(local_wifi->lock_fd, LOCK_EX | LOCK_NB)) < 0) {
            if (errno == EWOULDBLOCK) {
                sleep(1);
                continue;
            } else {
		return r;
            }
        } else {
            return 0;
        }
    }

    return ETIMEDOUT;
}

void release_flock(local_wifi_t *local_wifi) {
    if (local_wifi->lock_fd >= 0)
        close(local_wifi->lock_fd);

    local_wifi->lock_fd = -1;
}

/* Measure timing, returns in ns */
struct timespec ns_measure_timer_start() {
    struct timespec ret;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &ret);
    return ret;
}

long ns_measure_timer_stop(struct timespec start) {
    struct timespec end;
    clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &end);

    long diff;

    if (start.tv_sec == end.tv_sec) {
        if (end.tv_nsec > start.tv_nsec)
            diff = (end.tv_nsec - start.tv_nsec);
        else
            diff = (start.tv_nsec - end.tv_nsec);

        return diff;
    }

    // Difference in whole seconds, minus the partial second from
    // the start, plus the partial second past the end
    diff = ((start.tv_sec - end.tv_sec) * (long) 1e9) +
        start.tv_nsec + end.tv_nsec;

    return diff;
}

unsigned int wifi_chan_to_freq(unsigned int in_chan, enum wifi_chan_band in_band) {
    if (in_chan <= 0)
        return 0;

    switch (in_band) {
        case wifi_band_raw:
            return in_chan;

        case wifi_band_2ghz:
            if (in_chan == 14)
                return 2484;
            else if (in_chan < 14)
                return 2407 + in_chan * 5;
            break;

        case wifi_band_5ghz:
            if (in_chan >= 182 && in_chan <= 196)
                return 4000 + in_chan * 5;
            else
                return 5000 + in_chan * 5;
            break;

        case wifi_band_6ghz:
            if (in_chan == 2)
                return 5935;
            if (in_chan <= 253)
                return 5950 + in_chan * 5;
            break;

        default:
            return 0;
    }

    return 0;
}

unsigned int wifi_freq_to_chan(unsigned int in_freq) {
    if (in_freq < 2412)
        return in_freq;

    if (in_freq == 2484)
        return 14;
    else if (in_freq == 5935)
        return 2;
    else if (in_freq < 2484)
        return (in_freq - 2407) / 5;
    else if (in_freq >= 4910 && in_freq <= 4980)
        return (in_freq - 4000) / 5;
    else if (in_freq < 5950)
        return (in_freq - 5000) / 5;
    else if (in_freq <= 45000) /* DMG band lower limit */
        return (in_freq - 5950) / 5;
    else if (in_freq >= 58320 && in_freq <= 70200)
        return (in_freq - 56160) / 2160;
    else
        return 0;
}

enum wifi_chan_band wifi_freq_to_band(unsigned int in_freq) {
    if (in_freq >= 2400 && in_freq <= 2484) {
        return wifi_band_2ghz;
    }

    /* treat the weird 4ghz stuff as 5 */
    if (in_freq >= 4915 && in_freq <= 4980) {
        return wifi_band_5ghz;
    }

    if (in_freq >= 5180 && in_freq <= 5865) {
        return wifi_band_5ghz;
    }

    if (in_freq >= 5955 && in_freq <= 7115) {
        return wifi_band_6ghz;
    }

    return wifi_band_raw;
}

/* Find an interface, based on mode, that shares a parent with the provided
 * interface.  If somehow we're called with an existing monitor interface,
 * we'll find it as well.
 *
 * Mode is typically LINUX_WL_MODE_MONITOR
 *
 * Returns the ifnum index, or 0
 */
int find_interface_monitor_by_parent(local_wifi_t *local_wifi, const char *base_ifname) {
    char *base_parent, *if_parent;
    struct ifaddrs *ifaddr, *ifa;
    char errstr[STATUS_MAX];

    if (local_wifi->mac80211_socket == NULL)
        return 0;

    if ((base_parent = mac80211_find_parent(base_ifname)) == NULL)
        return 0;

    if (getifaddrs(&ifaddr) == -1)
        return 0;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if ((if_parent = mac80211_find_parent(ifa->ifa_name)) == NULL)
            continue;

        if (strcmp(if_parent, base_parent) == 0) {
            uint32_t mode;
            int index;

            if ((index = if_nametoindex(ifa->ifa_name)) == 0) {
                continue;
            }

            if (mac80211_get_iftype_cache(index, local_wifi->mac80211_socket,
                        local_wifi->mac80211_id, &mode, errstr) < 0) {
                continue;
            }

            if (mode != NL80211_IFTYPE_MONITOR)
                continue;

            free(if_parent);
            free(base_parent);
            freeifaddrs(ifaddr);
            return index;
        }

        free(if_parent);
    }

    freeifaddrs(ifaddr);
    free(base_parent);

    return 0;
}

/* Find the next unused interface number for a given interface name */
int find_next_ifnum(const char *basename) {
    int i;
    char ifname[IFNAMSIZ];

    for (i = 0; i < 100; i++) {
        snprintf(ifname, IFNAMSIZ, "%s%d", basename, i);

        if (if_nametoindex(ifname) == 0)
            return i;
    }

    return -1;
}

/* Convert a string into a local interpretation; allocate ret_localchan.
 */
void *chantranslate_callback(kis_capture_handler_t *caph, const char *chanstr) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    local_channel_t *ret_localchan = NULL;
    unsigned int parsechan, parse_center1;
    char parsetype[16];
    char mod;
    int r;
    unsigned int ci;
    char errstr[STATUS_MAX];

    /* Default to raw frequency */
    enum wifi_chan_band band_guess = wifi_band_raw;

    /* Match 6e channels */
    if (strcasestr(chanstr, "6e") != NULL) {
        r = sscanf(chanstr, "%uW6e", &parsechan);

        if (r != 1)
            r = sscanf(chanstr, "%u-W6e", &parsechan);

        if (r == 1) {
            ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
            memset(ret_localchan, 0, sizeof(local_channel_t));

            ret_localchan->chan_band = wifi_band_6ghz;

            /* 6e channels are shifted up by 190 channels to match the normal frequency code */
            (ret_localchan)->control_freq = wifi_chan_to_freq(parsechan, wifi_band_6ghz);

            // fprintf(stderr, "debug - localchan parse %s to %u\n", chanstr, ret_localchan->control_freq);

            return ret_localchan;
        }
    }

    /* Match HT20 */
    if (strcasestr(chanstr, "HT20") != NULL) {
        r = sscanf(chanstr, "%uHT20", &parsechan);

        if (r == 1) {
            /* Guess at the band from the channel #, we already eliminated 6ghz overlapping channels above */
            if (parsechan <= 14) {
                band_guess = wifi_band_2ghz;
            } else if (parsechan <= 196) {
                band_guess = wifi_band_5ghz;
            }

            ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
            memset(ret_localchan, 0, sizeof(local_channel_t));

            ret_localchan->chan_band = band_guess;
            (ret_localchan)->control_freq = wifi_chan_to_freq(parsechan, band_guess);
            (ret_localchan)->chan_type = NL80211_CHAN_HT20;

            return ret_localchan;
        } else {
            snprintf(errstr, STATUS_MAX, "%s could not parse channel %s; this does "
                    "not appear to be a valid HT20 channel",
                    local_wifi->name, chanstr);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
            return NULL;
        }
    }

    /* Match HT40+ and HT40- */
    if (strcasestr(chanstr, "HT40") != NULL) {
        ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
        memset(ret_localchan, 0, sizeof(local_channel_t));

        ret_localchan->chan_band = band_guess;

        r = sscanf(chanstr, "%uHT40%c", &parsechan, &mod);

        if (r != 2) {
            snprintf(errstr, STATUS_MAX, "%s could not parse channel %s; this does "
                    "not appear to be a valid HT40 channel",
                    local_wifi->name, chanstr);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
            return NULL;
        }

        /* Guess at the band from the channel #, we already eliminated 6ghz overlapping channels above */
        if (parsechan <= 14) {
            band_guess = wifi_band_2ghz;
        } else if (parsechan <= 196) {
            band_guess = wifi_band_5ghz;
        }

        if (r == 2) {
            (ret_localchan)->control_freq = wifi_chan_to_freq(parsechan, band_guess);

            if (mod == '-') {
                (ret_localchan)->chan_type = NL80211_CHAN_HT40MINUS;
                (ret_localchan)->chan_width = NL80211_CHAN_WIDTH_40;
                (ret_localchan)->center_freq1 = (ret_localchan)->control_freq - 10;

                /* Search for the ht channel record */
                for (ci = 0; ci < MAX_WIFI_HT_CHANNEL; ci++) {
                    if (wifi_ht_channels[ci].chan == parsechan ||
                            wifi_ht_channels[ci].freq == parsechan) {

                        if ((wifi_ht_channels[ci].flags & WIFI_HT_HT40MINUS) == 0) {
                            snprintf(errstr, STATUS_MAX, "%s requested channel %u as a HT40- "
                                    "channel; this does not appear to be a valid channel "
                                    "for 40MHz operation.", local_wifi->name, parsechan);
                            cf_send_message(caph, errstr, MSGFLAG_INFO);
                            return NULL;
                        }
                    }
                }
            } else if (mod == '+') {
                (ret_localchan)->chan_type = NL80211_CHAN_HT40PLUS;
                (ret_localchan)->chan_width = NL80211_CHAN_WIDTH_40;
                (ret_localchan)->center_freq1 = (ret_localchan)->control_freq + 10;

                /* Search for the ht channel record */
                for (ci = 0; ci < sizeof(wifi_ht_channels) /
                        sizeof (wifi_channel); ci++) {
                    if (wifi_ht_channels[ci].chan == parsechan ||
                            wifi_ht_channels[ci].freq == parsechan) {

                        if ((wifi_ht_channels[ci].flags & WIFI_HT_HT40PLUS) == 0) {
                            snprintf(errstr, STATUS_MAX, "requested channel %u as a HT40+ "
                                    "channel; this does not appear to be a valid channel "
                                    "for 40MHz operation.", parsechan);
                            cf_send_message(caph, errstr, MSGFLAG_INFO);
                            return NULL;
                        }
                    }
                }
            }
        } else {
            /* otherwise return it as a basic channel; we don't know what to do */
            snprintf(errstr, STATUS_MAX, "unable to parse attributes on channel "
                    "'%s', treating as standard non-HT channel.", chanstr);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
            return NULL;
        }

        return ret_localchan;
    }

    /* otherwise parse VHTXX, WXX, and VHTXX-YYY */
    r = sscanf(chanstr, "%u%15[^-]-%u", &parsechan, parsetype, &parse_center1);

    if (r <= 0) {
        snprintf(errstr, STATUS_MAX, "unable to parse any channel information from "
                "channel string '%s'", chanstr);
        cf_send_message(caph, errstr, MSGFLAG_ERROR);
        return NULL;
    }

    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    memset(ret_localchan, 0, sizeof(local_channel_t));

    /* Guess at the band from the channel #, we already eliminated 6ghz overlapping channels above */
    if (parsechan <= 14) {
        band_guess = wifi_band_2ghz;
    } else if (parsechan <= 196) {
        band_guess = wifi_band_5ghz;
    }

    ret_localchan->chan_band = band_guess;

    if (r == 1) {
        (ret_localchan)->control_freq = parsechan;
        return ret_localchan;
    }

    if (r >= 2) {
        (ret_localchan)->control_freq = parsechan;

        if (strcasecmp(parsetype, "w5") == 0) {
            (ret_localchan)->chan_width = NL80211_CHAN_WIDTH_5;
        } else if (strcasecmp(parsetype, "w10") == 0) {
            (ret_localchan)->chan_width = NL80211_CHAN_WIDTH_10;
        } else if (strcasecmp(parsetype, "vht80") == 0) {
            (ret_localchan)->chan_width = NL80211_CHAN_WIDTH_80;

            /* Do we have a hardcoded 80mhz freq pair? */
            if (r == 3) {
                (ret_localchan)->center_freq1 = parse_center1;
                (ret_localchan)->unusual_center1 = 1;
            } else {
                /* Search for the vht channel record to find the 80mhz center freq */
                for (ci = 0; ci < sizeof(wifi_ht_channels) /
                        sizeof (wifi_channel); ci++) {
                    if (wifi_ht_channels[ci].chan == parsechan ||
                            wifi_ht_channels[ci].freq == parsechan) {

                        if ((wifi_ht_channels[ci].flags & WIFI_HT_HT80) == 0) {
                            snprintf(errstr, STATUS_MAX, "requested channel %u as a "
                                    "VHT80 channel; this does not appear to be a valid "
                                    "channel for 80MHz operation, skipping channel",
                                    parsechan);
                            cf_send_message(caph, errstr, MSGFLAG_ERROR);
                            free(ret_localchan);
                            return NULL;
                        }

                        (ret_localchan)->control_freq = wifi_ht_channels[ci].freq;
                        (ret_localchan)->center_freq1 = wifi_ht_channels[ci].freq80;
                        return ret_localchan;
                    }
                }

                /* Fall through to error state if we found no valid vht80 channel */
                snprintf(errstr, STATUS_MAX, "requested channel %u as a "
                        "VHT80 channel; this does not appear to be a valid "
                        "channel for 80MHz operation, skipping channel",
                        parsechan);
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
                free(ret_localchan);
                return NULL;
            }
        } else if (strcasecmp(parsetype, "vht160") == 0) {
            (ret_localchan)->chan_width = NL80211_CHAN_WIDTH_160;

            /* Do we have a hardcoded 80mhz freq pair? */
            if (r == 3) {
                (ret_localchan)->center_freq1 = parse_center1;
                (ret_localchan)->unusual_center1 = 1;
            } else {
                /* Search for the vht channel record to find the 160mhz center freq */
                for (ci = 0; ci < sizeof(wifi_ht_channels) /
                        sizeof (wifi_channel); ci++) {
                    if (wifi_ht_channels[ci].chan == parsechan ||
                            wifi_ht_channels[ci].freq == parsechan) {

                        if ((wifi_ht_channels[ci].flags & WIFI_HT_HT160) == 0) {
                            snprintf(errstr, STATUS_MAX, "requested channel %u as a "
                                    "VHT160 channel; this does not appear to be a "
                                    "valid channel for 160MHz operation, skipping "
                                    "channel", parsechan);
                            cf_send_message(caph, errstr, MSGFLAG_ERROR);
                            free(ret_localchan);
                            return NULL;
                        }

                        (ret_localchan)->control_freq = wifi_ht_channels[ci].freq;
                        (ret_localchan)->center_freq1 = wifi_ht_channels[ci].freq160;
                        return ret_localchan;
                    }
                }

                /* Fall through to an error if we never found a vht160 for this */
                snprintf(errstr, STATUS_MAX, "requested channel %u as a "
                        "VHT160 channel; this does not appear to be a "
                        "valid channel for 160MHz operation, skipping "
                        "channel", parsechan);
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
                free(ret_localchan);
                return NULL;
            }
        } else {
            /* otherwise return it as a basic channel; we don't know what to do */
            snprintf(errstr, STATUS_MAX, "unable to parse attributes on channel "
                    "'%s', treating as standard non-HT channel.", chanstr);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
        }

    }

    return ret_localchan;
}

/* Convert a local interpretation of a channel back info a string;
 * 'chanstr' should hold at least STATUS_MAX characters; we'll never use
 * that many but it lets us do some cheaty stuff and re-use errstrs */
void local_channel_to_str(local_channel_t *chan, char *chanstr) {
    if (chan->chan_band == wifi_band_6ghz) {
        /* 6ghz */
        snprintf(chanstr, STATUS_MAX, "%uW6e", chan->control_freq);
    } else if (chan->chan_type == 0 && chan->chan_width == 0) {
        /* Basic channel with no HT/VHT */
        snprintf(chanstr, STATUS_MAX, "%u", chan->control_freq);
    } else if (chan->chan_type == NL80211_CHAN_HT20) {
        snprintf(chanstr, STATUS_MAX, "%uHT20", chan->control_freq);
    } else if (chan->chan_type == NL80211_CHAN_HT40MINUS) {
        snprintf(chanstr, STATUS_MAX, "%uHT40-", chan->control_freq);
    } else if (chan->chan_type == NL80211_CHAN_HT40PLUS) {
        snprintf(chanstr, STATUS_MAX, "%uHT40+", chan->control_freq);
    } else {
        /* We've got some channel width; work with them */
        switch (chan->chan_width) {
            case NL80211_CHAN_WIDTH_5:
                snprintf(chanstr, STATUS_MAX, "%uW5", chan->control_freq);
                break;
            case NL80211_CHAN_WIDTH_10:
                snprintf(chanstr, STATUS_MAX, "%uW10", chan->control_freq);
                break;
            case NL80211_CHAN_WIDTH_80:
                if (chan->unusual_center1) {
                    snprintf(chanstr, STATUS_MAX, "%uVHT80-%u",
                            chan->control_freq, chan->center_freq1);
                } else {
                    snprintf(chanstr, STATUS_MAX, "%uVHT80", chan->control_freq);
                }
                break;
            case NL80211_CHAN_WIDTH_160:
                if (chan->unusual_center1) {
                    snprintf(chanstr, STATUS_MAX, "%uVHT160-%u",
                            chan->control_freq, chan->center_freq1);
                } else {
                    snprintf(chanstr, STATUS_MAX, "%uVHT160", chan->control_freq);
                }
                break;
            default:
                /* Just put the basic freq if we can't figure out what to do */
                snprintf(chanstr, STATUS_MAX, "%u", chan->control_freq);
                break;
        }
    }
}

int populate_chanlist(kis_capture_handler_t *caph, char *interface, char *msg,
        unsigned int default_ht20, unsigned int expand_ht20,
        char ***chanlist, size_t *chanlist_sz) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    int ret;
    unsigned int ci, cp;
#ifdef HAVE_LINUX_WIRELESS
    unsigned int *iw_chanlist;
    char conv_chan[16];
    size_t chan_sz;
#endif
    size_t mod_chan_sz;
    unsigned int extended_flags = 0;
    char status[STATUS_MAX];

    char **chanlist_fetch;
    size_t chanlist_fetch_sz;

    if (local_wifi->use_ht_channels)
        extended_flags += MAC80211_GET_HT;
    if (local_wifi->use_vht_channels)
        extended_flags += MAC80211_GET_VHT;

    /* Prefer mac80211 channel fetch */
    ret = mac80211_get_chanlist(interface, extended_flags, msg, default_ht20, expand_ht20, &chanlist_fetch, &chanlist_fetch_sz);

    if (ret < 0 || chanlist_sz == 0) {
#ifdef HAVE_LINUX_WIRELESS
        snprintf(status, STATUS_MAX, "%s %s/%s could not fetch channels over netlink, falling "
                "back to WEXT ioctls.  This interface will not be able to tune to HT channels.",
                local_wifi->name, local_wifi->interface, local_wifi->cap_interface);
        cf_send_message(caph, msg, MSGFLAG_ERROR);

        ret = iwconfig_get_chanlist(interface, msg, &iw_chanlist, &chan_sz);

        /* We can't seem to get any channels from this interface, either
         * through mac80211 or siocgiwfreq so we can't do anything */
        if (ret < 0 || chan_sz == 0) {
            snprintf(status, STATUS_MAX, "%s %s/%s could not fetch channels over netlink or "
                    "via WEXT ioctls.  Can not open device with automatic channels, try "
                    "specifying a list of channels in the source definition.",
                    local_wifi->name, local_wifi->interface, local_wifi->cap_interface);
            cf_send_message(caph, msg, MSGFLAG_ERROR);
            return -1;
        }

        /* If we're filtering bands, count the number of channels */
        if (!local_wifi->band_any) {
            mod_chan_sz = 0;

            for (ci = 0; ci < chan_sz; ci++) {
                enum wifi_chan_band band = wifi_freq_to_band(iw_chanlist[ci]);

                if (band == wifi_band_2ghz && local_wifi->band_2_4)
                    mod_chan_sz++;
                if (band == wifi_band_5ghz && local_wifi->band_5)
                    mod_chan_sz++;
                if (band == wifi_band_6ghz && local_wifi->band_6)
                    mod_chan_sz++;
            }
        } else {
            mod_chan_sz = chan_sz;
        }

        *chanlist = (char **) malloc(sizeof(char *) * mod_chan_sz);

        cp = 0;

        for (ci = 0; ci < chan_sz; ci++) {
            if (!local_wifi->band_any) {
                enum wifi_chan_band band = wifi_freq_to_band(iw_chanlist[ci]);

                if (band == wifi_band_2ghz && !local_wifi->band_2_4)
                    continue;

                if (band == wifi_band_5ghz && !local_wifi->band_5)
                    continue;

                if (band == wifi_band_6ghz && !local_wifi->band_6)
                    continue;
            }

            snprintf(conv_chan, 16, "%u", wifi_freq_to_chan(iw_chanlist[ci]));
            (*chanlist)[cp] = strdup(conv_chan);
            cp++;
        }

        free(iw_chanlist);

        *chanlist_sz = mod_chan_sz;
#else
        snprintf(status, STATUS_MAX, "%s %s/%s could not fetch channels over netlink and "
                "was not compiled with WEXT ioctls.  To control this device, try rebuilding "
                "with the legacy WEXT kernel controls enabled in Kismet.",
                local_wifi->name, local_wifi->interface, local_wifi->cap_interface);
        cf_send_message(caph, msg, MSGFLAG_ERROR);
        return -1;

#endif
    } else {
        /* No bands for filtering */
        if (local_wifi->band_any) {
            *chanlist = chanlist_fetch;
            *chanlist_sz = chanlist_fetch_sz;
            return 1;
        }

        /* Otherwise filter */
        mod_chan_sz = 0;

        for (ci = 0; ci < chanlist_fetch_sz; ci++) {
            local_channel_t *lchan = chantranslate_callback(caph, chanlist_fetch[ci]);

            if (lchan->chan_band == wifi_band_2ghz && local_wifi->band_2_4) {
                mod_chan_sz++;
            } else if (lchan->chan_band == wifi_band_5ghz && local_wifi->band_5) {
                mod_chan_sz++;
            } else if (lchan->chan_band == wifi_band_6ghz && local_wifi->band_6) {
                mod_chan_sz++;
            } else {
                free(chanlist_fetch[ci]);
                chanlist_fetch[ci] = NULL;
            }
        }

        *chanlist = (char **) malloc(sizeof(char *) * mod_chan_sz);
        *chanlist_sz = mod_chan_sz;

        cp = 0;
        for (ci = 0; ci < chanlist_fetch_sz; ci++) {
            if (chanlist_fetch[ci] == NULL)
                continue;

            (*chanlist)[cp] = chanlist_fetch[ci];
            cp++;
        }

        free(chanlist_fetch);
    }

    return 1;
}

/* Channel control callback; actually set a channel.  Determines if our
 * custom channel needs a VHT frequency set. */
int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan,
        char *msg) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    int r;
    char errstr[STATUS_MAX];
    char chanstr[STATUS_MAX];

    struct timespec chanset_start_tm;
    long time_diff;

    if (privchan == NULL) {
        return 0;
    }

    chanset_start_tm = ns_measure_timer_start();

    if (!local_wifi->use_mac80211_channels) {
#ifdef HAVE_LINUX_WIRELESS
        r = iwconfig_set_channel(local_wifi->interface,
                channel->control_freq, errstr);
        time_diff = ns_measure_timer_stop(chanset_start_tm);

        if (local_wifi->verbose_statistics) {
            local_wifi->channel_set_ns_avg += time_diff;
            local_wifi->channel_set_ns_count++;

            if (local_wifi->channel_set_ns_count >= 100) {
                snprintf(msg, STATUS_MAX, "%s %s/%s average channel set time: %lunS",
                        local_wifi->name, local_wifi->interface, local_wifi->cap_interface,
                        local_wifi->channel_set_ns_avg / local_wifi->channel_set_ns_count);
                cf_send_message(caph, msg, MSGFLAG_INFO);
                local_wifi->channel_set_ns_avg = 0;
                local_wifi->channel_set_ns_count = 0;
            }
        }

        if (local_wifi->verbose_diagnostics && time_diff > (long) 1e8) {
            local_channel_to_str(channel, chanstr);
            snprintf(msg, STATUS_MAX, "%s %s/%s setting channel %s took longer than 100000uS; this is not "
                    "an error but may indicate kernel or bus contention.",
                    local_wifi->name, local_wifi->interface, local_wifi->cap_interface, chanstr);
            cf_send_message(caph, msg, MSGFLAG_ERROR);
        }

        if (r < 0) {
            /* Sometimes tuning a channel fails; this is only a problem if we fail
             * to tune a channel a bunch of times.  Spit out a tuning error at first;
             * if we continually fail, if we have a seqno we're part of a CONFIGURE
             * command and we send a configresp, otherwise send an error
             *
             * If seqno == 0 we're inside the chanhop, so we can tolerate failures.
             * If we're sending an explicit channel change command, error out
             * immediately.
             *
             * */
            if (local_wifi->seq_channel_failure < 10) {
                /*
                if (seqno == 0 && local_wifi->verbose_diagnostics) {
                    local_channel_to_str(channel, chanstr);
                    snprintf(msg, STATUS_MAX, "%s %s/%s could not set channel %s; ignoring error "
                            "and continuing (%s)",
                            local_wifi->name, local_wifi->interface, local_wifi->cap_interface,
                            chanstr, errstr);
                    cf_send_message(caph, msg, MSGFLAG_ERROR);
                }
                */

                return 0;
            } else {
                local_channel_to_str(channel, chanstr);
                snprintf(msg, STATUS_MAX, "%s %s/%s failed to set channel %s; skipping (%s)",
                                local_wifi->name, local_wifi->interface, local_wifi->cap_interface,
                                chanstr, errstr);

                if (seqno == 0) {
                    cf_send_error(caph, 0, msg);
                }

                return 0;
            }
        } else {
            local_wifi->seq_channel_failure = 0;

            if (seqno != 0) {
                /* Send a config response with a reconstituted channel if we're
                 * configuring the interface; re-use errstr as a buffer */
                local_channel_to_str(channel, errstr);
                cf_send_configresp(caph, seqno, 1, errstr);
            }
        }

        return 1;
#else
        local_channel_to_str(channel, chanstr);
        snprintf(msg, STATUS_MAX, "%s %s/%s failed to set channel %s; skipping (%s)",
                local_wifi->name, local_wifi->interface, local_wifi->cap_interface,
                chanstr, "unable to configure via netlink and Kismet not compiled "
                "with WEXT support");

        if (seqno == 0) {
            cf_send_error(caph, 0, msg);
        }

        return 0;

#endif
    } else {
        /* Otherwise we're using mac80211 which means we need to figure out
         * what kind of channel we're setting */
        /* fprintf(stderr, "debug - %s setting channel %d w %d\n", local_wifi->cap_interface, channel->control_freq, channel->chan_width); */

        if (channel->chan_width != 0) {
            /* An explicit channel width means we need to use _set_freq to set
             * a control freq, a width, and possibly an extended center frequency
             * for VHT; if center1 is 0 _set_frequency will automatically
             * exclude it and only set the width */
            r = mac80211_set_frequency_cache(local_wifi->mac80211_ifidx,
                    local_wifi->mac80211_socket, local_wifi->mac80211_id,
                    channel->control_freq, channel->chan_width,
                    channel->center_freq1, channel->center_freq2, errstr);
        } else {
            /* Otherwise for HT40 and non-HT channels, set the channel w/ any
             * flags present */
            r = mac80211_set_channel_cache(local_wifi->mac80211_ifidx,
                    local_wifi->mac80211_socket, local_wifi->mac80211_id,
                    channel->control_freq, channel->chan_type, errstr);
        }

        time_diff = ns_measure_timer_stop(chanset_start_tm);

        if (r >= 0 && local_wifi->verbose_statistics) {
            int count = 0;

            while (count < 1000) {
                unsigned int control_freq = 0,
                             chan_type = 0,
                             chan_width = 0,
                             center_freq1 = 0,
                             center_freq2 = 0;

                count++;

                mac80211_get_frequency_cache(local_wifi->mac80211_ifidx,
                        local_wifi->mac80211_socket, local_wifi->mac80211_id,
                        &control_freq, &chan_type, &chan_width, &center_freq1, &center_freq2,
                        errstr);

                if (channel->chan_width == 0 && control_freq == channel->control_freq && chan_type == channel->chan_type)
                    break;
                else if (channel->chan_width != 0 && control_freq == channel->control_freq && chan_width == channel->chan_width &&
                        center_freq1 == channel->center_freq1 && center_freq2 == channel->center_freq2)
                    break;
            }

            if (count >= 1000)
                snprintf(msg, STATUS_MAX, "%s %s/%s couldn't confirm channel set in 1000 checks.\n",
                        local_wifi->name, local_wifi->interface, local_wifi->cap_interface);

            time_diff = ns_measure_timer_stop(chanset_start_tm);

            local_wifi->channel_set_ns_avg += time_diff;
            local_wifi->channel_set_ns_count++;

            if (local_wifi->channel_set_ns_count >= 100) {
                snprintf(msg, STATUS_MAX, "%s %s/%s average channel set time: %lunS",
                        local_wifi->name, local_wifi->interface, local_wifi->cap_interface,
                        local_wifi->channel_set_ns_avg / local_wifi->channel_set_ns_count);
                cf_send_message(caph, msg, MSGFLAG_INFO);
                local_wifi->channel_set_ns_avg = 0;
                local_wifi->channel_set_ns_count = 0;
            }
        }


        if (local_wifi->verbose_diagnostics && time_diff > (long) 1e8) {
            local_channel_to_str(channel, chanstr);
            snprintf(msg, STATUS_MAX, "%s %s/%s setting channel %s took longer than 100000uS; this is not "
                    "an error but may indicate kernel or bus contention.",
                    local_wifi->name, local_wifi->interface, local_wifi->cap_interface,
                    chanstr);
            cf_send_message(caph, msg, MSGFLAG_ERROR);
        }

        /* Handle channel set results */
        if (r < 0) {
            /* If seqno == 0 we're inside the chanhop, so we can tolerate failures.
             * If we're sending an explicit channel change command, error out
             * immediately.
             */
            if (local_wifi->seq_channel_failure < 10) {
                if (local_wifi->verbose_diagnostics && seqno == 0) {
                    local_channel_to_str(channel, chanstr);
                    snprintf(msg, STATUS_MAX, "%s %s/%s could not set channel %s; ignoring error "
                            "and continuing (%s)",
                            local_wifi->name, local_wifi->interface, local_wifi->cap_interface,
                            chanstr, errstr);
                    cf_send_message(caph, msg, MSGFLAG_ERROR);
                }

                // Don't actually flag the channel
                return 1;
            } else {
                /* Never evict a channel, just skip */
                local_channel_to_str(channel, chanstr);
                snprintf(msg, STATUS_MAX, "%s %s/%s failed to set channel %s; skipping to next channel (%s)",
                        local_wifi->name, local_wifi->interface, local_wifi->cap_interface,
                        chanstr, errstr);

                if (seqno == 0) {
                    cf_send_error(caph, 0, msg);
                }

                // Don't actually flag the channel
                return 1;
            }
        } else {
            local_wifi->seq_channel_failure = 0;
            return 1;
        }
    }

    return 1;
}


int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    int ret;
    char errstr[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    uint8_t hwaddr[6];
    char driver[32] = "";

    unsigned int default_ht_20 = 0;
    unsigned int expand_ht_20 = 0;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    /* get the mac address; this should be standard for anything */
    if (ifconfig_get_hwaddr(interface, errstr, hwaddr) < 0) {
        free(interface);
        return 0;
    }

    /* get the driver */
    linux_getsysdrv(interface, driver);

    /* if we're hard rfkilled we can't do anything */
    if (linux_sys_get_rfkill(interface, LINUX_RFKILL_TYPE_HARD) == 1) {
        snprintf(msg, STATUS_MAX, "Interface '%s' is set to hard rfkill; check your "
                "wireless switch if you have one.", interface);
        free(interface);
        return -1;
    }

    /* Do we exclude HT or VHT channels?  Equally, do we force them to be turned on? */
    if ((placeholder_len = cf_find_flag(&placeholder, "ht_channels", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->use_ht_channels = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->use_ht_channels = 1;
        }
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "vht_channels", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->use_vht_channels = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->use_vht_channels = 1;
        }
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "default_ht20", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            default_ht_20 = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            default_ht_20 = 1;
        }
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "expand_ht20", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            expand_ht_20 = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            expand_ht_20 = 1;
        }
    }

    ret = populate_chanlist(caph, interface, errstr, default_ht_20, expand_ht_20,
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));

    (*ret_interface)->hardware = strdup(driver);

    free(interface);

    if (ret < 0) {
        return 0;
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name
         * and the mac address of the device */
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
                adler32_csum((unsigned char *) "kismet_cap_linux_wifi",
                    strlen("kismet_cap_linux_wifi")) & 0xFFFFFFFF,
                hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
                hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
        *uuid = strdup(errstr);
    }

    return 1;
}

int build_first_localdev_filter(char **filter) {
    typedef struct macaddr_list {
        uint8_t macaddr[6];
        struct macaddr_list *next;
    } macaddr_list_t;

    macaddr_list_t *macs = NULL;
    size_t num_macs = 0;
    size_t filtered_macs = 0;
    macaddr_list_t *mi = NULL, *mb = NULL;

    int mode;

    size_t filter_len = 0;
    unsigned int need_and = 0;
    size_t fpos = 0;

    DIR *devdir;
    struct dirent *devfile;
    char errstr[STATUS_MAX];

    if ((devdir = opendir("/sys/class/net/")) == NULL) {
        *filter = NULL;
        return 0;
    }

    /* Look at the files in the sys dir and see if they're wi-fi */
    while ((devfile = readdir(devdir)) != NULL) {
        /* Skip interfaces which are down */
        if (ifconfig_get_flags(devfile->d_name, errstr, &mode) < 0)
            continue;

        if ((mode & IFF_UP) == 0 && (mode & IFF_RUNNING) == 0)
            continue;

        mi = (macaddr_list_t *) malloc(sizeof(macaddr_list_t));

        if (ifconfig_get_hwaddr(devfile->d_name, errstr, mi->macaddr) < 0) {
            free(mi);
            continue;
        }

        /* Skip interfaces with a 0 mac */
        if (memcmp(mi->macaddr, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
            free(mi);
            continue;
        }

        mi->next = macs;
        macs = mi;

        num_macs++;
    }

    closedir(devdir);

    if (num_macs == 0) {
        *filter = NULL;
        return 0;
    }

    /*
       For now write the filter as a string and compile it
       'not ether host aa:bb:cc:dd:ee:ff'
       32 bytes per mac
       ' and '
       6 bytes per join
    */

    filter_len = (num_macs * 32) + ((num_macs - 1) * 6) + 1;

    *filter = (char *) malloc(filter_len);

    mi = macs;

    while (mi != NULL) {
        if (filtered_macs < 8) {
            filtered_macs++;

            if (need_and) {
                snprintf(*filter + fpos, filter_len - fpos, " and ");
                fpos += 5;
            }
            need_and = 1;

            snprintf(*filter + fpos, filter_len - fpos,
                    "not ether host %02x:%02x:%02x:%02x:%02x:%02x",
                    mi->macaddr[0], mi->macaddr[1], mi->macaddr[2],
                    mi->macaddr[3], mi->macaddr[4], mi->macaddr[5]);
            fpos += 32;
        }

        mb = mi->next;
        free(mi);
        mi = mb;
    }

    return num_macs;
}

int build_named_filters(char **interfaces, int num_interfaces, char **filter) {
    typedef struct macaddr_list {
        uint8_t macaddr[6];
        struct macaddr_list *next;
    } macaddr_list_t;

    macaddr_list_t *macs = NULL;
    size_t num_macs = 0;
    size_t filtered_macs = 0;
    macaddr_list_t *mi = NULL, *mb = NULL;

    size_t filter_len = 0;
    unsigned int need_and = 0;
    size_t fpos = 0;

    char errstr[STATUS_MAX];

    if (num_interfaces <= 0)
        return num_interfaces;

    int i_pos;

    for (i_pos = 0; i_pos < num_interfaces; i_pos++) {
        if (interfaces[i_pos] == NULL)
            continue;

        mi = (macaddr_list_t *) malloc(sizeof(macaddr_list_t));

        if (ifconfig_get_hwaddr(interfaces[i_pos], errstr, mi->macaddr) < 0) {
            free(mi);
            continue;
        }

        /* Skip interfaces with a 0 mac */
        if (memcmp(mi->macaddr, "\x00\x00\x00\x00\x00\x00", 6) == 0) {
            free(mi);
            continue;
        }

        mi->next = macs;
        macs = mi;

        num_macs++;
    }

    if (num_macs == 0) {
        *filter = NULL;
        return 0;
    }

    /*
       For now write the filter as a string and compile it
       'not ether host aa:bb:cc:dd:ee:ff'
       32 bytes per mac
       ' and '
       6 bytes per join
    */

    filter_len = (num_macs * 32) + ((num_macs - 1) * 6) + 1;

    *filter = (char *) malloc(filter_len);

    mi = macs;

    while (mi != NULL) {
        if (filtered_macs < 8) {
            filtered_macs++;

            if (need_and) {
                snprintf(*filter + fpos, filter_len - fpos, " and ");
                fpos += 5;
            }
            need_and = 1;

            snprintf(*filter + fpos, filter_len - fpos,
                    "not ether host %02x:%02x:%02x:%02x:%02x:%02x",
                    mi->macaddr[0], mi->macaddr[1], mi->macaddr[2],
                    mi->macaddr[3], mi->macaddr[4], mi->macaddr[5]);
            fpos += 32;
        }

        mb = mi->next;
        free(mi);
        mi = mb;
    }

    return num_macs;
}

int build_explicit_filters(char **stringmacs, int num_macs, char **filter) {
    size_t filter_len = 0;
    unsigned int need_and = 0;
    size_t fpos = 0;

    if (num_macs <= 0)
        return num_macs;

    int i_pos;
    int filtered_macs = 0;

    if (num_macs == 0) {
        *filter = NULL;
        return 0;
    }

    unsigned int mac_seg;

    /*
       For now write the filter as a string and compile it
       'not ether host aa:bb:cc:dd:ee:ff'
       32 bytes per mac
       ' and '
       6 bytes per join
    */

    filter_len = (num_macs * 32) + ((num_macs - 1) * 6) + 1;

    *filter = (char *) malloc(filter_len);

    for (i_pos = 0; i_pos < num_macs; i_pos++) {
        if (stringmacs[i_pos] == NULL)
            continue;

        if (sscanf(stringmacs[i_pos], "%02X:%02X:%02X:%02X:%02X:%02X",
                    &mac_seg, &mac_seg, &mac_seg,
                    &mac_seg, &mac_seg, &mac_seg) != 6)
            continue;

        if (filtered_macs < 8) {
            filtered_macs++;

            if (need_and) {
                snprintf(*filter + fpos, filter_len - fpos, " and ");
                fpos += 5;
            }
            need_and = 1;

            snprintf(*filter + fpos, filter_len - fpos,
                    "not ether host %17s", stringmacs[i_pos]);
            fpos += 32;
        }

    }

    return num_macs;
}


int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    /* Try to open an interface for monitoring
     *
     * - Confirm it's an interface, and that it's wireless, by doing a basic
     *   siocgiwchan channel fetch to see if wireless icotls work on it
     * - Get the current mode - is it already in monitor mode?  If so, we're done
     *   and the world is good
     * - Check and warn about reg domain
     * - Check for rfkill
     * - It's not in monitor mode.  Try to make a VIF via mac80211 for it; this is
     *   by far the most likely to succeed on modern systems.
     * - Figure out if we can name the vif something sane under new interface
     *   naming rules; preferably interfaceXmon
     * - Extract channels
     * - Generate UUID
     * - Initiate pcap
     */

    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;

    char *placeholder = NULL;
    int placeholder_len;

    uint8_t hwaddr[6];

    char errstr[STATUS_MAX];
    char errstr2[STATUS_MAX];
    char pcap_errstr[PCAP_ERRBUF_SIZE] = "";

    char ifnam[IFNAMSIZ];

    unsigned int default_ht_20 = 0;
    unsigned int expand_ht_20 = 0;

    *uuid = NULL;
    *dlt = 0;

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    unsigned int mode = 0;

    int ret;

    /* char regdom[5]; */

    char driver[32] = "";

    char *localchanstr = NULL;
    local_channel_t *localchan = NULL;

    int filter_locals = 0;
    char *ignore_filter = NULL;
    struct bpf_program bpf;

    int i;

#ifdef HAVE_LIBNM
    NMClient *nmclient = NULL;
    NMDevice *nmdevice = NULL;
    const GPtrArray *nmdevices;
    GError *nmerror = NULL;
#endif

    int num_filter_interfaces = 0;
    int num_filter_addresses = 0;
    char **filter_targets = NULL;

    unsigned int mac_seg;

    /* Clean up any existing local state on open; we can get re-opened if we're a
     * remote source */
    if (local_wifi->interface) {
        free(local_wifi->interface);
        local_wifi->interface = NULL;
    }

    if (local_wifi->cap_interface) {
        free(local_wifi->cap_interface);
        local_wifi->cap_interface = NULL;
    }

    if (local_wifi->base_phy) {
        free(local_wifi->base_phy);
        local_wifi->base_phy = NULL;
    }

    if (local_wifi->name) {
        free(local_wifi->name);
        local_wifi->name = NULL;
    }

    if (local_wifi->mac80211_socket) {
        mac80211_disconnect(local_wifi->mac80211_socket);
        local_wifi->mac80211_socket = NULL;
    }

    if (local_wifi->pd != NULL) {
        pcap_close(local_wifi->pd);
        local_wifi->pd = NULL;
    }

    /* Start processing the open */

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition");
        return -1;
    }

    local_wifi->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len =
                cf_find_flag(&placeholder, "name", definition)) > 0) {
        local_wifi->name = strndup(placeholder, placeholder_len);
    } else {
        local_wifi->name = strdup(local_wifi->interface);
    }

    /* Do we use verbose diagnostics? */
    if ((placeholder_len =
                cf_find_flag(&placeholder, "verbose", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->verbose_diagnostics = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->verbose_diagnostics = 1;
        }
    }

    /* Do we use extremely verbose statistics? */
    if ((placeholder_len =
                cf_find_flag(&placeholder, "statistics", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->verbose_statistics = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->verbose_statistics = 1;
        }
    }

    /* Do we filter packets for wardrive mode to mgmt only? */
    if ((placeholder_len =
                cf_find_flag(&placeholder, "filter_mgmt", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->wardrive_filter = false;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->wardrive_filter = true;
        }
    }

    /* Do we truncate all data? */
    if ((placeholder_len =
                cf_find_flag(&placeholder, "truncate_data", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->data_filter = false;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->data_filter = true;
        }
    }


    /* Do we ignore any other interfaces on this device? */
    if ((placeholder_len =
                cf_find_flag(&placeholder, "filter_locals", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            filter_locals = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            filter_locals = 1;
        }
    }

    if (filter_locals && (local_wifi->wardrive_filter || local_wifi->data_filter)) {
        snprintf(msg, STATUS_MAX, "Can not combine 'filter_mgmt', 'truncate_data', and "
                 "'filter_locals' or 'filter_interface' "
                 "please pick just one option.");
        return -1;
    }

    if ((num_filter_interfaces =
                cf_count_flag("filter_interface", definition)) > 0) {
        if (filter_locals) {
            snprintf(msg, STATUS_MAX, "Can not combine 'filter_locals' and 'filter_interface' "
                    "please pick one or the other.");
            return -1;
        }

        if (local_wifi->wardrive_filter || local_wifi->data_filter) {
            snprintf(msg, STATUS_MAX, "Can not combine 'filter_mgmt' or 'truncate_data' and 'filter_locals' or 'filter_interface' "
                     "please pick just one option.");
            return -1;
        }

        filter_targets = (char **) malloc(sizeof(char *) * num_filter_interfaces);

        for (i = 0; i < num_filter_interfaces; i++)
            filter_targets[i] = NULL;

        placeholder = definition;
        for (i = 0; i < num_filter_interfaces; i++) {
            if ((placeholder_len =
                        cf_find_flag(&placeholder, "filter_interface", placeholder)) <= 0) {
                snprintf(msg, STATUS_MAX, "Could not parse filter_interface from definition: "
                        "expected an interface.");

                for (i = 0; i < num_filter_interfaces; i++) {
                    if (filter_targets[i] != NULL) {
                        free(filter_targets[i]);
                    }
                }

                free(filter_targets);
                return -1;
            }

            filter_targets[i] = strndup(placeholder, placeholder_len);
        }
    }

    if ((num_filter_addresses =
                cf_count_flag("filter_address", definition)) > 0) {
        if (filter_locals) {
            snprintf(msg, STATUS_MAX, "Can not combine 'filter_locals' and 'filter_address' "
                    "please pick one or the other.");
            return -1;
        }

        if (num_filter_interfaces) {
            snprintf(msg, STATUS_MAX, "Can not combine 'filter_interface' and 'filter_address' "
                    "please pick one or the other.");
            return -1;
        }

        filter_targets = (char **) malloc(sizeof(char *) * num_filter_addresses);

        for (i = 0; i < num_filter_addresses; i++)
            filter_targets[i] = NULL;

        placeholder = definition;
        for (i = 0; i < num_filter_addresses; i++) {
            if ((placeholder_len =
                        cf_find_flag(&placeholder, "filter_address", placeholder)) <= 0) {
                snprintf(msg, STATUS_MAX, "Could not parse filter_address from definition: "
                        "expected an interface.");

                for (i = 0; i < num_filter_interfaces; i++) {
                    if (filter_targets[i] != NULL) {
                        free(filter_targets[i]);
                    }
                }

                free(filter_targets);
                return -1;
            }

            if (sscanf(placeholder, "%02X:%02X:%02X:%02X:%02X:%02X",
                        &mac_seg, &mac_seg, &mac_seg,
                        &mac_seg, &mac_seg, &mac_seg) != 6) {

                snprintf(msg, STATUS_MAX, "Could not parse MAC address from definition: "
                        "Expected MAC address of format AA:BB:CC:DD:EE:FF.");

                for (i = 0; i < num_filter_interfaces; i++) {
                    if (filter_targets[i] != NULL) {
                        free(filter_targets[i]);
                    }
                }

                free(filter_targets);
                return -1;
            }

            filter_targets[i] = strndup(placeholder, placeholder_len);
        }
    }

    /* Process the bands enabled on this device; if any band is set, the override
     * for 'any' is cleared and only that band is picked. */

    unsigned int band_mask = 0;
    if ((placeholder_len =
                cf_find_flag(&placeholder, "band24ghz", definition)) > 0) {
        if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            band_mask |= (1 << 0);
            band_mask |= (1 << 1);
        }
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "band5ghz", definition)) > 0) {
        if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            band_mask |= (1 << 0);
            band_mask |= (1 << 2);
        }
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "band6ghz", definition)) > 0) {
        if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            band_mask |= (1 << 0);
            band_mask |= (1 << 3);
        }
    }

    if (band_mask == (1 << 0)) {
        snprintf(errstr, STATUS_MAX, "%s has no enabled bands; defaulting to normal behavior and enabling all bands.",
                local_wifi->interface);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        band_mask = 0;
    }

    if (band_mask != 0) {
        if (band_mask == 0xF) {
            local_wifi->band_any = true;
            local_wifi->band_2_4 = true;
            local_wifi->band_5 = true;
            local_wifi->band_6 = true;
        } else {
            local_wifi->band_any = false;

            if (band_mask & (1 << 1))
                local_wifi->band_2_4 = true;
            else
                local_wifi->band_2_4 = false;

            if (band_mask & (1 << 2))
                local_wifi->band_5 = true;
            else
                local_wifi->band_5 = false;

            if (band_mask & (1 << 3))
                local_wifi->band_6 = true;
            else
                local_wifi->band_6 = false;
        }
    }

    /* Acquire the lock fd */
    if ((ret = acquire_interface_lock(local_wifi)) != 0) {
        snprintf(msg, STATUS_MAX, "Could not acquire the interface lockfile (%s), check the Kismet linuxwifi documentation for more information.", strerror(ret));
        return -1;
    }

    /* get the mac address; this should be standard for anything */
    if (ifconfig_get_hwaddr(local_wifi->interface, errstr, hwaddr) < 0) {
        snprintf(msg, STATUS_MAX, "Could not fetch interface address from '%s': %s",
                local_wifi->interface, errstr);
        return -1;
    }

    /* Get the index of the base name */
    if ((local_wifi->mac80211_ifidx = if_nametoindex(local_wifi->interface)) < 0) {
        snprintf(errstr, STATUS_MAX, "Could not find interface index for '%s'", local_wifi->interface);
        return -1;
    }

    /* get the driver */
    linux_getsysdrv(local_wifi->interface, driver);

    /* if we're hard rfkilled we can't do anything */
    if (linux_sys_get_rfkill(local_wifi->interface, LINUX_RFKILL_TYPE_HARD) == 1) {
        snprintf(msg, STATUS_MAX, "Interface '%s' is set to hard rfkill; check your "
                "wireless switch if you have one.", local_wifi->interface);
        return -1;
    }

    /* if we're soft rfkilled, unkill us */
    if (linux_sys_get_rfkill(local_wifi->interface, LINUX_RFKILL_TYPE_SOFT) == 1) {
        if (linux_sys_clear_rfkill(local_wifi->interface) < 0) {
            snprintf(msg, STATUS_MAX, "%s unable to activate interface '%s' set to "
                    "soft rfkill",
                    local_wifi->name, local_wifi->interface);
            return -1;
        }
        snprintf(errstr, STATUS_MAX, "%s removed soft-rfkill and enabled interface '%s'",
                local_wifi->name, local_wifi->interface);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name
     * and the mac address of the device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
                adler32_csum((unsigned char *) "kismet_cap_linux_wifi",
                    strlen("kismet_cap_linux_wifi")) & 0xFFFFFFFF,
                hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
                hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
        *uuid = strdup(errstr);
    }

    /* Look up the driver and set any special attributes */
    if (strcmp(driver, "8812au") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the 8812au driver, "
                "which has problems using mac80211 VIF mode.  Disabling mac80211 VIF "
                "creation but retaining mac80211 channel controls.",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);

        local_wifi->use_mac80211_vif = 0;
    } else if (strcmp(driver, "8814au") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the 8814au driver, "
                "which has problems using mac80211 VIF mode.  Disabling mac80211 VIF "
                "creation but retaining mac80211 channel controls.",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);

        local_wifi->use_mac80211_vif = 0;
    } else if (strcasecmp(driver, "rtl88XXau") == 0) {
        /* This driver changes its name all the time; sometimes its 88xxau sometimes it's 88XXau,
         * but both appear to handle iw dev set mode netlink. */
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the rtl88xxau driver, "
                "which can not mac80211 VIF mode.  Disabling mac80211 VIF "
                "creation but retaining mac80211 channel controls.  Beware, this driver is known "
                "to have issues with packet capture.",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);
        local_wifi->use_mac80211_vif = 0;
        local_wifi->use_mac80211_mode = 1;
    } else if (strcasecmp(driver, "88XXau") == 0) {
        /* This driver changes its name all the time; sometimes its 88xxau sometimes it's 88XXau,
         * but both appear to handle iw dev set mode netlink. */
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the rtl88xxau driver, "
                "which can not mac80211 VIF mode.  Disabling mac80211 VIF "
                "creation but retaining mac80211 channel controls.  Beware, this driver is known "
                "to have issues with packet capture.",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);
        local_wifi->use_mac80211_vif = 0;
        local_wifi->use_mac80211_mode = 1;
    } else if (strcmp(driver, "rtl8812au") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the rtl8812au driver, "
                "these drivers have been very unreliable and typically will not properly "
                "configure monitor mode.  We'll continue to try, but expect an error "
                "when configuring monitor mode in the next step.  You may have better "
                "luck with the drivers from https://github.com/aircrack-ng/rtl8812au",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);

        local_wifi->use_mac80211_vif = 0;
    } else if (strcmp(driver, "rtl8814au") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the rtl8814au driver, "
                "these drivers have been very unreliable and typically will not properly "
                "configure monitor mode.  We'll continue to try, but expect an error "
                "when configuring monitor mode in the next step.  You may have better "
                "luck with the drivers from https://github.com/aircrack-ng/rtl8812au",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);

        local_wifi->use_mac80211_vif = 0;
    } else if (strcmp(driver, "rtl88x2bu") == 0) {
#ifdef HAVE_LINUX_WIRELESS
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the rtl88x2bu driver, "
                "these drivers may have reliability problems, and do not work with VIFs.  "
                "We'll continue, but there may be errors.",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);
        local_wifi->use_mac80211_vif = 0;
        local_wifi->use_mac80211_channels = 0;
        local_wifi->up_before_mode = true;
#else
        snprintf(msg, STATUS_MAX, "Interface '%s' requires WEXT controls, but Kismet "
                "was compiled without WEXT support.", local_wifi->interface);
        return -1;
#endif
    } else if (strcmp(driver, "ath10k_pci") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the ath10k_pci "
                "driver, which is known to report large numbers of invalid packets. "
                "Kismet will attempt to filter these but it is not possible to "
                "cleanly filter all of them; you may see large quantities of spurious "
                "networks.",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);
    } else if (strcmp(driver, "brcmfmac") == 0 ||
            strcmp(driver, "brcmfmac_sdio") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks like it is a Broadcom "
                "binary driver found in the Raspberry Pi and some Android devices; "
                "this will ONLY work with the nexmon patches",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);
#if 0
    } else if (strcmp(driver, "iwlwifi") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks like an Intel iwlwifi device; under "
                "some driver and firmware versions these have shown significant problems tuning to "
                "HT and VHT channels, with firmware and driver crashes.  Newer kernels seem to solve "
                "this problem; if you're on an older version, set htchannels=false,vhtchannels=false "
                "in your source definition.", local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);
#endif
    }

    /* Try to connect to mac80211 and get the mode */
    local_wifi->mac80211_socket = NULL;

    if (mac80211_connect(&(local_wifi->mac80211_socket), &(local_wifi->mac80211_id), errstr) < 0) {
#ifdef HAVE_LINUX_WIRELESS
        /* If we didn't get a mac80211 handle we can't use mac80211, period, fall back
         * to trying to use the legacy ioctls */
        snprintf(errstr, STATUS_MAX, "%s interface '%s' falling back to legacy WEXT ioctl controls, "
                "this is unlikely to work on modern kernels or hardware", local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);

        local_wifi->mac80211_socket = NULL;
        local_wifi->use_mac80211_vif = 0;
        local_wifi->use_mac80211_channels = 0;
#else
        snprintf(msg, STATUS_MAX, "Interface '%s' requires WEXT controls, but Kismet "
                "was compiled without WEXT support.", local_wifi->interface);
        return -1;
#endif
    }

    /* Try to figure out the current mode from netlink if possible; if not, use iwconfig, and
     * then fail */
    ret = -1;

    mode = 0;

    if (local_wifi->mac80211_socket != NULL) {
        uint32_t nl_mode = 0;

        ret = mac80211_get_iftype_cache(local_wifi->mac80211_ifidx, local_wifi->mac80211_socket,
                local_wifi->mac80211_id, &nl_mode, errstr);

        if (ret > 0 && nl_mode == 0) {
            fprintf(stderr, "debug - netlink iftype success, but mode 0, soft failing\n");
            ret = -1;
        }

        /* Alias the netlink mode to the legacy mode */
        if (nl_mode == NL80211_IFTYPE_MONITOR) {
            mode = LINUX_WLEXT_MONITOR;
        }
    }

    /* failed at mac80211 because we don't have it or it didn't work */

    if (ret < 0) {
#ifdef HAVE_LINUX_WIRELESS
        if (iwconfig_get_mode(local_wifi->interface, errstr, &mode) < 0) {
            snprintf(msg, STATUS_MAX, "%s unable to get current wireless mode of "
                    "interface '%s': %s", local_wifi->name, local_wifi->interface, errstr);
            return -1;
        }
#else
        snprintf(msg, STATUS_MAX, "%s unable to get current wireless mode of "
                "interface '%s': %s", local_wifi->name, local_wifi->interface,
                "Interface did not respond to netlink, and Kismet compiled without "
                "WEXT support");
        return -1;
#endif
    }

    /* We think we can do something with this interface; if we have support,
     * connect to network manager.  Because it looks like nm keeps trying
     * to deliver reports to us as long as we're connected, DISCONNECT
     * when we're done! */
#ifdef HAVE_LIBNM
    nmclient = nm_client_new(NULL, &nmerror);

    if (nmclient == NULL) {
        if (nmerror != NULL) {
            snprintf(errstr, STATUS_MAX, "%s could not connect to NetworkManager, "
                    "cannot automatically prevent interface '%s' from being "
                    "modified if NetworkManager is running: %s",
                    local_wifi->name, local_wifi->interface, nmerror->message);
        } else {
            snprintf(errstr, STATUS_MAX, "%s could not connect to NetworkManager, "
                    "cannot automatically prevent interface '%s' from being "
                    "modified if NetworkManager is running.",
                    local_wifi->name, local_wifi->interface);
        }

        cf_send_message(caph, errstr, MSGFLAG_INFO);
    } else if (nm_client_get_nm_running(nmclient)) {
        nmdevices = nm_client_get_devices(nmclient);

        if (nmdevices != NULL) {
            for (i = 0; i < nmdevices->len; i++) {
                const NMDevice *d = g_ptr_array_index(nmdevices, i);

                if (strcmp(nm_device_get_iface((NMDevice *) d),
                            local_wifi->interface) == 0) {
                    nmdevice = (NMDevice *) d;
                    break;
                }
            }
        }
    }

    if (nmdevice != NULL) {
        local_wifi->reset_nm_management = nm_device_get_managed(nmdevice);

        if (local_wifi->reset_nm_management) {
            snprintf(errstr, STATUS_MAX, "%s telling NetworkManager not to control "
                    "interface '%s': you may need to re-initialize this interface "
                    "later or tell NetworkManager to control it again via 'nmcli'",
                    local_wifi->name, local_wifi->interface);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
            nm_device_set_managed(nmdevice, 0);
        }
    }

    /* We MUST make sure to release the networkmanager object later or we'll leak
     * memory continually as NM queues events for us */
#endif

    /* We got the mode earlier, and now we've told nm to ignore it - now, look at the mode, and
     * figure out what to do.
     *
     * If we're already in monitor, we don't need to make a vif or change mode.
     * If we're not in monitor and we're vif capable, we need to find an existing vif or make one
     * If we're not in monitor and we're legacy, we need to set iwmode
     */

    /* *********
     * Begin semaphore protected area
     * All returns or exits from this code must unlock the interface semaphore!
     * ********** */

    /* If we have a semaphore, acquire a lock; we need to be the only ones manipulating
     * interface names.  Linux can't handle two processes making vifs simultaneously
     * gracefully. */
    if ((ret = try_flock(local_wifi, 5)) != 0) {
        snprintf(msg, STATUS_MAX, "%s unable to acquire exclusive control of interface '%s' within 5"
                "seconds (%s), something is wrong, check the Kismet linuxwifi documentation.",
                local_wifi->name, local_wifi->interface, strerror(ret));
        return -1;
    }

    if (mode != LINUX_WLEXT_MONITOR) {
        unsigned int existing_ifnum;

        /* If we don't use vifs at all... */
        if (local_wifi->use_mac80211_vif == 0) {
            local_wifi->cap_interface = strdup(local_wifi->interface);
        } else {
            /* Look to see if there's a vif= flag specified on the source line; this
             * takes precedence over everything */
            if ((placeholder_len = cf_find_flag(&placeholder, "vif", definition)) > 0) {
                local_wifi->cap_interface = strndup(placeholder, placeholder_len);
                local_wifi->base_phy = mac80211_find_parent(local_wifi->cap_interface);
            } else {
                /* Look for an existing monitor mode interface on the base interface */
                existing_ifnum =
                    find_interface_monitor_by_parent(local_wifi, local_wifi->interface);

                if (existing_ifnum > 0) {
                    if (if_indextoname(existing_ifnum, ifnam) != NULL) {
                        local_wifi->cap_interface = strdup(ifnam);
                        local_wifi->base_phy = mac80211_find_parent(local_wifi->cap_interface);
                        snprintf(errstr, STATUS_MAX, "%s found existing monitor interface "
                                "'%s' for source interface '%s'",
                                local_wifi->name, local_wifi->cap_interface, local_wifi->interface);
                        cf_send_message(caph, errstr, MSGFLAG_INFO);
                    }
                }
            }
        }

        /* Otherwise we need to make a monitor interface.  Try to come up with the name. */
        if (local_wifi->cap_interface == NULL) {
            int ifnum;

            /* First we'd like to make a monitor vif if we can; can we fit that
             * in our interface name?  */
            if (strlen(local_wifi->interface) + 3 >= IFNAMSIZ) {
                /* Can't fit our name in, we have to make an unrelated name,
                 * we'll call it 'kismonX'; find the next kismonX interface */
                ifnum = find_next_ifnum("kismon");

                if (ifnum < 0) {
                    release_flock(local_wifi);

                    snprintf(msg, STATUS_MAX, "%s could not append 'mon' extension to "
                            "existing interface (%s) and could not find a kismonX "
                            "within 100 tries", local_wifi->name, local_wifi->interface);
                    return -1;
                }

                /* We know we're ok here; we got this by figuring out nothing
                 * matched and then enumerating our own */
                snprintf(ifnam, IFNAMSIZ, "kismon%d", ifnum);
            } else {
                snprintf(ifnam, IFNAMSIZ, "%smon", local_wifi->interface);
            }

            /* Dup our monitor interface name */
            local_wifi->cap_interface = strdup(ifnam);
            /* Grab our phy name */
            local_wifi->base_phy = mac80211_find_parent(ifnam);
        }
    } else {
        /* We're already monitor; dup the interface */
        local_wifi->cap_interface = strdup(local_wifi->interface);
        /* And try to grab the mac80211 phy */
        local_wifi->base_phy = mac80211_find_parent(local_wifi->interface);
    }

    /* We know what we're going to capture from now - either it exists already, or we need
     * to make it.  See if it exists and fetch the mode.  If it DOES exist (has a netif index)
     * but we can't get the mode, fail! */

    mode = 0;

    local_wifi->mac80211_ifidx = if_nametoindex(local_wifi->cap_interface);
    if (local_wifi->mac80211_ifidx > 0) {
        ret = -1;
        if (local_wifi->mac80211_socket != NULL) {
            uint32_t nl_mode = 0;

            ret = mac80211_get_iftype_cache(local_wifi->mac80211_ifidx, local_wifi->mac80211_socket,
                    local_wifi->mac80211_id, &nl_mode, errstr);

            if (ret > 0 && nl_mode == 0)
                ret = -1;

            /* Alias the netlink mode to the legacy mode */
            if (nl_mode == NL80211_IFTYPE_MONITOR)
                mode = LINUX_WLEXT_MONITOR;
        }

        if (ret < 0) {
#ifdef HAVE_LINUX_WIRELESS
            if (iwconfig_get_mode(local_wifi->interface, errstr, &mode) < 0) {
                release_flock(local_wifi);

                snprintf(msg, STATUS_MAX, "%s unable to get current wireless mode of "
                        "interface '%s': %s", local_wifi->name, local_wifi->interface, errstr);
                return -1;
            }
#else
            snprintf(msg, STATUS_MAX, "%s unable to get current wireless mode of "
                    "interface '%s': %s", local_wifi->name, local_wifi->interface,
                    "Interface did not respond to netlink, and Kismet compiled without "
                    "WEXT support");
            return -1;
#endif
        }
    }

    /* The interface we want to use isn't in monitor mode - and presumably
     * doesn't exist - so try to make a monitor vif via mac80211; this will
     * work with all modern drivers and we'd definitely rather do this.
     */
    if (mode != LINUX_WLEXT_MONITOR && local_wifi->use_mac80211_vif &&
            strcmp(local_wifi->interface, local_wifi->cap_interface) != 0) {
        /* First, look for some nl80211 flags in the arguments. */
        unsigned int num_flags = 0;
        unsigned int fi;
        unsigned int *flags = NULL;

        bool fcs = false;
        bool plcp = false;

        if ((placeholder_len = cf_find_flag(&placeholder, "fcsfail", definition)) > 0) {
            if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
                snprintf(errstr, STATUS_MAX,
                        "%s source '%s' configuring monitor interface to pass packets "
                        "which fail FCS checksum",
                        local_wifi->name, local_wifi->interface);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                num_flags++;
                fcs = true;
            }
        }

        if ((placeholder_len = cf_find_flag(&placeholder, "plcpfail",
                        definition)) > 0) {
            if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
                snprintf(errstr, STATUS_MAX,
                        "%s source '%s' configuring monitor interface to pass packets "
                        "which fail PLCP checksum", local_wifi->name, local_wifi->interface);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                num_flags++;
                plcp = true;
            }
        }

        /* Allocate the flag list */
        flags = (unsigned int *) malloc(sizeof(unsigned int) * num_flags);

        fi = 0;

        if (fcs)
            flags[fi++] = NL80211_MNTR_FLAG_FCSFAIL;

        if (plcp)
            flags[fi++] = NL80211_MNTR_FLAG_PLCPFAIL;

        /* Try to make the monitor vif */
        if (mac80211_create_monitor_vif(local_wifi->interface, local_wifi->cap_interface, flags,
                    num_flags, errstr) < 0) {

            /* Send an error message */
            snprintf(errstr2, STATUS_MAX, "%s failed to create monitor vif interface '%s' "
                    "for interface '%s': %s",
                    local_wifi->name, local_wifi->cap_interface,
                    local_wifi->interface, errstr);
            cf_send_message(caph, errstr2, MSGFLAG_ERROR);

            /* Forget the cap_iface and set it to the standard iface for the rest of our
             * attempts */
            if (local_wifi->cap_interface != NULL) {
                free(local_wifi->cap_interface);
                local_wifi->cap_interface = strdup(local_wifi->interface);
            }

            /* Try to switch the mode of this interface to monitor; maybe we're a
             * wlext or nexmon device after all.  Do we look like nexmon? */
            if (strcmp(driver, "brcmfmac") == 0 || strcmp(driver, "brcmfmac_sdio") == 0) {
                local_wifi->use_mac80211_vif = 0;

                local_wifi->nexmon = init_nexmon(local_wifi->interface);

                if (local_wifi->nexmon == NULL) {
                    release_flock(local_wifi);

                    snprintf(msg, STATUS_MAX, "%s interface '%s' looks like a Broadcom "
                            "embedded device but could not be initialized:  You MUST install "
                            "the nexmon patched drivers to use this device with Kismet",
                            local_wifi->name, local_wifi->interface);
                    return -1;
                }

                /* Nexmon needs the interface UP to place it into monitor mode properly.  Weird! */
                if (ifconfig_interface_up(local_wifi->cap_interface, errstr) != 0) {
                    release_flock(local_wifi);

                    snprintf(msg, STATUS_MAX, "%s could not bring up capture interface '%s', "
                            "check 'dmesg' for possible errors while loading firmware: %s",
                            local_wifi->name, local_wifi->cap_interface, errstr);
                    return -1;
                }

                if (nexmon_monitor(local_wifi->nexmon) < 0) {
                    release_flock(local_wifi);

                    snprintf(msg, STATUS_MAX, "%s could not place interface '%s' into monitor mode "
                            "via nexmon drivers; you MUST install the patched nexmon drivers to "
                            "use embedded broadcom interfaces with Kismet", local_wifi->name, local_wifi->interface);
                    return -1;
                }

            } else {
#ifdef HAVE_LINUX_WIRELESS
                /* Otherwise do we look like wext? */
                if (local_wifi->up_before_mode) {
                    if (ifconfig_interface_up(local_wifi->interface, errstr) != 0) {
                        release_flock(local_wifi);

                        snprintf(msg, STATUS_MAX, "%s could not bring up interface "
                                "'%s' to set monitor mode: %s",
                                local_wifi->name, local_wifi->interface, errstr);
                        free(flags);
                        return -1;
                    }
                } else {
                    if (ifconfig_interface_down(local_wifi->interface, errstr) != 0) {
                        release_flock(local_wifi);

                        snprintf(msg, STATUS_MAX, "%s could not bring down interface "
                                "'%s' to set monitor mode: %s",
                                local_wifi->name, local_wifi->interface, errstr);
                        free(flags);
                        return -1;
                    }
                }

                if (iwconfig_set_mode(local_wifi->interface, errstr,
                            LINUX_WLEXT_MONITOR) < 0) {
                    release_flock(local_wifi);

                    snprintf(errstr2, STATUS_MAX, "%s failed to put interface '%s' in monitor mode: %s",
                            local_wifi->name, local_wifi->interface, errstr);
                    cf_send_message(caph, errstr2, MSGFLAG_ERROR);

                    /* We've failed at everything */
                    snprintf(msg, STATUS_MAX, "%s failed to create a monitor vif and could "
                            "not set mode of existing interface, unable to put "
                            "'%s' into monitor mode.", local_wifi->name, local_wifi->interface);

                    free(flags);

                    return -1;
                } else {
                    snprintf(errstr2, STATUS_MAX, "%s configured '%s' as monitor mode "
                            "interface instead of using a monitor vif; will continue using "
                            "this interface as the capture source.",
                            local_wifi->name, local_wifi->interface);
                    cf_send_message(caph, errstr2, MSGFLAG_INFO);

                    local_wifi->use_mac80211_vif = 0;
                }
#else
            release_flock(local_wifi);
            snprintf(msg, STATUS_MAX, "%s (%s) could mot set mode via netlink, and Kismet "
                    "was not compiled with WEXT support.",
                    local_wifi->name, local_wifi->interface);
            free(flags);
            return -1;

#endif
            }
        } else {
            snprintf(errstr2, STATUS_MAX, "%s successfully created monitor interface "
                    "'%s' for interface '%s'", local_wifi->name, local_wifi->cap_interface,
                    local_wifi->interface);
        }

        free(flags);
    } else if (mode != LINUX_WLEXT_MONITOR) {
        /* Otherwise we want monitor mode but we don't have nl / found the same vif */
        if (local_wifi->up_before_mode) {
            if (ifconfig_interface_up(local_wifi->interface, errstr) != 0) {
                release_flock(local_wifi);

                snprintf(msg, STATUS_MAX, "%s could not bring up interface "
                        "'%s' to set monitor mode: %s",
                        local_wifi->name, local_wifi->interface, errstr);
                return -1;
            }
        } else {
            if (ifconfig_interface_down(local_wifi->interface, errstr) != 0) {
                release_flock(local_wifi);

                snprintf(msg, STATUS_MAX, "%s could not bring down interface "
                        "'%s' to set monitor mode: %s",
                        local_wifi->name, local_wifi->interface, errstr);
                return -1;
            }
        }

        if (strcmp(driver, "brcmfmac") == 0 || strcmp(driver, "brcmfmac_sdio") == 0) {
            /* Do we look like a nexmon brcm that is too old to handle vifs? */
            local_wifi->use_mac80211_vif = 0;

            local_wifi->nexmon = init_nexmon(local_wifi->interface);

            if (local_wifi->nexmon == NULL) {
                release_flock(local_wifi);

                snprintf(msg, STATUS_MAX, "%s interface '%s' looks like a Broadcom "
                        "embedded device but could not be initialized:  You MUST install "
                        "the nexmon patched drivers to use this device with Kismet",
                        local_wifi->name, local_wifi->interface);
                return -1;
            }

            /* Nexmon needs the interface UP to place it into monitor mode properly.  Weird! */
            if (ifconfig_interface_up(local_wifi->cap_interface, errstr) != 0) {
                release_flock(local_wifi);

                snprintf(msg, STATUS_MAX, "%s could not bring up capture interface '%s', "
                        "check 'dmesg' for possible errors while loading firmware: %s",
                        local_wifi->name, local_wifi->cap_interface, errstr);
                return -1;
            }

            if (nexmon_monitor(local_wifi->nexmon) < 0) {
                release_flock(local_wifi);

                snprintf(msg, STATUS_MAX, "%s could not place interface '%s' into monitor mode "
                        "via nexmon drivers; you MUST install the patched nexmon drivers to "
                        "use embedded broadcom interfaces with Kismet",
                        local_wifi->name, local_wifi->interface);
                return -1;
            }
        } else if (local_wifi->use_mac80211_mode) {
            /* If we're using mac80211 to set mode, try to do so here... */

            unsigned int num_flags = 0;
            unsigned int fi;
            unsigned int *flags = NULL;

            bool fcs = false;
            bool plcp = false;

            if ((placeholder_len = cf_find_flag(&placeholder, "fcsfail", definition)) > 0) {
                if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
                    snprintf(errstr, STATUS_MAX,
                            "%s source '%s' configuring monitor interface to pass packets "
                            "which fail FCS checksum",
                            local_wifi->name, local_wifi->interface);
                    cf_send_message(caph, errstr, MSGFLAG_INFO);
                    num_flags++;
                    fcs = true;
                }
            }

            if ((placeholder_len = cf_find_flag(&placeholder, "plcpfail",
                            definition)) > 0) {
                if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
                    snprintf(errstr, STATUS_MAX,
                            "%s source '%s' configuring monitor interface to pass packets "
                            "which fail PLCP checksum", local_wifi->name, local_wifi->interface);
                    cf_send_message(caph, errstr, MSGFLAG_INFO);
                    num_flags++;
                    plcp = true;
                }
            }

            /* Allocate the flag list */
            flags = (unsigned int *) malloc(sizeof(unsigned int) * num_flags);

            fi = 0;

            if (fcs)
                flags[fi++] = NL80211_MNTR_FLAG_FCSFAIL;

            if (plcp)
                flags[fi++] = NL80211_MNTR_FLAG_PLCPFAIL;

            if (mac80211_set_monitor_interface(local_wifi->interface, flags, num_flags, errstr) < 0) {
                free(flags);

                release_flock(local_wifi);

                snprintf(errstr2, STATUS_MAX, "%s %s failed to put interface in monitor mode: %s",
                        local_wifi->name, local_wifi->interface, errstr);
                cf_send_message(caph, errstr2, MSGFLAG_ERROR);

                /* We've failed at everything */
                snprintf(msg, STATUS_MAX, "%s could not not set mode of existing interface, "
                        "unable to put '%s' into monitor mode.", local_wifi->name, local_wifi->interface);
                return -1;

            }

            free(flags);
#ifdef HAVE_LINUX_WIRELESS
        } else if (iwconfig_set_mode(local_wifi->interface, errstr, LINUX_WLEXT_MONITOR) < 0) {
            release_flock(local_wifi);

            snprintf(errstr2, STATUS_MAX, "%s %s failed to put interface '%s' in monitor mode: %s",
                    local_wifi->name, local_wifi->cap_interface, local_wifi->interface, errstr);
            cf_send_message(caph, errstr2, MSGFLAG_ERROR);

            /* We've failed at everything */
            snprintf(msg, STATUS_MAX, "%s could not not set mode of existing interface, "
                    "unable to put '%s' into monitor mode.", local_wifi->name, local_wifi->interface);
            return -1;
#else
        } else if (!local_wifi->use_mac80211_mode) {
            release_flock(local_wifi);

            snprintf(errstr2, STATUS_MAX, "%s %s failed to put interface '%s' in monitor mode: %s",
                    local_wifi->name, local_wifi->cap_interface, local_wifi->interface,
                    "Interface can not use netlink controls, but Kismet was not compiled "
                    "with WEXT support.");
            cf_send_message(caph, errstr2, MSGFLAG_ERROR);

            /* We've failed at everything */
            snprintf(msg, STATUS_MAX, "%s could not not set mode of existing interface, "
                    "unable to put '%s' into monitor mode.", local_wifi->name, local_wifi->interface);
            return -1;
#endif
        } else {
            snprintf(errstr2, STATUS_MAX, "%s %s configured '%s' as monitor mode "
                    "interface instead of using a monitor vif",
                    local_wifi->name, local_wifi->cap_interface, local_wifi->interface);
            cf_send_message(caph, errstr2, MSGFLAG_INFO);
        }
    } else {
        if (strcmp(local_wifi->interface, local_wifi->cap_interface) == 0) {
            snprintf(errstr, STATUS_MAX, "%s interface '%s' is already in monitor mode",
                    local_wifi->name, local_wifi->interface);
        } else {
            snprintf(errstr, STATUS_MAX, "%s monitor interface '%s' already exists for "
                    "capture interface '%s', we'll use that.",
                    local_wifi->name, local_wifi->cap_interface, local_wifi->interface);
        }

        cf_send_message(caph, errstr, MSGFLAG_INFO);
    }

    release_flock(local_wifi);

    /* ********* End semaphore protected area ********** */

    /* Get the index and check the mode; if we didn't get into monitor mode, blow up */
    local_wifi->mac80211_ifidx = if_nametoindex(local_wifi->cap_interface);
    if (local_wifi->mac80211_ifidx > 0) {
        ret = -1;
        if (local_wifi->mac80211_socket != NULL && local_wifi->use_mac80211_vif) {
            uint32_t nl_mode = 0;

            ret = mac80211_get_iftype_cache(local_wifi->mac80211_ifidx, local_wifi->mac80211_socket,
                    local_wifi->mac80211_id, &nl_mode, errstr);

            if (ret > 0 && nl_mode == 0)
                ret = -1;

            /* Alias the netlink mode to the legacy mode */
            if (nl_mode > 0 && nl_mode != NL80211_IFTYPE_MONITOR) {
                release_flock(local_wifi);

                snprintf(msg, STATUS_MAX, "%s capture interface '%s' did not enter monitor "
                        "mode, something is wrong.", local_wifi->name, local_wifi->cap_interface);
                return -1;
            }
        }

        if (ret < 0) {
#ifdef HAVE_LINUX_WIRELESS
            if (iwconfig_get_mode(local_wifi->interface, errstr, &mode) < 0) {
                release_flock(local_wifi);

                snprintf(msg, STATUS_MAX, "%s capture interface '%s' did not enter monitor "
                        "mode, something is wrong.", local_wifi->name, local_wifi->cap_interface);
                return -1;
            }
#else
            release_flock(local_wifi);

            snprintf(msg, STATUS_MAX, "%s capture interface '%s' did not enter monitor "
                    "mode, something is wrong.  Kismet was not compiled with WEXT "
                    "support, so can not try legacy controls.",
                    local_wifi->name, local_wifi->cap_interface);
            return -1;
#endif
        }

    }

#ifdef HAVE_LIBNM
    /* Now, if we have a reference to networkmanager, try to tell it to ignore
     * the monitor mode interface, too, in case it gets any ideas */

    if (nmclient != NULL && nm_client_get_nm_running(nmclient)) {
        nmdevices = nm_client_get_devices(nmclient);

        if (nmdevices != NULL) {
            for (i = 0; i < nmdevices->len; i++) {
                const NMDevice *d = g_ptr_array_index(nmdevices, i);

                if (strcmp(nm_device_get_iface((NMDevice *) d),
                            local_wifi->cap_interface) == 0) {
                    nmdevice = (NMDevice *) d;
                    break;
                }
            }
        }
    }

    if (nmdevice != NULL) {
        local_wifi->reset_nm_management = nm_device_get_managed(nmdevice);

        if (local_wifi->reset_nm_management) {
            snprintf(errstr, STATUS_MAX, "%s telling NetworkManager not to control "
                    "interface '%s': you may need to re-initialize this interface "
                    "later or tell NetworkManager to control it again via 'nmcli'",
                    local_wifi->name, local_wifi->interface);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
            nm_device_set_managed(nmdevice, 0);
        }
    }

    /* We HAVE to unref the nmclient and disconnect here or it keeps trying
     * to deliver messages to us, filling up hundreds of megs of ram */
    if (nmclient != NULL)
        g_object_unref(nmclient);
#endif

    /* Bring down the parent interface if needed */
    if (strcmp(local_wifi->interface, local_wifi->cap_interface) != 0) {
        int ign_primary = 0;
        if ((placeholder_len = cf_find_flag(&placeholder, "ignoreprimary", definition)) > 0) {
            if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
                snprintf(errstr, STATUS_MAX,
                        "%s %s/%s ignoring state of primary interface and "
                        "leaving it in an 'up' state; this may cause problems "
                        "with channel hopping.",
                        local_wifi->name, local_wifi->interface, local_wifi->cap_interface);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                ign_primary = 1;
            }
        }

        if (!ign_primary) {
            snprintf(errstr2, STATUS_MAX, "%s bringing down parent interface '%s'",
                    local_wifi->name, local_wifi->interface);
            cf_send_message(caph, errstr2, MSGFLAG_INFO);

            if (ifconfig_interface_down(local_wifi->interface, errstr) != 0) {
                release_flock(local_wifi);

                snprintf(msg, STATUS_MAX, "%s could not bring down parent interface "
                        "'%s' to capture using '%s': %s",
                        local_wifi->name, local_wifi->interface, local_wifi->cap_interface, errstr);
                return -1;
            }
        }
    }

    /* bring the cap interface up */
    if (ifconfig_interface_up(local_wifi->cap_interface, errstr) != 0) {
        release_flock(local_wifi);

        snprintf(msg, STATUS_MAX, "%s could not bring up capture interface '%s', "
                "check 'dmesg' for possible errors while loading firmware: %s",
                local_wifi->name, local_wifi->cap_interface, errstr);
        return -1;
    }


    /* Do we exclude HT or VHT channels?  Equally, do we force them to be turned on? */
    if ((placeholder_len =
                cf_find_flag(&placeholder, "ht_channels", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->use_ht_channels = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->use_ht_channels = 1;
        }
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "vht_channels", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->use_vht_channels = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->use_vht_channels = 1;
        }
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "default_ht20", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            default_ht_20 = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            default_ht_20 = 1;
        }
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "expand_ht20", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            expand_ht_20 = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            expand_ht_20 = 1;
        }
    }

    (*ret_interface)->hardware = strdup(driver);

    ret = populate_chanlist(caph, local_wifi->cap_interface, errstr, default_ht_20, expand_ht_20,
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));
    if (ret < 0) {
        return -1;
    }

    if ((*ret_interface)->channels_len == 0) {
        snprintf(msg, STATUS_MAX,
                "%s %s/%s did not find any channels automatically; channels must be specified via "
                "the channels= or channel= source options.",
                local_wifi->name, local_wifi->interface, local_wifi->cap_interface);
        cf_send_message(caph, msg, MSGFLAG_INFO);
    }

    if ((placeholder_len = cf_find_flag(&placeholder, "channel", definition)) > 0) {
        localchanstr = strndup(placeholder, placeholder_len);

        localchan =
            (local_channel_t *) chantranslate_callback(caph, localchanstr);

        free(localchanstr);

        if (localchan == NULL) {
            snprintf(msg, STATUS_MAX,
                    "%s %s/%s could not parse channel= option provided in source "
                    "definition", local_wifi->name, local_wifi->interface, local_wifi->cap_interface);
            return -1;
        }

        local_channel_to_str(localchan, errstr);
        (*ret_interface)->chanset = strdup(errstr);

        snprintf(errstr, STATUS_MAX, "%s setting initial channel to %s",
                local_wifi->name, (*ret_interface)->chanset);
        cf_send_message(caph, errstr, MSGFLAG_INFO);

        if (chancontrol_callback(caph, 0, localchan, msg) < 0) {
            free(localchan);
            localchan = NULL;
            return -1;
        }
    }

    /* Open the pcap */
    local_wifi->pd = pcap_open_live(local_wifi->cap_interface,
            MAX_PACKET_LEN, 1, 1000, pcap_errstr);

    if (local_wifi->pd == NULL || strlen(pcap_errstr) != 0) {
        snprintf(msg, STATUS_MAX, "%s could not open capture interface '%s' on '%s' "
                "as a pcap capture: %s", local_wifi->name, local_wifi->cap_interface,
                local_wifi->interface, pcap_errstr);
        return -1;
    }

    if (local_wifi->wardrive_filter) {
        if (pcap_datalink(local_wifi->pd) == DLT_IEEE802_11_RADIO) {
            bpf.bf_insns = rt_pgm;
            bpf.bf_len = sizeof(rt_pgm) / sizeof(struct bpf_insn);
            if (pcap_setfilter(local_wifi->pd, &bpf) < 0) {
                snprintf(errstr, STATUS_MAX, "%s unable to install management packet filter: %s",
                         local_wifi->name, pcap_geterr(local_wifi->pd));
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
            }
        } else {
            snprintf(errstr, STATUS_MAX, "%s unable to install management packet filter on non-rtap link type %u/%s",
                     local_wifi->name, pcap_datalink(local_wifi->pd),
                     pcap_datalink_val_to_name(pcap_datalink(local_wifi->pd)));
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
        }
    } else if (local_wifi->data_filter) {
        if (pcap_datalink(local_wifi->pd) == DLT_IEEE802_11_RADIO) {
            bpf.bf_insns = rt_pgm_crop_data;
            bpf.bf_len = sizeof(rt_pgm_crop_data) / sizeof(struct bpf_insn);
            if (pcap_setfilter(local_wifi->pd, &bpf) < 0) {
                snprintf(errstr, STATUS_MAX, "%s unable to install data packet filter: %s",
                         local_wifi->name, pcap_geterr(local_wifi->pd));
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
            }
        } else {
            snprintf(errstr, STATUS_MAX, "%s unable to install data filter on non-rtap link type %u/%s",
                     local_wifi->name, pcap_datalink(local_wifi->pd),
                     pcap_datalink_val_to_name(pcap_datalink(local_wifi->pd)));
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
        }
    } else if (filter_locals) {
        if ((ret = build_first_localdev_filter(&ignore_filter)) > 0) {
            if (ret > 8) {
                snprintf(errstr, STATUS_MAX, "%s found more than 8 local interfaces (%d), limiting "
                        "the exclusion filter to the first 8 because of limited kernel filter memory.",
                        local_wifi->name, ret);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
            }

            if (pcap_compile(local_wifi->pd, &bpf, ignore_filter, 0, 0) < 0) {
                snprintf(errstr, STATUS_MAX, "%s unable to compile filter to exclude other "
                        "local interfaces: %s",
                        local_wifi->name, pcap_geterr(local_wifi->pd));
                cf_send_message(caph, errstr, MSGFLAG_INFO);
            } else {
                if (pcap_setfilter(local_wifi->pd, &bpf) < 0) {
                    snprintf(errstr, STATUS_MAX, "%s unable to assign filter to exclude other "
                            "local interfaces: %s",
                            local_wifi->name, pcap_geterr(local_wifi->pd));
                    cf_send_message(caph, errstr, MSGFLAG_INFO);
                }
            }

            free(ignore_filter);
        }
    } else if (num_filter_interfaces > 0) {
        if ((ret = build_named_filters(filter_targets, num_filter_interfaces, &ignore_filter)) > 0) {
            if (pcap_compile(local_wifi->pd, &bpf, ignore_filter, 0, 0) < 0) {
                snprintf(errstr, STATUS_MAX, "%s unable to compile filter to exclude "
                        "local interfaces: %s",
                        local_wifi->name, pcap_geterr(local_wifi->pd));
                cf_send_message(caph, errstr, MSGFLAG_INFO);
            } else {
                if (pcap_setfilter(local_wifi->pd, &bpf) < 0) {
                    snprintf(errstr, STATUS_MAX, "%s unable to assign filter to exclude "
                            "local interfaces: %s",
                            local_wifi->name, pcap_geterr(local_wifi->pd));
                    cf_send_message(caph, errstr, MSGFLAG_INFO);
                }
            }

            free(ignore_filter);

            for (i = 0; i < num_filter_interfaces; i++) {
                if (filter_targets[i] != NULL)
                    free(filter_targets[i]);
            }

            free(filter_targets);
        }
    } else if (num_filter_addresses > 0) {
        if ((ret = build_explicit_filters(filter_targets, num_filter_addresses, &ignore_filter)) > 0) {
            if (pcap_compile(local_wifi->pd, &bpf, ignore_filter, 0, 0) < 0) {
                snprintf(errstr, STATUS_MAX, "%s unable to compile filter to exclude "
                        "specific addresses: %s",
                        local_wifi->name, pcap_geterr(local_wifi->pd));
                cf_send_message(caph, errstr, MSGFLAG_INFO);
            } else {
                if (pcap_setfilter(local_wifi->pd, &bpf) < 0) {
                    snprintf(errstr, STATUS_MAX, "%s unable to assign filter to exclude "
                            "specific addresses: %s",
                            local_wifi->name, pcap_geterr(local_wifi->pd));
                    cf_send_message(caph, errstr, MSGFLAG_INFO);
                }
            }

            free(ignore_filter);

            for (i = 0; i < num_filter_addresses; i++) {
                if (filter_targets[i] != NULL)
                    free(filter_targets[i]);
            }

            free(filter_targets);
        }
    }

    local_wifi->datalink_type = pcap_datalink(local_wifi->pd);
    *dlt = local_wifi->datalink_type;

    if (strcmp(local_wifi->interface, local_wifi->cap_interface) != 0) {
        snprintf(msg, STATUS_MAX, "%s Linux Wi-Fi capturing from monitor vif '%s' on "
                "interface '%s'", local_wifi->name, local_wifi->cap_interface, local_wifi->interface);
    } else {
        snprintf(msg, STATUS_MAX, "%s Linux Wi-Fi capturing from interface '%s'",
                local_wifi->name, local_wifi->interface);
    }

    (*ret_interface)->capif = strdup(local_wifi->cap_interface);

    snprintf(errstr2, STATUS_MAX, "%s finished configuring %s/%s, ready to capture",
            local_wifi->name, local_wifi->interface, local_wifi->cap_interface);
    cf_send_message(caph, errstr2, MSGFLAG_INFO);

    if (localchan != NULL) {
        free(localchan);
        localchan = NULL;
    }

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces) {
    DIR *devdir;
    struct dirent *devfile;
    char errstr[STATUS_MAX];

    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;

    /* Basic list of devices */
    typedef struct wifi_list {
        char *device;
        char *flags;
        char *driver;
        struct wifi_list *next;
    } wifi_list_t;

    wifi_list_t *devs = NULL;
    size_t num_devs = 0;

    unsigned int i;
    int r;

    char driver[32] = "";

    if ((devdir = opendir("/sys/class/net/")) == NULL) {
        /* fprintf(stderr, "debug - no /sys/class/net dir?\n"); */

        /* Not an error, just nothing to do */
        *interfaces = NULL;
        return 0;
    }

    if (mac80211_connect(&(local_wifi->mac80211_socket), &(local_wifi->mac80211_id), errstr) < 0) {
        local_wifi->mac80211_socket = NULL;
    }

    /* Look at the files in the sys dir and see if they're wi-fi */
    while ((devfile = readdir(devdir)) != NULL) {
        /* if we can get the current channel with simple iwconfig ioctls
         * it's definitely a wifi device; even mac80211 devices respond
         * to it */
        unsigned int mode = -1;

        /* Try netlink first */
        if (local_wifi->mac80211_socket != NULL) {
            int ifidx = if_nametoindex(devfile->d_name);

            r = mac80211_get_iftype_cache(ifidx, local_wifi->mac80211_socket,
                    local_wifi->mac80211_id, &mode, errstr);
            if (mode == 0)
                r = -1;
        } else {
            r = -1;
        }

        /* Fallback to iwconfig */
#ifdef HAVE_LINUX_WIRELESS
        if (r < 0)
            r = iwconfig_get_mode(devfile->d_name, errstr, &mode);
#endif

        /* if we succeeded (iwconfig) or if we succeeded and have a valid mode (netlink) */
        if (r >= 0) {
            wifi_list_t *d = (wifi_list_t *) malloc(sizeof(wifi_list_t));
            num_devs++;
            d->device = strdup(devfile->d_name);
            d->flags = NULL;

            linux_getsysdrv(devfile->d_name, driver);
            d->driver = strdup(driver);

            d->next = devs;
            devs = d;
        }
    }

    mac80211_disconnect(local_wifi->mac80211_socket);

    closedir(devdir);

    if (num_devs == 0) {
        *interfaces = NULL;
        return 0;
    }

    *interfaces =
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * num_devs);

    i = 0;

    while (devs != NULL) {
        wifi_list_t *td = devs->next;

        /* Allocate an interface */
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        /* All these strings were strdup'd already so we assign the pointers and let the
         * cleanup of the interface list free them */
        (*interfaces)[i]->interface = devs->device;
        (*interfaces)[i]->flags = devs->flags;
        (*interfaces)[i]->hardware = devs->driver;

        free(devs);
        devs = td;

        i++;
    }

    return num_devs;
}

void pcap_dispatch_cb(u_char *user, const struct pcap_pkthdr *header,
        const u_char *data)  {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) user;
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    int ret;

    /* fprintf(stderr, "debug - pcap_dispatch - got packet %u\n", header->caplen); */

    /* Try repeatedly to send the packet; go into a thread wait state if
     * the write buffer is full & we'll be woken up as soon as it flushes
     * data out in the main select() loop */
    while (1) {
        if ((ret = cf_send_data(caph, NULL, 0,
                        NULL, NULL, header->ts, local_wifi->datalink_type,
                        header->len, header->caplen, (uint8_t *) data)) < 0) {
            pcap_breakloop(local_wifi->pd);
            fprintf(stderr, "%s %s/%s could not send packet to Kismet server, terminating.",
                    local_wifi->name, local_wifi->interface, local_wifi->cap_interface);
            cf_handler_spindown(caph);
        } else if (ret == 0) {
            /* Go into a wait for the write buffer to get flushed */
            cf_handler_wait_ringbuffer(caph);
            continue;
        } else {
            break;
        }
    }
}

void capture_thread(kis_capture_handler_t *caph) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    char errstr[PCAP_ERRBUF_SIZE];
    char *pcap_errstr;
    char iferrstr[STATUS_MAX];
    int ifflags = 0, ifret;

    /* Simple capture thread: since we don't care about blocking and
     * channel control is managed by the channel hopping thread, all we have
     * to do is enter a blocking pcap loop */

    pcap_loop(local_wifi->pd, -1, pcap_dispatch_cb, (u_char *) caph);

    pcap_errstr = pcap_geterr(local_wifi->pd);

    snprintf(errstr, PCAP_ERRBUF_SIZE, "%s interface '%s' closed: %s",
            local_wifi->name, local_wifi->cap_interface,
            strlen(pcap_errstr) == 0 ? "interface closed" : pcap_errstr );

    cf_send_error(caph, 0, errstr);

    ifret = ifconfig_get_flags(local_wifi->cap_interface, iferrstr, &ifflags);

    if (ifret < 0 || !(ifflags & IFF_UP)) {
        snprintf(errstr, PCAP_ERRBUF_SIZE, "%s interface '%s' no longer appears to be up; "
                "This can happen when it is unplugged, or another service like DHCP or "
                "NetworKManager has taken over and shut it down on us.",
                local_wifi->name, local_wifi->cap_interface);
        cf_send_error(caph, 0, errstr);
    }

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_wifi_t local_wifi = {
        .pd = NULL,
        .interface = NULL,
        .cap_interface = NULL,
        .base_phy = NULL,
        .name = NULL,
        .lock_fd = -1,
        .datalink_type = -1,
        .override_dlt = -1,
        .use_mac80211_vif = 1,
        .use_mac80211_channels = 1,
        .use_mac80211_mode = 0,
        .mac80211_socket = NULL,
        .up_before_mode = false,
        .use_ht_channels = 1,
        .use_vht_channels = 1,
        .wardrive_filter = 0,
        .data_filter = 0,
        .band_any = true,
        .band_2_4 = true,
        .band_5 = true,
        .band_6 = true,
        .seq_channel_failure = 0,
        .reset_nm_management = 0,
        .nexmon = NULL,
        .verbose_diagnostics = 0,
        .verbose_statistics = 0,
        .channel_set_ns_avg = 0,
        .channel_set_ns_count = 0,
    };

#ifdef HAVE_LIBNM
    NMClient *nmclient = NULL;
    const GPtrArray *nmdevices;
    GError *nmerror = NULL;
    int i;
#endif

    /* fprintf(stderr, "CAPTURE_LINUX_WIFI launched on pid %d\n", getpid()); */

    kis_capture_handler_t *caph = cf_handler_init("linuxwifi");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local_wifi);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    cf_handler_set_listdevices_cb(caph, list_callback);

    /* Set the translation cb */
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);

    /* Set the control cb */
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

    /* Set a channel hop spacing of 4 to get the most out of 2.4 overlap;
     * it does nothing and hurts nothing on 5ghz */
    cf_handler_set_hop_shuffle_spacing(caph, 4);

    int r = cf_handler_parse_opts(caph, argc, argv);
    if (r == 0) {
        return 0;
    } else if (r < 0) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* Support remote capture by launching the remote loop */
    cf_handler_remote_capture(caph);

    /* Jail our ns */
    cf_jail_filesystem(caph);

    /* Strip our privs */
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);

    /* We're done - try to reset the networkmanager awareness of the interface */

#ifdef HAVE_LIBNM
    if (local_wifi.reset_nm_management) {
        nmclient = nm_client_new(NULL, &nmerror);

        if (nmclient != NULL) {
            if (nm_client_get_nm_running(nmclient)) {
                nmdevices = nm_client_get_devices(nmclient);

                if (nmdevices != NULL) {
                    for (i = 0; i < nmdevices->len; i++) {
                        const NMDevice *d = g_ptr_array_index(nmdevices, i);

                        if (strcmp(nm_device_get_iface((NMDevice *) d),
                                    local_wifi.interface) == 0) {
                            nm_device_set_managed((NMDevice *) d, 1);
                            break;
                        }
                    }
                }
            }

            g_object_unref(nmclient);
        }
    }
#endif

    cf_handler_free(caph);

    return 1;
}

