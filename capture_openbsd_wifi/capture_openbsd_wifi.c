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

/* capture_openbsd_wifi
 *
 * Capture binary, written in pure c, which interfaces via the Kismet capture
 * protocol and feeds packets from, and is able to control, a wireless card on 
 * OpenBSD.
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

#include <stdlib.h>
#include <string.h>

/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>

/* According to earlier standards */
#include <err.h>
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

#include <net80211/ieee80211.h>
#include <net80211/ieee80211_ioctl.h>

#include "../config.h"

#include "../capture_framework.h"

#include "../interface_control.h"

#include "../wifi_ht_channels.h"

#define MAX_PACKET_LEN  8192

#ifndef nitems
#define nitems(_a)      (sizeof((_a)) / sizeof((_a)[0]))
#endif

int sock = -1;

// BPF program to parse radiotap and 802.11, and pass management and eapol ONLY
struct bpf_insn rt_pgm[] = {
    // 00 LDB [3]      a = pkt[3] second half of length
    BPF_STMT(BPF_LD + BPF_MODE(BPF_ABS) + BPF_SIZE(BPF_B), 3),
    // 01 LSH #8       a = a << 8
    BPF_STMT(BPF_ALU + BPF_OP(BPF_LSH), 8),
    // 02 TAX          x = a
    BPF_STMT(BPF_MISC + BPF_MISCOP(BPF_TAX), 0),
    // 03 LDB [2]      a = pkt[2] first half of length
    BPF_STMT(BPF_LD + BPF_MODE(BPF_ABS) + BPF_SIZE(BPF_B), 2),
    // 04 ADD X        a = a + x  // combine endian swapped
    BPF_STMT(BPF_ALU + BPF_OP(BPF_ADD) + BPF_SRC(BPF_X), 0),

    // 05 ST M[0]      m[0] = a (rtap length)
    BPF_STMT(BPF_ST, 0),
    // 06 TAX          x = a = rtap length
    BPF_STMT(BPF_MISC + BPF_MISCOP(BPF_TAX), 0),

    // 07 LDB [x + 0]  a = pkt[rtap + 0]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_B), 0),
    // 08 RSH #2       a = a >> 2
    BPF_STMT(BPF_ALU + BPF_OP(BPF_RSH), 2),
    // 09 AND 0x3      a = a & 0x3
    BPF_STMT(BPF_ALU + BPF_OP(BPF_AND), 3),

    // 10 JEQ #0       if a == 0 succeed
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x0, 0, 1),
    // 11 RET 0x40000  return success
    BPF_STMT(BPF_RET, 0x40000),

    // 12 JEQ #2       if a == 2, continue, else fail
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x2, 1, 0),
    // 13 RET 0x0      return fail
    BPF_STMT(BPF_RET, 0),

    // 14 LDB [x + 0]  a = pkt[rtap + 0]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_B), 0),
    // 15 RSH #4       a = a >> 4
    BPF_STMT(BPF_ALU + BPF_OP(BPF_RSH), 4),

    // 16 JEQ #0       a == 0x0 (subtype data)
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x0, 0, 2),
    // 17 LD #24        a = 24 (non-qos header len)
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IMM), 24),
    // 18 JMP          jump past qos
    BPF_STMT(BPF_JMP + BPF_JA, 3),

    // 19 JEQ #8       a == 0x8 (subtype qos data)
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x8, 1, 0),
    // 20 RET 0x0      return fail, not normal or qos
    BPF_STMT(BPF_RET, 0),

    // 21 LD #26       a = 26 (qos header len)
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IMM), 26),

    // 22 LDX M[0]     X = m[0] (rtap length)
    BPF_STMT(BPF_LDX + BPF_MODE(BPF_MEM), 0),
    // 23 ADD X        a = a + x
    BPF_STMT(BPF_ALU + BPF_OP(BPF_ADD) + BPF_SRC(BPF_X), 0),
    // 24 ST M[1]      m[1] = a (rtap length + offset length)
    BPF_STMT(BPF_ST, 1),
    // 25 TAX          x = a
    BPF_STMT(BPF_MISC + BPF_MISCOP(BPF_TAX), 0),

    // 26 LDH [x + 0]  a = pkt[rtap + header + 0]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_H), 0),
    // 27 JEQ 0xAAAA   a == 0xAAAA (SNAP header)
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0xAAAA, 0, 2),

    // 28 LDH [x + 0]  a = pkt[rtap + header + 6]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_H), 6),
    // 29 JEQ 0x888e   a == 0x888E eapol sig
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x888E, 1, 0),

    // 30 RET 0x0      return fail
    BPF_STMT(BPF_RET, 0),
    // 31 RET 0x0      return success
    BPF_STMT(BPF_RET, 0x40000),
};
unsigned int rt_pgm_len = 32;

// Pass management, EAPOL
// Crop other data to rtap+dot11 headers
struct bpf_insn rt_pgm_crop_data[] = {
    // 00 LDB [3]      a = pkt[3] second half of length
    BPF_STMT(BPF_LD + BPF_MODE(BPF_ABS) + BPF_SIZE(BPF_B), 3),
    // 01 LSH #8       a = a << 8
    BPF_STMT(BPF_ALU + BPF_OP(BPF_LSH), 8),
    // 02 TAX          x = a
    BPF_STMT(BPF_MISC + BPF_MISCOP(BPF_TAX), 0),
    // 03 LDB [2]      a = pkt[2] first half of length
    BPF_STMT(BPF_LD + BPF_MODE(BPF_ABS) + BPF_SIZE(BPF_B), 2),
    // 04 ADD X         a = a + x  // combine endian swapped
    BPF_STMT(BPF_ALU + BPF_OP(BPF_ADD) + BPF_SRC(BPF_X), 0),

    // 05 ST M[0]      m[0] = a (rtap length)
    BPF_STMT(BPF_ST, 0),
    // 06 TAX          x = a = rtap length
    BPF_STMT(BPF_MISC + BPF_MISCOP(BPF_TAX), 0),

    // Fetch frame type

    // 07 LDB [x + 0]  a = pkt[rtap + 0]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_B), 0),

    // 08 AND #0xC     a & 0xC - extract type
    BPF_STMT(BPF_ALU + BPF_OP(BPF_AND), 0xC),

    // 09 JEQ #0x0    if == 0, accept as management frame
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x0, 0, 1),
    // 10 RET 0x40000  return success
    BPF_STMT(BPF_RET, 0x40000),

    // 11 JEQ #2       if a == 0x8, continue - process data frames (0x8 == b1000)
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x8, 1, 0),
    // 12 RET 0x0      reject all other frames
    BPF_STMT(BPF_RET, 0),

    // 13 LDB [x + 0]  a = pkt[rtap + 0] - re-load A with FC byte
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_B), 0),
    // 14 AND #0xF0    a = a & 0xF0 - isolate subtype
    BPF_STMT(BPF_ALU + BPF_OP(BPF_AND), 0xF0),

    // 15 JEQ #0       a == 0x0 (subtype normal data)
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x0, 0, 2),
    // 16 LD #24        a = 24 (non-qos header len)
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IMM), 24),
    // 17 JMP          jump past qos (22)
    BPF_STMT(BPF_JMP + BPF_JA, 3),

    // 18 JEQ #0x80    a == 0x80 (subtype qos data)
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x80, 1, 0),
    // 29 RET 0x0      reject, data subtype we don't care to process
    BPF_STMT(BPF_RET, 0),

    // 20 LD #26       a = 26 - set qos header len
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IMM), 26),

    // 21 ST M[1]      m[1] = a (offset length) -- Store length before checking protected flag
    BPF_STMT(BPF_ST, 1),

    // 22 LDB [ x + 1]  a = pkt[rtap + 1] (flags)
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_B), 1),
    // 23 JSET 0x40   if a & 0x40 set protected bit
    BPF_JUMP(BPF_JMP + BPF_JSET, 0x40, 1, 0),

    // 24 LD #0       a = 0
    BPF_STMT(BPF_LD + BPF_SRC(BPF_K), 0),
    // 25 ST M[2]     m[2] = a
    BPF_STMT(BPF_ST, 2),

    // 26 LDA m[1] .   a = m[1] (saved data offset length)
    BPF_STMT(BPF_LD + BPF_MODE(BPF_MEM), 1),
    // 27 LDX M[0]     X = m[0] (rtap length)
    BPF_STMT(BPF_LDX + BPF_MODE(BPF_MEM), 0),
    // 28 ADD X        a = a + x
    BPF_STMT(BPF_ALU + BPF_OP(BPF_ADD) + BPF_SRC(BPF_X), 0),
    // 29 ST M[1]      m[1] = a (rtap length + offset length)
    BPF_STMT(BPF_ST, 1),
    // 30 TAX          x = a (x = total offset length)
    BPF_STMT(BPF_MISC + BPF_MISCOP(BPF_TAX), 0),

    // 31 LDA m[2] .   a = m[2] (saved flags)
    BPF_STMT(BPF_LD + BPF_MODE(BPF_MEM), 2),
    // 32 JEQ #0 .     a == 0x0 - truncate if it's a protected frame
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x0, 0, 6),

    // 33 LDH [x + 0]  a = pkt[rtap + header + 0] - X hasn't been changed since we loaded it
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_H), 0),
    // 34 JEQ 0xAAAA   a == 0xAAAA (SNAP header) or truncate
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0xAAAA, 0, 4),

    // 35 LDB [x + 6]  a = pkt[rtap + header + 6]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_B), 6),
    // 36 JEQ 0x88   a == 0x88 eapol sig or truncate
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x88, 0, 2),

    // 37 LDB [x + 7]  a = pkt[rtap + header + 7]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_B), 7),
    // 38 JEQ 0x8e   a == 0x8e eapol sig or truncate
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x8E, 0, 2),

    // truncate - m1 holds the total length of the headers+qos

    // 39 LDB mem[1]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_MEM), 1),
    // 40 RET a        Return a (limit packet length to rtap+dot11+qos?)
    BPF_STMT(BPF_RET + BPF_RVAL(BPF_A), 0),

    // 41 RET 0x0      return entire packet
    BPF_STMT(BPF_RET, 0x40000),
};
unsigned int rt_pgm_crop_data_len = 42;

// BPF program to parse raw 802.11 and pass management and eapol ONLY
struct bpf_insn dot11_pgm[] = {
    // 00 LDX #0       x = 0
    BPF_STMT(BPF_LDX + BPF_MODE(BPF_IMM), 0),

    // 01 LDB [x + 0]  a = pkt[0]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_B), 0),
    // 02 RSH #2       a = a >> 2
    BPF_STMT(BPF_ALU + BPF_OP(BPF_RSH), 2),
    // 03 AND 0x3      a = a & 0x3
    BPF_STMT(BPF_ALU + BPF_OP(BPF_AND), 3),

    // 04 JEQ #0       if a == 0 succeed
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x0, 0, 1),
    // 05 RET 0x40000  return success
    BPF_STMT(BPF_RET, 0x40000),

    // 06 JEQ #2       if a == 2, continue, else fail
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x2, 1, 0),
    // 07 RET 0x0      return fail
    BPF_STMT(BPF_RET, 0),

    // 08 LDB [x + 0]  a = pkt[rtap + 0]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_B), 0),
    // 09 RSH #4       a = a >> 4
    BPF_STMT(BPF_ALU + BPF_OP(BPF_RSH), 4),

    // 10 JEQ #0       a == 0x0 (subtype data)
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x0, 0, 2),
    // 11 LDX #24      x = 24 (non-qos header len)
    BPF_STMT(BPF_LDX + BPF_MODE(BPF_IMM), 24),
    // 12 JMP          jump past qos
    BPF_STMT(BPF_JMP + BPF_JA, 3),

    // 13 JEQ #8       a == 0x8 (subtype qos data)
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x8, 1, 0),
    // 14 RET 0x0      return fail, not normal or qos
    BPF_STMT(BPF_RET, 0),

    // 15 LDX #26      x = 26 (qos header len)
    BPF_STMT(BPF_LDX + BPF_MODE(BPF_IMM), 26),

    // 16 LDH [x + 0]  a = pkt[rtap + header + 0]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_H), 0),
    // 17 JEQ 0xAAAA   a == 0xAAAA (SNAP header)
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0xAAAA, 0, 2),

    // 18 LDH [x + 0]  a = pkt[rtap + header + 6]
    BPF_STMT(BPF_LD + BPF_MODE(BPF_IND) + BPF_SIZE(BPF_H), 6),
    // 19 JEQ 0x888e   a == 0x888E eapol sig
    BPF_JUMP(BPF_JMP + BPF_JEQ, 0x888E, 1, 0),

    // 20 RET 0x0      return fail
    BPF_STMT(BPF_RET, 0),
    // 21 RET 0x0      return success
    BPF_STMT(BPF_RET, 0x40000),
};
unsigned int dot11_pgm_len = 22;

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

void    
getsock(int naf)
{
        static int oaf = -1;

        if (oaf == naf)
                return;
        if (oaf != -1)
                close(sock);
        sock = socket(naf, SOCK_DGRAM, 0);
        if (sock == -1)
                oaf = -1;
        else
                oaf = naf;
}

void
setifxflags(local_wifi_t *local_wifi, int value)
{
        struct ifreq my_ifr;
	int xflags;

	bzero(&my_ifr, sizeof(struct ifreq));
        (void) strlcpy(my_ifr.ifr_name, local_wifi->interface, sizeof(my_ifr.ifr_name));
	my_ifr.ifr_index = local_wifi->mac80211_ifidx;
	getsock(AF_INET);
        if (ioctl(sock, SIOCGIFXFLAGS, (caddr_t)&my_ifr) == -1)
                warn("%s: SIOCGIFXFLAGS", my_ifr.ifr_name);
        xflags = my_ifr.ifr_flags;

        if (value < 0) {
                value = -value;
                xflags &= ~value;
        } else
                xflags |= value;
        my_ifr.ifr_flags = xflags;
        if (ioctl(sock, SIOCSIFXFLAGS, (caddr_t)&my_ifr) == -1)
                warn("%s: SIOCSIFXFLAGS", my_ifr.ifr_name);
}

void
setifflags(local_wifi_t *local_wifi, int value)
{
        struct ifreq my_ifr;
	int flags;

	bzero(&my_ifr, sizeof(struct ifreq));
        (void) strlcpy(my_ifr.ifr_name, local_wifi->interface, sizeof(my_ifr.ifr_name));
	my_ifr.ifr_index = local_wifi->mac80211_ifidx;
	getsock(AF_INET);
        if (ioctl(sock, SIOCGIFFLAGS, (caddr_t)&my_ifr) == -1)
                err(1, "%s: SIOCGIFFLAGS", my_ifr.ifr_name);
        flags = my_ifr.ifr_flags;

        if (value < 0) {
                value = -value;
                flags &= ~value;
        } else
                flags |= value;
        my_ifr.ifr_flags = flags;
        if (ioctl(sock, SIOCSIFFLAGS, (caddr_t)&my_ifr) == -1)
                err(1, "%s: SIOCSIFFLAGS", my_ifr.ifr_name);
}

void
setiflladdr(local_wifi_t *local_wifi, struct ether_addr *eap)
{
	struct ether_addr eabuf;
	struct ifreq my_ifr;

	arc4random_buf(&eabuf, sizeof eabuf);
	/* Non-multicast and claim it is a hardware address */
	eabuf.ether_addr_octet[0] &= 0xfc;
	
	strlcpy(my_ifr.ifr_name, local_wifi->interface, sizeof(my_ifr.ifr_name));
	my_ifr.ifr_addr.sa_len = ETHER_ADDR_LEN;
	my_ifr.ifr_addr.sa_family = AF_LINK;
	bcopy(eap, my_ifr.ifr_addr.sa_data, ETHER_ADDR_LEN);
	getsock(AF_INET);
	if (ioctl(sock, SIOCSIFLLADDR, (caddr_t)&my_ifr) == -1)
		warn("%s: SIOCSIFLLADDR", my_ifr.ifr_name);
	bcopy(&eabuf, eap, ETHER_ADDR_LEN);
	
}

void
setifchan(const char *ifname, unsigned int chan, int d)
{
        struct ieee80211chanreq channel;
        const char *errstr;

        if (d != 0)
                chan = IEEE80211_CHAN_ANY;

        strlcpy(channel.i_name, ifname, sizeof(channel.i_name));
        channel.i_channel = (u_int16_t)chan;
	getsock(AF_INET);
        if (ioctl(sock, SIOCS80211CHANNEL, (caddr_t)&channel) == -1)
                fprintf(stderr, "setifchan: %s: SIOCS80211CHANNEL", channel.i_name);
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

/* Convert a string into a local interpretation; allocate ret_localchan.
 */
void *chantranslate_callback(kis_capture_handler_t *caph, char *chanstr) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    local_channel_t *ret_localchan = NULL;
    unsigned int parsechan;
    sscanf(chanstr, "%u", &parsechan);
    ret_localchan = (local_channel_t *) malloc(sizeof(local_channel_t));
    memset(ret_localchan, 0, sizeof(local_channel_t));
    ret_localchan->chan_band = wifi_band_2ghz;
    (ret_localchan)->control_freq = wifi_chan_to_freq(parsechan, wifi_band_2ghz);
    return ret_localchan;
}

/* Convert a local interpretation of a channel back info a string;
 * 'chanstr' should hold at least STATUS_MAX characters; we'll never use
 * that many but it lets us do some cheaty stuff and re-use errstrs */
void local_channel_to_str(local_channel_t *chan, char *chanstr) {
}

int populate_chanlist(kis_capture_handler_t *caph, char *interface, char *msg, 
        unsigned int default_ht20, unsigned int expand_ht20,
        char ***chanlist, size_t *chanlist_sz) {

	char conv_chan[16];
        static struct ieee80211_chaninfo chans[256];
        struct ieee80211_chanreq_all ca;
        int i;
	unsigned int cp;

        bzero(&ca, sizeof(ca));
        bzero(chans, sizeof(chans));
        ca.i_chans = chans;	
	strlcpy(ca.i_name, interface, sizeof(ca.i_name));

	getsock(AF_INET);
        if (ioctl(sock, SIOCG80211ALLCHANS, &ca) != 0) {
                fprintf(stderr, "CAPTURE_OPENBSD_WIFI populate_chanlist %s: SIOCG80211ALLCHANS", ca.i_name);
                return -1;
	}
	cp = 0;
	*chanlist = (char **) malloc(sizeof(char *) * 256);
	for (i = 1; i < nitems(chans); i++) {
		if (chans[i].ic_freq == 0) {
			continue;
		}
		snprintf(conv_chan, 16, "%u", wifi_freq_to_chan(chans[i].ic_freq));
		(*chanlist)[cp] = strdup(conv_chan);
		cp++;
	}
	*chanlist_sz = cp;
    return 1;
}

/* Channel control callback; actually set a channel.  Determines if our
 * custom channel needs a VHT frequency set. */
int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan,
        char *msg) {

    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    local_channel_t *channel = (local_channel_t *) privchan;
    char errstr[STATUS_MAX];
    char chanstr[STATUS_MAX];

    struct timespec chanset_start_tm;
    long time_diff;

    if (privchan == NULL) {
        return 0;
    }

    chanset_start_tm = ns_measure_timer_start();
    setifchan(local_wifi->interface, wifi_freq_to_chan(channel->control_freq), 0);
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

    local_wifi->seq_channel_failure = 0;
    if (seqno != 0) {
        /* Send a config response with a reconstituted channel if we're
        * configuring the interface; re-use errstr as a buffer */
        local_channel_to_str(channel, errstr);
        cf_send_configresp(caph, seqno, 1, NULL, errstr);
    }

    return 1;
}


int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    return 1;
}

int build_first_localdev_filter(char **filter) {
    return 0;
}

int build_named_filters(char **interfaces, int num_interfaces, char **filter) {
    return 0;
}

int build_explicit_filters(char **stringmacs, int num_macs, char **filter) {
    return 0;
}


int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
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

    struct ether_addr *hwaddr = malloc(sizeof *hwaddr);

    char errstr[STATUS_MAX];
    char errstr2[STATUS_MAX];
    char pcap_errstr[PCAP_ERRBUF_SIZE] = "";

    unsigned int default_ht_20 = 0;
    unsigned int expand_ht_20 = 0;

    *uuid = NULL;
    *dlt = 0;

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    int ret;

    /* char regdom[5]; */

    char driver[32] = "";

    char *localchanstr = NULL;
    local_channel_t *localchan = NULL;

    int filter_locals = 0;
    char *ignore_filter = NULL;
    struct bpf_program bpf;

    int i;

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

    /* Get the index of the base name */
    if ((local_wifi->mac80211_ifidx = if_nametoindex(local_wifi->interface)) < 0) {
        snprintf(errstr, STATUS_MAX, "Could not find interface index for '%s'", local_wifi->interface);
        return -1;
    }

    // NOTE: LEFT OUT SOME LINUX RELATED STUFF HERE!!!

    /* set a random MAC */
    
    setiflladdr(local_wifi, hwaddr);

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name
     * and the mac address of the device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strndup(placeholder, placeholder_len);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
                adler32_csum((unsigned char *) "kismet_cap_openbsd_wifi",
                    strlen("kismet_cap_openbsd_wifi")) & 0xFFFFFFFF,
                hwaddr->ether_addr_octet[0] & 0xFF, hwaddr->ether_addr_octet[1] & 0xFF,
		hwaddr->ether_addr_octet[2] & 0xFF, hwaddr->ether_addr_octet[3] & 0xFF,
		hwaddr->ether_addr_octet[4] & 0xFF, hwaddr->ether_addr_octet[5] & 0xFF);
        *uuid = strdup(errstr);
    }
    free(hwaddr);

    /* set monitor mode */
    setifxflags(local_wifi, IFXF_MONITOR);
    /* bring up the interface */
    setifflags(local_wifi, IFF_UP);

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

    local_wifi->cap_interface = strdup(local_wifi->interface);

    ret = populate_chanlist(caph, local_wifi->cap_interface, errstr, default_ht_20, expand_ht_20,
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));
    if (ret < 0) {
        fprintf(stderr, "CAPTURE_OPENBSD_WIFI open_callback: populate_chanlist failed\n");
        return -1;
    }



    (*ret_interface)->hardware = strdup(driver);

    /* Open the pcap */
    local_wifi->pd = pcap_open_live(local_wifi->cap_interface,
            MAX_PACKET_LEN, 1, 1000, pcap_errstr);

    if (local_wifi->pd == NULL || strlen(pcap_errstr) != 0) {
        snprintf(msg, STATUS_MAX, "%s could not open capture interface '%s' on '%s' "
                "as a pcap capture: %s", local_wifi->name, local_wifi->cap_interface,
                local_wifi->interface, pcap_errstr);
        return -1;
    }

    if (pcap_set_datalink(local_wifi->pd, DLT_IEEE802_11_RADIO) || strlen(pcap_errstr) != 0) {
        snprintf(msg, STATUS_MAX, "%s could not set datalink to DLT_IEEE802_11_RADIO '%s' on '%s' "
                "on live capture: %s", local_wifi->name, local_wifi->cap_interface,
                local_wifi->interface, pcap_errstr);
        return -1;
    }

    if (local_wifi->wardrive_filter) {
        if (pcap_datalink(local_wifi->pd) == DLT_IEEE802_11_RADIO) {
            bpf.bf_len = rt_pgm_len;
            bpf.bf_insns = rt_pgm;
            if (pcap_setfilter(local_wifi->pd, &bpf) < 0) {
                snprintf(errstr, STATUS_MAX, "%s unable to install management packet filter: %s",
                         local_wifi->name, pcap_geterr(local_wifi->pd));
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
            }
        } else if (pcap_datalink(local_wifi->pd) == DLT_IEEE802_11) {
            bpf.bf_len = dot11_pgm_len;
            bpf.bf_insns = dot11_pgm;
            if (pcap_setfilter(local_wifi->pd, &bpf) < 0) {
                snprintf(errstr, STATUS_MAX, "%s unable to install management packet filter: %s",
                         local_wifi->name, pcap_geterr(local_wifi->pd));
                cf_send_message(caph, errstr, MSGFLAG_ERROR);
            }
        } else {
            snprintf(errstr, STATUS_MAX, "%s unable to install management packet filter on unknown link type %u/%s",
                     local_wifi->name, pcap_datalink(local_wifi->pd),
                     pcap_datalink_val_to_name(pcap_datalink(local_wifi->pd)));
            cf_send_message(caph, errstr, MSGFLAG_ERROR);
        }
    } else if (local_wifi->data_filter) {
        if (pcap_datalink(local_wifi->pd) == DLT_IEEE802_11_RADIO) {
            bpf.bf_len = rt_pgm_crop_data_len;
            bpf.bf_insns = rt_pgm_crop_data;
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

    snprintf(msg, STATUS_MAX, "%s OpenBSD Wi-Fi capturing from interface '%s'",
            local_wifi->name, local_wifi->interface);

    if (local_wifi->base_phy != NULL) {
        /*
        char ifbuf[1024];
        snprintf(ifbuf, 1024, "%s:%s", local_wifi->base_phy, local_wifi->cap_interface);
        (*ret_interface)->capif = strdup(ifbuf);
        */
        (*ret_interface)->capif = strdup(local_wifi->cap_interface);
    } else {
        (*ret_interface)->capif = strdup(local_wifi->cap_interface);
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "channel", definition)) > 0) {
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

    if (localchan != NULL) {
        free(localchan);
        localchan = NULL;
    }

    snprintf(errstr2, STATUS_MAX, "%s finished configuring %s, ready to capture",
            local_wifi->name, local_wifi->cap_interface);
    cf_send_message(caph, errstr2, MSGFLAG_INFO);

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces) {

    /* Basic list of devices */
    typedef struct wifi_list {
        char *device;
        char *flags;
        char *driver;
        struct wifi_list *next;
    } wifi_list_t;

    wifi_list_t *devs = NULL;
    size_t num_devs = 0;	

        struct ifgroupreq        ifgr;
        struct ifg_req          *ifg;
        int                      len, i = 0;

        getsock(AF_INET);
        bzero(&ifgr, sizeof(ifgr));
        strlcpy(ifgr.ifgr_name, "wlan", sizeof(ifgr.ifgr_name));
        if (ioctl(sock, SIOCGIFGMEMB, (caddr_t)&ifgr) == -1) {
                if (errno == EINVAL || errno == ENOTTY ||
                    errno == ENOENT)
			// there may be no interfaces in the wlan group
                        return (0);
        }

        len = ifgr.ifgr_len;
        if ((ifgr.ifgr_groups = calloc(1, len)) == NULL)
    		fprintf(stderr, "CAPTURE_OPENBSD_WIFI list_callback calloc problem\n");
        if (ioctl(sock, SIOCGIFGMEMB, (caddr_t)&ifgr) == -1)
    		fprintf(stderr, "CAPTURE_OPENBSD_WIFI list_callback SIOCGIFGMEMB failed: %s\n", ifgr.ifgr_name);
        for (ifg = ifgr.ifgr_groups; ifg && len >= sizeof(struct ifg_req); ifg++) {
		len -= sizeof(struct ifg_req);
		wifi_list_t *d = (wifi_list_t *) malloc(sizeof(wifi_list_t));
		num_devs++;
		d->device = strdup(ifg->ifgrq_member);
		d->flags = NULL;
		d->driver = NULL;
		d->next = devs;
		devs = d;
        }
        free(ifgr.ifgr_groups);
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

    /* Try repeatedly to send the packet; go into a thread wait state if
     * the write buffer is full & we'll be woken up as soon as it flushes
     * data out in the main select() loop */
    struct timeval ts;
    ts.tv_sec = header->ts.tv_sec;
    ts.tv_usec = header->ts.tv_usec;
    while (1) {
        if ((ret = cf_send_data(caph, 
                        NULL, NULL, NULL,
                        ts, 
                        local_wifi->datalink_type,
                        header->caplen, (uint8_t *) data)) < 0) {
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

    fprintf(stderr, "CAPTURE_OPENBSD_WIFI launched on pid %d\n", getpid());

    kis_capture_handler_t *caph = cf_handler_init("openbsdwifi");

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

    cf_handler_free(caph);

    return 1;
}

