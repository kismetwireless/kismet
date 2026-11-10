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

#ifndef __MM8108_KISMET_H__
#define __MM8108_KISMET_H__

/* The MM8108 through userspace-wifi, for the Kismet capture binary, free of kernel headers so
 * it can be used alongside capture_framework.h.
 *
 * userspace-wifi presents the MM8108 to mac80211 as a 5GHz radio: each 1, 2, 4 and 8MHz S1G
 * channel is a 20, 40, 80 and 160MHz 5GHz channel.  This translates back: channels are named
 * as Kismet names 802.11ah channels (27ah, one per channel number and so per width), and
 * frames get S1G radiotap, with the channel field in MHz on the 900MHz band and the driver's
 * S1G and kHz frequency TLVs. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct uwifi_dev;

struct mm_kis_iface {
    char ifname[40];
    char hardware[96];
};

typedef void (*mm_kis_log_t)(void *ctx, int level, const char *msg);
/* A radiotap header and an 802.11 frame, valid only during the call */
typedef void (*mm_kis_rx_t)(void *ctx, const uint8_t *rtap, size_t rtap_len, const uint8_t *frame,
        size_t frame_len);

/* Driver log messages at or below max_level (0 emergency .. 7 debug) go to log */
int mm_kis_init(const char *const *fw_paths, size_t n_paths, mm_kis_log_t log, void *ctx,
        int max_level);

/* MM8108 adapters, without opening them; free with free() */
int mm_kis_list(struct mm_kis_iface **list, size_t *n);
bool mm_kis_find(const char *ifname, char *hardware, size_t hw_len);

/* Opens an adapter and boots it.  firmware and boardfile are file names in the firmware
 * directories, NULL for the chip's own; country is the region when the adapter doesn't lock
 * one, NULL for US. */
struct uwifi_dev *mm_kis_open(const char *ifname, const char *firmware, const char *boardfile,
        const char *country, char *error, size_t error_len);
void mm_kis_close(struct uwifi_dev *dev);
void mm_kis_exit(void);

bool mm_kis_alive(struct uwifi_dev *dev);
const uint8_t *mm_kis_mac(struct uwifi_dev *dev);
/* The region the adapter booted with */
const char *mm_kis_country(struct uwifi_dev *dev);
void mm_kis_hardware(struct uwifi_dev *dev, char *out, size_t len);
/* Space separated country codes with channel plans */
void mm_kis_countries(char *buf, size_t len);
bool mm_kis_country_known(const char *country);

/* Usable channels as Kismet names, of the widths in MHz listed in widths (comma separated,
 * NULL for all); free each and the array with free() */
int mm_kis_channels(struct uwifi_dev *dev, const char *widths, char ***list, size_t *n);

/* Parses 27ah or 27 for this adapter; NULL if it isn't a usable channel.  Free with free(). */
void *mm_kis_parse_channel(struct uwifi_dev *dev, const char *chanstr);
const char *mm_kis_channel_name(const void *chan);
/* Returns 0 when tuned */
int mm_kis_set_channel(struct uwifi_dev *dev, const void *chan);

int mm_kis_start(struct uwifi_dev *dev, mm_kis_rx_t rx, void *ctx);

#endif
