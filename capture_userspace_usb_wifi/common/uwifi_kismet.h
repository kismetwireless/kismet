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

#ifndef __UWIFI_KISMET_H__
#define __UWIFI_KISMET_H__

/* Interface for the Kismet capture binary, free of kernel headers so it can be used
 * alongside capture_framework.h.
 *
 * Channels use Kismet's Wi-Fi names, as the Linux Wi-Fi datasource does:
 *   N, NHT20       20MHz on 2.4GHz or 5GHz
 *   NHT40+, NHT40- 40MHz with the secondary above or below
 *   NVHT80, NVHT160, NVHT80-C, NVHT160-C
 *                  80 or 160MHz, centre from the channel table or C (MHz or channel)
 *   NW6e           20MHz on 6GHz */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

struct uwifi_dev;

struct uwifi_kis_iface {
    char ifname[40];
    char hardware[96];
};

typedef void (*uwifi_kis_log_t)(void *ctx, int level, const char *msg);
/* data is a radiotap header and 802.11 frame, valid only during the call */
typedef void (*uwifi_kis_rx_t)(void *ctx, const uint8_t *data, size_t len);

/* Driver log messages at or below max_level (0 emergency .. 7 debug) go to log */
int uwifi_kis_init(const char *const *fw_paths, size_t n_paths, uwifi_kis_log_t log, void *ctx,
        int max_level);

/* Lists adapters without opening them; free with free() */
int uwifi_kis_list(struct uwifi_kis_iface **list, size_t *n);

/* Opens an adapter by interface name and loads firmware; error describes a failure */
struct uwifi_dev *uwifi_kis_open(const char *ifname, char *error, size_t error_len);
void uwifi_kis_close(struct uwifi_dev *dev);

bool uwifi_kis_alive(struct uwifi_dev *dev);
const uint8_t *uwifi_kis_mac(struct uwifi_dev *dev);
void uwifi_kis_hardware(struct uwifi_dev *dev, char *out, size_t len);

/* Every supported channel in Kismet names; free each and the array with free() */
int uwifi_kis_channels(struct uwifi_dev *dev, bool ht, bool vht, char ***list, size_t *n);

/* Parses a Kismet channel for this adapter; NULL if invalid.  Free with free(). */
void *uwifi_kis_parse_channel(struct uwifi_dev *dev, const char *chanstr, char *error, size_t error_len);
/* Returns 1 when tuned, 0 if the driver or firmware rejected the channel */
int uwifi_kis_set_channel(struct uwifi_dev *dev, const void *chan);
const char *uwifi_kis_channel_name(const void *chan);

int uwifi_kis_set_country(struct uwifi_dev *dev, const char *alpha2);
int uwifi_kis_start(struct uwifi_dev *dev, uwifi_kis_rx_t rx, void *ctx);

#endif
