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

/* Opt-in active probing for the Linux HCI source.
 *
 * Probing transmits: it asks devices for their names, or connects to them to
 * read the controller's version and features, so it is off unless the source
 * line or a runtime setting turns it on:
 *
 *     probe=off|name|info      name: resolve names of classic devices
 *                              info: names, plus connect and read version/features
 *     probe_interval=<sec>     least time between probes of one device
 *
 * At runtime the same key=value strings arrive through set_channel, like the
 * cell sources' settings.
 */

#ifndef __BT_PROBE_H__
#define __BT_PROBE_H__

#include <stddef.h>
#include <stdint.h>
#include <time.h>

typedef enum {
    BT_PROBE_OFF = 0,
    BT_PROBE_NAME = 1,
    BT_PROBE_INFO = 2,
} bt_probe_mode_t;

#define BT_PROBE_INTERVAL_DEFAULT 600
#define BT_PROBE_INTERVAL_MIN 60
#define BT_PROBE_INTERVAL_MAX 86400

typedef enum {
    BT_PROBE_SET_OK = 0,
    BT_PROBE_SET_BAD_SYNTAX,
    BT_PROBE_SET_UNKNOWN_KEY,
    BT_PROBE_SET_BAD_VALUE,
} bt_probe_set_result_t;

/* One key=value setting */
typedef struct {
    bt_probe_set_result_t result;
    int has_mode;
    bt_probe_mode_t mode;
    int has_interval;
    unsigned int interval;
} bt_probe_setting_t;

const char *bt_probe_mode_str(bt_probe_mode_t m);
int bt_probe_parse_mode(const char *s, size_t len, bt_probe_mode_t *out);
int bt_probe_parse_interval(const char *s, size_t len, unsigned int *out);

void bt_probe_parse_setting(const char *str, bt_probe_setting_t *out);

/* When each device was last probed; a direct-mapped table, so a collision only
 * lets a device be probed again early */
#define BT_PROBE_TABLE_SIZE 4096

typedef struct {
    uint8_t addr[6];
    uint8_t type;
    uint8_t used;
    time_t last;
} bt_probe_entry_t;

/* Devices waiting to be probed */
#define BT_PROBE_QUEUE_SIZE 64

typedef struct {
    uint8_t addr[6];
    uint8_t type;
} bt_probe_target_t;

typedef struct {
    bt_probe_entry_t table[BT_PROBE_TABLE_SIZE];
    bt_probe_target_t queue[BT_PROBE_QUEUE_SIZE];
    unsigned int q_head;
    unsigned int q_len;
} bt_probe_state_t;

void bt_probe_state_init(bt_probe_state_t *st);

/* Queue a device unless it was probed or queued within interval seconds;
 * returns 1 when queued */
int bt_probe_offer(bt_probe_state_t *st, const uint8_t *addr, uint8_t type,
        time_t now, unsigned int interval);

/* Ask for the name of a classic device unless it was asked for within interval
 * seconds; returns 1 when the name should be resolved */
int bt_probe_offer_name(bt_probe_state_t *st, const uint8_t *addr, time_t now,
        unsigned int interval);

/* Take the next queued device; returns 1 when there was one */
int bt_probe_next(bt_probe_state_t *st, bt_probe_target_t *out);

void bt_probe_flush(bt_probe_state_t *st);

#endif
