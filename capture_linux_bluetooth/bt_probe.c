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

#include <string.h>
#include <strings.h>

#include "bt_probe.h"

static int match(const char *s, size_t len, const char *word) {
    size_t wl = strlen(word);
    return len == wl && strncasecmp(s, word, wl) == 0;
}

const char *bt_probe_mode_str(bt_probe_mode_t m) {
    switch (m) {
        case BT_PROBE_NAME:
            return "name";
        case BT_PROBE_INFO:
            return "info";
        default:
            return "off";
    }
}

int bt_probe_parse_mode(const char *s, size_t len, bt_probe_mode_t *out) {
    if (match(s, len, "off") || match(s, len, "false") || match(s, len, "none"))
        *out = BT_PROBE_OFF;
    else if (match(s, len, "name") || match(s, len, "names"))
        *out = BT_PROBE_NAME;
    else if (match(s, len, "info") || match(s, len, "true"))
        *out = BT_PROBE_INFO;
    else
        return 0;

    return 1;
}

int bt_probe_parse_interval(const char *s, size_t len, unsigned int *out) {
    unsigned int v = 0;
    size_t i;

    if (len == 0 || len > 6)
        return 0;

    for (i = 0; i < len; i++) {
        if (s[i] < '0' || s[i] > '9')
            return 0;
        v = v * 10 + (unsigned int) (s[i] - '0');
    }

    if (v < BT_PROBE_INTERVAL_MIN || v > BT_PROBE_INTERVAL_MAX)
        return 0;

    *out = v;
    return 1;
}

void bt_probe_parse_setting(const char *str, bt_probe_setting_t *out) {
    const char *eq;
    size_t klen, vlen;

    memset(out, 0, sizeof(*out));

    if (str == NULL) {
        out->result = BT_PROBE_SET_BAD_SYNTAX;
        return;
    }

    /* One setting per string */
    eq = strchr(str, '=');
    if (eq == NULL || eq == str || strchr(eq + 1, '=') != NULL || strchr(str, ',') != NULL) {
        out->result = BT_PROBE_SET_BAD_SYNTAX;
        return;
    }

    klen = (size_t) (eq - str);
    vlen = strlen(eq + 1);

    if (match(str, klen, "probe")) {
        if (!bt_probe_parse_mode(eq + 1, vlen, &out->mode)) {
            out->result = BT_PROBE_SET_BAD_VALUE;
            return;
        }
        out->has_mode = 1;
    } else if (match(str, klen, "probe_interval")) {
        if (!bt_probe_parse_interval(eq + 1, vlen, &out->interval)) {
            out->result = BT_PROBE_SET_BAD_VALUE;
            return;
        }
        out->has_interval = 1;
    } else {
        out->result = BT_PROBE_SET_UNKNOWN_KEY;
        return;
    }

    out->result = BT_PROBE_SET_OK;
}

void bt_probe_state_init(bt_probe_state_t *st) {
    memset(st, 0, sizeof(*st));
}

static unsigned int slot(const uint8_t *addr, uint8_t type) {
    /* FNV-1a over the address and its type */
    uint32_t h = 2166136261u;
    unsigned int i;

    for (i = 0; i < 6; i++) {
        h ^= addr[i];
        h *= 16777619u;
    }

    h ^= type;
    h *= 16777619u;

    return h % BT_PROBE_TABLE_SIZE;
}

int bt_probe_offer(bt_probe_state_t *st, const uint8_t *addr, uint8_t type,
        time_t now, unsigned int interval) {
    bt_probe_entry_t *e = &st->table[slot(addr, type)];
    bt_probe_target_t *t;

    if (e->used && e->type == type && memcmp(e->addr, addr, 6) == 0 &&
            now >= e->last && (time_t) (now - e->last) < (time_t) interval)
        return 0;

    if (st->q_len >= BT_PROBE_QUEUE_SIZE)
        return 0;

    memcpy(e->addr, addr, 6);
    e->type = type;
    e->used = 1;
    e->last = now;

    t = &st->queue[(st->q_head + st->q_len) % BT_PROBE_QUEUE_SIZE];
    memcpy(t->addr, addr, 6);
    t->type = type;
    st->q_len++;

    return 1;
}

int bt_probe_offer_name(bt_probe_state_t *st, const uint8_t *addr, time_t now,
        unsigned int interval) {
    /* A type no connection uses keeps name requests apart in the table */
    const uint8_t type = 0x80;
    bt_probe_entry_t *e = &st->table[slot(addr, type)];

    if (e->used && e->type == type && memcmp(e->addr, addr, 6) == 0 &&
            now >= e->last && (time_t) (now - e->last) < (time_t) interval)
        return 0;

    memcpy(e->addr, addr, 6);
    e->type = type;
    e->used = 1;
    e->last = now;

    return 1;
}

int bt_probe_next(bt_probe_state_t *st, bt_probe_target_t *out) {
    if (st->q_len == 0)
        return 0;

    *out = st->queue[st->q_head];
    st->q_head = (st->q_head + 1) % BT_PROBE_QUEUE_SIZE;
    st->q_len--;

    return 1;
}

void bt_probe_flush(bt_probe_state_t *st) {
    st->q_head = 0;
    st->q_len = 0;
}
