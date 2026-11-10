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

#ifndef __UWIFI_GENL_H__
#define __UWIFI_GENL_H__

/* Minimal generic netlink client on a raw socket, without libnl.  Built against the
 * system's Linux headers, not kcompat's, so the interface uses no kernel types. */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define UWIFI_GENL_MSG_MAX 8192
#define UWIFI_GENL_ATTR_MAX 512

struct uwifi_genl;

struct uwifi_genl_msg {
    uint8_t buf[UWIFI_GENL_MSG_MAX];
    size_t len;
    bool overflow;
};

/* A received attribute; data is NULL when absent */
struct uwifi_genl_attr {
    const void *data;
    uint16_t len;
};

/* Opens a socket and resolves the family's id; NULL with errno set if either fails */
struct uwifi_genl *uwifi_genl_open(const char *family);
void uwifi_genl_close(struct uwifi_genl *g);
int uwifi_genl_fd(const struct uwifi_genl *g);
/* Joins a multicast group of the family by name */
int uwifi_genl_join(struct uwifi_genl *g, const char *group);

/* flags are NLM_F_* in addition to NLM_F_REQUEST */
void uwifi_genl_msg_init(struct uwifi_genl *g, struct uwifi_genl_msg *m, uint8_t cmd, uint16_t flags);
void uwifi_genl_put(struct uwifi_genl_msg *m, uint16_t type, const void *data, size_t len);
void uwifi_genl_put_u32(struct uwifi_genl_msg *m, uint16_t type, uint32_t v);
void uwifi_genl_put_u64(struct uwifi_genl_msg *m, uint16_t type, uint64_t v);
void uwifi_genl_put_str(struct uwifi_genl_msg *m, uint16_t type, const char *s);
void uwifi_genl_put_flag(struct uwifi_genl_msg *m, uint16_t type);

/* Sends; safe to call from several threads.  Returns 0 or a negative errno. */
int uwifi_genl_send(struct uwifi_genl *g, struct uwifi_genl_msg *m);

/* Called for each generic netlink message received: cmd and its top-level attributes,
 * indexed by type up to max */
typedef void (*uwifi_genl_cb_t)(void *ctx, uint8_t cmd, const struct uwifi_genl_attr *attrs, int max);

/* Receives one datagram and calls cb for each message in it.  Returns 1 if it held the
 * end of a dump, an acknowledgement or an error reply, 0 otherwise, or a negative errno if
 * the socket failed. */
int uwifi_genl_recv(struct uwifi_genl *g, uwifi_genl_cb_t cb, void *ctx, int max);

/* Sends a request with NLM_F_ACK (and NLM_F_DUMP if dump) and calls cb for each reply until
 * the kernel acknowledges it or ends the dump; for a socket no other thread receives on.
 * Returns the kernel's acknowledgement: 0, a negative errno, or a command's positive
 * result. */
int uwifi_genl_request(struct uwifi_genl *g, struct uwifi_genl_msg *m, bool dump, uwifi_genl_cb_t cb,
        void *ctx, int max);

/* Parses nested attributes */
void uwifi_genl_parse(const void *data, size_t len, struct uwifi_genl_attr *attrs, int max);

static inline uint32_t uwifi_genl_u32(const struct uwifi_genl_attr *a) {
    uint32_t v = 0;
    if (a->data && a->len >= 4)
        __builtin_memcpy(&v, a->data, 4);
    return v;
}

static inline uint64_t uwifi_genl_u64(const struct uwifi_genl_attr *a) {
    uint64_t v = 0;
    if (a->data && a->len >= 8)
        __builtin_memcpy(&v, a->data, 8);
    return v;
}

#endif
