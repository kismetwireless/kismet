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

#include <errno.h>
#include <stdio.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/genetlink.h>
#include <linux/netlink.h>

#include "genl.h"

#define GENL_MCAST_GROUPS_MAX 16

struct uwifi_genl {
    int fd;
    uint16_t family;
    /* The family id from the control family, while opening */
    uint16_t resolved;
    /* From the last acknowledgement or error the kernel sent */
    int last_error;
    uint32_t seq;
    pthread_mutex_t send_lock;

    struct {
        char name[GENL_NAMSIZ];
        uint32_t id;
    } groups[GENL_MCAST_GROUPS_MAX];
    int n_groups;
};

static void genl_parse_attrs(const void *data, size_t len, struct uwifi_genl_attr *attrs, int max) {
    const struct nlattr *nla = data;

    memset(attrs, 0, sizeof(*attrs) * (size_t) (max + 1));

    while (len >= NLA_HDRLEN && nla->nla_len >= NLA_HDRLEN && nla->nla_len <= len) {
        int type = nla->nla_type & NLA_TYPE_MASK;

        if (type <= max) {
            attrs[type].data = (const uint8_t *) nla + NLA_HDRLEN;
            attrs[type].len = (uint16_t) (nla->nla_len - NLA_HDRLEN);
        }

        size_t step = NLA_ALIGN(nla->nla_len);
        if (step >= len)
            break;
        len -= step;
        nla = (const struct nlattr *) ((const uint8_t *) nla + step);
    }
}

void uwifi_genl_parse(const void *data, size_t len, struct uwifi_genl_attr *attrs, int max) {
    genl_parse_attrs(data, len, attrs, max);
}

void uwifi_genl_msg_init(struct uwifi_genl *g, struct uwifi_genl_msg *m, uint8_t cmd, uint16_t flags) {
    struct nlmsghdr *nlh = (struct nlmsghdr *) m->buf;
    struct genlmsghdr *gh = (struct genlmsghdr *) NLMSG_DATA(nlh);

    memset(m->buf, 0, NLMSG_HDRLEN + GENL_HDRLEN);
    nlh->nlmsg_type = g->family;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    gh->cmd = cmd;
    gh->version = 1;
    m->len = NLMSG_HDRLEN + GENL_HDRLEN;
    m->overflow = false;
}

void uwifi_genl_put(struct uwifi_genl_msg *m, uint16_t type, const void *data, size_t len) {
    struct nlattr *nla = (struct nlattr *) (m->buf + m->len);
    size_t total = NLA_ALIGN(NLA_HDRLEN + len);

    if (m->len + total > sizeof(m->buf) || NLA_HDRLEN + len > UINT16_MAX) {
        m->overflow = true;
        return;
    }

    nla->nla_type = type;
    nla->nla_len = (uint16_t) (NLA_HDRLEN + len);
    if (len)
        memcpy((uint8_t *) nla + NLA_HDRLEN, data, len);
    memset((uint8_t *) nla + NLA_HDRLEN + len, 0, total - NLA_HDRLEN - len);
    m->len += total;
}

void uwifi_genl_put_u32(struct uwifi_genl_msg *m, uint16_t type, uint32_t v) {
    uwifi_genl_put(m, type, &v, sizeof(v));
}

void uwifi_genl_put_u64(struct uwifi_genl_msg *m, uint16_t type, uint64_t v) {
    uwifi_genl_put(m, type, &v, sizeof(v));
}

void uwifi_genl_put_str(struct uwifi_genl_msg *m, uint16_t type, const char *s) {
    uwifi_genl_put(m, type, s, strlen(s) + 1);
}

void uwifi_genl_put_flag(struct uwifi_genl_msg *m, uint16_t type) {
    uwifi_genl_put(m, type, NULL, 0);
}

int uwifi_genl_send(struct uwifi_genl *g, struct uwifi_genl_msg *m) {
    struct nlmsghdr *nlh = (struct nlmsghdr *) m->buf;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    ssize_t r;

    if (m->overflow)
        return -EMSGSIZE;

    pthread_mutex_lock(&g->send_lock);
    nlh->nlmsg_len = (uint32_t) m->len;
    nlh->nlmsg_seq = ++g->seq;
    r = sendto(g->fd, m->buf, m->len, 0, (struct sockaddr *) &sa, sizeof(sa));
    pthread_mutex_unlock(&g->send_lock);

    return r < 0 ? -errno : 0;
}

int uwifi_genl_recv(struct uwifi_genl *g, uwifi_genl_cb_t cb, void *ctx, int max) {
    static __thread uint8_t buf[65536];
    struct uwifi_genl_attr *attrs;
    ssize_t n;
    int done = 0;

    if ((n = recv(g->fd, buf, sizeof(buf), 0)) < 0)
        return -errno;

    if ((attrs = calloc((size_t) max + 1, sizeof(*attrs))) == NULL)
        return -ENOMEM;

    for (struct nlmsghdr *nlh = (struct nlmsghdr *) buf; NLMSG_OK(nlh, (size_t) n); nlh = NLMSG_NEXT(nlh, n)) {
        if (nlh->nlmsg_type == NLMSG_DONE) {
            done = 1;
            continue;
        }

        if (nlh->nlmsg_type == NLMSG_ERROR) {
            const struct nlmsgerr *e = NLMSG_DATA(nlh);
            g->last_error = e->error;
            done = 1;
            continue;
        }

        if (nlh->nlmsg_type != g->family || nlh->nlmsg_len < NLMSG_HDRLEN + GENL_HDRLEN)
            continue;

        const struct genlmsghdr *gh = NLMSG_DATA(nlh);
        genl_parse_attrs((const uint8_t *) gh + GENL_HDRLEN, nlh->nlmsg_len - NLMSG_HDRLEN - GENL_HDRLEN,
                attrs, max);
        if (cb)
            cb(ctx, gh->cmd, attrs, max);
    }

    free(attrs);
    return done;
}

int uwifi_genl_request(struct uwifi_genl *g, struct uwifi_genl_msg *m, bool dump, uwifi_genl_cb_t cb,
        void *ctx, int max) {
    struct nlmsghdr *nlh = (struct nlmsghdr *) m->buf;
    int r;

    nlh->nlmsg_flags |= NLM_F_ACK | (dump ? NLM_F_DUMP : 0);
    if ((r = uwifi_genl_send(g, m)) < 0)
        return r;

    g->last_error = 0;
    while ((r = uwifi_genl_recv(g, cb, ctx, max)) == 0)
        ;

    return r < 0 ? r : g->last_error;
}

/* The control family's reply: the family id and its multicast groups */
static void genl_family_cb(void *ctx, uint8_t cmd, const struct uwifi_genl_attr *attrs, int max) {
    struct uwifi_genl *g = ctx;
    const struct uwifi_genl_attr *grps = &attrs[CTRL_ATTR_MCAST_GROUPS];
    (void) cmd;
    (void) max;

    if (attrs[CTRL_ATTR_FAMILY_ID].data && attrs[CTRL_ATTR_FAMILY_ID].len >= 2)
        memcpy(&g->resolved, attrs[CTRL_ATTR_FAMILY_ID].data, 2);

    if (grps->data == NULL)
        return;

    const struct nlattr *nla = grps->data;
    size_t len = grps->len;

    while (len >= NLA_HDRLEN && nla->nla_len >= NLA_HDRLEN && nla->nla_len <= len &&
            g->n_groups < GENL_MCAST_GROUPS_MAX) {
        struct uwifi_genl_attr ga[CTRL_ATTR_MCAST_GRP_MAX + 1];

        genl_parse_attrs((const uint8_t *) nla + NLA_HDRLEN, nla->nla_len - NLA_HDRLEN, ga, CTRL_ATTR_MCAST_GRP_MAX);
        if (ga[CTRL_ATTR_MCAST_GRP_NAME].data && ga[CTRL_ATTR_MCAST_GRP_ID].data) {
            snprintf(g->groups[g->n_groups].name, sizeof(g->groups[0].name), "%.*s",
                    (int) ga[CTRL_ATTR_MCAST_GRP_NAME].len, (const char *) ga[CTRL_ATTR_MCAST_GRP_NAME].data);
            g->groups[g->n_groups].id = uwifi_genl_u32(&ga[CTRL_ATTR_MCAST_GRP_ID]);
            g->n_groups++;
        }

        size_t step = NLA_ALIGN(nla->nla_len);
        if (step >= len)
            break;
        len -= step;
        nla = (const struct nlattr *) ((const uint8_t *) nla + step);
    }
}

struct uwifi_genl *uwifi_genl_open(const char *family) {
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct uwifi_genl_msg *m = NULL;
    struct uwifi_genl *g;
    int r;

    if ((g = calloc(1, sizeof(*g))) == NULL)
        return NULL;
    pthread_mutex_init(&g->send_lock, NULL);

    if ((g->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC)) < 0 ||
            bind(g->fd, (struct sockaddr *) &sa, sizeof(sa)) < 0 ||
            (m = malloc(sizeof(*m))) == NULL) {
        r = -errno;
        goto fail;
    }

    /* Ask the control family, whose replies are passed to the callback until the id is known */
    g->family = GENL_ID_CTRL;
    uwifi_genl_msg_init(g, m, CTRL_CMD_GETFAMILY, 0);
    uwifi_genl_put_str(m, CTRL_ATTR_FAMILY_NAME, family);
    if ((r = uwifi_genl_request(g, m, false, genl_family_cb, g, CTRL_ATTR_MAX)) < 0)
        goto fail;

    if (g->resolved == 0) {
        r = -ENOENT;
        goto fail;
    }

    g->family = g->resolved;
    free(m);
    return g;

fail:
    free(m);
    if (g->fd >= 0)
        close(g->fd);
    pthread_mutex_destroy(&g->send_lock);
    free(g);
    errno = -r;
    return NULL;
}

int uwifi_genl_join(struct uwifi_genl *g, const char *group) {
    for (int i = 0; i < g->n_groups; i++) {
        if (strcmp(g->groups[i].name, group) != 0)
            continue;
        if (setsockopt(g->fd, SOL_NETLINK, NETLINK_ADD_MEMBERSHIP, &g->groups[i].id, sizeof(g->groups[i].id)) < 0)
            return -errno;
        return 0;
    }
    return -ENOENT;
}

void uwifi_genl_close(struct uwifi_genl *g) {
    if (g == NULL)
        return;
    close(g->fd);
    pthread_mutex_destroy(&g->send_lock);
    free(g);
}

int uwifi_genl_fd(const struct uwifi_genl *g) {
    return g->fd;
}
