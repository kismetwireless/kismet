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

/* Control the Nexmon drivers
 *
 * Definitions and control methods from the libnexio code in the
 * nexmon project
 */

#include "../config.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>


#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/netlink.h>

#include <stdbool.h>

#include <errno.h>

#include "linux_nexmon_control.h"

#define NETLINK_USER        31

struct nexmon_t *init_nexmon(const char *ifname) {
    struct nexmon_t *nmon = (struct nexmon_t *) malloc(sizeof(struct nexmon_t));

    int err = 0;
    struct sockaddr_nl *snl_tx = (struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));
    struct sockaddr_nl *snl_rx_ioctl = (struct sockaddr_nl *) malloc(sizeof(struct sockaddr_nl));
    struct timeval tv;

    memset(snl_tx, 0, sizeof(struct sockaddr_nl));
    memset(snl_rx_ioctl, 0, sizeof(struct sockaddr_nl));

    snl_tx->nl_family = AF_NETLINK;
    snl_tx->nl_pid = 0;
    snl_tx->nl_groups = 0;

    snl_rx_ioctl->nl_family = AF_NETLINK;
    snl_rx_ioctl->nl_pid = getpid();

    nmon->sock_tx = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (nmon->sock_tx < 0) {
        free(nmon);
        free(snl_tx);
        free(snl_rx_ioctl);
        return NULL;
    }

    nmon->sock_rx_ioctl = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (nmon->sock_rx_ioctl < 0) {
        close(nmon->sock_tx);
        free(nmon);
        free(snl_tx);
        free(snl_rx_ioctl);
        return NULL;
    }

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(nmon->sock_rx_ioctl, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    err = bind(nmon->sock_rx_ioctl, (struct sockaddr *) snl_rx_ioctl, sizeof(struct sockaddr));
    if (err) {
        close(nmon->sock_tx);
        close(nmon->sock_rx_ioctl);
        free(nmon);
        free(snl_tx);
        free(snl_rx_ioctl);
        return NULL;
    }

    err = connect(nmon->sock_tx, (struct sockaddr *) snl_tx, sizeof(struct sockaddr));
    if (err) {
        close(nmon->sock_tx);
        close(nmon->sock_rx_ioctl);
        free(nmon);
        free(snl_tx);
        free(snl_rx_ioctl);
        return NULL;
    }

    return nmon;
}

struct nex_ioctl {
    unsigned int cmd;   	/* common ioctl definition */
    void *buf;  			/* pointer to user buffer */
    unsigned int len;   	/* length of user buffer */
    bool set;   			/* get or set request (optional) */
    unsigned int used;  	/* bytes read or written (optional) */
    unsigned int needed;    /* bytes needed (optional) */
    unsigned int driver;    /* to identify target driver */
};

struct nexudp_header {
    char nex[3];
    char type;
    int securitycookie;
} __attribute__((packed));

struct nexudp_ioctl_header {
    struct nexudp_header nexudphdr;
    unsigned int cmd;
    unsigned int set;
    char payload[1];
} __attribute__((packed));

#define NEXUDP_IOCTL            		  0
#define WLC_SET_MONITOR                 108
#define WLC_IOCTL_MAGIC          0x14e46c77

int nexmon_monitor(struct nexmon_t *nmon) {
    struct nex_ioctl ioc;
    uint32_t monitor_value = 2;
    int ret = 0;

    ioc.cmd = WLC_SET_MONITOR;
    ioc.buf = &monitor_value;
    ioc.len = 4;
    ioc.set = true;
    ioc.driver = WLC_IOCTL_MAGIC;

    int frame_len = ioc.len + sizeof(struct nexudp_ioctl_header) - sizeof(char);
    int rx_frame_len = 0;
    struct nexudp_ioctl_header *frame;

    struct nlmsghdr *nlh = (struct nlmsghdr *) malloc(NLMSG_SPACE(frame_len));
    memset(nlh, 0, NLMSG_SPACE(frame_len));
    nlh->nlmsg_len = NLMSG_SPACE(frame_len);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    frame = (struct nexudp_ioctl_header *) NLMSG_DATA(nlh);

    memcpy(&frame->nexudphdr.nex, "NEX", 3);
    frame->nexudphdr.type = NEXUDP_IOCTL;
    frame->nexudphdr.securitycookie = nmon->securitycookie;

    frame->cmd = ioc.cmd;
    frame->set = ioc.set;

    memcpy(frame->payload, ioc.buf, ioc.len);

    send(nmon->sock_tx, nlh, nlh->nlmsg_len, 0);

    rx_frame_len = recv(nmon->sock_rx_ioctl, nlh, nlh->nlmsg_len, 0);

    free(nlh);

    if (rx_frame_len < 0) {
        ret = -1;
    }

    return ret;
}

