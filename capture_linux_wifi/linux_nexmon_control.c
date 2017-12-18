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

#include <net/if.h>

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>

#include <stdbool.h>

#include <errno.h>

#include "linux_nexmon_control.h"

struct nexmon_t *init_nexmon(const char *ifname) {
    struct nexmon_t *nmon = (struct nexmon_t *) malloc(sizeof(struct nexmon_t));

    nmon->ifr = (struct ifreq *) malloc(sizeof(struct ifreq));
    memset(nmon->ifr, 0, sizeof(struct ifreq));
    snprintf(nmon->ifr->ifr_name, sizeof(nmon->ifr->ifr_name), "%s", ifname);

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

#define WLC_SET_MONITOR                 108
#define WLC_IOCTL_MAGIC          0x14e46c77

int nexmon_monitor(struct nexmon_t *nmon) {
    struct nex_ioctl ioc;
    uint32_t monitor_value = 2;
    int s, ret;

    ioc.cmd = WLC_SET_MONITOR;
    ioc.buf = &monitor_value;
    ioc.len = 4;
    ioc.set = true;
    ioc.driver = WLC_IOCTL_MAGIC;

    nmon->ifr->ifr_data = (void *) &ioc;

    if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0) 
        return -1;

    ret = ioctl(s, SIOCDEVPRIVATE, nmon->ifr);

    if (ret < 0 && errno != EAGAIN)
        return -1;

    close(s);
    return ret;
}

