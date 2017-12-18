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

#ifndef __LINUX_NEXMON_CONTROL_H__
#define __LINUX_NEXMON_CONTROL_H__

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <net/if.h>

struct nexmon_t {
    int sock_rx_ioctl;
    int sock_rx_frame;
    int sock_tx;
    int securitycookie;
};

struct nexmon_t *init_nexmon(const char *ifname);
int nexmon_monitor(struct nexmon_t *nmon);

#endif

