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

#ifndef __WIRED_FILTER_H__
#define __WIRED_FILTER_H__

/* The filter check, apart from wired_util so that and its tests and fuzzers
 * don't need libpcap */

#include <stdio.h>

#include <pcap.h>

#include "wired_util.h"

/* Any netmask but PCAP_NETMASK_UNKNOWN; it only tells apart a filter needing one */
#define WIRED_CHECK_NETMASK     0xffffff00U

/* The filter compiled for Ethernet without the interface, with its netmask
 * (PCAP_NETMASK_UNKNOWN when it has no IPv4 address), so a mistake fails the open
 * before the interface is brought up.  Returns 1 when it compiles, 0 when it
 * only would given a netmask ('ip broadcast'), or -1, with libpcap's error in
 * err; a filter wrong either way gets the error from the compile with one */
static inline int wired_filter_check(const char *filter, bpf_u_int32 netmask, char *err,
        size_t err_len) {
    struct bpf_program prog;
    pcap_t *dead;
    int r = -1;

    if ((dead = pcap_open_dead(DLT_EN10MB, (int) WIRED_SNAPLEN_MAX)) == NULL) {
        snprintf(err, err_len, "out of memory");
        return -1;
    }

    if (pcap_compile(dead, &prog, filter, 1, netmask) == 0) {
        pcap_freecode(&prog);
        r = 1;
    } else {
        snprintf(err, err_len, "%s", pcap_geterr(dead));

        if (netmask == PCAP_NETMASK_UNKNOWN) {
            if (pcap_compile(dead, &prog, filter, 1, WIRED_CHECK_NETMASK) == 0) {
                pcap_freecode(&prog);
                r = 0;
            } else {
                snprintf(err, err_len, "%s", pcap_geterr(dead));
            }
        }
    }

    pcap_close(dead);
    return r;
}

#endif
