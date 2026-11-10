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

#ifndef __UWIFI_PCAP_H__
#define __UWIFI_PCAP_H__

/* Minimal radiotap pcap writer, safe to call from the receive thread, and reader */

#include <stddef.h>
#include <stdint.h>

struct uwifi_pcap;

/* A path of "-" writes to stdout, flushing each packet so it can be piped */
struct uwifi_pcap *uwifi_pcap_open(const char *path);
/* Returns 0, or -1 if the write failed */
int uwifi_pcap_write(struct uwifi_pcap *p, const uint8_t *data, size_t len);
void uwifi_pcap_close(struct uwifi_pcap *p);

#define UWIFI_DLT_IEEE802_11 105
#define UWIFI_DLT_IEEE802_11_RADIO 127

struct uwifi_pcap_reader;

/* Opens a pcap of either byte order and microsecond or nanosecond timestamps */
struct uwifi_pcap_reader *uwifi_pcap_read_open(const char *path, uint32_t *linktype);
/* Returns the packet length and points data at it until the next call; 0 at the end, -1
 * for a truncated or corrupt file */
int uwifi_pcap_read_next(struct uwifi_pcap_reader *r, const uint8_t **data);
void uwifi_pcap_read_close(struct uwifi_pcap_reader *r);

#endif
