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

#ifndef __REMOTE_ANNOUNCEMENT_H__
#define __REMOTE_ANNOUNCEMENT_H__ 

#include <stdint.h>

/* A simple remote announcement packet */
#define REMOTE_ANNOUNCE_TAG         0x4b49534d4554 
#define REMOTE_ANNOUNCE_VERSION     1

typedef struct _kismet_remote_announce {
    uint64_t tag;
    uint16_t announce_version; /* Announcement version, BE */
    uint32_t server_port; /* Server capture port, BE */
    uint32_t remote_port; /* Remote capture port, BE */
    uint64_t server_ts_sec; /* Server timestamp in seconds, BE */
    uint64_t server_ts_usec; /* Server timestamp useconds, BE */
    char uuid[36]; /* NOT null terminated server UUID */
    char name[32]; /* NULL TERMINATED server name */
} __attribute__((packed)) kismet_remote_announce;

#endif /* ifndef REMOTE_ANNOUNCEMENT_H */
