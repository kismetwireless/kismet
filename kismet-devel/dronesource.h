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

#ifndef __DRONESOURCE_H__
#define __DRONESOURCE_H__

#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

#include "packetsource.h"
#include "packetstream.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

class DroneSource : public KisPacketSource {
public:
    int OpenSource(const char *dev, card_type ctype);

    int CloseSource();

    int FetchDescriptor() { return drone_fd; }

    int FetchPacket(kis_packet *packet);

protected:
    int Drone2Common(kis_packet *packet);

    int valid;

    short int port;
    char hostname[MAXHOSTNAMELEN];

    int drone_fd;

    struct sockaddr_in drone_sock, local_sock;
    struct hostent *drone_host;

    stream_frame_header fhdr;
    stream_packet_header phdr;
    uint8_t data[MAX_PACKET_LEN];
};

// ifdef
#endif
