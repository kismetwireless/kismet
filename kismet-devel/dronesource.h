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

// This needs to be rewritten to spin correctly and read data into a buffer and
// then return full packets.

class DroneSource : public KisPacketSource {
public:
    DroneSource(string in_name, string in_dev) : KisPacketSource(in_name, in_dev) { }

    int OpenSource();

    int CloseSource();

    int FetchDescriptor() { return drone_fd; }

    int FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata);

    // We don't have a channel on the drone, let the packets speak for themselves
    int FetchChannel() { return 0; }

protected:
    int Drone2Common(kis_packet *packet, uint8_t *data, uint8_t *moddata);

    int valid;

    int resyncs;

    short int port;
    char hostname[MAXHOSTNAMELEN];

    int drone_fd;

    struct sockaddr_in drone_sock, local_sock;
    struct hostent *drone_host;

    // How many bytes of the current stage do we have
    unsigned int stream_recv_bytes;
    // Queue of data
    stream_frame_header fhdr;
    stream_packet_header phdr;
    stream_version_packet vpkt;
    uint8_t databuf[MAX_PACKET_LEN];

    unsigned int resyncing;
};

// Nothing but a registrant for us
KisPacketSource *dronesource_registrant(string in_name, string in_device,
                                        char *in_err);


// ifdef
#endif
