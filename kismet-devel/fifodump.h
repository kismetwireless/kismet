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

// Write a pcap/wtap compatable data dump to a FIFO pipe.

#ifndef __FIFODUMP_H__
#define __FIFODUMP_H__

#include "config.h"

#include <stdio.h>
#include "packet.h"
#include "dumpfile.h"

#define PCAP_MAGIC          0xa1b2c3d4

class FifoDumpFile : public virtual DumpFile {
public:
    int OpenDump(const char *file);

    int CloseDump();

    int DumpPacket(const packet_info *in_info, const kis_packet *packet);

protected:
    /* Stolen from libwiretap */

    /* "libpcap" file header (minus magic number). */
    struct pcap_hdr {
        uint16_t version_major;  /* major version number */
        uint16_t version_minor;  /* minor version number */
        int32_t  thiszone;   /* GMT to local correction */
        uint32_t sigfigs;    /* accuracy of timestamps */
        uint32_t snaplen;    /* max length of captured packets, in octets */
        uint32_t network;    /* data link type */
    };
    /* "libpcap" record header. */
    struct pcaprec_hdr {
        uint32_t ts_sec;     /* timestamp seconds */
        uint32_t ts_usec;    /* timestamp microseconds */
        uint32_t incl_len;   /* number of octets of packet saved in file */
        uint32_t orig_len;   /* actual length of packet */
    };

    FILE *dump_file;

    uint8_t mangle_data[MAX_PACKET_LEN];
    uint8_t mangle_moddata[MAX_PACKET_LEN];
    kis_packet mangle_packet;


};

#endif

