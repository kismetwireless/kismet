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

#include "wtapfilesource.h"

#ifdef HAVE_LIBWIRETAP

int WtapFileSource::OpenSource(const char *dev, card_type ctype) {
    snprintf(type, 64, "Wtap Save File");

    paused = 0;

    int err;

    packfile = wtap_open_offline(dev, &err, false);
    if (packfile == NULL) {
        snprintf(errstr, 1024, "Wtap file source unable to open %s: %s",
                 dev, strerror(err));
        return -1;
    }

    snprintf(errstr, 1024, "Wtap file source opened %s", dev);
    return 1;
}

int WtapFileSource::CloseSource() {

    if (packfile != NULL)
        wtap_close(packfile);
    return 1;
}

int WtapFileSource::FetchPacket(pkthdr *in_header, u_char *in_data) {
    int err;
    long int offset;

#ifdef HAVE_WTAPREAD_INTINT
    if (!wtap_read(packfile, &err, (int *) &offset)) 
#else
    if (!wtap_read(packfile, &err, &offset))
#endif
    {
        snprintf(errstr, 1024, "Wtap file source failed to read packet.");
        return -1;
    }

    packet_header = wtap_phdr(packfile);

    if (packet_header == NULL) {
        snprintf(errstr, 1024, "Wtap file source failed to read header.\n");
        return -1;
    }

    packet_data = wtap_buf_ptr(packfile);

    if (packet_data == NULL) {
        snprintf(errstr, 1024, "Wtap file source failed to read data.\n");
        return -1;
    }

    if (paused)
        return 0;

    Wtap2Common(in_header, in_data);

    return(in_header->len);

}

int WtapFileSource::Wtap2Common(pkthdr *in_header, u_char *in_data) {

    memset(in_header, 0, sizeof(pkthdr));
    memset(in_data, 0, MAX_PACKET_LEN);

    in_header->caplen = packet_header->caplen;

    if (packet_header->caplen > MAX_PACKET_LEN)
        in_header->len = MAX_PACKET_LEN;
    else
        in_header->len = packet_header->caplen;

    in_header->quality = -1;
    in_header->signal = -1;
    in_header->noise = -1;

    in_header->ts.tv_sec = packet_header->ts.tv_sec;
    in_header->ts.tv_usec = packet_header->ts.tv_usec;

    memcpy(in_data, packet_data, in_header->len);

    return 1;
}


#endif

