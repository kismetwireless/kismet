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

    if (wtap_file_encap(packfile) != WTAP_ENCAP_IEEE_802_11) {
        snprintf(errstr, 1024, "Wtap file '%s' not an 802.11 encapsulation.", dev);
        return -1;
    }

    num_packets = 0;

    snprintf(errstr, 1024, "Wtap file source opened %s", dev);
    return 1;
}

int WtapFileSource::CloseSource() {

    if (packfile != NULL)
        wtap_close(packfile);
    return 1;
}

int WtapFileSource::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
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

    Wtap2Common(packet, data, moddata);

    num_packets++;

    usleep(1);
    return(packet->caplen);

}

int WtapFileSource::Wtap2Common(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    memset(packet, 0, sizeof(kis_packet));

    packet->caplen = kismin(packet_header->caplen, (uint32_t) MAX_PACKET_LEN);
    packet->len = packet->caplen;

    packet->quality = -1;
    packet->signal = -1;
    packet->noise = -1;

    packet->ts.tv_sec = packet_header->ts.tv_sec;
    packet->ts.tv_usec = packet_header->ts.tv_usec;

    packet->data = data;
    packet->moddata = moddata;
    packet->modified = 0;

    // We don't use GPS for wtapfiles
    /*
    if (gpsd != NULL) {
        gps->FetchLoc(&packet->gps_lat, &packet->gps_lon, &packet->gps_alt,
                      &packet->gps_spd, &packet->gps_fix);
    }
    */

    memcpy(packet->data, packet_data, packet->caplen);

    // We assume all packets are 802.11b for now
    packet->carrier = carrier_80211b;

    return 1;
}

int WtapFileSource::SetChannel(unsigned int chan) {

    return 1;
}


#endif

