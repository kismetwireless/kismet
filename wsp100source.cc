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

/*
    WSP100 support added by Chris Waters.  chris.waters@networkchemistry.com

    This supports the WSP100 device under Cygwin and Linux

    2/6/2003 - gherlein@herlein.com added TZSP NULL packet generation
    to support late model firmware requirement for this
    heartbeat packet.  Must be sent within every 32 sec and
    must come from the listen port of kismet.

*/

#include "config.h"

#include "wsp100source.h"

#ifdef HAVE_WSP100

#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <fcntl.h>

// Straight-C callback
int Wsp100PokeSensor(server_timer_event *evt, void *call_parm) {
    // Poke it
    ((Wsp100Source *) call_parm)->PokeSensor();

    // And we want to use the event record over again - that is, obey the
    // recurrance field
    return 1;
}

// Build UDP listener code

int Wsp100Source::OpenSource(const char *dev, card_type ctype) {
    char listenhost[1024];
    struct hostent *filter_host;

    snprintf(type, 64, "WSP100 Remote Sensor on %s", dev);
    cardtype = ctype;

    // Device is handled as a host:port pair - remote host we accept data
    // from, local port we open to listen for it.  yeah, it's a little weird.
    if (sscanf(dev, "%1024[^:]:%hd", listenhost, &port) < 2) {
        snprintf(errstr, 1024, "Couldn't parse host:port: '%s'", dev);
        return -1;
    }

    if ((filter_host = gethostbyname(listenhost)) == NULL) {
        snprintf(errstr, 1024, "Couldn't resolve host: '%s'", listenhost);
        return -1;
    }

    memcpy((char *) &filter_addr.s_addr, filter_host->h_addr_list[0], filter_host->h_length);

    if ((udp_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(errstr, 1024, "Couldn't create UDP socket: %s", strerror(errno));
        return -1;
    }

    memset(&serv_sockaddr, 0, sizeof(serv_sockaddr));
    serv_sockaddr.sin_family = AF_INET;
    serv_sockaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_sockaddr.sin_port = htons(port);

    if (bind(udp_sock, (struct sockaddr *) &serv_sockaddr, sizeof(serv_sockaddr)) < 0) {
        snprintf(errstr, 1024, "Couldn't bind to UDP socket: %s", strerror(errno));
        return -1;
    }

    paused = 0;

    valid = 1;

    // Register 'poke' events
    poke_event_id = RegisterServerTimer(TZSP_NULL_PACKET_SLICE, NULL, 1,
                                        &Wsp100PokeSensor, (void *) this);

    return 1;
}

int Wsp100Source::CloseSource() {
    if (valid)
        close(udp_sock);

    valid = 0;

    RemoveServerTimer(poke_event_id);

    return 1;
}

int Wsp100Source::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    if (valid == 0)
        return 0;

    struct sockaddr_in cli_sockaddr;
#ifdef HAVE_SOCKLEN_T
    socklen_t cli_len;
#else
    int cli_len;
#endif
    cli_len = sizeof(cli_sockaddr);
    memset(&cli_sockaddr, 0, sizeof(cli_sockaddr));

    if ((read_len = recvfrom(udp_sock, (char *) data, MAX_PACKET_LEN, 0,
                             (struct sockaddr *) &cli_sockaddr, &cli_len)) < 0) {
        if (errno != EINTR) {
            snprintf(errstr, 1024, "recvfrom() error %d (%s)", errno, strerror(errno));
            return -1;
        }
    }

    // Find out if it came from an IP associated with our target sensor system
    if (cli_sockaddr.sin_addr.s_addr != filter_addr.s_addr)
        return 0;

    if (paused || Wsp2Common(packet, data, moddata) == 0) {
        return 0;
    }

    return(packet->caplen);
}

int Wsp100Source::Wsp2Common(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    memset(packet, 0, sizeof(kis_packet));

    uint16_t datalink_type = 0;
    datalink_type = kptoh16(&data[2]);

    if (datalink_type != KWTAP_ENCAP_IEEE_802_11) {
        return 0;
    }

    // Iterate through the dynamic list of tags
    uint8_t pos = 4;
    while (pos < read_len) {
        uint8_t tag, len = 0, bail = 0;
        tag = data[pos++];

        switch (tag) {
        case WSP100_TAG_PAD:
            len = 0;
            break;
        case WSP100_TAG_END:
            len = 0;
            bail = 1;
            break;
        case WSP100_TAG_RADIO_SIGNAL:
            len = data[pos++];
            packet->signal = data[pos];
            break;
        case WSP100_TAG_RADIO_NOISE:
            len = data[pos++];
            packet->noise = data[pos];
            break;
        case WSP100_TAG_RADIO_RATE:
            // We don't handle the rate yet
            len = data[pos++];
            break;
        case WSP100_TAG_RADIO_TIME:
            len = data[pos++];

            /*
             Either the packet timestamp or my decoding of it is broken, so put our
             own timestamp in

             time_sec = kptoh32(&data[pos]);
             in_header->ts.tv_sec = time_sec;
             */

            gettimeofday(&packet->ts, NULL);

            break;
        case WSP100_TAG_RADIO_MSG:
            // We don't really care about this since we get the packet type from
            // the packet contents later
            len = data[pos++];
            break;
        case WSP100_TAG_RADIO_CF:
            // What does this mean?  Ignore it for now.
            len = data[pos++];
            break;
        case WSP100_TAG_RADIO_UNDECR:
            // We don't really care about this, either
            len = data[pos++];
            break;
        case WSP100_TAG_RADIO_FCSERR:
            len = data[pos++];
            packet->error = data[pos];
            break;
        case WSP100_TAG_RADIO_CHANNEL:
            // We get this off the other data inside the packets so we ignore this...
            len = data[pos++];
            break;
        default:
            // Unknown tag, try to keep going by getting the length and skipping
            len = data[pos++];
            break;
        }

        pos += len;

        if (bail)
            break;
    }

    packet->caplen = read_len - pos;
    packet->len = packet->caplen;

    packet->data = data;
    packet->moddata = moddata;
    packet->modified = 0;

    memcpy(packet->data, data + pos, packet->caplen);

    packet->carrier = carrier_80211b;

    return 1;

}

void Wsp100Source::PokeSensor() {
    uint32_t null_frame = TZSP_NULL_PACKET;
    sendto(udp_sock, &null_frame, sizeof(null_frame), 0, (struct sockaddr *) &serv_sockaddr,
           sizeof(struct sockaddr));
}

// wsp100
#endif
