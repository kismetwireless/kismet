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
    
    This files contains support for the Network Chemistry WSP100 under cygwin.
    The WSP100 can be used by kismet like any other network interface, just 
    specify the MAC address of the sensor you wish to use when asked for the 
    capture interface.

    To create a cygwin import library for the SensorManager interface DLL (sm_if.dll)
    copy and paste the following commands to the shell:

echo EXPORTS > sm_if.def
echo "\tStartSensor" >> sm_if.def
echo "\tStopSensor" >> sm_if.def
echo "\tGetPacket" >> sm_if.def
dlltool --def sm_if.def --dllname sm_if.dll --output-lib sm_if.a

    For some reason the treatment of underscores is not consistent with Borland
    B++ Builder so the sm_if.dll functions used in this file are prefixed with
    underscores.
*/

#include "config.h"

#include "wsp100source.h"

#ifdef HAVE_WSP100

#include <errno.h>
#include <string.h>
#include <time.h>
#include <stdio.h>

#ifdef SYS_CYGWIN
// Build code that links to the wsp100 DLL on windows

extern "C" {
#include "sm_if.h"
};

int Wsp100Source::OpenSource(const char *dev, card_type ctype) {
    snprintf(type, 64, "WSP100 Remote Sensor");

    paused = 0;

    /* Attempt to start the named sensor. */
    if ( _StartSensor((char*)dev) != 0 ) {
        snprintf(errstr, 1024, "Unable to find WSP100: %s.", dev);
        return(-1);
    }

    snprintf(errstr, 1024, "WSP100 connection opened.");
    return(1);
}

int Wsp100Source::CloseSource() {
    /* Unconditionally stop the sensor and assume that there were no errors. */
    _StopSensor();

    return 1;
}

int Wsp100Source::FetchPacket(pkthdr *in_header, u_char *in_data) {
    int Length = 3000;
    unsigned char Buffer[3000];
    int Offset = 35; // Size of the TZSP header. TODO: the TZSP header is variable
                     // length so this should be computed correctly.

    _GetPacket(&Length, Buffer);
    if ( Length > 0 ) {
        gettimeofday(&in_header->ts, NULL);

        in_header->caplen = Length - Offset;

        if (Length - Offset > MAX_PACKET_LEN)
            in_header->len = MAX_PACKET_LEN;
        else
            in_header->len = Length - Offset;

        // TODO: copy the signal strength out of the TZSP header.
        in_header->quality = 0;
        in_header->signal = 0;
        in_header->noise = 0;

        memcpy(in_data, &Buffer[Offset], in_header->len);
    }
    return(Length);
}

#else
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

    return 1;
}

int Wsp100Source::CloseSource() {
    if (valid)
        close(udp_sock);

    valid = 0;

    return 1;
}

int Wsp100Source::FetchPacket(pkthdr *in_header, u_char *in_data) {
    if (valid == 0)
        return 0;

    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(udp_sock, &rset);

    struct timeval tm;
    tm.tv_sec = 0;
    tm.tv_usec = 0;

    if (select(udp_sock + 1, &rset, NULL, NULL, &tm) < 0) {
        if (errno != EINTR) {
            snprintf(errstr, 1024, "select() error %d (%s)", errno, strerror(errno));
            return -1;
        }
    }

    if (!FD_ISSET(udp_sock, &rset))
        return 0;

    struct sockaddr_in cli_sockaddr;
    socklen_t cli_len = sizeof(cli_sockaddr);
    memset(&cli_sockaddr, 0, sizeof(cli_sockaddr));

    if ((read_len = recvfrom(udp_sock, data, MAX_PACKET_LEN, 0,
                             (struct sockaddr *) &cli_sockaddr, &cli_len)) < 0) {
        snprintf(errstr, 1024, "recvfrom() error %d (%s)", errno, strerror(errno));
        return -1;
    }

    // Find out if it came from an IP associated with our target sensor system
    if (cli_sockaddr.sin_addr.s_addr != filter_addr.s_addr)
        return 0;

    if (paused || Wsp2Common(in_header, in_data) == 0) {
        return 0;
    }

    return(in_header->len);
}

int Wsp100Source::Wsp2Common(pkthdr *in_header, u_char *in_data) {
    memset(in_header, 0, sizeof(pkthdr));
    memset(in_data, 0, MAX_PACKET_LEN);

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
            in_header->quality = data[pos];
            break;
        case WSP100_TAG_RADIO_NOISE:
            len = data[pos++];
            in_header->noise = data[pos];
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

            gettimeofday(&in_header->ts, NULL);

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
            // We need to find a way to handle this to flag a noise/error packet
            len = data[pos++];
            in_header->error = 1;
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

    in_header->len = read_len - pos;
    in_header->caplen = read_len - pos;
    memcpy(in_data, &data[pos], in_header->len);

    return 1;

}

// cygwin/other
#endif

// wsp100
#endif
