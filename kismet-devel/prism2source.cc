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

#include "config.h"

#include <errno.h>
#include <string.h>
#include <time.h>
#include "prism2source.h"

#ifdef HAVE_LINUX_NETLINK

int Prism2Source::OpenSource(const char *dev, card_type ctype) {
    snprintf(type, 64, "Prism/2 (DEPRECATED)");

    paused = 0;

    int fds[2], r;

    fd = -1;

    struct sockaddr_nl addr;
    r = pipe(fds);

    if (r < 0) {
        snprintf(errstr, 1024, "Prism2 open pipe() failed. (%s)", strerror(errno));
        return(-1);
    }

    read_sock = fds[0];
    write_sock = fds[1];

    fd = socket(PF_NETLINK, SOCK_RAW, MCAST_GRP_SNIFF);

    if (fd < 0) {
        snprintf(errstr, 1024, "Prism2 open socket() failed. (%s)", strerror(errno));
        return(-1);
    }

    memset (&addr, 0, sizeof(addr));
    addr.nl_family = PF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = MCAST_GRP_SNIFF;

    if (bind(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_nl)) < 0) {
        snprintf(errstr, 1024, "Prism2 open bind() failed. (%s)", strerror(errno));
        return(-1);
    }

    snprintf(errstr, 1024, "Prism2 capture source opened.");
    return(1);
}

int Prism2Source::CloseSource() {
    return 1;
}

int Prism2Source::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    fd_set rs;
    int r;
    struct timeval tim;
    struct timeval *ptm;

    if (read_sock < 0 || fd < 0) {
        snprintf(errstr, 1024, "Prism2 fetch failed. (source not open)");
        return(-1);
    }

    FD_ZERO(&rs);
    FD_SET(fd, &rs);
    FD_SET(read_sock, &rs);

    if (PRISM2_READ_TIMEOUT >= 0) {
        tim.tv_sec = PRISM2_READ_TIMEOUT / 1000;
        tim.tv_usec = (PRISM2_READ_TIMEOUT % 1000) * 1000;
        ptm = &tim;
    } else {
        ptm = NULL;
    }

    r = select((read_sock > fd) ? read_sock + 1 : fd + 1,
               &rs, NULL, NULL, ptm);
    if (r < 0) {
        snprintf(errstr, 1024, "Prism2 fetch select() failed. (%s)", strerror(errno));
        return(-1);
    }
    if (r == 0) {
        if (PRISM2_READ_TIMEOUT >= 0)
            return(0);
    }

    if (FD_ISSET(read_sock, &rs)) {
        char a;
        read(read_sock, &a, 1);
    }

//    u_char buf[MAX_PACKET_LEN];
    if (FD_ISSET(fd, &rs)) {
        r = recv(fd, buffer, MAX_PACKET_LEN, 0);
        if (r < 0) {
            // We ignore ENOBUFS since it seems to happen fairly often and is really
            // annoying.
            if (errno == ENOBUFS)
                return 0;

            snprintf(errstr, 1024, "Prism2 fetch recv() failed. (%s)", strerror(errno));
            return -1;
        }
    }

    if (paused) return 0;

    Prism2Common(packet, data, moddata);

    return(packet->caplen);
}

int Prism2Source::Prism2Common(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    memset(packet, 0, sizeof(kis_packet));

    sniff_packet_t *sniff_info = (sniff_packet_t *) buffer;

    gettimeofday(&packet->ts, NULL);

    packet->data = data;
    packet->moddata = moddata;
    packet->modified = 0;

    packet->caplen = kismin(sniff_info->frmlen.data, (uint32_t) MAX_PACKET_LEN);
    packet->len = packet->caplen;

    // Copy the quality out of the prism2 header
    packet->quality = sniff_info->sq.data;
    packet->signal = sniff_info->signal.data;
    packet->noise = sniff_info->noise.data;

    int offset = sizeof(sniff_packet_t);

    memcpy(packet->data, &buffer[offset], packet->caplen);

    packet->carrier = carrier_80211b;

    return 1;
}

#endif
