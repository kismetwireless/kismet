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

#include "dronesource.h"

int DroneSource::OpenSource(const char *dev, card_type ctype) {
    char listenhost[1024];

    snprintf(type, 64, "Drone Remote Capture on %s", dev);
    cardtype = ctype;

    // Device is handled as a host:port pair - remote host we accept data
    // from, local port we open to listen for it.  yeah, it's a little weird.
    if (sscanf(dev, "%1024[^:]:%hd", listenhost, &port) < 2) {
        snprintf(errstr, 1024, "Couldn't parse host:port: '%s'", dev);
        return -1;
    }

    // Resolve the hostname we were given/found to see if it's actually
    // valid
    if ((drone_host = gethostbyname(listenhost)) == NULL) {
        snprintf(errstr, 1024, "Could not resolve host \"%s\"\n", listenhost);
        return (-1);
    }

    strncpy(hostname, listenhost, MAXHOSTNAMELEN);

    // Set up our socket
    //bzero(&client_sock, sizeof(client_sock));
    memset(&drone_sock, 0, sizeof(drone_sock));
    drone_sock.sin_family = drone_host->h_addrtype;
    memcpy((char *) &drone_sock.sin_addr.s_addr, drone_host->h_addr_list[0],
           drone_host->h_length);
    drone_sock.sin_port = htons(port);

    if ((drone_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        snprintf(errstr, 1024, "socket() failed %d (%s)\n", errno, strerror(errno));
        return (-2);
    }

    // Bind to the local half of the pair
    local_sock.sin_family = AF_INET;
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    local_sock.sin_port = htons(0);

    if (bind(drone_fd, (struct sockaddr *) &local_sock, sizeof(local_sock)) < 0) {
        snprintf(errstr, 1024, "bind() failed %d (%s)\n", errno, strerror(errno));
        return (-3);
    }

    // Connect
    if (connect(drone_fd, (struct sockaddr *) &drone_sock, sizeof(drone_sock)) < 0) {
        snprintf(errstr, 1024, "connect() failed %d (%s)\n", errno, strerror(errno));
        return (-4);
    }

    /*
    int save_mode = fcntl(drone_fd, F_GETFL, 0);
    if (save_mode == -1) {
        snprintf(errstr, 1024, "failed fcntl get %d (%s)\n", errno, strerror(errno));
        return (-5);
    }
    if (fcntl(drone_fd, F_SETFL, save_mode | O_NONBLOCK) < 0) {
        snprintf(errstr, 1024, "failed fcntl set %d (%s)\n", errno, strerror(errno));
        return (-6);
        }
        */

    paused = 0;

    valid = 1;

    return 1;
}

int DroneSource::CloseSource() {
    if (valid)
        close(drone_fd);

    valid = 0;

    return 1;
}

int DroneSource::FetchPacket(kis_packet *packet) {
    if (valid == 0)
        return 0;

    fd_set rset;
    FD_ZERO(&rset);
    FD_SET(drone_fd, &rset);

    struct timeval tm;
    tm.tv_sec = 0;
    tm.tv_usec = 0;

    if (select(drone_fd + 1, &rset, NULL, NULL, &tm) < 0) {
        if (errno != EINTR) {
            snprintf(errstr, 1024, "select() error %d (%s)", errno, strerror(errno));
            return -1;
        }
    }

    if (!FD_ISSET(drone_fd, &rset))
        return 0;

    // Fetch the frame header
    if (read(drone_fd, &fhdr, sizeof(struct stream_frame_header)) < (ssize_t) sizeof(struct stream_frame_header)) {
        snprintf(errstr, 1024, "short read() getting frame header: %d (%s)",
                 errno, strerror(errno));
        return -1;
    }

    if (fhdr.frame_type == STREAM_FTYPE_VERSION) {
        // Handle the version and generate an error if it's a mismatch

        stream_version_packet vpkt;

        if (read(drone_fd, &vpkt, sizeof(struct stream_version_packet)) <
            (ssize_t) sizeof(struct stream_version_packet)) {
            snprintf(errstr, 1024, "short read() getting version packet: %d (%s)",
                     errno, strerror(errno));
            return -1;
        }

        if (ntohs(vpkt.drone_version) != STREAM_DRONE_VERSION) {
            snprintf(errstr, 1024, "version mismatch:  Drone sending version %d, expected %d.",
                     ntohs(vpkt.drone_version), STREAM_DRONE_VERSION);
            return -1;
        }

        return 0;
    } else if (fhdr.frame_type == STREAM_FTYPE_PACKET) {
        // Bail if we have a frame header too small for a packet of any sort
        if (ntohl(fhdr.frame_len) <= sizeof(struct stream_packet_header)) {
            snprintf(errstr, 1024, "frame too small to hold a packet.");
            return -1;
        }

        // Fetch the packet header
        if (read(drone_fd, &phdr, sizeof(struct stream_packet_header)) < (ssize_t) sizeof(stream_packet_header)) {
            snprintf(errstr, 1024, "short read() getting packet header: %d (%s)",
                     errno, strerror(errno));
            return -1;
        }

        if (ntohs(phdr.drone_version) != STREAM_DRONE_VERSION) {
            snprintf(errstr, 1024, "version mismatch:  Drone sending version %d, expected %d.",
                     ntohs(phdr.drone_version), STREAM_DRONE_VERSION);
            return -1;
        }


        if (ntohl(phdr.caplen) <= 0)
            return 0;

        if (ntohl(phdr.caplen) > MAX_PACKET_LEN)
            phdr.caplen = (uint32_t) htonl(MAX_PACKET_LEN);
        if (ntohl(phdr.len) > MAX_PACKET_LEN)
            phdr.len = (uint32_t) htonl(MAX_PACKET_LEN);

        // Finally, fetch the indicated packet data.
        int ret;
        if ((ret = read(drone_fd, data, ntohl(phdr.caplen))) < (ssize_t) ntohl(phdr.caplen)) {
            snprintf(errstr, 1024, "%d short read() getting packet content: %d (%s)",
                     ret, errno, strerror(errno));
            return -1;
        }

        if (paused || Drone2Common(packet) == 0) {
            return 0;
        }

        return(packet->caplen);

    } else {
        // Bail if we don't know the packet type
        snprintf(errstr, 1024, "unknown frame type %d", fhdr.frame_type);
        return -1;
    }

    return 0;
}

int DroneSource::Drone2Common(kis_packet *packet) {
    memset(packet, 0, sizeof(kis_packet));

    packet->len = (uint32_t) ntohl(phdr.len);
    packet->caplen = (uint32_t) ntohl(phdr.caplen);
    packet->ts.tv_sec = (uint64_t) ntoh64(phdr.tv_sec);
    packet->ts.tv_usec = (uint64_t) ntoh64(phdr.tv_usec);
    packet->quality = (uint16_t) ntohs(phdr.quality);
    packet->signal = (uint16_t) ntohs(phdr.signal);
    packet->noise = (uint16_t) ntohs(phdr.noise);
    packet->channel = phdr.channel;
    packet->carrier = (carrier_type) phdr.carrier;
    packet->error = phdr.error;
    packet->encoding = (encoding_type) phdr.encoding;
    packet->datarate = (uint32_t) ntohl(phdr.datarate);

    packet->data = new uint8_t[packet->caplen];
    packet->moddata = NULL;

    memcpy(packet->data, data, packet->caplen);

    return 1;
}


