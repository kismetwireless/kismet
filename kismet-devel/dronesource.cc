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

#include "util.h"
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

int DroneSource::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    if (valid == 0)
        return 0;

    unsigned int bcount;
    uint8_t *inbound;

    // Fetch the frame header
    bcount = 0;
    inbound = (uint8_t *) &fhdr;
    while (bcount < sizeof(struct stream_frame_header)) {
        int ret = 0;

        if ((ret = read(drone_fd, &inbound[bcount],
                        (ssize_t) sizeof(struct stream_frame_header) - bcount)) < 0) {
            snprintf(errstr, 1024, "read() error getting frame header: %d %s",
                     errno, strerror(errno));
            return -1;
        }

        bcount += ret;
    }

    if (fhdr.frame_type == STREAM_FTYPE_VERSION) {
        // Handle the version and generate an error if it's a mismatch

        stream_version_packet vpkt;

        bcount = 0;
        inbound = (uint8_t *) &vpkt;
        while (bcount < sizeof(struct stream_version_packet)) {
            int ret = 0;

            if ((ret = read(drone_fd, &inbound[bcount],
                            (ssize_t) sizeof(struct stream_version_packet) - bcount)) < 0) {
                snprintf(errstr, 1024, "read() error getting version packet: %d %s",
                         errno, strerror(errno));
                return -1;
            }

            bcount += ret;
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

        bcount = 0;
        inbound = (uint8_t *) &phdr;
        while (bcount < sizeof(struct stream_packet_header)) {
            int ret = 0;

            if ((ret = read(drone_fd, &inbound[bcount],
                            (ssize_t) sizeof(struct stream_packet_header) - bcount)) < 0) {
                snprintf(errstr, 1024, "read() error getting packet header: %d %s",
                         errno, strerror(errno));
                return -1;
            }

            bcount += ret;
        }

        if (ntohs(phdr.drone_version) != STREAM_DRONE_VERSION) {
            snprintf(errstr, 1024, "version mismatch:  Drone sending version %d, expected %d.",
                     ntohs(phdr.drone_version), STREAM_DRONE_VERSION);
            return -1;
        }

        if (ntohl(phdr.caplen) <= 0 || ntohl(phdr.len) <= 0) {
            snprintf(errstr, 1024, "drone sent us a 0-length packet.");
            return -1;
        }

        if (ntohl(phdr.caplen) > MAX_PACKET_LEN || ntohl(phdr.len) > MAX_PACKET_LEN) {
            snprintf(errstr, 1024, "drone sent us an oversized packet.");
            return -1;
        }

        // Finally, fetch the indicated packet data.
        bcount = 0;
        while (bcount < ntohl(phdr.caplen)) {
            int ret = 0;

            if ((ret = read(drone_fd, &data[bcount], ntohl(phdr.caplen) - bcount)) < 0) {
                snprintf(errstr, 1024, "read() error getting packet content: %d %s",
                         errno, strerror(errno));
                return -1;
            }

            bcount += ret;
        }

        if (paused || Drone2Common(packet, data, moddata) == 0) {
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

int DroneSource::Drone2Common(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    memset(packet, 0, sizeof(kis_packet));

    packet->len = (uint32_t) ntohl(phdr.len);
    packet->caplen = (uint32_t) ntohl(phdr.caplen);
    packet->ts.tv_sec = (uint64_t) kis_ntoh64(phdr.tv_sec);
    packet->ts.tv_usec = (uint64_t) kis_ntoh64(phdr.tv_usec);
    packet->quality = (uint16_t) ntohs(phdr.quality);
    packet->signal = (uint16_t) ntohs(phdr.signal);
    packet->noise = (uint16_t) ntohs(phdr.noise);
    packet->channel = phdr.channel;
    packet->carrier = (carrier_type) phdr.carrier;
    packet->error = phdr.error;
    packet->encoding = (encoding_type) phdr.encoding;
    packet->datarate = (uint32_t) ntohl(phdr.datarate);

    packet->gps_lat = Pair2Float((int16_t) ntohs(phdr.gps_lat),
                                 (int64_t) kis_ntoh64(phdr.gps_lat_mant));
    packet->gps_lon = Pair2Float((int16_t) ntohs(phdr.gps_lon),
                                 (int64_t) kis_ntoh64(phdr.gps_lon_mant));
    packet->gps_alt = Pair2Float((int16_t) ntohs(phdr.gps_alt),
                                 (int64_t) kis_ntoh64(phdr.gps_alt_mant));
    packet->gps_spd = Pair2Float((int16_t) ntohs(phdr.gps_spd),
                                 (int64_t) kis_ntoh64(phdr.gps_spd_mant));
    packet->gps_fix = phdr.gps_fix;

    packet->data = data;
    packet->moddata = moddata;
    packet->modified = 0;

    memcpy(packet->data, data, packet->caplen);

    return 1;
}

int DroneSource::SetChannel(unsigned int chan) {

    return 1;
}


