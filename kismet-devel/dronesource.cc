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

int DroneSource::OpenSource() {
    char listenhost[1024];

    // Device is handled as a host:port pair - remote host we accept data
    // from, local port we open to listen for it.  yeah, it's a little weird.
    if (sscanf(interface.c_str(), "%1024[^:]:%hd", listenhost, &port) < 2) {
        snprintf(errstr, 1024, "Couldn't parse host:port: '%s'", interface.c_str());
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

    resyncs = 0;
    resyncing = 0;

    num_packets = 0;

    stream_recv_bytes = 0;

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
  
    uint8_t *inbound;
    int ret = 0;
    fd_set rset;
    struct timeval tm;
    unsigned int offset = 0;

    // Read more of our frame header if we need to
    if (stream_recv_bytes < sizeof(struct stream_frame_header)) {
        inbound = (uint8_t *) &fhdr;
        if ((ret = read(drone_fd, &inbound[stream_recv_bytes],
             (ssize_t) sizeof(struct stream_frame_header) - stream_recv_bytes)) < 0) {
            snprintf(errstr, STATUS_MAX, "drone read() error getting frame header %d:%s",
                     errno, strerror(errno));
            return -1;
        }
        stream_recv_bytes += ret;
        // printf("debug - we got %d bytes of the fhdr, total %d\n", ret, stream_recv_bytes);

        // Leave if we aren't done
        if (stream_recv_bytes < sizeof(struct stream_frame_header))
            return 0;
        
        // Validate it
        if (ntohl(fhdr.frame_sentinel) != STREAM_SENTINEL) {
            int8_t cmd = STREAM_COMMAND_FLUSH;
            int ret = 0;

            // debug
            /*
             for (unsigned int x = 0; x < sizeof(struct stream_frame_header); x++) {
                printf("%02X ", ((uint8_t *) &fhdr)[x]);
            }
            printf("\n");

            printf("debug - resyncing\n");
            */

            stream_recv_bytes = 0;
            resyncs++;

            if (resyncs > 20) {
                snprintf(errstr, 1024, "too many resync attempts, something is wrong.");
                return -1;
            }

            if (resyncing == 1)
                return 0;

            resyncing = 1;
            
            if ((ret = write(drone_fd, &cmd, 1)) < 1) {
                snprintf(errstr, 1024, "write() error attempting to flush "
                         "packet stream: %d %s",
                         errno, strerror(errno));
                return -1;
            }

            return 0;
        }

        resyncing = 0;
        resyncs = 0;
        
        // printf("debug - We got a valid header\n");
        
        // See if we keep looking for more packet pieces
        FD_ZERO(&rset);
        FD_SET(drone_fd, &rset);
        tm.tv_sec = 0;
        tm.tv_usec = 0;

        if (select(drone_fd + 1, &rset, NULL, NULL, &tm) <= 0)
            return 0;

        // printf("debug - moving on past header in the same call, select thinks we have data\n");

    }

    // Handle version packets
    offset = sizeof(struct stream_frame_header);
    if (fhdr.frame_type == STREAM_FTYPE_VERSION && stream_recv_bytes >= offset && 
        stream_recv_bytes < offset + sizeof(stream_version_packet)) {

        inbound = (uint8_t *) &vpkt;
        if ((ret = read(drone_fd, &inbound[stream_recv_bytes - offset],
                        (ssize_t) sizeof(struct stream_version_packet) - 
                        (stream_recv_bytes - offset))) < 0) {

            snprintf(errstr, STATUS_MAX, "drone read() error getting version "
                     "packet %d:%s", errno, strerror(errno));
            return -1;
        }
        stream_recv_bytes += ret;

        // Leave if we aren't done
        if ((stream_recv_bytes - offset) < sizeof(struct stream_version_packet))
            return 0;

        // Validate
        if (ntohs(vpkt.drone_version) != STREAM_DRONE_VERSION) {
            snprintf(errstr, 1024, "version mismatch:  Drone sending version %d, "
                     "expected %d.", ntohs(vpkt.drone_version), STREAM_DRONE_VERSION);
            return -1;
        }

        stream_recv_bytes = 0;

        // printf("debug - version packet valid\n\n");

        return 0;
    } 
    
    if (fhdr.frame_type == STREAM_FTYPE_PACKET && stream_recv_bytes >= offset &&
        stream_recv_bytes < offset + sizeof(struct stream_packet_header)) {

        // printf("debug - considering a stream packet header\n");
        
        // Bail if we have a frame header too small for a packet of any sort
        if (ntohl(fhdr.frame_len) <= sizeof(struct stream_packet_header)) {
            snprintf(errstr, 1024, "frame too small to hold a packet.");
            return -1;
        }

        inbound = (uint8_t *) &phdr;
        if ((ret = read(drone_fd, &inbound[stream_recv_bytes - offset],
                        (ssize_t) sizeof(struct stream_packet_header) - 
                        (stream_recv_bytes - offset))) < 0) {
            snprintf(errstr, STATUS_MAX, "drone read() error getting packet "
                     "header %d:%s", errno, strerror(errno));
            return -1;
        }
        stream_recv_bytes += ret;

        // Leave if we aren't done
        if ((stream_recv_bytes - offset) < sizeof(struct stream_packet_header))
            return 0;

        if (ntohs(phdr.drone_version) != STREAM_DRONE_VERSION) {
            snprintf(errstr, 1024, "version mismatch:  Drone sending version %d, "
                     "expected %d.", ntohs(phdr.drone_version), STREAM_DRONE_VERSION);
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

        //printf("debug - drone sent us a packet header indicating %d long.\n", (uint32_t) ntohl(phdr.len));
        
        // See if we keep looking for more packet pieces
        FD_ZERO(&rset);
        FD_SET(drone_fd, &rset);
        tm.tv_sec = 0;
        tm.tv_usec = 0;

        if (select(drone_fd + 1, &rset, NULL, NULL, &tm) <= 0)
            return 0;

        // printf("debug - got a valid packet header and still rading in the same call\n");
    }

    offset = sizeof(struct stream_frame_header) + sizeof(struct stream_packet_header);
    if (fhdr.frame_type == STREAM_FTYPE_PACKET && stream_recv_bytes >= offset) {

        unsigned int plen = (uint32_t) ntohl(phdr.len);

        inbound = (uint8_t *) databuf;
        if ((ret = read(drone_fd, &inbound[stream_recv_bytes - offset],
                        (ssize_t) plen - (stream_recv_bytes - offset))) < 0) {
            snprintf(errstr, STATUS_MAX, "drone read() error getting packet "
                     "header %d:%s", errno, strerror(errno));
            return -1;
        }
        stream_recv_bytes += ret;

        // Leave if we aren't done
        if ((stream_recv_bytes - offset) < plen)
            return 0;

        // If we have it all, complete it and return
        if (paused || Drone2Common(packet, data, moddata) == 0) {
            stream_recv_bytes = 0;
            return 0;
        }

        num_packets++;

        packet->parm = parameters;

        stream_recv_bytes = 0;

        // printf("debug - we got all of the packet that was %d long\n", plen);

        return(packet->caplen);
    } else {
        // printf("debug - somehow not a stream packet or too much data...  type %d recv %d\n", fhdr.frame_type, stream_recv_bytes);
    }

    if (fhdr.frame_type != STREAM_FTYPE_PACKET && 
        fhdr.frame_type != STREAM_FTYPE_VERSION) {
        // Bail if we don't know the packet type
        snprintf(errstr, 1024, "unknown frame type %d", fhdr.frame_type);

        // debug
        for (unsigned int x = 0; x < sizeof(struct stream_frame_header); x++) {
            printf("%02X ", ((uint8_t *) &fhdr)[x]);
        }
        printf("\n");
        
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
    packet->gps_heading = Pair2Float((int16_t) ntohs(phdr.gps_heading),
                                     (int64_t) kis_ntoh64(phdr.gps_heading_mant));
    packet->gps_fix = phdr.gps_fix;

    packet->data = data;
    packet->moddata = moddata;
    packet->modified = 0;

    memcpy(packet->sourcename, phdr.sourcename, 32);

    memcpy(packet->data, databuf, packet->caplen);

    return 1;
}

KisPacketSource *dronesource_registrant(string in_name, string in_device,
                                        char *in_err) {
    return new DroneSource(in_name, in_device);
}

