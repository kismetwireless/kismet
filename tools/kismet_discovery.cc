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
 * Example of a Kismet server discovery tool that waits for the broadcast server announcement
 * and prints out the available info.
 *
 * This will, obviously, only find servers which are configured for broadcast with
 * server_announce enabled.
 */

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <time.h>

#include "remote_announcement.h"
#include "kis_endian.h"

int main(int argc, const char *argv[]) {
    struct sockaddr_in lsin;
    int sock;

    memset(&lsin, 0, sizeof(struct sockaddr_in));
    lsin.sin_family = AF_INET;
    lsin.sin_port = htons(2501);
    lsin.sin_addr.s_addr = INADDR_ANY;

    if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
        fprintf(stderr, "ERROR:  Could not create listening socket for announcements: %s\n",
                strerror(errno));
        exit(1);
    }

    if (bind(sock, (struct sockaddr *) &lsin, sizeof(lsin)) < 0) {
        fprintf(stderr, "ERROR:  Could not bind to listening socket for announcements: %s\n",
                strerror(errno));
        close(sock);
        exit(1);
    }

    printf("Listening for Kismet server announcements...\n");

    while(1) {
        int r;
        struct msghdr rcv_msg;
        struct iovec iov;
        kismet_remote_announce announcement;
        struct sockaddr_in recv_addr;
        time_t ts;

        iov.iov_base = &announcement;
        iov.iov_len = sizeof(kismet_remote_announce);

        rcv_msg.msg_name = &recv_addr;
        rcv_msg.msg_namelen = sizeof(recv_addr);
        rcv_msg.msg_iov = &iov;
        rcv_msg.msg_iovlen = 1;
        rcv_msg.msg_control = NULL;
        rcv_msg.msg_controllen = 0;

        if ((r = recvmsg(sock, &rcv_msg, 0) < 0)) {
            fprintf(stderr, "ERROR:  Failed receiving announcement: %s\n", strerror(errno));
            close(sock);
            exit(1);
        }

        if (be64toh(announcement.tag) != REMOTE_ANNOUNCE_TAG)
            fprintf(stderr, "WARNING:  Corrupt/invalid announcement seen\n");

        ts = be64toh(announcement.server_ts_sec);

        printf("Kismet server %s - %.36s (%s)\n", inet_ntoa(recv_addr.sin_addr),
                announcement.uuid, announcement.name);
        printf("      Server port: %u\n", be32toh(announcement.server_port));
        printf("  Remote cap port: %u\n", be32toh(announcement.remote_port));
        printf("      Server time: %s\n", ctime(&ts));
        printf("\n");

    }

}
