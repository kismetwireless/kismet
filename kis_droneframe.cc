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
#include "packet.h"
#include "droneproto.h"
#include "kis_droneframe.h"

KisDroneFramework::KisDroneFramework() {
    fprintf(stderr, "*** KisDroneFramework() This constructor should never be called!!\n");
}

KisDroneFramework::KisDroneFramework(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;
    netserver = NULL;
}

KisDroneFramework::~KisDroneFramework() {
    // Remove our message handler
}

int KisDroneFramework::Accept(int in_fd) {
    // Create their options
    client_opt *opt = new client_opt;
    client_optmap[in_fd] = opt;

    opt->validated = 0;

    return 1;
}

int KisDroneFramework::ParseData(int in_fd) {
    int len, rlen;
    uint8_t *buf;

    len = netserver->FetchReadLen(in_fd);
    buf = new uint8_t[len + 1];
    int pos = 0;
    int rpos = 0;
    
    if (netserver->ReadData(in_fd, buf, len, &rlen) < 0) {
        globalreg->messagebus->InjectMessage("KisDroneFramework::ParseData failed to fetch data from "
                                             "the client.", MSGFLAG_ERROR);
        return -1;
    }

    while (pos < rlen) {
        if ((rlen - pos) >= (int) DRONE_HEADER_LEN) {
            stream_frame_header *sfh = (stream_frame_header *) &(buf[pos]);
            uint32_t flen;

            // Check sentinel and such 
            if (kis_ntoh32(sfh->frame_sentinel) != DRONE_SENTINEL) {
                globalreg->messagebus->InjectMessage("KisDroneFramework::ParseData got packet with invalid "
                                                     "frame sentinel, dropping connection.", MSGFLAG_ERROR);
                KillConnection(in_fd);
            }

            // Convert the len
            flen = kis_ntoh32(sfh->frame_len);

            // blow up if we don't have a complete frame 
            if ((rlen - pos) < (int) flen)
                break;

            pos += (int) DRONE_HEADER_LEN;

            if (sfh->frame_type == DRONE_FTYPE_LOGIN) {
                stream_login_packet *lp;
                char pw[33];

                // Grab their connection info since we'll need it if they logged in
                // or failed to
                struct sockaddr_in cli_addr;
                char hostip[16];
                netserver->FetchClientConnectInfo(in_fd, (void *) &cli_addr);
                snprintf(hostip, 16, "%s", inet_ntoa(cli_addr.sin_addr));
                
                if (flen < DRONE_LOGIN_LEN) {
                    snprintf(errstr, STATUS_MAX, "KisDroneFramework::ParseData got login pcket from %s with "
                             "invalid frame length, dropping connection.", hostip);
                    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
                    KillConnection(in_fd);
                    return -1;
                }
               
                lp = (stream_login_packet *) &(buf[pos]);

                // Match the version first since it's cheap
                if (lp->version != DRONE_STREAM_VERSION) {
                    snprintf(errstr, STATUS_MAX, "KisDroneFramework::ParseData got login from %s "
                             "invalid version %d, expected %d", hostip, lp->version, DRONE_STREAM_VERSION);
                    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
                    KillConnection(in_fd);
                    return -1;
                }
                
                memcpy(pw, lp->password, 32);
                pw[32] = '\0';

                // Compare passwords and blow them up if it's not valid
                if (strncmp(pw, passwd.c_str(), 32) != 0) {
                    snprintf(errstr, STATUS_MAX, "KisDroneFramework::ParseData got login from %s "
                             "with invalid password", hostip);
                    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
                    KillConnection(in_fd);
                    return -1;
                }

                client_optmap[in_fd]->validated = 1;
            } else if (sfh->frame_type == DRONE_FTYPE_PACKET) {
                stream_packet_header *lh;
                uint8_t *pd;
                uint32_t dlen;
                struct sockaddr_in cli_addr;
                char hostip[16];

                if (flen < DRONE_PACKET_LEN) {
                    netserver->FetchClientConnectInfo(in_fd, (void *) &cli_addr);
                    snprintf(hostip, 16, "%s", inet_ntoa(cli_addr.sin_addr));
                
                    snprintf(errstr, STATUS_MAX, "KisDroneFramework::ParseData got data pcket from %s with "
                             "invalid frame length, dropping connection.", hostip);
                    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
                    KillConnection(in_fd);
                    return -1;
                }
               
                lh = (stream_packet_header *) &(buf[pos]);
                dlen = kis_ntoh32(lh->len);

            }

            pos += flen;

        } else {
            // Blow up that we don't even have a complete header 
            break;
        }
    }

    // Mark the data we've processed as read 
    netserver->MarkRead(in_fd, pos);

    return 1;
}

int KisDroneFramework::KillConnection(int in_fd) {
    // Do a little testing here since we might not have an opt record
    map<int, client_opt *>::iterator citr = client_optmap.find(in_fd);
    if (citr != client_optmap.end()) {
        delete citr->second;
        client_optmap.erase(citr);
    }

    return 1;
}

int KisDroneFramework::SendToClient(int in_fd, int in_len, const void *in_data) {
    return 0;
}

int KisDroneFramework::SendToAll(int in_len, const void *in_data) {
    vector<int> clvec;
    int nsent = 0;

    netserver->FetchClientVector(&clvec);

    for (unsigned int x = 0; x < clvec.size(); x++) {
        if (SendToClient(clvec[x], in_len, in_data) > 0)
            nsent++;
    }

    return nsent;
}

int KisDroneFramework::FetchNumClients() {
    return netserver->FetchNumClients();
}

