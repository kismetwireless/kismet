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

int Prism2Source::OpenSource() {
    char errstr[STATUS_MAX];
    channel = 0;
    paused = 0;

    int fds[2], r;

    fd = -1;

    struct sockaddr_nl addr;
    r = pipe(fds);

    if (r < 0) {
        snprintf(errstr, STATUS_MAX, "Prism2 open pipe() failed. (%s)", strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return(-1);
    }

    read_sock = fds[0];
    write_sock = fds[1];

    fd = socket(PF_NETLINK, SOCK_RAW, MCAST_GRP_SNIFF);

    if (fd < 0) {
        snprintf(errstr, STATUS_MAX, "Prism2 open socket() failed. (%s)", strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return(-1);
    }

    memset (&addr, 0, sizeof(addr));
    addr.nl_family = PF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = MCAST_GRP_SNIFF;

    if (bind(fd, (struct sockaddr *) &addr, sizeof(struct sockaddr_nl)) < 0) {
        snprintf(errstr, STATUS_MAX, "Prism2 open bind() failed. (%s)", strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return(-1);
    }

    num_packets = 0;

    return(1);
}

int Prism2Source::CloseSource() {
    close(fd);
    return 1;
}

int Prism2Source::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    char errstr[STATUS_MAX];
    fd_set rs;
    int r;
    struct timeval tim;
    struct timeval *ptm;

    if (read_sock < 0 || fd < 0) {
        snprintf(errstr, STATUS_MAX, "Prism2 fetch failed. (source not open)");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
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
        snprintf(errstr, STATUS_MAX, "Prism2 fetch select() failed. (%s)", strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
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

            snprintf(errstr, STATUS_MAX, "Prism2 fetch recv() failed. (%s)", strerror(errno));
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }
    }

    if (paused) return 0;

    Prism2Common(packet, data, moddata);

    num_packets++;

    snprintf(packet->sourcename, 32, "%s", name.c_str());
    packet->parm = parameters;

    return(packet->caplen);
}

int Prism2Source::Prism2Common(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    memset(packet, 0, sizeof(kis_packet));

    sniff_packet_t *sniff_info = (sniff_packet_t *) buffer;

    gettimeofday(&packet->ts, NULL);

    packet->data = data;
    packet->moddata = moddata;
    packet->modified = 0;

    if (globalreg->gpsd != NULL) {
        globalreg->gpsd->FetchLoc(&packet->gps_lat, &packet->gps_lon, &packet->gps_alt,
                                  &packet->gps_spd, &packet->gps_heading, &packet->gps_fix);
    }

    // Trim the FCS
    packet->caplen = kismin(sniff_info->frmlen.data - 4, (uint32_t) MAX_PACKET_LEN);
    packet->len = packet->caplen;

    // Copy the radio levels out
    packet->signal = sniff_info->signal.data;
    packet->noise = sniff_info->noise.data;

    int offset = sizeof(sniff_packet_t);

    memcpy(packet->data, &buffer[offset], packet->caplen);

    packet->carrier = carrier_80211b;

    return 1;
}

int Prism2Source::FetchChannel() {

    return 0;
}

// ----------------------------------------------------------------------------
// // Registrant and control functions outside of the class

KisPacketSource *prism2source_registrant(REGISTRANT_PARMS) {
    return new Prism2Source(globalreg, in_name, in_device);
}

int monitor_wlanng_legacy(MONITOR_PARMS) {
    char errstr[STATUS_MAX];
    char cmdline[2048];

    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Delta_Flags(in_dev, errstr, IFF_UP | IFF_RUNNING | IFF_PROMISC) < 0) {
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }

    // Enable the interface
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true", in_dev, initch);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(errstr, STATUS_MAX, "Unable to execute '%s'", cmdline);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }

    return 0;
}

int chancontrol_wlanng_legacy(CHCONTROL_PARMS) {
    char errstr[STATUS_MAX];
    char cmdline[2048];

    // Set the channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true "
             ">/dev/null 2>/dev/null", in_dev, in_ch);
    if (RunSysCmd(cmdline) < 0) {
        snprintf(errstr, STATUS_MAX, "Unable to execute '%s'", cmdline);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }

    return 0;
}

#endif
