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

#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>

#include "pcapsource.h"

#ifdef HAVE_LIBPCAP

// I hate libpcap, I really really do.  Stupid callbacks...
pcap_pkthdr callback_header;
u_char callback_data[MAX_PACKET_LEN];


int PcapSource::OpenSource(const char *dev, card_type ctype) {
    cardtype = ctype;

    snprintf(type, 64, "libpcap device %s", dev);

    char unconst_dev[64];
    snprintf(unconst_dev, 64, "%s", dev);

    errstr[0] = '\0';
    pd = pcap_open_live(unconst_dev, MAX_PACKET_LEN, 1, 1000, errstr);

    if (strlen(errstr) > 0)
        return -1; // Error is already in errstr

    paused = 0;

    errstr[0] = '\0';

    datalink_type = pcap_datalink(pd);

    // Blow up if we're not valid 802.11 headers
#if (defined(SYS_FREEBSD) || defined(SYS_OPENBSD))
    if (datalink_type == DLT_EN10MB) {
        snprintf(type, 64, "libpcap device %s [ BSD EN10MB HACK ]", dev);
        fprintf(stderr, "WARNING:  pcap reports link type of EN10MB but we'll fake it on BSD.\n");
        datalink_type = KDLT_BSD802_11;
    }
#else
    if (datalink_type == DLT_EN10MB) {
        snprintf(errstr, 1024, "pcap reported netlink type 1 (EN10MB) for %s.  This probably means you're not in RFMON mode or your drivers are reporting a bad value.  Make sure you have run kismet_monitor.",
                dev);
        return -1;
    }
#endif

    if (datalink_type != KDLT_BSD802_11 && datalink_type != DLT_IEEE802_11 &&
        datalink_type != DLT_PRISM_HEADER) {
        fprintf(stderr, "WARNING:  Unknown link type %d reported.  Continuing on blindly...\n",
                datalink_type);
        snprintf(type, 64, "libpcap device %s linktype %d",
                 dev, datalink_type);
    }

#ifdef HAVE_PCAP_NONBLOCK
    pcap_setnonblock(pd, 1, errstr);
#elif !defined(SYS_OPENBSD)
    // do something clever  (Thanks to Guy Harris for suggesting this).
    int save_mode = fcntl(pcap_fileno(pd), F_GETFL, 0);
    if (fcntl(pcap_fileno(pd), F_SETFL, save_mode | O_NONBLOCK) < 0) {
        snprintf(errstr, 1024, "fcntl failed, errno %d (%s)",
                 errno, strerror(errno));
    }
#endif

    if (strlen(errstr) > 0)
        return -1; // Ditto

    snprintf(errstr, 1024, "Pcap Source opened %s", dev);
    return 1;
}

int PcapSource::CloseSource() {
    pcap_close(pd);
    return 1;
}

void PcapSource::Callback(u_char *bp, const struct pcap_pkthdr *header,
                                 const u_char *in_data) {
    memcpy(&callback_header, header, sizeof(pcap_pkthdr));
    memcpy(callback_data, in_data, header->len);
}

int PcapSource::FetchPacket(kis_packet *packet) {
    int ret;
    //unsigned char *udata = '\0';

    if ((ret = pcap_dispatch(pd, 1, PcapSource::Callback, NULL)) < 0) {
        snprintf(errstr, 1024, "Pcap Get Packet pcap_dispatch() failed");
        return -1;
    }

    if (ret == 0)
        return 0;

    if (paused || Pcap2Common(packet) == 0) {
        return 0;
    }

    return(packet->caplen);
}

int PcapSource::Pcap2Common(kis_packet *packet) {
    memset(packet, 0, sizeof(kis_packet));

    int callback_offset = 0;

    packet->ts = callback_header.ts;

    // Get the power from the datalink headers if we can, otherwise use proc/wireless
    if (datalink_type == DLT_PRISM_HEADER) {
        if (callback_header.caplen < sizeof(wlan_ng_prism2_header)) {
            snprintf(errstr, 1024, "pcap Pcap2Common saw undersized capture frame for prism2-header data.");
            packet->len = 0;
            packet->caplen = 0;
            return 0;
        }

        wlan_ng_prism2_header *p2head = (wlan_ng_prism2_header *) callback_data;

        packet->caplen = min(p2head->frmlen.data, (uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;

        // Set our offset for extracting the actual data
        callback_offset = sizeof(wlan_ng_prism2_header);

        packet->quality = p2head->sq.data;
        packet->signal = p2head->signal.data;
        packet->noise = p2head->noise.data;

        packet->channel = p2head->channel.data;

    } else if (datalink_type == KDLT_BSD802_11) {
        // Process our hacked in BSD type
        if (callback_header.caplen < sizeof(bsd_80211_header)) {
            snprintf(errstr, 1024, "pcap Pcap2Common saw undersized capture frame for bsd-header header.");
            packet->len = 0;
            packet->caplen = 0;
            return 0;
        }

        packet->caplen = min(callback_header.caplen - sizeof(bsd_80211_header), (uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;

        bsd_80211_header *bsdhead = (bsd_80211_header *) callback_data;
        packet->signal = bsdhead->wi_signal;

        // No noise level so quality = percentage of max signal level
        packet->quality = (packet->signal * 100) / 256;

        // Adjust to take out the BSD header

        // Set our offset
        callback_offset = sizeof(bsd_80211_header);

    } else {
        packet->caplen = min(callback_header.caplen, (uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;

        // Fill in the connection info from the wireless extentions, if we can
#ifdef HAVE_LINUX_WIRELESS
        FILE *procwireless;

        if ((procwireless = fopen("/proc/net/wireless", "r")) != NULL) {
            char wdata[1024];
            fgets(wdata, 1024, procwireless);
            fgets(wdata, 1024, procwireless);
            fgets(wdata, 1024, procwireless);

            int qual, lev, noise;
            char qupd, lupd, nupd;
            sscanf(wdata+14, "%d%c %d%c %d%c", &qual, &qupd, &lev, &lupd, &noise, &nupd);

            if (qupd != '.')
                qual = 0;
            if (lupd != '.')
                lev = 0;
            if (nupd != '.')
                noise = 0;

            fclose(procwireless);

            packet->quality = qual;
            packet->signal = lev;
            packet->noise = noise;
        }
#endif
    }

    if (cardtype == card_cisco_bsd && (callback_offset + packet->caplen) > 26) {
        // The cisco BSD drivers seem to insert 2 bytes of crap

        packet->len -= 2;
        packet->caplen -= 2;

        packet->data = new uint8_t[packet->caplen];

        memcpy(packet->data, callback_data + callback_offset, 24);
        memcpy(packet->data + 24, callback_data + callback_offset + 26, packet->caplen - 26);
    } else if (cardtype == card_prism2_bsd && (callback_offset + packet->caplen) > 46) {
        // The freebsd prism2 drivers insert 22 bytes of crap

        packet->len -= 22;
        packet->caplen -= 22;

        packet->data = new uint8_t[packet->caplen];

        memcpy(packet->data, callback_data + callback_offset, 24);
        memcpy(packet->data + 24, callback_data + callback_offset + 46, packet->caplen - 46);

    } else {
        // Otherwise we don't do anything or we don't have enough of a packet to do anything
        // with.
        packet->data = new uint8_t[packet->caplen];

        memcpy(packet->data, callback_data + callback_offset, packet->caplen);
    }

    // For now, anything not the ar5k is 802.11b
    if (cardtype == card_ar5k)
        packet->carrier = carrier_80211a;
    else
        packet->carrier = carrier_80211b;

    return 1;
}

#endif

