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

#include <stdio.h>
#include <sys/ioctl.h>
#include <errno.h>

#include "genericsource.h"

#ifdef HAVE_LINUX_WIRELESS

int GenericSource::OpenSource(const char *dev, card_type ctype) {
    snprintf(type, 64, "generic ssid source (DEFUNCT)");

    strncpy(interface, dev, 64);

    sock = socket(AF_INET, SOCK_DGRAM, 0);

    // Set the essid to null to begin with
    if (SetGenericEssid(NULL) < 0)
        return -1;

    gettimeofday(&ts, NULL);

    return 1;
}

int GenericSource::CloseSource() {
    return 1;
}

int GenericSource::FetchPacket(pkthdr *in_header, u_char *in_data) {
    // We only do this twice a second, because otherwise we tank
    // the system.
    timeval new_ts;
    gettimeofday(&new_ts, NULL);
    if (ts.tv_sec == new_ts.tv_sec && new_ts.tv_usec - ts.tv_usec < 500000) {
        //printf("not fetching, %d %d , %d %d\n", ts.tv_sec, ts.tv_usec, new_ts.tv_sec, new_ts.tv_usec);
        return 0;
    }
    ts = new_ts;

    int ret;

    if (paused) return 0;

    if ((ret = GetGenericInfo()) < 0)
        return -1;

    if (ret != 0) {
        Generic2Common(in_header, in_data);
    }

    // Reset our SSID to null
    if (SetGenericEssid(NULL) < 0)
        return -1;

    if (ret == 0)
        return 0;

    return in_header->len;
}

int GenericSource::Generic2Common(pkthdr *in_header, u_char *in_data) {
    // I hate Wavelan so very very much.  Because all it can give us is
    // essid's, we have to build a whole 802.11 data packet and fake it
    // so that the rest of Kismet can dissect them correctly.

    memset(in_header, 0, sizeof(pkthdr));
    memset(in_data, 0, MAX_PACKET_LEN);


    // We'll write the packet data, then we'll write the header once we
    // know how big we are.
    int packetlen = 0;

    frame_control fc;

    memset(&fc, 0, sizeof(frame_control));

    // Fill it in.  A lot of this we could leave blank and let the zero
    // take care of it, but tis is easier to keep track of.
    fc.version = 0;
    fc.type = 0;
    fc.subtype = 8;
    fc.from_ds = 0;
    fc.to_ds = 0;
    fc.more_fragments = 0;
    fc.power_management = 0;
    fc.more_data = 0;
    fc.wep = 0;
    fc.order = 0;

    // Write the frame control, and offset
    memcpy(in_data, &fc, sizeof(frame_control));
    packetlen += sizeof(frame_control);

    uint8_t buf[128];
    memset(buf, 0, 128);

    // We just want the zeroed stuff for duration, 2 bytes
    memcpy(in_data + packetlen, buf, 2);
    packetlen += 2;

    // Dest - Broadcast MAC
    buf[0] = 0xff; buf[1] = 0xff; buf[2] = 0xff;
    buf[3] = 0xff; buf[4] = 0xff; buf[5] = 0xff;

    memcpy(in_data + packetlen, buf, 6);
    packetlen += 6;

    // Source - Our MAC
    memcpy(in_data + packetlen, mac, 6);
    packetlen += 6;

    // BSSID - Our MAC
    memcpy(in_data + packetlen, mac, 6);
    packetlen += 6;

    // We don't care about fragment or sequence number
    memset(buf, 0, 128);
    memcpy(in_data + packetlen, buf, 2);
    packetlen += 2;

    // OK, we've written our entire 802.11 header, time for the management data
    // that means something

    // We don't care about timestamping it
    memcpy(in_data + packetlen, buf, 8);
    packetlen += 8;

    // We don't care about the beacon interval
    memcpy(in_data + packetlen, buf, 2);
    packetlen += 2;

    uint8_t cap = 0;
    // Everything is an AP... We don't know anything else, unfortunately.
    cap |= (1 << 7);
    memcpy(in_data + packetlen, &cap, 1);
    packetlen += 1;
    // Likewise, we don't care about CFP
    memcpy(in_data + packetlen, buf, 1);
    packetlen += 1;

    // Tagged parameters.  Annoying to read, annoying to write, but we only
    // need one (for now).  Buf is still nulled so we can write that.
    // Tag 0
    memcpy(in_data + packetlen, buf, 1);
    packetlen += 1;
    // Length... We'll reuse our capabilities field
    cap = strlen(essid);
    memcpy(in_data + packetlen, &cap, 1);
    packetlen += 1;
    // Data
    memcpy(in_data + packetlen, essid, cap);
    packetlen += cap;

    // Now fill in our common header
    in_header->caplen = packetlen;
    in_header->len = packetlen;

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

        in_header->quality = qual;
        in_header->signal = lev;
        in_header->noise = noise;
    }


    gettimeofday(&in_header->ts, 0);

    return 1;
}

int GenericSource::SetGenericEssid(const char *essid_in) {
    // Liberated from gtkskan

    struct iwreq wrq;

    char buf[IW_ESSID_MAX_SIZE + 1];

    memset(&wrq, 0, sizeof(wrq));
    memset(buf, 0, sizeof(buf));

    strcpy(wrq.ifr_name, interface);

    if(essid_in == NULL) {
        wrq.u.essid.flags = 0;
    } else {
        wrq.u.essid.flags = 1;
        strcpy(buf, essid_in);
  }

  wrq.u.essid.pointer = (caddr_t) buf;
  wrq.u.essid.length = strlen(buf) + 1;

  if (ioctl(sock, SIOCSIWESSID, &wrq) < 0) {
      snprintf(errstr, 1024, "Generic source SIOCSIWESSID failed: %s", strerror(errno));
      return -1;
  }

  return 1;
}

int GenericSource::GetGenericInfo() {
    struct iwreq wrq;

    char buf[IW_ESSID_MAX_SIZE + 1];

    memset(buf, 0, sizeof(buf));
    memset(&wrq, 0, sizeof(wrq));

    // Fill in the request input block
    strcpy(wrq.ifr_name, interface);
    wrq.u.essid.pointer = (caddr_t) buf;
    wrq.u.essid.length = 0;
    wrq.u.essid.flags = 0;


    if (ioctl(sock, SIOCGIWESSID, &wrq) < 0) {
        snprintf(errstr, 1024, "Generic source SIOCGIWESSID failed: %s", strerror(errno));
        return -1;
    }

    if (buf[0] == '\0')
        return 0;

    // Copy the SSID into our local records
    strncpy(essid, buf, IW_ESSID_MAX_SIZE);

    // Reset the buffer
    memset(buf, 0, sizeof(buf));

    // Re-issue a new ioctl to fetch the MAC of the AP we found
    if (ioctl(sock, SIOCGIWAP, &wrq) < 0) {
        snprintf(errstr, 1024, "Generic source SIOCGIWAP failed: %s", strerror(errno));
        return -1;
    }

    if (wrq.u.ap_addr.sa_data[0] == 0x44 && wrq.u.ap_addr.sa_data[1] == 0x44 &&
        wrq.u.ap_addr.sa_data[2] == 0x44) {
        return 0;
    }

    // Copy the MAC into our local records
    memcpy(mac, wrq.u.ap_addr.sa_data, MAC_LEN);

    return 1;

}

#endif

