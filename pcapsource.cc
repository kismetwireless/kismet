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
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#ifdef HAVE_LINUX_WIRELESS
#include <linux/wireless.h>
#endif

#ifdef SYS_OPENBSD
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <dev/ic/if_wi_ieee.h>
#endif

#include "pcapsource.h"
#include "util.h"

#ifdef HAVE_LIBPCAP

// This is such a bad thing to do...
#include <pcap-int.h>

// Pcap global callback structs
pcap_pkthdr callback_header;
u_char callback_data[MAX_PACKET_LEN];

// Open a source
int PcapSource::OpenSource() {
    channel = 0;

    errstr[0] = '\0';

    char *unconst = strdup(interface.c_str());

    pd = pcap_open_live(unconst, MAX_PACKET_LEN, 1, 1000, errstr);

    free(unconst);

    if (strlen(errstr) > 0)
        return -1; // Error is already in errstr

    paused = 0;

    errstr[0] = '\0';

    num_packets = 0;

    if (DatalinkType() < 0)
        return -1;

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
    
    return 1;
}

// Datalink, override as appropriate
carrier_type PcapSource::IEEE80211Carrier() {
    int ch = FetchChannel();

    if (ch > 0 && ch <= 14)
        return carrier_80211b;
    else if (ch > 34)
        return carrier_80211a;

    return carrier_unknown;
}

// Errorcheck the datalink type
int PcapSource::DatalinkType() {
    datalink_type = pcap_datalink(pd);

    // Blow up if we're not valid 802.11 headers
#if (defined(SYS_FREEBSD) || defined(SYS_OPENBSD))
    if (datalink_type == DLT_EN10MB) {
        fprintf(stderr, "WARNING:  pcap reports link type of EN10MB but we'll fake it on BSD.\n"
                "This may not work the way we want it to.\n");
#if (defined(SYS_FREEBSD) || defined(SYS_NETBSD))
        fprintf(stderr, "WARNING:  Most Free and Net BSD drivers do not report rfmon packets\n"
                "correctly.  Kismet will probably not run correctly.");
#endif
        datalink_type = KDLT_BSD802_11;
    }
#else
    if (datalink_type == DLT_EN10MB) {
        snprintf(errstr, 1024, "pcap reported netlink type 1 (EN10MB) for %s.  "
                 "This probably means you're not in RFMON mode or your drivers are "
                 "reporting a bad value.  Make sure you have the correct drivers "
                 "and that entering monitor mode succeeded.", interface.c_str());
        return -1;
    }
#endif

    if (datalink_type != KDLT_BSD802_11 && datalink_type != DLT_IEEE802_11 &&
        datalink_type != DLT_PRISM_HEADER) {
        fprintf(stderr, "WARNING:  Unknown link type %d reported.  Continuing on blindly...\n",
                datalink_type);
    }

    return 1;
}

int PcapSource::CloseSource() {
    pcap_close(pd);
    return 1;
}

int PcapSource::FetchDescriptor() {
    return pcap_fileno(pd);
}

void PcapSource::Callback(u_char *bp, const struct pcap_pkthdr *header,
                                 const u_char *in_data) {
    memcpy(&callback_header, header, sizeof(pcap_pkthdr));
    memcpy(callback_data, in_data, header->len);
}

int PcapSource::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int ret;
    //unsigned char *udata = '\0';

    if ((ret = pcap_dispatch(pd, 1, PcapSource::Callback, NULL)) < 0) {
        snprintf(errstr, 1024, "Pcap Get Packet pcap_dispatch() failed");
        return -1;
    }

    if (ret == 0)
        return 0;

    if (paused || ManglePacket(packet, data, moddata) == 0) {
        return 0;
    }

    num_packets++;

    // Set the name
    snprintf(packet->sourcename, 32, "%s", name.c_str());
    
    // Set the parameters
    packet->parm = parameters;
    
    return(packet->caplen);
}

int PcapSource::ManglePacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int ret = 0;
    memset(packet, 0, sizeof(kis_packet));
    
    packet->ts = callback_header.ts;
    packet->data = data;
    packet->moddata = moddata;
    packet->modified = 0;

    if (gpsd != NULL) {
        gpsd->FetchLoc(&packet->gps_lat, &packet->gps_lon, &packet->gps_alt,
                       &packet->gps_spd, &packet->gps_heading, &packet->gps_fix);
    }

    if (datalink_type == DLT_PRISM_HEADER) {
        ret = Prism2KisPack(packet, data, moddata);
    } else if (datalink_type == KDLT_BSD802_11) {
        ret = BSD2KisPack(packet, data, moddata);
    } else {
        packet->caplen = kismin(callback_header.caplen, (uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;
        memcpy(packet->data, callback_data, packet->caplen);
        ret = 1;
    }

    // Fetch the channel if we know how and it hasn't been filled in already
    if (packet->channel == 0)
        packet->channel = FetchChannel();

    if (packet->carrier == carrier_unknown)
        packet->carrier = IEEE80211Carrier();
    
    return ret;

}

int PcapSource::Prism2KisPack(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int header_found = 0;
    int callback_offset = 0;

    // See if we have an AVS wlan header...
    avs_80211_1_header *v1hdr = (avs_80211_1_header *) callback_data;
    if (callback_header.caplen >= sizeof(avs_80211_1_header) &&
        ntohl(v1hdr->version) == 0x80211001 && header_found == 0) {

        if (ntohl(v1hdr->length) > callback_header.caplen) {
            snprintf(errstr, 1024, "pcap prism2 converter got corrupted AVS header length");
            packet->len = 0;
            packet->caplen = 0;
            return 0;
        }

        header_found = 1;

        // Nasty hack to strip FCS if its all 0xFF that some drivers put in.
        // Find a better way to do this.
        int fcs = 0;
        if (memcmp((uint32_t *) &callback_data[kismin(callback_header.caplen, 
                                                      (uint32_t) MAX_PACKET_LEN) - 4], 
                   "\xFF\xFF\xFF\xFF", 4) == 0) {
            fcs = 4;
        } 

        // Subtract the packet FCS since kismet doesn't do anything terribly bright
        // with it right now
        packet->caplen = kismin(callback_header.caplen - ntohl(v1hdr->length) - fcs, 
                                (uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;

        /*
        packet->caplen = kismin(callback_header.caplen - 4 - ntohl(v1hdr->length), (uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;
        */

        callback_offset = ntohl(v1hdr->length);

        // We REALLY need to do something smarter about this and handle the RSSI
        // type instead of just copying
        packet->signal = ntohl(v1hdr->ssi_signal);
        packet->noise = ntohl(v1hdr->ssi_noise);

        packet->channel = ntohl(v1hdr->channel);

        switch (ntohl(v1hdr->phytype)) {
            case 1:
                packet->carrier = carrier_80211fhss;
            case 2:
                packet->carrier = carrier_80211dsss;
                break;
            case 4:
            case 5:
                packet->carrier = carrier_80211b;
                break;
            case 6:
            case 7:
                packet->carrier = carrier_80211g;
                break;
            case 8:
                packet->carrier = carrier_80211a;
                break;
            default:
                packet->carrier = carrier_unknown;
                break;
        }

        packet->encoding = (encoding_type) ntohl(v1hdr->encoding);

        packet->datarate = (int) ntohl(v1hdr->datarate);
    }

    // See if we have a prism2 header
    wlan_ng_prism2_header *p2head = (wlan_ng_prism2_header *) callback_data;
    if (callback_header.caplen >= sizeof(wlan_ng_prism2_header) &&
        header_found == 0) {

        header_found = 1;

        // Nasty hack to strip FCS if its all 0xFF that some drivers put in.
        // Find a better way to do this.
        int fcs = 0;
        if (memcmp((uint32_t *) &callback_data[kismin(p2head->frmlen.data, 
                                                      (uint32_t) MAX_PACKET_LEN) - 4], 
                   "\xFF\xFF\xFF\xFF", 4) == 0) {
            fcs = 4;
        } 

        // Subtract the packet FCS since kismet doesn't do anything terribly bright
        // with it right now
        packet->caplen = kismin(p2head->frmlen.data - fcs, (uint32_t) MAX_PACKET_LEN);
        packet->len = packet->caplen;


        // Set our offset for extracting the actual data
        callback_offset = sizeof(wlan_ng_prism2_header);

        // packet->quality = p2head->sq.data;
        packet->signal = p2head->signal.data;
        packet->noise = p2head->noise.data;

        packet->channel = p2head->channel.data;

    }

    if (header_found == 0) {
        snprintf(errstr, 1024, "pcap prism2 convverter saw undersized capture frame");
        packet->len = 0;
        packet->caplen = 0;
        return 0;
    }

    memcpy(packet->data, callback_data + callback_offset, packet->caplen);

    return 1;

}

int PcapSource::BSD2KisPack(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int callback_offset = 0;

    // Process our hacked in BSD type
    if (callback_header.caplen < sizeof(bsd_80211_header)) {
        snprintf(errstr, 1024, "pcap bsd converter saw undersized capture frame for bsd header.");
        packet->len = 0;
        packet->caplen = 0;
        return 0;
    }

    packet->caplen = kismin(callback_header.caplen - sizeof(bsd_80211_header), (uint32_t) MAX_PACKET_LEN);
    packet->len = packet->caplen;

    // Fetch the channel if we know how and it hasn't been filled in already
    if (packet->channel == 0)
        packet->channel = FetchChannel();

    bsd_80211_header *bsdhead = (bsd_80211_header *) callback_data;

    packet->signal = bsdhead->wi_signal;
    packet->noise = bsdhead->wi_silence;

    // We're not going to even try to do quality measurements
    // packet->quality = ((packet->signal - packet->noise) * 100) / 256;

    // Set our offset
    callback_offset = sizeof(bsd_80211_header);
    if ((callback_offset + packet->caplen) > 68) {
        // 802.11 header
        memcpy(packet->data, callback_data + callback_offset, 24);

        // Adjust for driver appended snap and 802.3 headers
        if (packet->data[0] > 0x08) {
            packet->len -= 8;
            packet->caplen -= 8;
            memcpy(packet->data + 24, callback_data + callback_offset + 46, packet->caplen - 16);

        } else {

            memcpy(packet->data + 24, callback_data + callback_offset + 46, packet->caplen - 60);
        }

	// skip driver appended prism header
        packet->len -= 14;
        packet->caplen -= 14;

    } else {
        memcpy(packet->data, callback_data + callback_offset, packet->caplen);
    }

    return 1;
}

int PcapSource::FetchChannel() {
    return 0;
}

// Open an offline file with pcap
int PcapSourceFile::OpenSource() {
    channel = 0;

    errstr[0] = '\0';

    pd = pcap_open_offline(interface.c_str(), errstr);

    if (strlen(errstr) > 0)
        return -1; // Error is already in errstr

    paused = 0;

    errstr[0] = '\0';

    num_packets = 0;

    if (DatalinkType() < 0)
        return -1;
    
    return 1;
}

// Nasty hack into pcap priv functions to get the file descriptor.  This
// most likely is a bad idea.
int PcapSourceFile::FetchDescriptor() {
    return fileno(pd->sf.rfile);
}

int PcapSourceFile::FetchChannel() {
    return 0;
}

int PcapSourceFile::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int ret;
    //unsigned char *udata = '\0';

    ret = pcap_dispatch(pd, 1, PcapSource::Callback, NULL);

    if (ret < 0) {
        snprintf(errstr, 1024, "Pcap Get Packet pcap_dispatch() failed");
        return -1;
    } else if (ret == 0) {
        snprintf(errstr, 1024, "Pcap file reached end of capture.");
        return -1;
    }

    if (paused || ManglePacket(packet, data, moddata) == 0) {
        return 0;
    }

    num_packets++;

    // Set the name
    snprintf(packet->sourcename, 32, "%s", name.c_str());
    
    // Set the parameters
    packet->parm = parameters;
    
    return(packet->caplen);
}

#ifdef HAVE_LINUX_WIRELESS
// Simple alias to our ifcontrol interface
int PcapSourceWext::FetchChannel() {
    // Use wireless extensions to get the channel
    return Iwconfig_Get_Channel(interface.c_str(), errstr);
}

// Carrier override
carrier_type PcapSource11G::IEEE80211Carrier() {
    int ch = FetchChannel();

    if (ch > 0 && ch <= 14)
        return carrier_80211g;
    else if (ch > 34)
        return carrier_80211a;

    return carrier_unknown;
}
#endif

#ifdef SYS_LINUX
int PcapSourceWrt54g::FetchPacket(kis_packet *packet, uint8_t *data, uint8_t *moddata) {
    int ret;
    //unsigned char *udata = '\0';

    if ((ret = pcap_dispatch(pd, 1, PcapSource::Callback, NULL)) < 0) {
        snprintf(errstr, 1024, "Pcap Get Packet pcap_dispatch() failed");
        return -1;
    }

    if (ret == 0)
        return 0;

    if (paused || ManglePacket(packet, data, moddata) == 0) {
        return 0;
    }

    // Junk packets that are too big, this is the only real way to detect crap
    // packets...
    if (packet->caplen == MAX_PACKET_LEN) {
        // printf("debug - dropping large wrt54g packet\n");
        return 0;
    }
    
    num_packets++;

    // Set the name
    snprintf(packet->sourcename, 32, "%s", name.c_str());
    
    // Set the parameters
    packet->parm = parameters;
    
    return(packet->caplen);
}

carrier_type PcapSourceWrt54g::IEEE80211Carrier() {
    int ch = FetchChannel();

    if (ch > 0 && ch <= 14)
        return carrier_80211g;
    else if (ch > 34)
        return carrier_80211a;

    return carrier_unknown;
}
#endif

#ifdef SYS_OPENBSD
int PcapSourceOpenBSDPrism::FetchChannel() {
    struct wi_req wreq;                                                     
    struct ifreq ifr;                                                       
    int skfd;

	if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		snprintf(errstr, 1024, "Failed to create AF_INET socket: %s",
                 strerror(errno));
		return -1;
	}

    bzero((char *)&wreq, sizeof(wreq));                                     
    wreq.wi_len = WI_MAX_DATALEN;                                           
    wreq.wi_type = WI_RID_CURRENT_CHAN; 

    bzero((char *)&ifr, sizeof(ifr));                                       
    strlcpy(ifr.ifr_name, interface.c_str(), sizeof(ifr.ifr_name));
    ifr.ifr_data = (caddr_t)&wreq;                                          

	if (ioctl(skfd, SIOCGWAVELAN, &ifr) < 0) {
        close(skfd);
		snprintf(errstr, 1024, "Channel set ioctl failed: %s",
                 strerror(errno));
		return -1;
	}

    close(skfd);
    return wreq.wi_val[0];                                                  
}
#endif

// ----------------------------------------------------------------------------
// Registrant and control functions outside of the class

KisPacketSource *pcapsource_registrant(string in_name, string in_device,
                                       char *in_err) {
    return new PcapSource(in_name, in_device);
}

KisPacketSource *pcapsource_file_registrant(string in_name, string in_device,
                                            char *in_err) {
    return new PcapSourceFile(in_name, in_device);
}

#ifdef HAVE_LINUX_WIRELESS
KisPacketSource *pcapsource_wext_registrant(string in_name, string in_device, 
                                            char *in_err) {
    return new PcapSourceWext(in_name, in_device);
}

KisPacketSource *pcapsource_ciscowifix_registrant(string in_name, string in_device, char *in_err) {
    vector<string> devbits = StrTokenize(in_device, ":");

    if (devbits.size() < 2) {
        snprintf(in_err, STATUS_MAX, "Invalid device pair '%s'", in_device.c_str());
        return NULL;
    }

    return new PcapSourceWext(in_name, devbits[1]);
}

KisPacketSource *pcapsource_11g_registrant(string in_name, string in_device,
                                           char *in_err) {
    return new PcapSource11G(in_name, in_device);
}
#endif

#ifdef SYS_LINUX
KisPacketSource *pcapsource_wrt54g_registrant(string in_name, string in_device,
                                              char *in_err) {
    return new PcapSourceWrt54g(in_name, in_device);
}
#endif

#ifdef SYS_OPENBSD
KisPacketSource *pcapsource_openbsdprism2_registrant(string in_name, string in_device,
                                                     char *in_err) {
    return new PcapSourceOpenBSDPrism(in_name, in_device);
}
#endif

// Monitor commands
#ifdef HAVE_LINUX_WIRELESS
// Cisco uses its own config file in /proc to control modes
int monitor_cisco(const char *in_dev, int initch, char *in_err) {
    FILE *cisco_config;
    char cisco_path[128];

    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Linux(in_dev, in_err) < 0)
        return -1;

    // Zero the ssid
    if (Iwconfig_Blank_SSID(in_dev, in_err) < 0)
        return -1;
    
    // Build the proc control path
    snprintf(cisco_path, 128, "/proc/driver/aironet/%s/Config", in_dev);

    if ((cisco_config = fopen(cisco_path, "w")) == NULL) {
        snprintf(in_err, STATUS_MAX, "Unable to open cisco control file '%s' %d:%s",
                 cisco_path, errno, strerror(errno));
        return -1;
    }

    fprintf(cisco_config, "Mode: r\n");
    fprintf(cisco_config, "Mode: y\n");
    fprintf(cisco_config, "XmitPower: 1\n");

    fclose(cisco_config);

    // Channel can't be set on cisco with these drivers.

    return 0;
}

// Cisco uses its own config file in /proc to control modes
//
// I was doing this with ioctls but that seems to cause lockups while
// this method doesn't.  I don't think I like these drivers.
int monitor_cisco_wifix(const char *in_dev, int initch, char *in_err) {
    FILE *cisco_config;
    char cisco_path[128];
    vector<string> devbits = StrTokenize(in_dev, ":");

    if (devbits.size() < 2) {
        snprintf(in_err, STATUS_MAX, "Invalid device pair '%s'", in_dev);
        return -1;
    }

    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Linux(devbits[0].c_str(), in_err) < 0)
        return -1;
    if (Ifconfig_Linux(devbits[1].c_str(), in_err) < 0)
        return -1;

    // Zero the ssid
    if (Iwconfig_Blank_SSID(devbits[0].c_str(), in_err) < 0)
        return -1;
    if (Iwconfig_Blank_SSID(devbits[1].c_str(), in_err) < 0)
        return -1;
    
    // Build the proc control path
    snprintf(cisco_path, 128, "/proc/driver/aironet/%s/Config", devbits[0].c_str());

    if ((cisco_config = fopen(cisco_path, "w")) == NULL) {
        snprintf(in_err, STATUS_MAX, "Unable to open cisco control file '%s' %d:%s",
                 cisco_path, errno, strerror(errno));
        return -1;
    }

    fprintf(cisco_config, "Mode: r\n");
    fprintf(cisco_config, "Mode: y\n");
    fprintf(cisco_config, "XmitPower: 1\n");

    fclose(cisco_config);

    // Channel can't be set on cisco with these drivers.

    return 0;
}

// Hostap uses iwpriv and iwcontrol settings to control monitor mode
int monitor_hostap(const char *in_dev, int initch, char *in_err) {
    int ret;
    int monret;
   
    // Try to use the iwpriv command to set monitor mode.  Some versions of
    // hostap require this, some don't, so don't fail on the monitor ioctl
    // if we can't find it, it might get removed in the future.
    if ((ret = Iwconfig_Set_IntPriv(in_dev, "monitor", 3, 0, in_err)) < 0) {
        if (ret != -2)
            return -1;
    }
   
    // Try to set wext monitor mode.  We're good if one of these succeeds...
    if ((monret = monitor_wext(in_dev, initch, in_err)) < 0 && ret < 0)
        return -1;

    // If we didn't set wext mode, set the channel manually
    if (monret < 0 && chancontrol_wext(in_dev, initch, in_err, NULL) < 0)
        return -1;

    return 0;
}

// Orinoco uses iwpriv and iwcontrol settings to control monitor mode
int monitor_orinoco(const char *in_dev, int initch, char *in_err) {
    int ret;
    
    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Linux(in_dev, in_err) < 0) 
        return -1;

    // Zero the ssid
    if (Iwconfig_Blank_SSID(in_dev, in_err) < 0) 
        return -1;

    // Socket lowpower cards seem to need a little time for the firmware to settle
    // down between these calls, so we'll just sleep for everyone.  It won't hurt
    // to add a few more ms onto an indefinitely blocking ioctl setup
    usleep(5000);

    // Set the monitor mode iwpriv controls.  Explain more if we fail on monitor.
    if ((ret = Iwconfig_Set_IntPriv(in_dev, "monitor", 1, initch, in_err)) < 0) {
        if (ret == -2)
            snprintf(in_err, 1024, "Could not find 'monitor' private ioctl.  This "
                     "typically means that the drivers have not been patched or the "
                     "patched drivers are being loaded.  See the troubleshooting "
                     "section of the README for more information.");
        return -1;
    }

    // The channel is set by the iwpriv so we're done.
    
    return 0;
}

// Acx100 uses the packhdr iwpriv control to set link state, rest is normal
int monitor_acx100(const char *in_dev, int initch, char *in_err) {
    // Set the packhdr iwpriv control to 1
    if (Iwconfig_Set_IntPriv(in_dev, "packhdr", 1, 0, in_err) < 0) {
        return -1;
    }
    
    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err) < 0)
        return -1;

    return 0;
}

// vtar5k iwpriv control to set link state, rest is normal
int monitor_vtar5k(const char *in_dev, int initch, char *in_err) {
    // Set the prism iwpriv control to 1
    if (Iwconfig_Set_IntPriv(in_dev, "prism", 1, 0, in_err) < 0) {
        return -1;
    }
    
    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err) < 0)
        return -1;

    return 0;
}

// Madwifi stuff uses iwpriv mode
int monitor_madwifi_a(const char *in_dev, int initch, char *in_err) {
    if (Iwconfig_Set_IntPriv(in_dev, "mode", 1, 0, in_err) < 0)
        return -1;

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err) < 0)
        return -1;

    return 0;
}

int monitor_madwifi_b(const char *in_dev, int initch, char *in_err) {
    if (Iwconfig_Set_IntPriv(in_dev, "mode", 2, 0, in_err) < 0)
        return -1;

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err) < 0)
        return -1;

    return 0;
}

int monitor_madwifi_g(const char *in_dev, int initch, char *in_err) {
    if (Iwconfig_Set_IntPriv(in_dev, "mode", 3, 0, in_err) < 0)
        return -1;

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err) < 0)
        return -1;

    return 0;
}

int monitor_madwifi_comb(const char *in_dev, int initch, char *in_err) {
    if (Iwconfig_Set_IntPriv(in_dev, "mode", 0, 0, in_err) < 0)
        return -1;

    // The rest is standard wireless extensions
    if (monitor_wext(in_dev, initch, in_err) < 0)
        return -1;

    return 0;
}

// Call the standard monitor but ignore error codes since channel
// setting won't work.  This is a temp kluge.
int monitor_prism54g(const char *in_dev, int initch, char *in_err) {
    int ret = monitor_wext(in_dev, initch, in_err);

    if (ret < 0 && ret != -2)
        return ret;
    
    return 0;
}

// "standard" wireless extension monitor mode
int monitor_wext(const char *in_dev, int initch, char *in_err) {
    struct iwreq wrq;
    int skfd;

    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Linux(in_dev, in_err) < 0) 
        return -1;

    // Zero the ssid
    if (Iwconfig_Blank_SSID(in_dev, in_err) < 0) 
        return -1;

    // Kick it into rfmon mode
    if ((skfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to create AF_INET DGRAM socket %d:%s", 
                 errno, strerror(errno));
        return -1;
    }

    // Get mode and see if we're already in monitor, don't try to go in
    // if we are (cisco doesn't like rfmon rfmon)
    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);

    if (ioctl(skfd, SIOCGIWMODE, &wrq) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to get mode %d:%s", 
                 errno, strerror(errno));
        close(skfd);
        return -1;
    }

    if (wrq.u.mode == LINUX_WLEXT_MONITOR) {
        close(skfd);
        return 0;
    }

    // Set it
    //
    memset(&wrq, 0, sizeof(struct iwreq));
    strncpy(wrq.ifr_name, in_dev, IFNAMSIZ);
    wrq.u.mode = LINUX_WLEXT_MONITOR;

    if (ioctl(skfd, SIOCSIWMODE, &wrq) < 0) {
        snprintf(in_err, STATUS_MAX, "Failed to set monitor mode: %s.  This usually "
                 "means your drivers either do not support monitor mode, or use a "
                 "different mechanism for getting to it.  Make sure you have a "
                 "version of your drivers that support monitor mode, and consult "
                 "the troubleshooting section of the README.", 
                 strerror(errno));
        close(skfd);
        return -1;
    }
    
    // Set the initial channel - if we ever get a pcapsource that needs a hook
    // back into the class, this will have to be rewritten
    if (chancontrol_wext(in_dev, initch, in_err, NULL) < 0) {
        close(skfd);
        return -2;
    }
    
    close(skfd);
    return 0;
}
#endif

#ifdef SYS_LINUX
// wlan-ng modern standard
int monitor_wlanng(const char *in_dev, int initch, char *in_err) {
    // I really didn't want to do this...
    char cmdline[2048];

    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Linux(in_dev, in_err) < 0) 
        return -1;

    // Enable the interface
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_ifstate ifstate=enable", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Turn off WEP
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset mibattribute=dot11PrivacyInvoked=false", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Don't exclude packets
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset mibattribute=dot11ExcludeUnencrypted=false", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Turn on rfmon on the initial channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true prismheader=true", in_dev, initch);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;
    
    return 0;
}

// wlan-ng avs
int monitor_wlanng_avs(const char *in_dev, int initch, char *in_err) {
    // I really didn't want to do this...
    char cmdline[2048];

    // Bring the device up, zero its ip, and set promisc
    if (Ifconfig_Linux(in_dev, in_err) < 0) 
        return -1;

    // Enable the interface
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_ifstate ifstate=enable", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Turn off WEP
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset "
             "mibattribute=dot11PrivacyInvoked=false", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Don't exclude packets
    snprintf(cmdline, 2048, "wlanctl-ng %s dot11req_mibset "
             "mibattribute=dot11ExcludeUnencrypted=false", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    // Turn on rfmon on the initial channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d prismheader=false "
             "wlanheader=true stripfcs=false keepwepflags=false enable=true", in_dev, initch);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;
    
    return 0;
}

int monitor_wrt54g(const char *in_dev, int initch, char *in_err) {
    char cmdline[2048];

    snprintf(cmdline, 2048, "/usr/sbin/wl monitor 1");
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    return 0;
}

#endif

#ifdef SYS_OPENBSD
// This should be done programattically...
int monitor_openbsd_cisco(const char *in_dev, int initch, char *in_err) {
    char cmdline[2048];

    snprintf(cmdline, 2048, "ancontrol -i %s -o 1", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    snprintf(cmdline, 2048, "ancontrol -i %s -p 1", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;

    snprintf(cmdline, 2048, "ancontrol -i %s -M 7", in_dev);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;
    
    return 0;
}

int monitor_openbsd_prism2(const char *in_dev, int initch, char *in_err) {

	struct wi_req		wreq;
	struct ifreq		ifr;

	int	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		snprintf(in_err, 1024, "Failed to create AF_INET socket: %s",
                 strerror(errno));
		return -1;
	}

	// Set our initial channel
	bzero((char *)&wreq, sizeof(wreq));
	wreq.wi_len = WI_MAX_DATALEN;
	wreq.wi_type = WI_DEBUG_CHAN;
	wreq.wi_val[0] = htole16(initch);

	bzero((char *)&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, in_dev, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&wreq;

	if (ioctl(s, SIOCSPRISM2DEBUG, &ifr) < 0) {
        close(s);
		snprintf(in_err, 1024, "Channel set ioctl failed: %s",
                 strerror(errno));
		return -1;
	}

	// Disable power managment
	bzero((char *)&wreq, sizeof(wreq));
	wreq.wi_len = WI_MAX_DATALEN;
	wreq.wi_type = WI_RID_PM_ENABLED;
	wreq.wi_val[0] = 0;

	if (ioctl(s, SIOCSWAVELAN, &ifr) < 0) {
        close(s);
		snprintf(in_err, 1024, "Power management ioctl failed: %s",
                 strerror(errno));
		return -1;
	}

	// Lower AP density, better radio threshold settings?
	bzero((char *)&wreq, sizeof(wreq));
	wreq.wi_len = WI_MAX_DATALEN;
	wreq.wi_type = WI_RID_SYSTEM_SCALE;
	wreq.wi_val[0] = 1;

	if (ioctl(s, SIOCSWAVELAN, &ifr) < 0) {
        close(s);
		snprintf(in_err, 1024, "AP Density ioctl failed: %s",
                 strerror(errno));
		return -1;
	}

	// Enable driver processing of 802.11b frames
	bzero((char *)&wreq, sizeof(wreq));
	wreq.wi_len = WI_MAX_DATALEN;
	wreq.wi_type = WI_RID_PROCFRAME;
	wreq.wi_val[0] = 1;

	if (ioctl(s, SIOCSWAVELAN, &ifr) < 0) {
        close(s);
		snprintf(in_err, 1024, "Driver processing ioctl failed: %s",
                 strerror(errno));
		return -1;
	}

	// Disable roaming, we don't want the card to probe
	bzero((char *)&wreq, sizeof(wreq));
	wreq.wi_len = WI_MAX_DATALEN;
	wreq.wi_type = WI_RID_ROAMING_MODE;
	wreq.wi_val[0] = 3;

	if (ioctl(s, SIOCSWAVELAN, &ifr) < 0) {
        close(s);
		snprintf(in_err, 1024, "Roaming disable ioctl failed: %s",
                 strerror(errno));
		return -1;
	}

	// Enable monitor mode
	bzero((char *)&wreq, sizeof(wreq));
	wreq.wi_len = WI_MAX_DATALEN;
	wreq.wi_type = WI_DEBUG_MONITOR;
	wreq.wi_val[0] = 1;

	if (ioctl(s, SIOCSPRISM2DEBUG, &ifr) < 0) {
        close(s);
		snprintf(in_err, 1024, "Monitor mode ioctl failed: %s",
                 strerror(errno));
		return -1;
	}

    close(s);

    return 0;
}
#endif

// Channel change commands
#ifdef HAVE_LINUX_WIRELESS
// Generic wireless "iwconfig channel x" 
int chancontrol_wext(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    return(Iwconfig_Set_Channel(in_dev, in_ch, in_err));
}

// Use iwpriv to control the channel for orinoco
int chancontrol_orinoco(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    int ret;
    
    // Set the monitor mode iwpriv controls.  Explain more if we fail on monitor.
    if ((ret = Iwconfig_Set_IntPriv(in_dev, "monitor", 1, in_ch, in_err)) < 0) {
        if (ret == -2) 
            snprintf(in_err, 1024, "Could not find 'monitor' private ioctl.  This "
                     "typically means that the drivers have not been patched or the "
                     "patched drivers are being loaded.  See the troubleshooting "
                     "section of the README for more information.");
        return -1;
    }

    // The channel is set by the iwpriv so we're done.
    
    return 0;
}

// Madwifi needs to change modes accordinly
int chancontrol_madwifi_ab(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    /*
    if (in_ch > 0 && in_ch <= 14) {
        if (Iwconfig_Set_IntPriv(in_dev, "mode", 2, 0, in_err) < 0)
            return -1;
    } else {
        if (Iwconfig_Set_IntPriv(in_dev, "mode", 1, 0, in_err) < 0)
            return -1;
    }
    */
    return chancontrol_wext(in_dev, in_ch, in_err, in_ext);
}

int chancontrol_madwifi_ag(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    if (in_ch > 0 && in_ch <= 14) {
        if (Iwconfig_Set_IntPriv(in_dev, "mode", 3, 0, in_err) < 0)
            return -1;
    } else {
        if (Iwconfig_Set_IntPriv(in_dev, "mode", 1, 0, in_err) < 0)
            return -1;
    }

    return chancontrol_wext(in_dev, in_ch, in_err, in_ext);
}

int chancontrol_prism54g(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    // Run the wireless extention stuff and scrap the error codes
    chancontrol_wext(in_dev, in_ch, in_err, in_ext);

    return 0;
}

#endif

#ifdef SYS_LINUX
int chancontrol_wlanng(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    // I really didn't want to do this...
    char cmdline[2048];

    // Turn on rfmon on the initial channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d enable=true "
             "prismheader=true >/dev/null 2>&1", in_dev, in_ch);
    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;
    
    return 0;
    
}

int chancontrol_wlanng_avs(const char *in_dev, int in_ch, char *in_err, void *in_ext) {
    // I really didn't want to do this...
    char cmdline[2048];

    // Turn on rfmon on the initial channel
    snprintf(cmdline, 2048, "wlanctl-ng %s lnxreq_wlansniff channel=%d "
             "prismheader=false wlanheader=true stripfcs=false keepwepflags=false "
             "enable=true >/dev/null 2>&1", in_dev, in_ch);

    if (ExecSysCmd(cmdline, in_err) < 0)
        return -1;
    
    return 0;
    
}
#endif

#ifdef SYS_OPENBSD
int chancontrol_openbsd_prism2(const char *in_dev, int in_ch, char *in_err, 
                               void *in_ext) {

	struct wi_req		wreq;
	struct ifreq		ifr;
	int		s;

	bzero((char *)&wreq, sizeof(wreq));
	wreq.wi_len = WI_MAX_DATALEN;
	wreq.wi_type = WI_DEBUG_CHAN;
	wreq.wi_val[0] = htole16(in_ch);

	bzero((char *)&ifr, sizeof(ifr));
	strlcpy(ifr.ifr_name, in_dev, sizeof(ifr.ifr_name));
	ifr.ifr_data = (caddr_t)&wreq;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s == -1) {
		snprintf(in_err, 1024, "Failed to create AF_INET socket: %s",
                 strerror(errno));
		return -1;
	}

	if (ioctl(s, SIOCSPRISM2DEBUG, &ifr) < 0) {
        close(s);
		snprintf(in_err, 1024, "Channel set ioctl failed: %s", strerror(errno));
		return -1;
	}

	close(s);

	return 0;
}
#endif

#endif

