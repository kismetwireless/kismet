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

#include "kis_packsources.h"

KisPacketSource *nullsource_registrant(string in_name, string in_device, 
                                       char *in_err) {
    return new NullPacketSource(in_name, in_device);
}

int unmonitor_nullsource(const char *in_dev, int initch, 
                         char *in_err, void **in_if, void *in_ext) {
    return 0;
}

int RegisterKismetSources(Packetsourcetracker *sourcetracker) {
    // Register all our packet sources
    // RegisterPacketsource(name, root, channelset, init channel, register,
    // monitor, unmonitor, channelchanger)
    //
    // We register sources we known about but didn't compile support for as
    // NULL so we can report a sensible error if someone tries to use it
 
    // Null source
    sourcetracker->RegisterPacketsource("none", 0, "na", 0,
                                        nullsource_registrant,
                                        NULL, unmonitor_nullsource, NULL, 0);
    
    // Drone
    sourcetracker->RegisterPacketsource("kismet_drone", 0, "na", 0,
                                       dronesource_registrant,
                                       NULL, unmonitor_dronesource, NULL, 0);
    
    // pcap supported sources 
#ifdef HAVE_LIBPCAP
    // pcapfile doesn't have channel or monitor controls
    sourcetracker->RegisterPacketsource("pcapfile", 0, "na", 0,
                                       pcapsource_file_registrant,
                                       NULL, unmonitor_pcapfile, NULL, 0);
#else
    REG_EMPTY_CARD(sourcetracker, "pcapfile");
#endif

#if defined(HAVE_LIBPCAP) && defined(HAVE_LINUX_WIRELESS)
    // Linux wext-driven cards
    sourcetracker->RegisterPacketsource("cisco", 1, "IEEE80211b", 6,
                                       pcapsource_wext_registrant,
                                       monitor_cisco, unmonitor_cisco, 
                                       chancontrol_wext, 1);
    sourcetracker->RegisterPacketsource("cisco_wifix", 1, "IEEE80211b", 6,
                                       pcapsource_ciscowifix_registrant,
                                       monitor_cisco_wifix, NULL, NULL, 1);
    sourcetracker->RegisterPacketsource("hostap", 1, "IEEE80211b", 6,
                                       pcapsource_wext_registrant,
                                       monitor_hostap, unmonitor_hostap, 
                                       chancontrol_wext, 1);
    sourcetracker->RegisterPacketsource("orinoco", 1, "IEEE80211b", 6,
                                       pcapsource_wext_registrant,
                                       monitor_orinoco, unmonitor_orinoco, 
                                       chancontrol_orinoco, 1);
    sourcetracker->RegisterPacketsource("orinoco_14", 1, "IEEE80211b", 6,
                                        pcapsource_wext_registrant,
                                        monitor_orinoco, unmonitor_orinoco,
                                        chancontrol_orinoco, 1);
    sourcetracker->RegisterPacketsource("acx100", 1, "IEEE80211b", 6,
                                       pcapsource_wextfcs_registrant,
                                       monitor_acx100, unmonitor_acx100, 
                                       chancontrol_wext, 1);
    sourcetracker->RegisterPacketsource("admtek", 1, "IEEE80211b", 6,
                                        pcapsource_wext_registrant,
                                        monitor_admtek, unmonitor_admtek,
                                        chancontrol_wext, 1);
    sourcetracker->RegisterPacketsource("vtar5k", 1, "IEEE80211a", 36,
                                       pcapsource_wext_registrant,
                                       monitor_vtar5k, NULL, chancontrol_wext, 1);
    sourcetracker->RegisterPacketsource("atmel_usb", 1, "IEEE80211b", 6,
                                       pcapsource_wext_registrant,
                                       monitor_wext, unmonitor_wext, 
                                       chancontrol_wext, 1);

    sourcetracker->RegisterPacketsource("madwifi_a", 1, "IEEE80211a", 36,
                                        pcapsource_wextfcs_registrant,
                                        monitor_madwifi_a, unmonitor_madwifi, 
                                        chancontrol_wext, 1);
    sourcetracker->RegisterPacketsource("madwifi_b", 1, "IEEE80211b", 6,
                                        pcapsource_wextfcs_registrant,
                                        monitor_madwifi_b, unmonitor_madwifi, 
                                        chancontrol_wext, 1);
    sourcetracker->RegisterPacketsource("madwifi_g", 1, "IEEE80211g", 6,
                                        pcapsource_11gfcs_registrant,
                                        monitor_madwifi_g, unmonitor_madwifi, 
                                        chancontrol_wext, 1);
    sourcetracker->RegisterPacketsource("madwifi_ab", 1, "IEEE80211ab", 6,
                                        pcapsource_wextfcs_registrant,
                                        monitor_madwifi_comb, unmonitor_madwifi, 
                                        chancontrol_madwifi_ab, 1);
    sourcetracker->RegisterPacketsource("madwifi_ag", 1, "IEEE80211ab", 6,
                                        pcapsource_11gfcs_registrant,
                                        monitor_madwifi_comb, unmonitor_madwifi, 
                                        chancontrol_madwifi_ag, 1);

    sourcetracker->RegisterPacketsource("prism54g", 1, "IEEE80211g", 6,
                                        pcapsource_11g_registrant,
                                        monitor_prism54g, unmonitor_prism54g,
                                        chancontrol_prism54g, 1);

    sourcetracker->RegisterPacketsource("wlanng_wext", 1, "IEEE80211b", 6,
                                        pcapsource_wlanng_registrant,
                                        monitor_wlanng_avs, NULL,
                                        chancontrol_wext, 1);

    sourcetracker->RegisterPacketsource("ipw2100", 1, "IEEE80211b", 6,
                                        pcapsource_wext_registrant,
                                        monitor_ipw2100, unmonitor_ipw2100,
                                        chancontrol_ipw2100, 1);

    sourcetracker->RegisterPacketsource("ipw2200", 1, "IEEE80211g", 6,
                                        pcapsource_wext_registrant,
                                        monitor_ipw2200, unmonitor_ipw2200,
                                        chancontrol_ipw2200, 1);

    sourcetracker->RegisterPacketsource("ipw2915", 1, "IEEE80211ab", 6,
                                        pcapsource_wext_registrant,
                                        monitor_ipw2200, unmonitor_ipw2200,
                                        chancontrol_ipw2200, 1);

    sourcetracker->RegisterPacketsource("rt2400", 1, "IEEE80211b", 6,
                                        pcapsource_wext_registrant,
                                        monitor_wext, unmonitor_wext,
                                        chancontrol_wext, 1);
    sourcetracker->RegisterPacketsource("rt2500", 1, "IEEE80211g", 6,
                                        pcapsource_11g_registrant,
                                        monitor_wext, unmonitor_wext,
                                        chancontrol_wext, 1);
    sourcetracker->RegisterPacketsource("rt8180", 1, "IEEE80211b", 6,
                                        pcapsource_wext_registrant,
                                        monitor_wext, unmonitor_wext,
                                        chancontrol_wext, 1);

#else
    // Register the linuxwireless pcap stuff as null
    REG_EMPTY_CARD(sourcetracker, "cisco");
    REG_EMPTY_CARD(sourcetracker, "cisco_wifix");
    REG_EMPTY_CARD(sourcetracker, "hostap");
    REG_EMPTY_CARD(sourcetracker, "orinoco");
    REG_EMPTY_CARD(sourcetracker, "acx100");
    REG_EMPTY_CARD(sourcetracker, "vtar5k");

    REG_EMPTY_CARD(sourcetracker, "madwifi_a");
    REG_EMPTY_CARD(sourcetracker, "madwifi_b");
    REG_EMPTY_CARD(sourcetracker, "madwifi_g");
    REG_EMPTY_CARD(sourcetracker, "madwifi_ab");
    REG_EMPTY_CARD(sourcetracker, "madwifi_ag");

    REG_EMPTY_CARD(sourcetracker, "prism54g");

    REG_EMPTY_CARD(sourcetracker, "ipw2100");
    REG_EMPTY_CARD(sourcetracker, "ipw2200");
    REG_EMPTY_CARD(sourcetracker, "ipw2915");

    REG_EMPTY_CARD(sourcetracker, "rt2400");
    REG_EMPTY_CARD(sourcetracker, "rt2500");
    REG_EMPTY_CARD(sourcetracker, "rt8180");

    REG_EMPTY_CARD(sourcetracker, "wlanng_wext");
#endif

#if defined(HAVE_LIBPCAP) && defined(SYS_LINUX)
    sourcetracker->RegisterPacketsource("wlanng", 1, "IEEE80211b", 6,
                                       pcapsource_wlanng_registrant,
                                       monitor_wlanng, NULL, chancontrol_wlanng, 1);
    sourcetracker->RegisterPacketsource("wlanng_avs", 1, "IEEE80211b", 6,
                                       pcapsource_wlanng_registrant,
                                       monitor_wlanng_avs, NULL,
                                       chancontrol_wlanng_avs, 1);
    sourcetracker->RegisterPacketsource("wrt54g", 1, "na", 0,
                                        pcapsource_wrt54g_registrant,
                                        monitor_wrt54g, NULL, NULL, 0);
#else
    REG_EMPTY_CARD(sourcetracker, "wlanng");
    REG_EMPTY_CARD(sourcetracker, "wlanng_avs");
    REG_EMPTY_CARD(sourcetracker, "wrt54g");
#endif

#if defined(SYS_LINUX) && defined(HAVE_LINUX_NETLINK)
    sourcetracker->RegisterPacketsource("wlanng_legacy", 1, "IEEE80211b", 6,
                                        prism2source_registrant,
                                        monitor_wlanng_legacy, NULL,
                                        chancontrol_wlanng_legacy, 1);
#else
    REG_EMPTY_CARD(sourcetracker, "wlanng_legacy");
#endif

#if defined(HAVE_LIBPCAP) && defined(SYS_OPENBSD)
    sourcetracker->RegisterPacketsource("cisco_openbsd", 1, "IEEE80211b", 6,
                                       pcapsource_registrant,
                                       monitor_openbsd_cisco, NULL, NULL, 1);
    sourcetracker->RegisterPacketsource("prism2_openbsd", 1, "IEEE80211b", 6,
                                       pcapsource_openbsdprism2_registrant,
                                       monitor_openbsd_prism2, NULL,
                                       chancontrol_openbsd_prism2, 1);
#else
    REG_EMPTY_CARD(sourcetracker, "cisco_openbsd");
    REG_EMPTY_CARD(sourcetracker, "prism2_openbsd");
#endif

#if (defined(HAVE_RADIOTAP) && defined(HAVE_LIBPCAP) && (defined(SYS_NETBSD) || defined(SYS_OPENBSD) || defined(SYS_FREEBSD)))
    sourcetracker->RegisterPacketsource("radiotap_bsd_ab", 1, "IEEE80211ab", 6,
                                        pcapsource_radiotap_registrant,
                                        monitor_bsd, unmonitor_bsd,
                                        chancontrol_bsd, 1);
    sourcetracker->RegisterPacketsource("radiotap_bsd_a",1, "IEEE80211a", 6,
                                        pcapsource_radiotap_registrant,
                                        monitor_bsd, unmonitor_bsd,
                                        chancontrol_bsd, 1);
    sourcetracker->RegisterPacketsource("radiotap_bsd_b",1, "IEEE80211b", 6,
                                        pcapsource_radiotap_registrant,
                                        monitor_bsd, unmonitor_bsd,
                                        chancontrol_bsd, 1);
#else
    REG_EMPTY_CARD(sourcetracker, "radiotap_bsd_ab");
    REG_EMPTY_CARD(sourcetracker, "radiotap_bsd_a");
    REG_EMPTY_CARD(sourcetracker, "radiotap_bsd_b");
#endif

#if defined(HAVE_LIBWIRETAP)
    sourcetracker->RegisterPacketsource("wtapfile", 0, "na", 0,
                                       wtapfilesource_registrant,
                                       NULL, NULL, NULL, 0);
#else
    REG_EMPTY_CARD(sourcetracker, "wtapfile");
#endif

#if defined(HAVE_WSP100)
    sourcetracker->RegisterPacketsource("wsp100", 0, "IEEE80211b", 6,
                                        wsp100source_registrant,
                                        monitor_wsp100, NULL, chancontrol_wsp100, 0);
#else
    REG_EMPTY_CARD(sourcetracker, "wsp100");
#endif

#if defined(HAVE_VIHAHEADERS)
    sourcetracker->RegisterPacketsource("viha", 1, "IEEE80211b", 6,
                                        vihasource_registrant,
                                        NULL, NULL, chancontrol_viha, 0);
#else
    REG_EMPTY_CARD(sourcetracker, "viha");
#endif

    return 1;
}


