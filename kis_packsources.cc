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

int RegisterKismetSources(Packetsourcetracker *sourcetracker) {
    // Register all our packet sources
    // RegisterPacketsource(name, root, channelset, init channel, register,
    // monitor, unmonitor, channelchanger)
    //
    // We register sources we known about but didn't compile support for as
    // NULL so we can report a sensible error if someone tries to use it
   
    // Drone
    sourcetracker->RegisterPacketsource("kismet_drone", 0, "na", 0,
                                       dronesource_registrant,
                                       NULL, NULL, NULL);
    
    // pcap supported sources 
#ifdef HAVE_LIBPCAP
    // pcapfile doesn't have channel or monitor controls
    sourcetracker->RegisterPacketsource("pcapfile", 0, "na", 0,
                                       pcapsource_file_registrant,
                                       NULL, NULL, NULL);
#else
    REG_EMPTY_CARD(sourcetracker, "pcapfile");
#endif

#if defined(HAVE_LIBPCAP) && defined(HAVE_LINUX_WIRELESS)
    // Linux wext-driven cards
    sourcetracker->RegisterPacketsource("cisco", 1, "IEEE80211b", 6,
                                       pcapsource_wext_registrant,
                                       monitor_cisco, NULL, chancontrol_wext);
    sourcetracker->RegisterPacketsource("cisco_wifix", 1, "IEEE80211b", 6,
                                       pcapsource_ciscowifix_registrant,
                                       monitor_cisco_wifix, NULL, chancontrol_wext);
    sourcetracker->RegisterPacketsource("hostap", 1, "IEEE80211b", 6,
                                       pcapsource_wext_registrant,
                                       monitor_hostap, NULL, chancontrol_wext);
    sourcetracker->RegisterPacketsource("orinoco", 1, "IEEE80211b", 6,
                                       pcapsource_wext_registrant,
                                       monitor_orinoco, NULL, chancontrol_orinoco);
    sourcetracker->RegisterPacketsource("acx100", 1, "IEEE80211b", 6,
                                       pcapsource_wext_registrant,
                                       monitor_acx100, NULL, chancontrol_wext);
    sourcetracker->RegisterPacketsource("vtar5k", 1, "IEEE80211a", 36,
                                       pcapsource_wext_registrant,
                                       monitor_vtar5k, NULL, chancontrol_wext);
#else
    // Register the linuxwireless pcap stuff as null
    REG_EMPTY_CARD(sourcetracker, "cisco");
    REG_EMPTY_CARD(sourcetracker, "cisco_wifix");
    REG_EMPTY_CARD(sourcetracker, "hostap");
    REG_EMPTY_CARD(sourcetracker, "orinoco");
    REG_EMPTY_CARD(sourcetracker, "acx100");
    REG_EMPTY_CARD(sourcetracker, "vtar5k");
#endif

#if defined(HAVE_LIBPCAP) && defined(SYS_LINUX)
    sourcetracker->RegisterPacketsource("wlanng", 1, "IEEE80211b", 6,
                                       pcapsource_registrant,
                                       monitor_wlanng, NULL, chancontrol_wlanng);
    sourcetracker->RegisterPacketsource("wlanng_avs",1, "IEEE80211b", 6,
                                       pcapsource_registrant,
                                       monitor_wlanng_avs, NULL, chancontrol_wlanng_avs);

#else
    REG_EMPTY_CARD(sourcetracker, "wlanng");
    REG_EMPTY_CARD(sourcetracker, "wlanng_avs");
#endif

#if defined(HAVE_LIBPCAP) && defined(SYS_OPENBSD)
    sourcetracker->RegisterPacketsource("cisco_openbsd", 1, "IEEE80211b", 6,
                                       pcapsource_registrant,
                                       monitor_openbsd_cisco, NULL, NULL);
    sourcetracker->RegisterPacketsource("prism2_openbsd", 1, "IEEE80211b", 6,
                                       pcapsource_registrant,
                                       monitor_openbsd_prism2, NULL,
                                       chancontrol_openbsd_prism2);
#else
    REG_EMPTY_CARD(sourcetracker, "cisco_openbsd");
    REG_EMPTY_CARD(sourcetracker, "prism2_openbsd");
#endif

#if defined(HAVE_LIBWIRETAP)
    sourcetracker->RegisterPacketsource("wtapfile", 0, "na", 0,
                                       wtapfilesource_registrant,
                                       NULL, NULL, NULL);
#else
    REG_EMPTY_CARD(sourcetracker, "wtapfile");
#endif

#if defined(HAVE_WSP100)
    sourcetracker->RegisterPacketsource("wsp100", 0, "IEEE80211b", 6,
                                        wsp100source_registrant,
                                        monitor_wsp100, NULL, chancontrol_wsp100);
#else
    REG_EMPTY_CARD(sourcetracker, "wsp100");
#endif

    return 1;
}


