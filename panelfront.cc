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

#include <math.h>
#include <sys/types.h>
#include <dirent.h>

#if defined(SYS_OPENBSD) && defined(HAVE_MACHINE_APMVAR_H)
#include <machine/apmvar.h>
#endif

#ifdef SYS_NETBSD
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/envsys.h>
#include <fcntl.h>
#include <paths.h>
#endif

#include "panelfront.h"
#include "displaynetworksort.h"

#if (defined(HAVE_LIBNCURSES) && defined(HAVE_LIBPANEL) && defined(BUILD_PANEL))

char *KismetHelpText[] = {
    "KISMET PANELS INTERFACE",
    "QUICK REFERENCE",
    "  Key  Action",
    "   e   List Kismet servers",
    "   z   Toggle fullscreen zoom of network view",
    "   m   Toggle muting of sound and speech",
    "   t   Tag (or untag) selected network",
    "   g   Group tagged networks",
    "   u   Ungroup current group",
    "   c   Show clients in current network",
    "   L   Lock channel hopping to the current network channel",
    "   H   Return to normal channel hopping",
    "  +/-  Expand/collapse groups",
    "  ^L   Force a screen redraw.",
    "",
    "POPUP WINDOWS",
    "   h   Help (What you're looking at now)",
    "   n   Name current network",
    "   i   Detailed information about selected network",
    "   s   Sort network list",
    "   l   Show wireless card power levels",
    "   d   Dump printable strings",
    "   r   Packet rate graph",
    "   a   Statistics",
    "   p   Dump packet type",
    "   f   Follow network center",
    "   w   Track alerts",
    "   x   Close popup window",
    "",
    "   Q   Quit",
    "",
    "The panels interface supports displaying networks and clients detected",
    "by Kismet grouping of multiple networks, sorting of networks and",
    "clients, reporting the signal and noise levels of the wireless card,",
    "displaying printable strings, packet types, and many other features.",
    "",
    "The panels interface is divided into three primary views:",
    "1. Network display - This is where the networks are listed.",
    "2. Statistics - This lists the number of networks, packets, etc.",
    "3. Status - This scrolls recent events which may be noteworthy.",
    "",
    "Several types of network and client types are tracked:",
    "Network/Group types:",
    "  P       Probe request - no associated connection yet",
    "  A       Access point - standard wireless network",
    "  H       Ad-hoc - point-to-point wireless network",
    "  T       Turbocell - Turbocell (aka Karlnet or Lucent Outdoor",
    "           Router) network",
    "  G       Group - Group of wireless networks",
    "  D       Data - Data only network with no control packets.",
    "",
    "Status flags give a brief overview about information discovered on the",
    "network.",
    "  F    Vulnerable factory configuration.  Many people don't bother to",
    "       ever change the configuration on their WAP.  This is bad.",
    "  T#   Address range of # octets found via TCP traffic",
    "  U#   Address range of # octets found via UDP traffic",
    "  A#   Address range of # octets found via ARP traffic",
    "  D    Address range found via observed DHCP traffic",
    "  W    WEPed network decrypted with user-supplied key",
	"",
	"WEP (W) flags show the type of encryption detected on the network.",
	"  N    No encryption detected",
	"  Y    Standard WEP encryption",
	"  O    Other encryption methods detected.  See the network details for",
	"       more information.",
    "",
    "SELECTING NETWORKS:",
    "The default sorting method is Autofit.  This fits as many currently active",
    "networks on the display as possible, and does not scroll.  ALL NETWORK ",
    "SELECTION, TAGGING, GROUPING, SCROLLING, AND SO ON IS DISABLED IN AUTOFIT ",
    "MODE.  Sort the network display by one of the other methods to select and",
    "group networks.  Autofit mode changes the location of networks too ",
    "frequently make selecting a single network realistic.",
    "If all of the requested columns can not be fit on the screen, the left",
    "and right keys can be used to scroll the column display.",
    "",
    "For more information, consult the README and man pages",
    NULL
};


// Narrow text
char *KismetHelpTextNarrow[] = {
    "KISMET PANELS INTERFACE",
    "KISMET NETWORK PANEL",
    "Key Action",
    " e  List Kismet servers",
    " z  Toggle fullscreen net list",
    " m  Toggle muting",
    " t  Tag (or untag) selected",
    " g  Group tagged networks",
    " u  Ungroup current group",
    " c  Show clients",
    " L  Lock to network channel",
    " H  Return to channel hopping",
    "",
    "POPUP WINDOWS",
    "   h   Help",
    "   n   Name network",
    "   i   Detailed information",
    "   s   Sort network list",
    "   l   Show signal levels",
    "   d   Dump printable strings",
    "   r   Packet rate graph",
    "   a   Statistics",
    "   p   Dump packet type",
    "   f   Follow network",
    "   w   Track alerts",
    "   x   Close popup window",
    "",
    "   q   Quit",
    NULL
};


char *KismetHelpDetails[] = {
    "NETWORK DETAILS",
    "This panel lists in depth information about",
    "the selected network or group, which may or",
    "may not be available in the normal columns ",
    "display.",
    " Key   Action",
    " Up    Scroll list up",
    " Down  Scroll list down",
    "  c    Display clients for network or group",
    "  n    Display next network or group",
    "  p    Display previous network or group",
    "  q    Close popup",
    NULL
};


char *KismetSortText[] = {
    "Key  Sort                Key  Sort",
    " a   Auto-fit (standard)  c   Channel",
    " f   First time seen      F   First time seen (descending)",
    " l   Latest time seen     L   Latest time seen (descending)",
    " b   BSSID                B   BSSID (descending)",
    " s   SSID                 S   SSID (descending)",
    " p   Packet count         P   Packet count (descending)",
    " Q   Signal power level   w   Wep",
    " x   Cancel",
    NULL
};


char *KismetSortTextNarrow[] = {
    "Key Sort        Key Sort",
    " a  Auto-fit     c  Channel",
    " f  First time   F  First time (d)",
    " l  Latest time  L  Latest time (d)",
    " b  BSSID        B  BSSID (d)",
    " s  SSID         S  SSID (d)",
    " p  Packet count P  Packet count (d)",
    " w  WEP          Q  Power level",
    " x  Cancel",
    NULL
};

char *KismetClientSortText[] = {
    "Key  Sort                Key  Sort",
    " a   Auto-fit (standard)  c   Channel",
    " f   First time seen      F   First time seen (descending)",
    " l   Latest time seen     L   Latest time seen (descending)",
    " m   MAC                  M   MAC (descending)",
    " p   Packet count         P   Packet count (descending)",
    " w   WEP                  Q   Signal power level",
    " x   Cancel",
    NULL
};

char *KismetClientSortTextNarrow[] = {
    "Key Sort        Key Sort",
    " a  Auto-fit     c  Channel",
    " f  First time   F  First time (d)",
    " l  Latest time  L  Latest time (d)",
    " m  MAC          M  MAC (d)",
    " p  Packet count P  Packet count (d)",
    " w  WEP          Q  Power level",
    " x  Cancel",
    NULL
};

char *KismetHelpPower[] = {
    "KISMET POWER",
    "This panel lists the overall signal (S) and "
    "noise (N) levels reported by the wireless card, if",
    "they are available."
    " Key   Action",
    "  q    Close popup",
    NULL
};


char *KismetHelpRate[] = {
    "KISMET PACKET RATE",
    "This panel displays a moving graph of the rate at which",
    "packets are seen.  The graph covers the last 5 minutes.",
    " Key   Action",
    "  q    Close popup",
    NULL
};


char *KismetHelpGps[] = {
    "KISMET NETWORK FOLLOW",
    "This panel estimates the center of a network, the current",
    "direction of travel, and the direction of the network center",
    "and distance relative to the current direction of movement.",
    " Key   Action",
    "  s    Follow location of strongest packet",
    "  c    Follow location of estimated network center",
    "  q    Close popup",
    NULL
};


char *KismetHelpStats[] = {
    "KISMET NETWORK STATISTICS",
    "This panel displays overall statistics about the wireless",
    "networks seen, including how many are encrypted with WEP",
    "and how many match known factory default values.",
    " Key   Action",
    " Up    Scroll window up",
    " Down  Scroll window down",
    "  q    Close popup",
    NULL
};


char *KismetHelpDump[] = {
    "KISMET STRING DUMP",
    "This panel displays printable strings from uencrypted data",
    "packets.  This is basially equivalent to the 'strings' command",
    "in unix.",
    " Key   Action",
    "  c    Clear string window",
    "  p    Pause scrolling",
    "  t    Toggle display of string timestamp",
    "  a    Toggle display of strings from tagged networks or all",
    "       networks.",
    "  q    Close popup",
    NULL
};


char *KismetHelpPack[] = {
    "KISMET PACKET DUMP",
    "This panel displays information about the packet types seen.",
    "It is divided into 2 segments - The upper quarter displays a",
    "simple history of a larger number of recent packets while the ",
    "bottom 3 quarters displays detailed information about a smaller",
    "number of packets.",
    "'N ' - Noise",
    "'U ' - Unknown",
    "'Mx' - Management frame",
    "  'Ma' - Association request",
    "  'MA' - Association response",
    "  'Mr' - Reassociation request",
    "  'MR' - Reassociation response",
    "  'Mp' - Probe request",
    "  'MP' - Probe response",
    "  'MB' - Beacon",
    "  'MM' - ATIM",
    "  'MD' - Disassociation",
    "  'Mt' - Authentication",
    "  'MT' - Deauthentication",
    "  'M?' - Unknown management frame",
    "'Px' - Physcial frame",
    "  'Pt' - Request to send",
    "  'PT' - Clear to send",
    "  'PA' - Data Ack",
    "  'Pc' - CF End",
    "  'PC' - CF End+Ack",
    "  'P?' - Unknown phy frame",
    "'Dx' - Data frame",
    "  'DD' - Data frame",
    "  'Dc' - Data+CF+Ack",
    "  'Dp' - Data+CF+Poll",
    "  'DP' - Data+CF+Ack+Poll",
    "  'DN' - Data Null",
    "  'Da' - CF Ack",
    "  'DA' - CF Ack+Poll",
    "  'D?' - Unknown data frame",
    " Key   Action",
    "  p    Pause scrolling",
    "  a    Toggle display of strings from tagged networks or all",
    "       networks.",
    "  q    Close popup",
    NULL
};

char *KismetHelpAlert[] = {
    "KISMET ALERTS",
    "This panel tracks alert conditions, such as NetStumbler clients",
    "or DOS attacks.",
    " Key   Action",
    "  t    Toggle display of alert condition timestamp",
    "  q    Close popup",
    NULL
};

char *KismetClientHelpText[] = {
    "KISMET CLIENT LIST",
    "QUICK REFERENCE",
    "  Key  Action",
    "   s   Sort list of clients",
    "   i   Detailed info on selected client",
    "   n   Display next network or group",
    "   p   Display previous network or group",
    "   q   Quit client list",
    "",
    "This panel lists all the clients known to be associated with a selected",
    "wireless network.  Clients can be other wireless nodes or systems on the",
    "wired network with traffic bridged to the wireless.  Client types are",
    "shown as:",
    "  F       From DS - client broadcast from wireless distribution system.",
    "          These clients are typically wired systems.",
    "  T       To DS - client transmitted over the wireless to the",
    "          distribution system.  These clients are typically wireless nodes",
    "  I       Intra DS - client is a node of the distribution system talking",
    "          to another node in the distribution system",
    "  E       Established - client has been seen entering and leaving the DS.",
    "          These are typically wireless nodes.",
    "  -       Unknown - client is in an unknown state",
    NULL,
};

char *KismetClientHelpDetails[] = {
    "CLIENT DETAILS",
    "This panel lists in depth information about",
    "the selected client, which may or may not be",
    "available in the normal columns display.",
    " Key   Action",
    " Up    Scroll list up",
    " Down  Scroll list down",
    "  n    Display next client",
    "  p    Display previous client",
    "  q    Close popup",
    NULL
};

char *KismetHelpServer[] = {
    "KISMET SERVERS",
    " Key   Action",
    " Up    Scroll list up",
    " Down  Scroll list down",
    "  t    Tag (or untag) selected server",
    "  p    Make selected server the primary source",
    "  c    Connect to new server",
    "  d    Disconnect from selected server",
    "  r    Reconnect to selected server",
    "  q    Close server list",
    "",
    "Kismet supports monitoring data from several servers simultaneously.",
    "When connected to multiple servers, only servers which are tagged",
    "are displayed.  The server flagged as the 'primary' server is used for",
    "GPS and time data.  Packet and network counts, packet rates, and",
    "statistics are calculated for all of the available servers.  Networks",
    "detected by two servers are displayed twice.",
    "Servers tagged for display are denoted by a '*'",
    "The primary server is denoted by a 'P'",
    NULL
};

char *KismetIntroText[] = {
    "",
    "Welcome to the Kismet panels frontend.",
    "Context help is available for all displays, press 'H' at any time",
    "for more information.",
    "",
    "This message can be turned off by editing the kismet_ui.conf file.",
    "",
    "Press <Space> to continue.",  
    NULL
};

PanelFront::PanelFront() {
    errstr[0] = '\0';

    sortby = sort_auto;
    client_sortby = client_sort_auto;
    snprintf(main_sortxt, 24, "(Autofit)");

    client = NULL;

    clear_dump = 0;

    hsize = COLS;
    vsize = LINES;

    //cutoff = 0;

    muted = 0;

	auto_agroup = auto_pgroup = auto_dgroup = 0;

    // Push blanks into the RRD history vector
    packet_history.reserve(60 * 5);
    for (unsigned int x = 0; x < (60 * 5); x++)
        packet_history.push_back(0);

    max_packet_rate = 0;

    lat = lon = alt = spd = heading = 0;
    fix = 0;
    last_lat = last_lon = last_alt = last_spd = last_heading = 0;
    last_fix = 0;

    num_networks = num_packets = num_crypt = num_interesting = num_noise =
        num_dropped = packet_rate = 0;

    context = NULL;

    tainted = 0;

    // Do we have an acpi info file?
    if (access("/proc/acpi/info", R_OK) != 0) {
        use_acpi = 0;
    } else {
        use_acpi = 1;
    }

    probe_group = NULL;
    data_group = NULL;
	adhoc_group = NULL;
    details_network = NULL;
    server_time = 0;
    bat_ac = 0;
    bat_charging = 0;
    bat_time = 0;
    bat_percentage = 0;

    localnets_dirty = 0;
}

PanelFront::~PanelFront() {
    // Delete the dynamically allocated contexts
    for (unsigned int x = 0; x < context_list.size(); x++)
        delete context_list[x];
}

void PanelFront::PopulateGroups(TcpClient *in_client) {
	vector<wireless_network *> clientlist;
	vector<wireless_network *> probevec;
	vector<wireless_network *> datavec;
	vector<wireless_network *> advec;

	if (auto_pgroup || auto_dgroup || auto_agroup) {
		clientlist = in_client->FetchNetworkList();
		
		for (unsigned int x = 0; x < clientlist.size(); x++) {
			wireless_network *net = clientlist[x];

			if (net->dispnet != NULL)
				continue;

			if (net->type == network_probe && auto_pgroup) {
				probevec.push_back(net);
			} else if (net->type == network_adhoc && auto_agroup) {
				advec.push_back(net);
			} else if (net->type == network_data && auto_dgroup) {
				datavec.push_back(net);
			}
		}

		// Build the group if we need to
		if (probe_group == NULL && auto_pgroup) {
			probe_group = CreateGroup(0, "autogroup_probe", "Probe Networks");
		}
		// If we group, compare the size of the group and the size of the
		// network vec and add them all if we need to
		if (auto_pgroup && probevec.size() + probe_group->networks.size()) {
			for (unsigned int x = 0; x < probevec.size(); x++) {
				probe_group = AddToGroup(probe_group, probevec[x]);
			}
		}

		// Build the group if we need to
		if (data_group == NULL && auto_dgroup) {
			data_group = CreateGroup(0, "autogroup_data", "Data Networks");
		}
		// If we group, compare the size of the group and the size of the
		// network vec and add them all if we need to
		if (auto_dgroup && datavec.size() + data_group->networks.size()) {
			for (unsigned int x = 0; x < datavec.size(); x++) {
				data_group = AddToGroup(data_group, datavec[x]);
			}
		}

		// Build the group if we need to
		if (adhoc_group == NULL && auto_agroup) {
			adhoc_group = CreateGroup(0, "autogroup_adhoc", "Adhoc Networks");
		}
		// If we group, compare the size of the group and the size of the
		// network vec and add them all if we need to
		if (auto_agroup && advec.size() + adhoc_group->networks.size()) {
			for (unsigned int x = 0; x < advec.size(); x++) {
				adhoc_group = AddToGroup(adhoc_group, advec[x]);
			}
		}
	}

	Frontend::PopulateGroups(in_client);
}

void PanelFront::UpdateGroups() {
    int move_details = 0;

    localnets_dirty = 0;

    // Try to autogroup probe, data, and adhoc networks
    if (auto_pgroup || auto_dgroup || auto_agroup) {
        // Count the probes
        vector<display_network *> probevec;
        vector<display_network *> datavec;
		vector<display_network *> advec;

        for (unsigned int x = 0; x < group_vec.size(); x++) {
            display_network *dnet = group_vec[x];

            if (dnet->networks.size() != 1) {
                continue;
            }

			if (dnet->virtnet == NULL) {
				dnet->virtnet = new wireless_network;
				*(dnet->virtnet) = *(dnet->networks[0]);
			}

            if (auto_pgroup && dnet->virtnet->type == network_probe && 
                dnet != probe_group) {
                probevec.push_back(dnet);
            } else if (auto_dgroup && dnet != data_group &&
                       (dnet->virtnet->type == network_data ||
                        dnet->virtnet->llc_packets == 0)) {
                datavec.push_back(dnet);
            } else if (auto_agroup && dnet != adhoc_group &&
					   (dnet->virtnet->type == network_adhoc)) {
				advec.push_back(dnet);
			}
        }

		if (probevec.size() > 1) {
            if (probe_group == NULL) {
                probe_group = CreateGroup(0, "autogroup_probe", "Probe Networks");
            }

            for (unsigned int x = 0; x < probevec.size(); x++) {
                display_network *dnet = probevec[x];

                if (dnet == details_network)
                    move_details = 1;

                probe_group = AddToGroup(probe_group, dnet);

                if (move_details == 1) {
                    move_details = 0;
                    details_network = probe_group;
                }
            }
        }

		if (datavec.size() > 1) {
            if (data_group == NULL) {
                data_group = CreateGroup(0, "autogroup_data", "Data Networks");
            }

            for (unsigned int x = 0; x < datavec.size(); x++) {
                display_network *dnet = datavec[x];

                if (dnet == details_network)
                    move_details = 1;

                data_group = AddToGroup(data_group, dnet);

                if (move_details == 1) {
                    move_details = 0;
                    details_network = data_group;
                }
            }
        }

		if (advec.size() > 1) {
			if (adhoc_group == NULL) {
				adhoc_group = CreateGroup(0, "autogroup_adhoc", "Adhoc networks");
			}

			for (unsigned int x = 0; x < advec.size(); x++) {
				display_network *dnet = advec[x];

				if (dnet == details_network)
					move_details = 1;

				adhoc_group = AddToGroup(adhoc_group, dnet);

				if (move_details == 1) {
					move_details = 0;
					details_network = adhoc_group;
				}
			}
		}
    }

    // Call our generic parent update... is this bad form?  It works, anyhow.
    Frontend::UpdateGroups();
}

void PanelFront::DestroyGroup(display_network *in_group) {
	// Handle when we destroy the details stuff
	if (in_group == details_network) {
		details_network = NULL;
	}

    // Handle when we destroy the probe group
    if (in_group == probe_group) {
        probe_group = NULL;
    } else if (in_group == data_group) {
        data_group = NULL;
    } else if (in_group == adhoc_group) {
		adhoc_group = NULL;
	}

	localnets_dirty = 1;
	
    Frontend::DestroyGroup(in_group);
}

void PanelFront::AddClient(TcpClient *in_client) {
    server_context *new_context = new server_context;
    new_context->client = in_client;
    context_list.push_back(new_context);
    client_list.push_back(in_client);

    new_context->tagged = 1;

    if (context == NULL) {
        client = in_client;
        context = new_context;
        context->primary = 1;
    }

    // Enable all the protocols we handle
    in_client->EnableProtocol("GPS");
    in_client->EnableProtocol("INFO");
    in_client->EnableProtocol("REMOVE");
    in_client->EnableProtocol("NETWORK");
    in_client->EnableProtocol("CLIENT");
    in_client->EnableProtocol("ALERT");
    in_client->EnableProtocol("STATUS");
    in_client->EnableProtocol("CARD");
}

void PanelFront::FetchClients(vector<TcpClient *> *in_vec) {
    in_vec->clear();
    *in_vec = client_list;
}

TcpClient *PanelFront::FetchPrimaryClient() {
    return client;
}

int PanelFront::InitDisplay(int in_decay, time_t in_start) {
    start_time = in_start;

    decay = in_decay;
    int colorkilled = 0;

    initscr();
    if (prefs["color"] == "true") {
        if (!has_colors()) {
            prefs["color"] = "false";
            color = 0;
            colorkilled = 1;
        } else {
            color = 1;
#ifdef HAVE_ASSUME_DEFAULT_COLORS
            assume_default_colors(color_map["text"].index, color_map["background"].index);
#else
            use_default_colors();
#endif
            start_color();
            init_pair(COLOR_WHITE, COLOR_WHITE, color_map["background"].index);
            init_pair(COLOR_RED, COLOR_RED, color_map["background"].index);
            init_pair(COLOR_MAGENTA, COLOR_MAGENTA, color_map["background"].index);
            init_pair(COLOR_GREEN, COLOR_GREEN, color_map["background"].index);
            init_pair(COLOR_CYAN, COLOR_CYAN, color_map["background"].index);
            init_pair(COLOR_BLUE, COLOR_BLUE, color_map["background"].index);
            init_pair(COLOR_YELLOW, COLOR_YELLOW, color_map["background"].index);
        }
    }

    net_win = new kis_window;
    net_win->win = newwin(LINES-statheight, COLS-infowidth, 0, 0);
    net_win->pan = new_panel(net_win->win);
    net_win->printer = &PanelFront::MainNetworkPrinter;
    net_win->input = &PanelFront::MainInput;
    net_win->title = "Network List";
    net_win->start = 0;
    net_win->end = 0;
    net_win->selected = 0;
    net_win->max_display = net_win->win->_maxy - 3;
    net_win->print_width = net_win->win->_maxx - 2;
    net_win->col_start = net_win->col_selected = net_win->col_end = 0;
    nodelay(net_win->win, true);
    keypad(net_win->win, true);
    move_panel(net_win->pan, 0, 0);

    info_win = new kis_window;
    info_win->win = newwin(LINES-statheight, infowidth, 0, 0);
    info_win->pan = new_panel(info_win->win);
    info_win->printer = &PanelFront::MainInfoPrinter;
    info_win->title = "Info";
    info_win->max_display = info_win->win->_maxy - 2;
    info_win->print_width = info_win->win->_maxx - 2;
    info_win->col_start = info_win->col_selected = info_win->col_end = 0;
    nodelay(info_win->win, true);
    keypad(info_win->win, true);
    move_panel(info_win->pan, 0, COLS-infowidth);

    stat_win = new kis_window;
    stat_win->win = newwin(statheight, COLS, 0, 0);
    stat_win->pan = new_panel(stat_win->win);
    stat_win->printer = &PanelFront::MainStatusPrinter;
    stat_win->title = "Status";
    stat_win->max_display = stat_win->win->_maxy - 2;
    stat_win->print_width = stat_win->win->_maxx - 2;
    stat_win->col_start = stat_win->col_selected = stat_win->col_end = 0;
    nodelay(stat_win->win, true);
    keypad(stat_win->win, true);
    scrollok(stat_win->win, 1);
    move_panel(stat_win->pan, LINES-statheight, 0);

    noecho();
    cbreak();

    window_list.push_back(stat_win);
    window_list.push_back(info_win);
    window_list.push_back(net_win);

    cur_window = window_list.back();
    top_panel(cur_window->pan);

    zoomed = 0;

    muted = 0;

	if (colorkilled)
        WriteStatus("Terminal cannot support colors, turning off color options.");

    // Spawn intro
    if (prefs["showintro"] != "false")
        SpawnWindow("Welcome to Kismet",
                    &PanelFront::IntroPrinter, &PanelFront::IntroInput, 10, 66);

    return 0;
}

void PanelFront::RescaleDisplay() {
    for (list<kis_window *>::iterator x = window_list.begin();
         x != window_list.end(); ++x) {
        kis_window *kwin = *x;

        if (kwin == net_win) {
            wresize(net_win->win, LINES-statheight, COLS-infowidth);
            net_win->max_display = net_win->win->_maxy - 3;
            net_win->print_width = net_win->win->_maxx - 2;
            replace_panel(net_win->pan, net_win->win);
            move_panel(net_win->pan, 0, 0);
        } else if (kwin == info_win) {
            wresize(info_win->win, LINES-statheight, infowidth);
            info_win->max_display = info_win->win->_maxy - 2;
            info_win->print_width = info_win->win->_maxx - 2;
            replace_panel(info_win->pan, info_win->win);
            move_panel(info_win->pan, 0, COLS-infowidth);
        } else if (kwin == stat_win) {
            wresize(stat_win->win, statheight, COLS);
            stat_win->max_display = stat_win->win->_maxy - 2;
            stat_win->print_width = stat_win->win->_maxx - 2;
            replace_panel(stat_win->pan, stat_win->win);
            move_panel(stat_win->pan, LINES-statheight, 0);
        } else {
            int xchange = kwin->win->_maxx, ychange = kwin->win->_maxy;
            int needresize = 0;

            if (kwin->win->_begx + kwin->win->_maxx >= COLS) {
                needresize = 1;
                xchange = COLS - 2;
            }

            if (kwin->win->_begy + kwin->win->_maxy >= LINES) {
                needresize = 1;
                ychange = LINES - 2;
            }

            if (needresize) {
                wresize(kwin->win, ychange, xchange);
                kwin->max_display = kwin->win->_maxy - 2;
                kwin->print_width = kwin->win->_maxx - 2;
                replace_panel(kwin->pan, kwin->win);
            }

        }
    }
}

PanelFront::main_columns PanelFront::Token2MainColumn(string in_token) {
    if (in_token == "decay") {
        return mcol_decay;
    } else if (in_token == "name") {
        return mcol_name;
    } else if (in_token == "shortname") {
        return mcol_shortname;
    } else if (in_token == "ssid") {
        return mcol_ssid;
    } else if (in_token == "shortssid") {
        return mcol_shortssid;
    } else if (in_token == "type") {
        return mcol_type;
    } else if (in_token == "wep") {
        return mcol_wep;
    } else if (in_token == "channel") {
        return mcol_channel;
    } else if (in_token == "data") {
        return mcol_data;
    } else if (in_token == "llc") {
        return mcol_llc;
    } else if (in_token == "crypt") {
        return mcol_crypt;
    } else if (in_token == "weak") {
        return mcol_weak;
    } else if (in_token == "bssid") {
        return mcol_bssid;
    } else if (in_token == "flags") {
        return mcol_flags;
    } else if (in_token == "ip") {
        return mcol_ip;
    } else if (in_token == "packets") {
        return mcol_packets;
    } else if (in_token == "info") {
        return mcol_info;
    } else if (in_token == "maxrate") {
        return mcol_maxrate;
    } else if (in_token == "manuf") {
        return mcol_manuf;
    } else if (in_token == "signal") {
        return mcol_signal;
        /*
    } else if (in_token == "quality") {
        return mcol_quality;
        */
    } else if (in_token == "noise") {
        return mcol_noise;
    } else if (in_token == "clients") {
        return mcol_clients;
    } else if (in_token == "size") {
        return mcol_datasize;
    } else if (in_token == "signalbar") {
        return mcol_signalbar;
        /*
    } else if (in_token == "qualitybar") {
        return mcol_qualitybar;
        */
    } else if (in_token == "dupeiv") {
        return mcol_dupeiv;
    } else {
        return mcol_unknown;
    }

    return mcol_unknown;

}

PanelFront::client_columns PanelFront::Token2ClientColumn(string in_token) {
    if (in_token == "decay") {
        return ccol_decay;
    } else if (in_token == "type") {
        return ccol_type;
    } else if (in_token == "mac") {
        return ccol_mac;
    } else if (in_token == "manuf") {
        return ccol_manuf;
    } else if (in_token == "data") {
        return ccol_data;
    } else if (in_token == "crypt") {
        return ccol_crypt;
    } else if (in_token == "weak") {
        return ccol_weak;
    } else if (in_token == "maxrate") {
        return ccol_maxrate;
    } else if (in_token == "ip") {
        return ccol_ip;
    } else if (in_token == "signal") {
        return ccol_signal;
        /*
    } else if (in_token == "quality") {
        return ccol_quality;
        */
    } else if (in_token == "noise") {
        return ccol_noise;
    } else if (in_token == "size") {
        return ccol_datasize;
    }

    return ccol_unknown;
}

void PanelFront::SetMainColumns(string in_columns) {
    vector<string> tokens = StrTokenize(in_columns, ",");

    column_vec.clear();

    for (unsigned int x = 0; x < tokens.size(); x++)
        column_vec.push_back(Token2MainColumn(tokens[x]));
}

void PanelFront::SetClientColumns(string in_columns) {
    vector<string> tokens = StrTokenize(in_columns, ",");

    client_column_vec.clear();

    for (unsigned int x = 0; x < tokens.size(); x++)
        client_column_vec.push_back(Token2ClientColumn(tokens[x]));
}

int PanelFront::WriteStatus(string status) {
    vector<string> wrapped = LineWrap(status, 4, stat_win->print_width - 1);

    for (unsigned int wrx = 0; wrx < wrapped.size(); wrx++)
        stat_win->text.push_back(wrapped[wrx]);

    tainted = 1;

    return 1;

    /*
    wmove(statuswin, 1, 0);
    winsertln(statuswin);
    mvwaddstr(statuswin, 1, 2, status.substr(0, COLS-4).c_str());
    */
}

// Handle drawing all the windows
int PanelFront::DrawDisplay() {
    if (hsize != COLS || vsize != LINES) {
        hsize = COLS; vsize = LINES;
        RescaleDisplay();
    }

    list<kis_window *> remove;

    // Each window gets cleared and the printer for it run
    for (list<kis_window *>::iterator x = window_list.begin();
         x != window_list.end(); ++x) {
        kis_window *kwin = *x;

        if (kwin->win == NULL || kwin->pan == NULL) {
            WriteStatus("Something is wrong with the window list");
            remove.push_back(kwin);
            continue;
        }

        werase(kwin->win);
        if (color)
            wattrset(kwin->win, color_map["border"].pair);
        //box(kwin->win, '|', '-');

        if (prefs["simpleborders"] == "true")
            box(kwin->win, '|', '-');
        else
            box(kwin->win, ACS_VLINE, ACS_HLINE);

        if (color) {
            wattron(kwin->win, color_map["text"].pair);
            wattrset(kwin->win, color_map["title"].pair);
        }
        mvwaddstr(kwin->win, 0, 2, kwin->title.c_str());
        if (color)
            wattrset(kwin->win, color_map["text"].pair);

        // Call the printer
        int ret;
        ret = (this->*kwin->printer)(kwin);

        // Clean up any windows that ask to quit
        if (ret == 0)
            remove.push_back(kwin);
    }

    for (list<kis_window *>::iterator x = remove.begin();
         x != remove.end(); ++x)
        DestroyWindow(*x);

    cur_window = window_list.back();
    wmove(cur_window->win, 0, 0);

    update_panels();
    doupdate();

    tainted = 0;

    return 1;
}

int PanelFront::EndDisplay() {
    endwin();


    return 1;
}

void PanelFront::ZoomNetworks() {
    // We refer directly to our nontransients here, too, but like netline it's safe
    // because nobody can make those go away
    if (zoomed == 0) {
        wresize(net_win->win, LINES, COLS);
        replace_panel(net_win->pan, net_win->win);
        net_win->max_display = net_win->win->_maxy - 3;
        net_win->print_width = net_win->win->_maxx - 2;
        zoomed = 1;
    } else {
        wresize(net_win->win, LINES-statheight, COLS-infowidth);
        replace_panel(net_win->pan, net_win->win);
        net_win->max_display = net_win->win->_maxy - 3;
        net_win->print_width = net_win->win->_maxx - 2;

        if (net_win->selected > net_win->max_display)
            net_win->selected = net_win->max_display;

        zoomed = 0;
    }
    DrawDisplay();
}

PanelFront::kis_window *PanelFront::SpawnWindow(string in_title, panel_printer in_print, 
                                                key_handler in_input, int in_x, 
                                                int in_y) {
    kis_window *kwin = new kis_window;

    kwin->title = in_title;
    kwin->printer = in_print;
    kwin->input = in_input;
    kwin->start = 0;
    kwin->end = 0;
    kwin->col_start = 0;
    kwin->col_end = 0;
    kwin->col_selected = 0;
    kwin->selected = 0;
    kwin->paused = 0;
    kwin->scrollable = 0;
    kwin->toggle0 = 0;
    kwin->toggle1 = 0;
    kwin->toggle2 = 0;

    if (in_x == -1 || in_x + 2 > LINES)
        if (LINES < 10) {
            in_x = LINES;
        } else {
            in_x = LINES-5;
        }

    if (in_y == -1 || in_y + 2 > COLS)
        if (COLS < 15) {
            in_y = COLS;
        } else {
            in_y = COLS-8;
        }

    in_x += 2;
    in_y += 4;

    kwin->max_display = in_x - 2;
    kwin->print_width = in_y - 3;

    kwin->win = newwin(in_x, in_y, 0, 0);
    if (kwin->win == NULL) {
        WriteStatus("Error making window");
        delete kwin;
        return NULL;
    }

    kwin->pan = new_panel(kwin->win);
    nodelay(kwin->win, true);
    keypad(kwin->win, true);

    move_panel(kwin->pan, (LINES/2) - (in_x/2), (COLS/2) - (in_y/2));
    show_panel(kwin->pan);
    window_list.push_back(kwin);
    cur_window = kwin;
    DrawDisplay();
    return kwin;
}

// Spawn a text helpbox with the included help stuff
void PanelFront::SpawnHelp(char **in_helptext) {
    kis_window *kwin = new kis_window;

    // Fill in the window a bit
    kwin->title = in_helptext[0];
    kwin->printer = &PanelFront::TextPrinter;
    kwin->input = &PanelFront::TextInput;
    kwin->start = 0;
    kwin->end = 0;
    kwin->selected = 0;
    kwin->scrollable = 1;

    // Now find the length and the maximum width.  Accomodate them if we can.
    int width = 0;
    int height = 0;
    unsigned int x = 1;
    while (1) {
        if (in_helptext[x] == NULL)
            break;
        if ((int) strlen(in_helptext[x]) > width)
            width = strlen(in_helptext[x]);
        x++;
    }

    if (x < 2)
        return;

    height = x - 1;

    if (width + 5 > COLS)
        width = COLS - 5;
    if (height + 5 > LINES)
        height = LINES - 5;

    // Resize our text to fit our max possible width and cache it
    char *resize = new char[width+1];
    x = 1;
    while (1) {
        if (in_helptext[x] == NULL)
            break;
        snprintf(resize, width+1, "%s", in_helptext[x]);
        kwin->text.push_back(resize);
        x++;
    }
    delete[] resize;

    height += 2;
    width += 5;

    kwin->max_display = height - 2;
    kwin->print_width = width - 3;

    kwin->win = newwin(height, width, 0, 0);
    if (kwin->win == NULL) {
        WriteStatus("Error making window.");
        delete kwin;
        return;
    }

    kwin->pan = new_panel(kwin->win);
    nodelay(kwin->win, true);
    keypad(kwin->win, true);

    move_panel(kwin->pan, (LINES/2) - (height/2), (COLS/2) - (width/2));
    show_panel(kwin->pan);
    window_list.push_back(kwin);
    cur_window = kwin;

    DrawDisplay();
}

void PanelFront::DestroyWindow(kis_window *in_win) {
    // If we're not the last one we have to reshuffle
    if (in_win != window_list.back()) {
        for (list<kis_window *>::iterator x = window_list.begin(); x != window_list.end(); ++x) {
            if (*x == in_win) {
                window_list.erase(x);
                break;
            }
        }
    } else {
        list<kis_window *>::iterator x = window_list.end();
        x--;
        window_list.erase(x);
    }

    // Wipe out the record now
    hide_panel(in_win->pan);
    del_panel(in_win->pan);
    delwin(in_win->win);

    // Free up the memory
    delete in_win;

    in_win = NULL;

    cur_window = window_list.back();
}

int PanelFront::Poll() {
    int ch;

    if ((ch = wgetch(cur_window->win)) == ERR)
        return 0;

    // fprintf(stderr, "Got: %d (%c)\n", ch, ch);

    // Catch the redraw event ^L
    if (ch == 12) {
        clearok(curscr, 1);

        DrawDisplay();

        return 1;
    }

    int ret;
    ret = (this->*cur_window->input)(cur_window, ch);

    if (ret == 0)
        DestroyWindow(cur_window);

    cur_window = window_list.back();

    DrawDisplay();

    return ret;
}

void PanelFront::UpdateContexts() {
    lat = lon = alt = spd = 0;
    fix = 0;
    last_lat = last_lon = last_alt = last_spd = 0;
    last_fix = 0;

    quality = power = noise = 0;

    num_networks = 0;
    num_packets = 0;
    num_crypt = 0;
    num_interesting = 0;
    num_noise = 0;
    num_dropped = 0;
    packet_rate = 0;

    int aggrate = 0; int aggadjrate = 0;

    for (unsigned int x = 0; x < context_list.size(); x++) {
        server_context *con = context_list[x];

        if (con->client == NULL)
            continue;

        // Update GPS
        float newlat, newlon, newalt, newspd, newheading;
        int newfix;
        con->client->FetchLoc(&newlat, &newlon, &newalt, &newspd, &newheading, &newfix);

        if (GPSD::EarthDistance(newlat, newlon, last_lat, last_lon) > 10) {
            con->last_lat = con->lat;
            con->last_lon = con->lon;
            con->last_spd = con->spd;
            con->last_alt = con->alt;
            con->last_fix = con->fix;
            con->last_heading = con->heading;
        }

        con->lat = newlat;
        con->lon = newlon;
        con->alt = newalt;
        con->spd = newspd;
        con->heading = newheading;
        con->fix = newfix;

        // Update quality
        con->quality = con->client->FetchQuality();
        con->power = con->client->FetchPower();
        con->noise = con->client->FetchNoise();

        // Update time
        con->server_time = con->client->FetchTime();

        if (con->primary == 1) {
            // Bring the primary contexts info into our class settings
            client = con->client;

            lat = con->lat;
            lon = con->lon;
            alt = con->alt;
            spd = con->spd;
            heading = con->heading;
            fix = con->fix;

            last_lat = con->last_lat;
            last_lon = con->last_lon;
            last_alt = con->last_alt;
            last_spd = con->last_spd;
            last_heading = con->last_heading;
            last_fix = con->last_fix;

            quality = con->quality;
            power = con->power;
            noise = con->noise;

            server_time = con->server_time;
        }


        // Update packet rate
        int rate = con->client->FetchNumPackets() - con->client->FetchNumDropped();
        int adjrate = con->client->FetchPacketRate();

        if (adjrate > con->max_packet_rate)
            con->max_packet_rate = adjrate;
        con->packet_history.push_back(rate);
        if (con->packet_history.size() > (60 * 5))
            con->packet_history.erase(con->packet_history.begin());

        // Update other info
        con->num_networks = con->client->FetchNumNetworks();
        con->num_packets = con->client->FetchNumPackets();
        con->num_crypt = con->client->FetchNumCrypt();
        con->num_interesting = con->client->FetchNumInteresting();
        con->num_noise = con->client->FetchNumNoise();
        con->num_dropped = con->client->FetchNumDropped();
        con->packet_rate = con->client->FetchPacketRate();

        if (con->tagged) {
            // combine tagged info
            aggrate += rate;
            aggadjrate += adjrate;

            num_networks += con->num_networks;
            num_packets += con->num_packets;
            num_crypt += con->num_crypt;
            num_interesting += con->num_interesting;
            num_noise += con->num_noise;
            num_dropped += con->num_dropped;
        }

    }

    packet_rate = aggadjrate;
    if (aggadjrate > max_packet_rate)
        max_packet_rate = aggadjrate;
    packet_history.push_back(aggrate);
    if (packet_history.size() > (60 * 5))
        packet_history.erase(packet_history.begin());

}

int PanelFront::Tick() {
    // We should be getting a 1-second tick - secondary to a draw event, because
    // we can cause our own draw events which wouldn't necessarily be a good thing

    // Update all the contexts
    UpdateContexts();

    // Now fetch the APM data (if so desired)
    if (monitor_bat) {
#ifdef SYS_LINUX
        char buf[128];

        if (use_acpi == 0) {
            // Lifted from gkrellm's battery monitor, fetch the APM info
            FILE *apm;
            int ac_line_status, battery_status, flag, percentage, apm_time;
            char units[32];

            if ((apm = fopen("/proc/apm", "r")) == NULL ||
		fgets(buf, 128, apm) == NULL) {
                bat_available = 0;
                bat_ac = 0;
                bat_percentage = 0;
                bat_time = 0;
                bat_charging = 0;
            } else {
                sscanf(buf, "%*s %*d.%*d %*x %x %x %x %d%% %d %s\n", &ac_line_status,
                       &battery_status, &flag, &percentage, &apm_time, units);

                if ((flag & 0x80) == 0 && battery_status != 0xFF)
                    bat_available = 1;
                else
                    bat_available = 0;

                if (ac_line_status == 1)
                    bat_ac = 1;
                else
                    bat_ac = 0;

                if (battery_status == 3)
                    bat_charging = 1;
                else
                    bat_charging = 0;

                bat_percentage = percentage;

                if (apm_time == -1)
                    bat_time = 0;
                else
                    bat_time = apm_time;

                if (!strncmp(units, "min", 32))
                    bat_time *= 60;
            }
	    if (apm!=NULL)
	      fclose(apm);
        } else {
            DIR *batteries, *ac_adapters;
            struct dirent *this_battery, *this_adapter;
            FILE *acpi;
            char battery_state[PATH_MAX];
            int rate = 1, remain = 0, current = 0;
            static int total_remain = 0, total_cap = 0;
            int batno = 0;
            const int info_res = 5;
            static int info_timer = 0;

            ac_adapters = opendir("/proc/acpi/ac_adapter");

            while (ac_adapters != NULL && ((info_timer % info_res) == 0) && 
				   ((this_adapter = readdir(ac_adapters)) != NULL)) {
                if (this_adapter->d_name[0] == '.')
                    continue;
                // safe overloaded use of battery_state path var
                snprintf(battery_state, sizeof(battery_state), 
						 "/proc/acpi/ac_adapter/%s/state", this_adapter->d_name);
                if ((acpi = fopen(battery_state, "r")) == NULL)
                    continue;
                if (acpi != NULL) {
                    while(fgets(buf, 128, acpi)) {
                        if (strstr(buf, "on-line") != NULL)
                            bat_ac = 1;
                        else
                            bat_ac = 0;
                    }
                    fclose(acpi);
                }
            }

            if (ac_adapters != NULL)
                closedir(ac_adapters);

            batteries = opendir("/proc/acpi/battery");

            if (batteries == NULL)
                bat_available = 0;
            else
                bat_available = 1;

            if (!bat_available || ((info_timer % info_res) == 0)) {
                bat_percentage = 0;
                bat_time = 0;
                bat_charging = 0;
                total_remain = total_cap = 0;
            }

            while (batteries != NULL && ((info_timer % info_res) == 0) && 
				   ((this_battery = readdir(batteries)) != NULL)) {
                if (this_battery->d_name[0] == '.')
                    continue;
                snprintf(battery_state, sizeof(battery_state), 
						 "/proc/acpi/battery/%s/state", this_battery->d_name);
                if ((acpi = fopen(battery_state, "r")) == NULL)
                    continue;
                while (fgets(buf, 128, acpi))
                {
                    if (strncmp(buf, "present:", 8 ) == 0)
                    {
                        // No information for this battery
                        if (strstr(buf, "no" ))
                            continue;
                    }
                    else if (strncmp(buf, "charging state:", 15) == 0)
                    {
                        // the space makes it different than discharging
                        if (strstr(buf, " charging" ))
                            bat_charging = 1;
                    }
                    else if (strncmp(buf, "present rate:", 13) == 0)
                        rate = atoi(buf + 25);
                    else if (strncmp(buf, "remaining capacity:", 19) == 0)
                    {
                        remain = atoi(buf + 25);
                        total_remain += remain;
                    }
                    else if (strncmp(buf, "present voltage:", 17) == 0)
                        current = atoi(buf + 25);
                }
                total_cap += bat_full_capacity[batno];
                fclose(acpi);
                if (bat_charging)
                    bat_time += int((float(bat_full_capacity[batno] - remain) / 
									 rate) * 3600);
                else
                    bat_time += int((float(remain) / rate) * 3600);
                batno++;
            }
            if (total_cap > 0)
				bat_percentage = int((float(total_remain) / total_cap) * 100);
			info_timer++;

            if (batteries != NULL)
                closedir(batteries);
        }

#elif defined(SYS_OPENBSD) && defined(HAVE_MACHINE_APMVAR_H)

		struct apm_power_info api;
		int apmfd;

		if ((apmfd = open("/dev/apm", O_RDONLY)) < 0) {
			bat_available = 0;
			WriteStatus("Unable to open /dev/apm\n");
			return 1;
		} else if (ioctl(apmfd, APM_IOC_GETPOWER, &api) < 0) {
			bat_available = 0;
			WriteStatus("Apm ioctl failed\n");
			close(apmfd);
			return 1;
		} else {
			close(apmfd);
			switch(api.battery_state) {
				case APM_BATT_UNKNOWN:
					bat_available = 0;
				case APM_BATTERY_ABSENT:
					bat_available = 0;
				default:
					bat_available = 1;
			}
			if (bat_available == 1) {
				bat_percentage = (int)api.battery_life;
				bat_time = (int)api.minutes_left * 60;
				if (api.battery_state == APM_BATT_CHARGING) {
					bat_ac = 1;
					bat_charging = 1;
				} else {
					switch (api.ac_state) {
						case APM_AC_ON:
							bat_ac = 1;
							if (bat_percentage < 100) {
								bat_charging = 1;
							} else {
								bat_charging = 0;
							}
							break;
						default:
							bat_ac = 0;
							bat_charging = 0;
					}
				}
			}
		}
#elif defined(SYS_NETBSD)
		static int fd = -1;
		int i;
		envsys_basic_info_t info;
		envsys_tre_data_t data;
		unsigned int charge = 0;
		unsigned int maxcharge = 0;
		unsigned int rate = 0;

		if(fd < 0 && (fd = open(_PATH_SYSMON, O_RDONLY)) < 0)
		{
			bat_available = 0;
			WriteStatus("Unable to open " _PATH_SYSMON);
			return 1;
		}
		bat_ac = 0;
		bat_available = 0;
		bat_charging = 0;
		bat_percentage = 0;
		bat_time = 0;
		for(i = 0; i >= 0; i++)
		{
			memset(&info, 0, sizeof(info));
			info.sensor = i;
			if(ioctl(fd, ENVSYS_GTREINFO, &info) == -1)
			{
				bat_available = 0;
				WriteStatus("ioctl ENVSYS_GTREINFO failed");
				return 1;
			}
			if(!(info.validflags & ENVSYS_FVALID))
				break;
			memset(&data, 0, sizeof(data));
			data.sensor = i;
			if(ioctl(fd, ENVSYS_GTREDATA, &data) == -1)
			{
				bat_available = 0;
				WriteStatus("ioctl ENVSYS_GTREDATA failed");
				return 1;
			}
			if(!(data.validflags & ENVSYS_FVALID))
				continue;
			if(strcmp("acpiacad0 connected", info.desc) == 0)
				bat_ac = data.cur.data_us;
			else if(strcmp("acpibat0 charge", info.desc) == 0)
			{
				bat_available = 1;
				bat_percentage = (unsigned int)((data.cur.data_us * 100.0) / data.max.data_us);
				charge = data.cur.data_us;
				maxcharge = data.max.data_us;
			}
			else if(strcmp("acpibat0 charging", info.desc) == 0)
				bat_charging = data.cur.data_us > 0 ? 1 : 0;
			else if(strcmp("acpibat0 discharge rate", info.desc) == 0)
				rate = data.cur.data_us;
		}
		if(bat_charging != 0)
			bat_time = rate ? (unsigned int)((maxcharge - charge) * 3600.0 / rate) : 0;
		else
			bat_time = rate ? (unsigned int)((charge * 3600.0) / rate) : 0;
#endif
    }

    return 1;
}

void PanelFront::AddPrefs(map<string, string> in_prefs) {
    prefs = in_prefs;

    SetMainColumns(prefs["columns"]);
    SetClientColumns(prefs["clientcolumns"]);

    if (prefs["autogroup_probe"] == "true") 
        auto_pgroup = 1;
    if (prefs["autogroup_data"] == "true") 
        auto_dgroup = 1;
	if (prefs["autogroup_adhoc"] == "true")
		auto_agroup = 1;

    if (use_acpi) {
        char buf[80];
        DIR* batteries;
        FILE* info;
        struct dirent* this_battery;
        char battery_info[PATH_MAX];
        int batno = 0;
        bat_available = 0;
        batteries = opendir("/proc/acpi/battery");
        while (batteries != NULL && (this_battery = readdir(batteries)) != NULL)
        {
            // Skip . and ..
            if (this_battery->d_name[0] == '.')
                continue;
            snprintf(battery_info, sizeof(battery_info), "/proc/acpi/battery/%s/info", this_battery->d_name);
            info = fopen(battery_info, "r");
            bat_full_capacity[batno] = 0;
            if ( info != NULL ) {
                while (fgets(buf, sizeof(buf), info) != NULL)
                    if (1 == sscanf(buf, "last full capacity:      %d mWh", &bat_full_capacity[batno]))
                        continue;
                fclose(info);
                bat_available = 1;
            }
            batno++;
        }
        closedir(batteries);
    }

    if (prefs["apm"] == "true")
        monitor_bat = 1;
    else
        monitor_bat = 0;

    if (prefs["color"] == "true") {
        color_map["background"] = ColorParse(prefs["backgroundcolor"]);
        color_map["text"] = ColorParse(prefs["textcolor"]);
        color_map["border"] = ColorParse(prefs["bordercolor"]);
        color_map["title"] = ColorParse(prefs["titlecolor"]);
        color_map["wep"] = ColorParse(prefs["wepcolor"]);
        color_map["factory"] = ColorParse(prefs["factorycolor"]);
        color_map["open"] = ColorParse(prefs["opencolor"]);
        color_map["monitor"] = ColorParse(prefs["monitorcolor"]);
        color_map["cloak"] = ColorParse(prefs["cloakcolor"]);
    }

}

PanelFront::color_pair PanelFront::ColorParse(string in_color) {
    string clr = in_color;
    color_pair ret;

    // First, find if theres a hi-
    if (clr.substr(0, 3) == "hi-") {
        ret.bold = 1;
        clr = clr.substr(3, clr.length() - 3);
    }

    // Then match all the colors
    if (clr == "black")
        ret.index = COLOR_BLACK;
    else if (clr == "red")
        ret.index = COLOR_RED;
    else if (clr == "green")
        ret.index = COLOR_GREEN;
    else if (clr == "yellow")
        ret.index = COLOR_YELLOW;
    else if (clr == "blue")
        ret.index = COLOR_BLUE;
    else if (clr == "magenta")
        ret.index = COLOR_MAGENTA;
    else if (clr == "cyan")
        ret.index = COLOR_CYAN;
    else if (clr == "white")
        ret.index = COLOR_WHITE;


    if (ret.index != -1) {
        ret.pair = COLOR_PAIR(ret.index);

        if (ret.bold)
            ret.pair |= A_BOLD;
                
    } else {
        ret.pair = 0;
    }

    return ret;
}

#endif

