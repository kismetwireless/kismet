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

#include "panelfront.h"
#include "displaynetworksort.h"

#if (defined(HAVE_LIBNCURSES) && defined(HAVE_LIBPANEL) && defined(BUILD_PANEL))

char *KismetHelpText[] = {
    "KISMET PANELS INTERFACE",
    "KISMET NETWORK PANEL",
    "  Key  Action",
    "   z   Toggle fullscreen zoom of network view",
    "   m   Toggle muting of sound and speech",
    "   t   Tag (or untag) selected network",
    "   g   Group tagged networks",
    "   u   Ungroup current group",
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
    "   x   Close popup window",
    "",
    "   Q   Quit",
    NULL
};


// Narrow text
char *KismetHelpTextNarrow[] = {
    "KISMET PANELS INTERFACE",
    "KISMET NETWORK PANEL",
    "Key Action",
    " z  Toggle fullscreen net list",
    " m  Toggle muting",
    " t  Tag (or untag) selected",
    " g  Group tagged networks",
    " u  Ungroup current group",
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
    " q   Signal Quality       Q   Signal power level",
    " w   WEP                  x   Cancel",
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
    " q  Quality      Q  Power level",
    " w  WEP          x  Cancel",
    NULL
};

char *KismetHelpPower[] = {
    "KISMET POWER",
    "This panel lists the overall quality (Q), signal (S)",
    "and noise (N) levels reported by the wireless card, if",
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
    "'B' - Beacon      ; 'r' - Probe request  ; 'e' - Encrypted data",
    "'w' - Weak data   ; 'd' - Data           ; 'a' - Ad-hoc",
    "'n' - Noise       ; 'R' - Probe Response ; 'A' - Reassociation",
    " Key   Action",
    "  p    Pause scrolling",
    "  q    Close popup",
    NULL
};


string PanelFront::Mac2String(uint8_t *mac, char seperator) {
    char tempstr[MAC_STR_LEN];

    // There must be a better way to do this...
    if (seperator != '\0')
        snprintf(tempstr, MAC_STR_LEN, "%02X%c%02X%c%02X%c%02X%c%02X%c%02X",
                 mac[0], seperator, mac[1], seperator, mac[2], seperator,
                 mac[3], seperator, mac[4], seperator, mac[5]);
    else
        snprintf(tempstr, MAC_STR_LEN, "%02X%02X%02X%02X%02X%02X",
                 mac[0], mac[1], mac[2],
                 mac[3], mac[4], mac[5]);

    string temp = tempstr;
    return temp;
}


PanelFront::PanelFront() {
    errstr[0] = '\0';

    sortby = sort_auto;

    client = NULL;

    clear_dump = 0;

    hsize = COLS;
    vsize = LINES;

    //cutoff = 0;

    muted = 0;

    // Push blanks into the RRD history vector
    for (unsigned int x = 0; x < (60 * 5); x++)
        packet_history.push_back(0);

    max_packet_rate = 0;

    lat = lon = alt = spd = 0;
    fix = 0;
    last_lat = last_lon = last_alt = last_spd = 0;
    last_fix = 0;

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

    return 0;
}

void PanelFront::RescaleDisplay() {
    wresize(net_win->win, LINES-statheight, COLS-infowidth);
    net_win->max_display = net_win->win->_maxy - 3;
    net_win->print_width = net_win->win->_maxx - 2;
    replace_panel(net_win->pan, net_win->win);
    move_panel(net_win->pan, 0, 0);

    wresize(info_win->win, LINES-statheight, infowidth);
    info_win->max_display = info_win->win->_maxy - 2;
    info_win->print_width = info_win->win->_maxx - 2;
    replace_panel(info_win->pan, info_win->win);
    move_panel(info_win->pan, 0, COLS-infowidth);

    wresize(stat_win->win, statheight, COLS);
    stat_win->max_display = stat_win->win->_maxy - 2;
    stat_win->print_width = stat_win->win->_maxx - 2;
    replace_panel(stat_win->pan, stat_win->win);
    move_panel(stat_win->pan, LINES-statheight, 0);
}

void PanelFront::SetColumns(string in_columns) {
    unsigned int begin = 0;
    unsigned int end = in_columns.find(",");

    column_vec.clear();

    while (end < in_columns.size()) {
        string opt = in_columns.substr(begin, end-begin);
        begin = end+1;
        end = in_columns.find(",", begin);

        column_vec.push_back(opt);
    }

    column_vec.push_back(in_columns.substr(begin, in_columns.size()));
}

int PanelFront::WriteStatus(string status) {
    stat_win->text.push_back(status);

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

    return 1;
}

// This argument list is getting increasingly nasty, hopefully I'll be able to
// come back and clean all this up
string PanelFront::NetLine(wireless_network *net, const char *name, int sub,
                           int group, int expanded, int tagged) {
    char retchr[4096];
    char tmpchr[4096];

    memset(retchr, 0, 4096);
    memset(tmpchr, 0, 4096);

    // We rip into our reference to non-transient netwin here since this only EVER
    // generates a line for netwin to display.  We'll do a little sanity checking just
    // to make sure someone isn't trying to do something weird to us - I refuse to beleive
    // anyone is USING a screen with more than 4096 columns.
    int print_width = net_win->print_width;
    if (net_win->print_width > 4096) {
        net_win->print_width = 4096;
        print_width = 4096;
    }

    if (tagged)
        snprintf(retchr, 4096, "*");
    else if (group && expanded)
        snprintf(retchr, 4096, "-");
    else if (group && !expanded)
        snprintf(retchr, 4096, "+");
    else if (sub)
        snprintf(retchr, 4096, "|");

    int pos = 2;
    for (unsigned int col = 0; col < column_vec.size(); col++) {
        char element[1024];
        int len = 0;

        if (column_vec[col] == "decay") {
            if ((client->FetchTime() - net->last_time) < decay)
                snprintf(element, 1024, "!");
            else if ((client->FetchTime() - net->last_time) < (decay * 2))
                snprintf(element, 1024, ".");
            else
                snprintf(element, 1024, " ");
            len = 1;
        } else if (column_vec[col] == "name") {
            if (net->cloaked) {
                snprintf(element, 26, "<%s>", name);
            } else {
                snprintf(element, 26, "%s", name);
            }
            len = 25;
        } else if (column_vec[col] == "shortname") {
            if (net->cloaked) {
                snprintf(element, 16, "<%s>", name);
            } else {
                snprintf(element, 16, "%s", name);
            }
            len = 15;
        } else if (column_vec[col] == "ssid") {
            if (net->cloaked) {
                snprintf(element, 26, "<%s>", net->ssid.c_str());
            } else {
                snprintf(element, 26, "%s", net->ssid.c_str());
            }
            len = 25;
        } else if (column_vec[col] == "shortssid") {
            if (net->cloaked) {
                snprintf(element, 16, "<%s>", net->ssid.c_str());
            } else {
                snprintf(element, 16, "%s", net->ssid.c_str());
            }
            len = 15;
        } else if (column_vec[col] == "type") {
            if (group)
                snprintf(element, 1024, "G");
            else if (net->type == network_ap)
                snprintf(element, 1024, "A");
            else if (net->type == network_adhoc)
                snprintf(element, 1024, "H");
            else if (net->type == network_probe)
                snprintf(element, 1024, "P");
            else if (net->type == network_data)
                snprintf(element, 1024, "D");
            else if (net->type == network_lor)
                snprintf(element, 1024, "O");
            else
                snprintf(element, 1024, "?");

            len = 1;
        } else if (column_vec[col] == "wep") {
            if (net->wep)
                snprintf(element, 1024, "Y");
            else
                snprintf(element, 1024, "N");
            len = 1;
        } else if (column_vec[col] == "channel") {
            if (net->channel == 0)
                snprintf(element, 3, "--");
            else
                snprintf(element, 3, "%02d", net->channel);
            len = 2;
        } else if (column_vec[col] == "data") {
            snprintf(element, 6, "%5d", net->data_packets);
            len = 5;
        } else if (column_vec[col] == "llc") {
            snprintf(element, 6, "%5d", net->llc_packets);
            len = 5;
        } else if (column_vec[col] == "crypt") {
            snprintf(element, 6, "%5d", net->crypt_packets);
            len = 5;
        } else if (column_vec[col] == "weak") {
            snprintf(element, 6, "%5d", net->interesting_packets);
            len = 5;
        } else if (column_vec[col] == "packets") {
            snprintf(element, 7, "%6d", net->data_packets + net->llc_packets);
            len = 6;
        } else if (column_vec[col] == "bssid") {
            snprintf(element, 18, "%s", net->bssid.c_str());
            len = 17;
        } else if (column_vec[col] == "info") {
            snprintf(element, 16, "%s", net->beacon_info.c_str());
            len = 15;
        } else if (column_vec[col] == "flags") {
            char atype;
            if (net->ipdata.atype == address_dhcp)
                atype = 'D';
            else if (net->ipdata.atype == address_arp)
                atype = 'A';
            else if (net->ipdata.atype == address_udp)
                atype = 'U';
            else if (net->ipdata.atype == address_tcp)
                atype = 'T';
            else if (net->ipdata.atype == address_group)
                atype = 'G';
            else
                atype = ' ';

            snprintf(element, 6, "%c%c%c%c%c",
                     net->manuf_score == manuf_max_score ? 'F' : ' ',
                     atype,
                     (net->ipdata.atype > address_factory && net->ipdata.octets != 0) ? net->ipdata.octets + '0' : ' ',
                     net->cisco_equip.size() > 0 ? 'C' : ' ',
                     ' ');
            len = 5;
        } else if (column_vec[col] == "ip") {
            if (net->ipdata.atype == address_none) {
                snprintf(element, 1024, "0.0.0.0");
            } else {
                snprintf(element, 16, "%d.%d.%d.%d",
                         net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                         net->ipdata.range_ip[2], net->ipdata.range_ip[3]);
            }
            len = 15;
        } else if (column_vec[col] == "mask") {
            if (net->ipdata.atype == address_none) {
                snprintf(element, 1024, "0.0.0.0");
            } else {
                snprintf(element, 16, "%d.%d.%d.%d",
                         net->ipdata.mask[0], net->ipdata.mask[1],
                         net->ipdata.mask[2], net->ipdata.mask[3]);
            }
            len = 15;
        } else if (column_vec[col] == "gateway") {
            if (net->ipdata.atype == address_none) {
                snprintf(element, 1024, "0.0.0.0");
            } else {
                snprintf(element, 16, "%d.%d.%d.%d",
                         net->ipdata.gate_ip[0], net->ipdata.gate_ip[1],
                         net->ipdata.gate_ip[2], net->ipdata.gate_ip[3]);
            }
            len = 15;
        } else if (column_vec[col] == "maxrate") {
            snprintf(element, 6, "%2.1f", net->maxrate);
            len = 5;
        } else if (column_vec[col] == "manuf") {
            if (net->manuf_id >= 0 && net->manuf_id < manuf_num) {
                snprintf(element, 9, "%s", manuf_list[net->manuf_id].short_manuf.c_str());
            } else {
                snprintf(element, 9, "Unknown");
            }
            len = 8;
        } else if (column_vec[col] == "signal") {
            snprintf(element, 4, "%3d", net->signal);
            len = 3;
        } else if (column_vec[col] == "quality") {
            snprintf(element, 4, "%3d", net->quality);
            len = 3;
        } else if (column_vec[col] == "noise") {
            snprintf(element, 4, "%3d", net->noise);
            len = 3;
        }

        if (pos + len > print_width)
            break;

//        fprintf(stderr, "%s ... %s\n", retchr, element);

        snprintf(tmpchr, 4096, "%*s %s", (-1) * pos, retchr, element);

        strncpy(retchr, tmpchr, 4096);

//        snprintf(retchr, 4096, "%*s %s", (-1) * pos, retchr, element);

//        mvwaddstr(netwin, num+voffset, pos, element);

        pos += len + 1;
    }

    string ret = retchr;

    return ret;
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

void PanelFront::SpawnWindow(string in_title, panel_printer in_print, key_handler in_input,
                             int in_x, int in_y) {
    kis_window *kwin = new kis_window;

    kwin->title = in_title;
    kwin->printer = in_print;
    kwin->input = in_input;
    kwin->start = 0;
    kwin->end = 0;
    kwin->selected = 0;
    kwin->paused = 0;
    kwin->scrollable = 0;

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
        return;
    }

    kwin->pan = new_panel(kwin->win);
    nodelay(kwin->win, true);
    keypad(kwin->win, true);

    move_panel(kwin->pan, (LINES/2) - (in_x/2), (COLS/2) - (in_y/2));
    show_panel(kwin->pan);
    window_list.push_back(kwin);
    cur_window = kwin;
    DrawDisplay();
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
    if (height + 2 > LINES)
        height = LINES - 2;

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

    int ret;
    ret = (this->*cur_window->input)(cur_window, ch);

    if (ret == 0)
        DestroyWindow(cur_window);

    cur_window = window_list.back();

    DrawDisplay();

    return ret;
}

int PanelFront::Tick() {
    // We should be getting a 1-second tick - secondary to a draw event, because
    // we can cause our own draw events which wouldn't necessarily be a good thing

    last_lat = lat; last_lon = lon;
    last_spd = spd; last_alt = alt;
    last_fix = fix;

    client->FetchLoc(&lat, &lon, &alt, &spd, &fix);


    // Pull our packet count, store it, and bounce if we're
    // holding more than 5 minutes worth.

    int rate = client->FetchNumPackets() - client->FetchNumDropped();

    // Find the delta change since the last event and push it as the max seen packet
    // rate if it's larger.
    int adjrate;
    if (packet_history[packet_history.size()] != 0) {
        adjrate = rate - packet_history[packet_history.size()];
    } else {
        adjrate = 0;
    }
    if (adjrate > max_packet_rate)
        max_packet_rate = adjrate;


    packet_history.push_back(rate);

    if (packet_history.size() > (60 * 5))
        packet_history.erase(packet_history.begin());


    // Now fetch the APM data (if so desired)
    if (monitor_bat) {
#ifdef SYS_LINUX
        char buf[128];

#ifndef HAVE_ACPI
        // Lifted from gkrellm's battery monitor
        FILE *apm;
        int ac_line_status, battery_status, flag, percentage, time;
        char units[32];

        if ((apm = fopen("/proc/apm", "r")) == NULL) {
            bat_available = 0;
            bat_ac = 0;
            bat_percentage = 0;
            bat_time = 0;
            bat_charging = 0;
        } else {
            fgets(buf, 128, apm);
            fclose(apm);

            sscanf(buf, "%*s %*d.%*d %*x %x %x %x %d%% %d %s\n", &ac_line_status,
                   &battery_status, &flag, &percentage, &time, units);

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
            bat_time = time;

            if (!strncmp(units, "min", 32))
                bat_time *= 60;
        }
#else // ACPI
        FILE *acpi;
        int rate = 1, remain = 0, current = 0;
        bat_available = 0;
        if ((acpi = fopen(prefs["acpistatefile"].c_str(), "r")) != NULL) {
            while (fgets(buf, 128, acpi))
            {
                if (strncmp(buf, "present:", 8 ) == 0)
                {
                    // No information for this battery
                    if (strstr(buf, "no" ))
                        break;
                    else
                        bat_available = 1;
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
                    remain = atoi(buf + 25);
                else if (strncmp(buf, "present voltage:", 17) == 0)
                    current = atoi(buf + 25);
            }
            fclose(acpi);
            bat_percentage = int((float(remain) / bat_full_capacity) * 100);
            if (bat_charging)
                bat_time = int((float(bat_full_capacity - remain) / rate) * 3600);
            else
                bat_time = int((float(remain) / rate) * 3600);
        }
        else {
            bat_ac = 0;
            bat_percentage = 0;
            bat_time = 0;
            bat_charging = 0;
        }
#endif
#endif
    }

    return 1;
}

void PanelFront::AddPrefs(map<string, string> in_prefs) {
    prefs = in_prefs;

    SetColumns(prefs["columns"]);

#ifdef HAVE_ACPI
	char buf[80];
	FILE *info = fopen(prefs["acpiinfofile"].c_str(), "r");
	bat_full_capacity = 3000; // Avoid div by zero by guessing, however unlikely to be right
	if ( info != NULL ) {
		while (fgets(buf, sizeof(buf), info) != NULL)
			if (1 == sscanf(buf, "last full capacity:      %d mWh", &bat_full_capacity)) 
				break;
		fclose(info);
	}
#endif
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
