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
    "QUICK REFERENCE",
    "  Key  Action",
    "   z   Toggle fullscreen zoom of network view",
    "   m   Toggle muting of sound and speech",
    "   t   Tag (or untag) selected network",
    "   g   Group tagged networks",
    "   u   Ungroup current group",
    "   c   Show clients in current network",
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
    "  O       Lucent - Lucent Outdoor Router network",
    "  G       Group - Group of wireless networks",
    "  D       Data - Data only network with no control packets.",
    "",
    "Client types:",
    "  F       From DS - client broadcast from wireless distribution system",
    "  T       To DS - client transmitted over the wireless to the",
    "          distribution system",
    "  I       Intra DS - client is a node of the distribution system talking",
    "          to another node in the distribution system",
    "  E       Established - client has been seen entering and leaving the DS",
    "  -       Unknown - client is in an unknown state",
    "",
    "Status flags give a brief overview about information discovered on the",
    "network.",
    "  F    Vulnerable factory configuration.  Many people don't bother to",
    "       ever change the configuration on their WAP.  This is bad.",
    "  T#   Address range of # octets found via TCP traffic",
    "  U#   Address range of # octets found via UDP traffic",
    "  A#   Address range of # octets found via ARP traffic",
    "  D    Address range found via observed DHCP traffic",
    "",
    "SELECTING NETWORKS:",
    "The default sorting method is Autofit.  This fits as many currently active",
    "networks on the display as possible, and does not scroll.  ALL NETWORK ",
    "SELECTION, TAGGING, GROUPING, SCROLLING, AND SO ON IS DISABLED IN AUTOFIT ",
    "MODE.  Sort the network display by one of the other methods to select and",
    "group networks.  Autofit mode changes the location of networks too ",
    "frequently make selecting a single network realistic.",
    "",
    "For more information, consult the documentation in the docs/ directory",
    "of the Kismet source package.",
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
    " c  Show clients",
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

char *KismetClientSortText[] = {
    "Key  Sort                Key  Sort",
    " a   Auto-fit (standard)  c   Channel",
    " f   First time seen      F   First time seen (descending)",
    " l   Latest time seen     L   Latest time seen (descending)",
    " m   MAC                  M   MAC (descending)",
    " p   Packet count         P   Packet count (descending)",
    " w   WEP                  q   Quality",
    " Q   Power level          x   Cancel",
    NULL
};

char *KismetClientSortTextNarrow[] = {
    "Key Sort        Key Sort",
    " a  Auto-fit     c  Channel",
    " f  First time   F  First time (d)",
    " l  Latest time  L  Latest time (d)",
    " m  MAC          M  MAC (d)",
    " p  Packet count P  Packet count (d)",
    " w  WEP          q  Quality",
    " Q  Power level  x  Cancel",
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

char *KismetHelpAlert[] = {
    "KISMET ALERTS",
    "This panel tracks alert conditions, such as NetStumbler clients",
    "or DOS attacks.",
    " Key   Action",
    "  t    Toggle display of alert condition timestamp",
    "  q    Close popup",
    NULL
};

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
    } else if (in_token == "mask") {
        return mcol_mask;
    } else if (in_token == "gateway") {
        return mcol_gateway;
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
    } else if (in_token == "quality") {
        return mcol_quality;
    } else if (in_token == "noise") {
        return mcol_noise;
    } else if (in_token == "clients") {
        return mcol_clients;
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
    } else if (in_token == "quality") {
        return ccol_quality;
    } else if (in_token == "noise") {
        return ccol_noise;
    }

    return ccol_unknown;
}

void PanelFront::SetMainColumns(string in_columns) {
    unsigned int begin = 0;
    unsigned int end = in_columns.find(",");

    column_vec.clear();

    while (end < in_columns.size()) {
        string opt = in_columns.substr(begin, end-begin);
        begin = end+1;
        end = in_columns.find(",", begin);

        column_vec.push_back(Token2MainColumn(opt));
    }

    column_vec.push_back(Token2MainColumn(in_columns.substr(begin, in_columns.size())));
}

void PanelFront::SetClientColumns(string in_columns) {
    unsigned int begin = 0;
    unsigned int end = in_columns.find(",");

    client_column_vec.clear();

    while (end < in_columns.size()) {
        string opt = in_columns.substr(begin, end-begin);
        begin = end+1;
        end = in_columns.find(",", begin);

        client_column_vec.push_back(Token2ClientColumn(opt));
    }

    client_column_vec.push_back(Token2ClientColumn(in_columns.substr(begin, in_columns.size())));
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

    int adjrate = client->FetchPacketRate();
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
        int ac_line_status, battery_status, flag, percentage, apm_time;
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
        } else {
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

    SetMainColumns(prefs["columns"]);
    SetClientColumns(prefs["clientcolumns"]);
//    SetColumns(prefs["clientcolumns"], &client_column_vec);

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
