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
    " w  WEP          x  Cancel",
    NULL
};
#define SORT_SIZE 8

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

        werase(kwin->win);
        if (color)
            wattrset(kwin->win, color_map["border"].pair);
        box(kwin->win, '|', '-');
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
                     (net->ipdata.atype > address_factory && net->ipdata.octets != 0 && net->ipdata.octets != 4) ? net->ipdata.octets + '0' : ' ',
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
        width = COLS - 4;
    if (height + 2 > LINES)
        height = LINES - 1;

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

    height += 2;
    width += 5;

    kwin->max_display = height - 2;
    kwin->print_width = width - 3;

    kwin->win = newwin(height, width, 0, 0);
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


int PanelFront::MainNetworkPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;
    WINDOW *netwin = kwin->win;

    int drop;

    // One:  Get our new data from the client
    PopulateGroups();
    // Two:  Recalculate all our agregate data
    UpdateGroups();
    // Three: Copy it to our own local vector so we can sort it.
    vector<display_network *> display_vector = group_vec;

    //vector<wireless_network *> network_vector = client->FetchNetworkList();

    char sortxt[24];
    sortxt[0] = '\0';

    switch (sortby) {
    case sort_auto:
        // Trim it ourselves for autofit mode.
        // This is really easy because we don't allow groups to be expanded in autofit
        // mode, so we just make it fit.

        snprintf(sortxt, 24, "(Autofit)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortLastTimeLT());

        drop = display_vector.size() - kwin->max_display - 1;

        if (drop > 0) {
            display_vector.erase(display_vector.begin(), display_vector.begin() + drop);
        }
        sort(display_vector.begin(), display_vector.end(), DisplaySortFirstTimeLT());
        kwin->start = 0;

        break;

        // Otherwise, go on to sort the groups by the other means available to us...
    case sort_channel:
        snprintf(sortxt, 24, "(Channel)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortChannel());
        break;
    case sort_first:
        snprintf(sortxt, 24, "(First Seen)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortFirstTimeLT());
        break;
    case sort_first_dec:
        snprintf(sortxt, 24, "(First Seen desc)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortFirstTime());
        break;
    case sort_last:
        snprintf(sortxt, 24, "(Latest Seen)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortLastTimeLT());
        break;
    case sort_last_dec:
        snprintf(sortxt, 24, "(Latest Seen desc)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortLastTime());
        break;
    case sort_bssid:
        snprintf(sortxt, 24, "(BSSID)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortBSSIDLT());
        break;
    case sort_bssid_dec:
        snprintf(sortxt, 24, "(BSSID desc)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortBSSID());
        break;
    case sort_ssid:
        snprintf(sortxt, 24, "(SSID)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortSSIDLT());
        break;
    case sort_ssid_dec:
        snprintf(sortxt, 24, "(SSID desc)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortSSID());
        break;
    case sort_wep:
        snprintf(sortxt, 24, "(WEP)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortWEP());
        break;
    case sort_packets:
        snprintf(sortxt, 24, "(Packets)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortPacketsLT());
        break;
    case sort_packets_dec:
        snprintf(sortxt, 24, "(Packets desc)");

        sort(display_vector.begin(), display_vector.end(), DisplaySortPackets());
        break;
    }

//    last_displayed.erase(last_displayed.begin(), last_displayed.begin() + last_displayed.size());
//    last_displayed = display_vector;
    //    last_displayed = network_vector;

    last_displayed.clear();

    int num = 0;
    int voffset = 2;

    // Print the headers
    int pos = 4;

    for (unsigned int col = 0; col < column_vec.size(); col++) {
        char title[1024];
        int len = 0;

        if (column_vec[col] == "decay") {
            snprintf(title, 1024, " ");
            len = 1;
        } else if (column_vec[col] == "name") {
            snprintf(title, 1024, "Name");
            len = 25;
        } else if (column_vec[col] == "shortname") {
            snprintf(title, 1024, "Name");
            len = 15;
        } else if (column_vec[col] == "ssid") {
            snprintf(title, 1024, "SSID");
            len = 25;
        } else if (column_vec[col] == "shortssid") {
            snprintf(title, 1024, "SSID");
            len = 15;
        } else if (column_vec[col] == "type") {
            snprintf(title, 1024, "T");
            len = 1;
        } else if (column_vec[col] == "wep") {
            snprintf(title, 1024, "W");
            len = 1;
        } else if (column_vec[col] == "channel") {
            snprintf(title, 1024, "Ch");
            len = 2;
        } else if (column_vec[col] == "data") {
            snprintf(title, 1024, " Data");
            len = 5;
        } else if (column_vec[col] == "llc") {
            snprintf(title, 1024, "  LLC");
            len = 5;
        } else if (column_vec[col] == "crypt") {
            snprintf(title, 1024, "Crypt");
            len = 5;
        } else if (column_vec[col] == "weak") {
            snprintf(title, 1024, " Weak");
            len = 5;
        } else if (column_vec[col] == "bssid") {
            snprintf(title, 1024, "BSSID");
            len = 17;
        } else if (column_vec[col] == "flags") {
            snprintf(title, 1024, "Flags");
            len = 5;
        } else if (column_vec[col] == "ip") {
            snprintf(title, 1024, "IP Range");
            len = 15;
        } else if (column_vec[col] == "mask") {
            snprintf(title, 1024, "IP Mask");
            len = 15;
        } else if (column_vec[col] == "gateway") {
            snprintf(title, 1024, "IP Gateway");
            len = 15;
        } else if (column_vec[col] == "packets") {
            snprintf(title, 1024, "Packts");
            len = 6;
        } else if (column_vec[col] == "info") {
            snprintf(title, 1024, "Beacon Info");
            len = 15;
        } else if (column_vec[col] == "maxrate") {
            snprintf(title, 1024, "Rate");
            len = 5;
        } else if (column_vec[col] == "manuf") {
            snprintf(title, 1024, "Manuf");
            len = 8;
        } else if (column_vec[col] == "signal") {
            snprintf(title, 1024, "Sgn");
            len = 3;
        } else if (column_vec[col] == "quality") {
            snprintf(title, 1024, "Qly");
            len = 3;
        } else if (column_vec[col] == "noise") {
            snprintf(title, 1024, "Nse");
            len = 3;
        } else {
            len = -1;
        }

        if (pos + len > kwin->print_width + 2)
            break;

        if (color)
            wattrset(kwin->win, color_map["title"].pair);
        mvwaddstr(netwin, 1, pos, title);
        if (color)
            wattrset(kwin->win, color_map["text"].pair);

        pos += len + 1;

    }

    //cutoff = 0;

    for (unsigned int i = kwin->start; i < display_vector.size(); i++) {

        /*
        if (display_vector[i]->networks.size() == 0)
        continue;
        */

        last_displayed.push_back(display_vector[i]);

        wireless_network *net = &display_vector[i]->virtnet;

        if (net->manuf_score == manuf_max_score && color)
            wattrset(kwin->win, color_map["factory"].pair);
        else if (net->wep && color)
            wattrset(kwin->win, color_map["wep"].pair);
        else if (color)
            wattrset(kwin->win, color_map["open"].pair);

        if (i == (unsigned) (kwin->start + kwin->selected) && sortby != sort_auto) {
            wattron(netwin, A_REVERSE);
            char bar[1024];
            memset(bar, ' ', 1024);
            int w = kwin->print_width;
            if (w >= 1024)
                w = 1024;
            bar[w] = '\0';
            mvwaddstr(netwin, num+voffset, 2, bar);
        }

        string netline;

        // Build the netline for the group or single host and tag it for expansion if
        // appropriate for this sort and group
        netline = NetLine(net,
                          display_vector[i]->name == "" ? display_vector[i]->virtnet.ssid.c_str() : display_vector[i]->name.c_str(),
                          0,
                          display_vector[i]->type == group_host ? 0 : 1,
                          sortby == sort_auto ? 0 : display_vector[i]->expanded,
                          display_vector[i]->tagged);

        mvwaddstr(netwin, num+voffset, 1, netline.c_str());

        if (i == (unsigned) (kwin->start + kwin->selected) && sortby != sort_auto)
            wattroff(netwin, A_REVERSE);

        if (color)
            wattrset(kwin->win, color_map["text"].pair);

        num++;
        kwin->end = i;

        if (num > kwin->max_display)
            break;

        if (sortby == sort_auto || display_vector[i]->type != group_bundle ||
            display_vector[i]->expanded == 0)
            continue;

        // If we we're a group and we're expanded, show all our subgroups
        vector<wireless_network *> sortsub = display_vector[i]->networks;
        switch (sortby) {
        case sort_auto:
            break;
        case sort_channel:
            sort(sortsub.begin(), sortsub.end(), SortChannel());
            break;
        case sort_first:
            sort(sortsub.begin(), sortsub.end(), SortFirstTimeLT());
            break;
        case sort_first_dec:
            sort(sortsub.begin(), sortsub.end(), SortFirstTime());
            break;
        case sort_last:
            sort(sortsub.begin(), sortsub.end(), SortLastTimeLT());
            break;
        case sort_last_dec:
            sort(sortsub.begin(), sortsub.end(), SortLastTime());
            break;
        case sort_bssid:
            sort(sortsub.begin(), sortsub.end(), SortBSSIDLT());
            break;
        case sort_bssid_dec:
            sort(sortsub.begin(), sortsub.end(), SortBSSID());
            break;
        case sort_ssid:
            sort(sortsub.begin(), sortsub.end(), SortSSIDLT());
            break;
        case sort_ssid_dec:
            sort(sortsub.begin(), sortsub.end(), SortSSID());
            break;
        case sort_wep:
            sort(sortsub.begin(), sortsub.end(), SortWEP());
            break;
        case sort_packets:
            sort(sortsub.begin(), sortsub.end(), SortPacketsLT());
            break;
        case sort_packets_dec:
            sort(sortsub.begin(), sortsub.end(), SortPackets());
            break;
        }

        for (unsigned int y = 0; y < sortsub.size(); y++) {
            net = display_vector[i]->networks[y];

            netline = NetLine(net, net->ssid.c_str(), 1, 0, 0, 0);

            if (net->manuf_score == manuf_max_score && color)
                wattrset(kwin->win, color_map["factory"].pair);
            else if (net->wep && color)
                wattrset(kwin->win, color_map["wep"].pair);
            else if (color)
                wattrset(kwin->win, color_map["open"].pair);

            mvwaddstr(netwin, num+voffset, 1, netline.c_str());

            if (color)
                wattrset(kwin->win, color_map["text"].pair);

            num++;

            if (num > kwin->max_display) {
                //cutoff = 1;
                break;
            }
        }

        if (num > kwin->max_display)
            break;
    }

    // This is inefficient but we already did all the calculations with expanded
    // groups so there isn't a better way.  If somehow with the new drawing our
    // selected line ends up past the end of the screen, force it to the end.
    if ((kwin->start + kwin->selected) > kwin->end) {
        kwin->selected = kwin->end - kwin->start;
        MainNetworkPrinter(in_window);
        return 1;
    }

    last_draw_size = group_vec.size();


    if (color)
        wattrset(kwin->win, color_map["title"].pair);
    mvwaddstr(netwin, 0, kwin->title.length() + 4, sortxt);
    if (color)
        wattrset(kwin->win, color_map["text"].pair);

    if (kwin->start != 0 && sortby != sort_auto) {
        mvwaddstr(netwin, 0, netwin->_maxx - 10, "(-) Up");
    }

    if (kwin->end < (int) (group_vec.size() - 1) && sortby != sort_auto) {
        mvwaddstr(netwin, netwin->_maxy,
                  netwin->_maxx - 10, "(+) Down");
    }

#ifdef HAVE_GPS
    char gpsdata[80];
//    if (gps != NULL) {
    float lat, lon, alt, spd;
    int mode;

    client->FetchLoc(&lat, &lon, &alt, &spd, &mode);

    if (!(lat == 0 && lon == 0 && alt == 0 && spd == 0 && mode == 0)) {

        char fix[16];

        if (metric) {
            alt = alt / 3.3;
            spd = spd * 1.6093;
        }

        if (mode == -1)
            snprintf(fix, 16, "No signal");
        else if (mode == 2)
            snprintf(fix, 5, "2D");
        else if (mode == 3)
            snprintf(fix, 5, "3D");
        else
            snprintf(fix, 5, "NONE");

        // Convert if we're less than a mile/hr or kilom/hr
        int spdslow = 0;
        if (spd < 0.5) {
            spdslow = 1;
            if (metric)
                spd = spd * 0.2222;
            else
                spd = spd * 1.4666;
        }

        snprintf(gpsdata, 80, "Lat %.3f Lon %.3f Alt %.1f%c Spd %.3f%s Fix %s",
                 lat, lon, alt,
                 metric ? 'm' : 'f',
                 spd,
                 spdslow ? (metric ? "m/h" : "f/s") : (metric ? "km/h" : "m/h"),
                 fix);

        if (color)
            wattrset(kwin->win, color_map["monitor"].pair);
        mvwaddstr(netwin, netwin->_maxy, 2, gpsdata);
        if (color)
            wattrset(kwin->win, color_map["text"].pair);

        // fprintf(stderr, "found: %f %f %f %f\n", lat, lon, alt, spd);

    }
#endif


    return 1;
}

int PanelFront::MainInfoPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;
    WINDOW *infowin = kwin->win;

    mvwaddch(infowin, LINES-statheight-1, 3, 'H');
    mvwaddch(infowin, LINES-statheight-1, 5, 'M');
    mvwaddch(infowin, LINES-statheight-1, 7, 'S');

    // Now draw the info window
    char info[kwin->print_width];

    mvwaddstr(infowin, 1, 2, "Ntwrks");
    snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, client->FetchNumNetworks());
    mvwaddstr(infowin, 2, 2, info);

    mvwaddstr(infowin, 3, 2, "Pckets");
    snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, client->FetchNumPackets());
    mvwaddstr(infowin, 4, 2, info);

    if (kwin->max_display > 6) {
        mvwaddstr(infowin, 5, 2, "Cryptd");
        snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, client->FetchNumCrypt());
        mvwaddstr(infowin, 6, 2, info);
    }

    if (kwin->max_display > 8) {
        mvwaddstr(infowin, 7, 2, "  Weak");
        snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, client->FetchNumInteresting());
        mvwaddstr(infowin, 8, 2, info);
    }

    if (kwin->max_display > 10) {
        mvwaddstr(infowin, 9, 2, " Noise");
        snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, client->FetchNumNoise());
        mvwaddstr(infowin, 10, 2, info);
    }

    if (kwin->max_display > 12) {
        mvwaddstr(infowin, 11, 2, "Discrd");
        snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, client->FetchNumDropped());
        mvwaddstr(infowin, 12, 2, info);
    }

    if (kwin->max_display > 14) {
        unsigned int pktsec = 0;
        // This should never be, but we'll check to be sure
        if (packet_history.size() >= 2)
            pktsec = packet_history[packet_history.size() - 1] -
                packet_history[packet_history.size() - 2];
        mvwaddstr(infowin, 13, 2, "Pkts/s");
        snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, pktsec);
        mvwaddstr(infowin, 14, 2, info);
    }

    if (client->Valid())
        mvwaddstr(infowin, LINES-statheight-2, 2, "Elapsd");
    else
        mvwaddstr(infowin, LINES-statheight-2, 2, "Discon");

    time_t elapsed = client->FetchTime() - start_time;
    snprintf(info, infowidth-2, "%02d%02d%02d",
             (int) (elapsed / 60) / 60, (int) (elapsed / 60) % 60,
             (int) elapsed % 60);
    mvwaddstr(infowin, infowin->_maxy, 2, info);

    return 1;
}

int PanelFront::MainStatusPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;
    WINDOW *statuswin = kwin->win;

    if (kwin->text.size() != 0) {
        int drop = kwin->text.size() - kwin->max_display - 1;
        if (drop > 0) {
            kwin->text.erase(kwin->text.begin(), kwin->text.begin() + drop);
        }

        // This is kind of funky
        char *trim = new char[kwin->print_width];
        for (unsigned int x = kwin->text.size(); x > 0; x--) {
            snprintf(trim, kwin->print_width, "%s", kwin->text[x-1].c_str());
            mvwaddstr(kwin->win, 2 + kwin->max_display - x, 3, trim);
        }
    }

    if (monitor_bat) {
        char batdata[80];

        if (bat_available) {
            snprintf(batdata, 80, "Battery: %s%s%d%% %0dh%0dm%0ds",
                     bat_ac ? "AC " : "",
                     bat_charging ? "charging " : "",
                     bat_percentage,
                     (int) (bat_time / 60) / 60,
                     (int) (bat_time / 60) % 60,
                     (int) (bat_time % 60));
        } else {
            snprintf(batdata, 80, "Battery: unavailable%s",
                     bat_ac ? ", AC power" : "");
        }

        if (color)
            wattrset(kwin->win, color_map["monitor"].pair);
        mvwaddstr(statuswin, statuswin->_maxy, 2, batdata);
        if (color)
            wattrset(kwin->win, color_map["text"].pair);

    }

    return 1;
}

int PanelFront::TextPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    unsigned int x;
    char *txt = new char[kwin->print_width + 1];
    for (x = 0; x + kwin->start < kwin->text.size() &&
         x < (unsigned int) kwin->max_display; x++) {
        snprintf(txt, kwin->print_width + 1, "%s", kwin->text[x+kwin->start].c_str());
        mvwaddstr(kwin->win, 1+x, 2, txt);
    }
    delete txt;

    kwin->end = x+kwin->start;

    if (kwin->start != 0) {
        mvwaddstr(kwin->win, 0, kwin->win->_maxx - 10, "(-) Up");
    }

    if (kwin->end < (int) (kwin->text.size() - 1)) {
        mvwaddstr(kwin->win, kwin->win->_maxy, kwin->win->_maxx - 10, "(+) Down");
    }

    return 1;
}

int PanelFront::SortPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    int x = 0;
    while (1) {
        if (KismetSortText[x] == NULL)
            break;
        if (kwin->win->_maxx < 64)
            mvwaddstr(kwin->win, 1+x, 2, KismetSortTextNarrow[x]);
        else
            mvwaddstr(kwin->win, 1+x, 2, KismetSortText[x]);
        x++;
    }

    return 1;
}

int PanelFront::PowerPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    int quality, power, noise;

    quality = client->FetchQuality();
    power = client->FetchPower();
    noise = client->FetchNoise();

    if (quality == -1 && power == -1 && noise == -1) {
        mvwaddstr(kwin->win, 2, 2, "Server did not report card power levels.");
        mvwaddstr(kwin->win, 3, 2, "No card information is available.");
        return 1;
    }

    int width = kwin->win->_maxx - 10;

    if (width <= 5) {
        return 0;
    }

    char *bar = new char[width+1];

    if (quality > LINKQ_MAX)
        quality = LINKQ_MAX;
    if (power > LEVEL_MAX)
        power = LEVEL_MAX;
    if (noise > NOISE_MAX)
        noise = NOISE_MAX;

    double qperc = 0, pperc = 0, nperc = 0;
    if (quality != 0)
        qperc = (double) quality/LINKQ_MAX;
    if (power != 0)
        pperc = (double) power/LEVEL_MAX;
    if (noise != 0)
        nperc = (double) noise/NOISE_MAX;

    int qbar = 0, pbar = 0, nbar = 0;
    qbar = (int) (width * qperc);
    pbar = (int) (width * pperc);
    nbar = (int) (width * nperc);

    memset(bar, '=', width);
    memset(bar, 'X', qbar);
    bar[width] = '\0';
    mvwaddstr(kwin->win, 1, 2, "Q:");
    mvwaddstr(kwin->win, 1, 5, bar);

    memset(bar, '=', width);
    memset(bar, 'X', pbar);
    bar[width] = '\0';
    mvwaddstr(kwin->win, 2, 2, "P:");
    mvwaddstr(kwin->win, 2, 5, bar);

    memset(bar, '=', width);
    memset(bar, 'X', nbar);
    bar[width] = '\0';
    mvwaddstr(kwin->win, 3, 2, "N:");
    mvwaddstr(kwin->win, 3, 5, bar);

    snprintf(bar, width, "%d", quality);
    mvwaddstr(kwin->win, 1, width+6, bar);
    snprintf(bar, width, "%d", power);
    mvwaddstr(kwin->win, 2, width+6, bar);
    snprintf(bar, width, "%d", noise);
    mvwaddstr(kwin->win, 3, width+6, bar);

    return 1;
}

// Details
int PanelFront::DetailsPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    char output[1024];
    kwin->text.clear();

    int print_width = kwin->print_width;
    if (print_width > 1024)
        print_width = 1024;

    if (details_network->name == "")
        snprintf(output, print_width, "Name    : %s", details_network->virtnet.ssid.c_str());
    else
        snprintf(output, print_width, "Name    : %s", details_network->name.c_str());
    kwin->text.push_back(output);

    if (details_network->networks.size() > 1) {
        snprintf(output, print_width, "Networks: %d", details_network->networks.size());
        kwin->text.push_back(output);
    }

    for (unsigned int x = 0; x < details_network->networks.size(); x++) {
        wireless_network *dnet = details_network->networks[x];

        if (details_network->networks.size() > 1) {
            if (x != 0) {
                snprintf(output, print_width, " ");
                kwin->text.push_back(output);
            }
            snprintf(output, print_width, "Network %d", x+1);
            kwin->text.push_back(output);
        }

        // Convert the current details network into a vector of strings, so that
        // we can scroll it
        snprintf(output, print_width, "SSID    : %s", dnet->ssid.c_str());
        kwin->text.push_back(output);
    
        if (dnet->cloaked) {
            snprintf(output, print_width, "          SSID Cloaking on/Closed Network");
            kwin->text.push_back(output);
        }

        snprintf(output, print_width, "Manuf   : %s",
                 dnet->manuf_id >= 0 ? manuf_list[dnet->manuf_id].name.c_str() :
                 "Unknown");
        kwin->text.push_back(output);

        if (dnet->manuf_score == manuf_max_score) {
            snprintf(output, print_width, "     FACTORY CONFIGURATION");
            kwin->text.push_back(output);
        }

        snprintf(output, print_width, "BSSID   : %s", dnet->bssid.c_str());
        kwin->text.push_back(output);
    
        snprintf(output, print_width, "Max Rate: %2.1f", dnet->maxrate);
        kwin->text.push_back(output);
    
        snprintf(output, print_width, "First   : %.24s", ctime((const time_t *) &dnet->first_time));
        kwin->text.push_back(output);
    
        snprintf(output, print_width, "Latest  : %.24s", ctime((const time_t *) &dnet->last_time));
        kwin->text.push_back(output);
    
        switch (dnet->type) {
        case network_ap:
            snprintf(output, print_width, "Type    : Access Point (infrastructure)");
            break;
        case network_adhoc:
            snprintf(output, print_width, "Type    : Ad-hoc");
            break;
        case network_probe:
            snprintf(output, print_width, "Type    : Probe request (searching client)");
            break;
        case network_data:
            snprintf(output, print_width, "Type    : Data (no network control traffic)");
            break;
        case network_remove:
            break;
        }
        kwin->text.push_back(output);
    
        if (dnet->beacon_info.size() > 0) {
            snprintf(output, print_width, "Info    : %s", dnet->beacon_info.c_str());
            kwin->text.push_back(output);
        }
    
        snprintf(output, print_width, "Channel : %d", dnet->channel);
        kwin->text.push_back(output);
        snprintf(output, print_width, "WEP     : %s", dnet->wep ? "Yes" : "No");
        kwin->text.push_back(output);
    
        snprintf(output, print_width, "Beacon  : %d (%f sec)", dnet->beacon,
                 (float) dnet->beacon * 1024 / 1000000);
        kwin->text.push_back(output);
    
        snprintf(output, print_width, "Packets : %d",
                 dnet->data_packets +
                 dnet->llc_packets +
                 dnet->crypt_packets);
        kwin->text.push_back(output);
        snprintf(output, print_width, "  Data    : %d", dnet->data_packets);
        kwin->text.push_back(output);
        snprintf(output, print_width, "  LLC     : %d", dnet->llc_packets);
        kwin->text.push_back(output);
        snprintf(output, print_width, "  Crypt   : %d", dnet->crypt_packets);
        kwin->text.push_back(output);
        snprintf(output, print_width, "  Weak    : %d", dnet->interesting_packets);
        kwin->text.push_back(output);
    
        switch (dnet->ipdata.atype) {
        case address_none:
            snprintf(output, print_width, "IP Type : None detected");
            break;
        case address_factory:
            snprintf(output, print_width, "IP Type : Factory default");
            break;
        case address_udp:
            snprintf(output, print_width, "IP Type : UDP (%d octets)", dnet->ipdata.octets);
            break;
        case address_tcp:
            snprintf(output, print_width, "IP Type : TCP (%d octets)", dnet->ipdata.octets);
            break;
        case address_arp:
            snprintf(output, print_width, "IP Type : ARP (%d octets)", dnet->ipdata.octets);
            break;
        case address_dhcp:
            snprintf(output, print_width, "IP Type : DHCP");
            break;
        case address_group:
            snprintf(output, print_width, "IP Type : Group (aggregate)");
            break;
        }
        kwin->text.push_back(output);
    
        if (dnet->ipdata.atype != address_none) {
            snprintf(output, print_width, "IP Range: %d.%d.%d.%d",
                     dnet->ipdata.range_ip[0], dnet->ipdata.range_ip[1],
                     dnet->ipdata.range_ip[2], dnet->ipdata.range_ip[3]);
            kwin->text.push_back(output);
    
            if (dnet->ipdata.atype == address_dhcp || dnet->ipdata.atype == address_factory) {
                snprintf(output, print_width, "Netmask : %d.%d.%d.%d",
                         dnet->ipdata.mask[0], dnet->ipdata.mask[1],
                         dnet->ipdata.mask[2], dnet->ipdata.mask[3]);
                kwin->text.push_back(output);
    
                snprintf(output, print_width, "Gateway : %d.%d.%d.%d",
                        dnet->ipdata.gate_ip[0], dnet->ipdata.gate_ip[1],
                        dnet->ipdata.gate_ip[2], dnet->ipdata.gate_ip[3]);
                kwin->text.push_back(output);
            }
    
        }
    
        if (dnet->gps_fixed != -1) {
            snprintf(output, print_width, "Min Loc : Lat %f Lon %f Alt %f Spd %f",
                     dnet->min_lat, dnet->min_lon,
                     dnet->min_alt, dnet->min_spd);
            kwin->text.push_back(output);
            snprintf(output, print_width, "Max Loc : Lat %f Lon %f Alt %f Spd %f",
                     dnet->max_lat, dnet->max_lon,
                     dnet->max_alt, dnet->max_spd);
            kwin->text.push_back(output);

            double diagdist = EarthDistance(dnet->min_lat, dnet->min_lon,
                                            dnet->max_lat, dnet->max_lon);

            if (metric) {
                if (diagdist < 1000)
                    snprintf(output, print_width, "Range   : %f meters", diagdist);
                else
                    snprintf(output, print_width, "Range   : %f kilometers", diagdist / 1000);
            } else {
                diagdist *= 3.3;
                if (diagdist < 5280)
                    snprintf(output, print_width, "Range   : %f feet", diagdist);
                else
                    snprintf(output, print_width, "Range   : %f miles", diagdist / 5280);
            }
            kwin->text.push_back(output);
        }
    }

    // Now we just use the text printer to handle the rest for us

    return TextPrinter(in_window);
}

int PanelFront::PackPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    if (client->GetMaxPackInfos() != (kwin->max_display / 4) * (kwin->print_width - 1))
        client->SetMaxPackInfos((kwin->max_display / 4) * (kwin->print_width - 1));

    if (kwin->paused != 0) {
        mvwaddstr(kwin->win, 0, kwin->win->_maxx - 10, "Paused");

        return TextPrinter(in_window);
    }

    vector<packet_info> packinfo = client->FetchPackInfos();

    // Print the single-character lines
    int singles = 0;
    kwin->text.clear();
    string data;
    for (unsigned int x = 0; x < packinfo.size(); x++) {
        switch(packinfo[x].type) {
        case packet_beacon:
            data += "B";
            break;
        case packet_probe_req:
            data += "r";
            break;
        case packet_data:
        case packet_ap_broadcast:
            if (packinfo[x].encrypted && !packinfo[x].interesting)
                data += "e";
            else if (packinfo[x].interesting)
                data += "w";
            else
                data += "d";
            break;
        case packet_adhoc:
        case packet_adhoc_data:
            data += "a";
            break;
        case packet_probe_response:
            data += "R";
            break;
        case packet_noise:
            data += "n";
            break;
        case packet_reassociation:
            data += "A";
            break;
        default:
            data += "?";
            break;
        }

        if ((x+1) % (kwin->print_width - 1) == 0) {
            kwin->text.push_back(data);
            data.erase();
            singles++;
        }
    }

    do {
        kwin->text.push_back(data);
        data.erase();
        singles++;
    } while (singles <= kwin->max_display / 4);

    unsigned int start = 0;
    if ((unsigned int) (kwin->max_display + (kwin->max_display / 4)) < packinfo.size())
        start = packinfo.size() - kwin->max_display + (kwin->max_display / 4);

    char cdata[1024];
    char *dtype = "";
    char dsubtype[1024], srcport[12], dstport[12];
    struct servent *srcserv, *dstserv;
    for (unsigned int x = start; x < packinfo.size(); x++) {
        snprintf(cdata, 1024, "%.8s - Packet", ctime(&packinfo[x].time)+11);
        switch(packinfo[x].type) {
        case packet_beacon:
            snprintf(cdata, 1024, "%.8s %s BEACON '%s'",
                     ctime(&packinfo[x].time) + 11,
                     Mac2String(packinfo[x].bssid_mac, ':').c_str(),
                     packinfo[x].ssid);
            break;
        case packet_probe_req:
            snprintf(cdata, 1024, "%.8s %s PROBE-REQ '%s'",
                     ctime(&packinfo[x].time) + 11,
                     Mac2String(packinfo[x].source_mac, ':').c_str(),
                     packinfo[x].ssid);
            break;
        case packet_data:
        case packet_ap_broadcast:
        case packet_adhoc_data:
            dsubtype[0] = '\0';

            if (packinfo[x].encrypted && !packinfo[x].interesting) {
                dtype = "ENCRYPTED DATA";
            } else if (packinfo[x].interesting) {
                dtype = "ENCRYPTED DATA (WEAK)";
            } else {
                dtype = "DATA";
                switch (packinfo[x].proto.type) {
                case proto_netbios:
                case proto_netbios_tcp:
                    dtype = "NETBIOS";
                    switch (packinfo[x].proto.nbtype) {
                    case proto_netbios_host:
                        snprintf(dsubtype, 1024, "HOST '%s'",
                                 packinfo[x].proto.netbios_source);
                        break;
                    case proto_netbios_master:
                        snprintf(dsubtype, 1024, "MASTER '%s'",
                                  packinfo[x].proto.netbios_source);
                        break;
                    case proto_netbios_domain:
                        snprintf(dsubtype, 1024, "DOMAIN '%s'",
                                 packinfo[x].proto.netbios_source);
                        break;
                    case proto_netbios_query:
                        snprintf(dsubtype, 1024, "QUERY '%s'",
                                 packinfo[x].proto.netbios_source);
                        break;
                    case proto_netbios_pdcquery:
                        snprintf(dsubtype, 1024, "PDC QUERY");
                        break;
                    default:
                        break;
                    }
                    break;
                case proto_udp:
                case proto_dhcp_server:
                    srcserv = getservbyport(htons(packinfo[x].proto.sport), "udp");
                    dstserv = getservbyport(htons(packinfo[x].proto.dport), "udp");
                    sprintf(srcport, "%d", packinfo[x].proto.sport);
                    sprintf(dstport, "%d", packinfo[x].proto.dport);

                    snprintf(dsubtype, 1024, "UDP %d.%d.%d.%d:%s->%d.%d.%d.%d:%s",
                             packinfo[x].proto.source_ip[0], packinfo[x].proto.source_ip[1],
                             packinfo[x].proto.source_ip[2], packinfo[x].proto.source_ip[3],
                             srcserv ? srcserv->s_name : srcport,
                             packinfo[x].proto.dest_ip[0], packinfo[x].proto.dest_ip[1],
                             packinfo[x].proto.dest_ip[2], packinfo[x].proto.dest_ip[3],
                             dstserv ? dstserv->s_name : dstport);
                    break;
                case proto_misc_tcp:
                    srcserv = getservbyport(htons(packinfo[x].proto.sport), "tcp");
                    dstserv = getservbyport(htons(packinfo[x].proto.dport), "tcp");
                    sprintf(srcport, "%d", packinfo[x].proto.sport);
                    sprintf(dstport, "%d", packinfo[x].proto.dport);
                    snprintf(dsubtype, 1024, "TCP %d.%d.%d.%d:%s->%d.%d.%d.%d:%s",
                             packinfo[x].proto.source_ip[0], packinfo[x].proto.source_ip[1],
                             packinfo[x].proto.source_ip[2], packinfo[x].proto.source_ip[3],
                             srcserv ? srcserv->s_name : srcport,
                             packinfo[x].proto.dest_ip[0], packinfo[x].proto.dest_ip[1],
                             packinfo[x].proto.dest_ip[2], packinfo[x].proto.dest_ip[3],
                             dstserv ? dstserv->s_name : dstport);
                    break;
                case proto_arp:
                    snprintf(dsubtype, 1024, "ARP %d.%d.%d.%d->%d.%d.%d.%d",
                             packinfo[x].proto.source_ip[0], packinfo[x].proto.source_ip[1],
                             packinfo[x].proto.source_ip[2], packinfo[x].proto.source_ip[3],
                             packinfo[x].proto.dest_ip[0], packinfo[x].proto.dest_ip[1],
                             packinfo[x].proto.dest_ip[2], packinfo[x].proto.dest_ip[3]);
                    break;
                case proto_ipx_tcp:
                    snprintf(dsubtype, 1024, "IPX");
                    break;
                default:
                    break;
                }
            }

            snprintf(cdata, 1024, "%.8s %s %s %s",
                     ctime(&packinfo[x].time) + 11,
                     Mac2String(packinfo[x].bssid_mac, ':').c_str(),
                     dtype, dsubtype);
            break;
        case packet_adhoc:
            snprintf(cdata, 1024, "%.8s %s ADHOC '%s'",
                     ctime(&packinfo[x].time) + 11,
                     Mac2String(packinfo[x].bssid_mac, ':').c_str(),
                     packinfo[x].ssid);
            break;
        case packet_probe_response:
            snprintf(cdata, 1024, "%.8s %s PROBE RESPONSE '%s'",
                     ctime(&packinfo[x].time) + 11,
                     Mac2String(packinfo[x].bssid_mac, ':').c_str(),
                     packinfo[x].ssid);
            break;
        case packet_noise:
            snprintf(cdata, 1024, "%.8s %s NOISE",
                     ctime(&packinfo[x].time) + 11,
                     Mac2String(packinfo[x].bssid_mac, ':').c_str());
            break;
        case packet_reassociation:
            snprintf(cdata, 1024, "%.8s %s REASSOCIATION '%s'",
                     ctime(&packinfo[x].time) + 11,
                     Mac2String(packinfo[x].bssid_mac, ':').c_str(),
                     packinfo[x].ssid);
            break;
        default:
            snprintf(cdata, 1024, "%.8s %s UNKNOWN",
                     ctime(&packinfo[x].time) + 11,
                     Mac2String(packinfo[x].bssid_mac, ':').c_str());
            break;
        }

        kwin->text.push_back(cdata);
    }

    return TextPrinter(in_window);
}

int PanelFront::DumpPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    if (client->GetMaxStrings() != kwin->max_display)
        client->SetMaxStrings(kwin->max_display);

    if (clear_dump) {
        client->ClearStrings();
        kwin->text.clear();
        clear_dump = 0;
    } else if (!kwin->paused) {
        kwin->text = client->FetchStrings();
    }

    /*
    if (kwin->text.size() > (unsigned) kwin->max_display)
        kwin->text.erase(kwin->text.begin(), kwin->text.begin() +
        (kwin->text.size() - kwin->max_display));
        */

    if (kwin->paused != 0) {
        mvwaddstr(kwin->win, 0, kwin->win->_maxx - 10, "Paused");
    }

    return TextPrinter(in_window);
}

// We're special -- because we capture an entire string of user input, we have to
// do this ourselves, and we don't give control back until we get it.
int PanelFront::GroupNamePrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    char gname[26];
    int print_width = kwin->print_width;

    if (print_width > 25)
        print_width = 25;

    mvwaddstr(kwin->win, 1, 2, "Group name:");

    // The text field is reversed
    wattron(kwin->win, WA_REVERSE);

    memset(gname, ' ', print_width);
    gname[print_width] = '\0';

    mvwaddstr(kwin->win, 2, 2, gname);

    wattroff(kwin->win, WA_REVERSE);

    if (details_network->name == "")
        snprintf(gname, print_width - 9, "%s", details_network->virtnet.ssid.c_str());
    else
        snprintf(gname, print_width - 9, "%s", details_network->name.c_str());
    mvwaddstr(kwin->win, 3, 2, "Default: ");
    mvwaddstr(kwin->win, 3, 11, gname);

    echo();
    nocbreak();
    nodelay(kwin->win, 0);

    wattron(kwin->win, WA_REVERSE);
    mvwgetnstr(kwin->win, 2, 2, gname, print_width-1);
    wattroff(kwin->win, WA_REVERSE);

    noecho();
    cbreak();

    // Return 0 to tell them to kill the popup
    if (strlen(gname) == 0)
        return 0;

    details_network->name = gname;
    group_name_map[details_network->tag] = gname;

    return 0;
}

int PanelFront::StatsPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    vector<string> details_text;
    char output[1024];

    const int print_width = kwin->print_width;

    snprintf(output, print_width, "Start   : %s", ctime((const time_t *) &start_time));
    details_text.push_back(output);

    snprintf(output, print_width, "Networks: %d", client->FetchNumNetworks());
    details_text.push_back(output);

    vector<wireless_network *> netlist = client->FetchNetworkList();

    int wep_count = 0, vuln_count = 0;
    int channelperc[CHANNEL_MAX];
    int maxch = 0;

    memset(channelperc, 0, sizeof(int) * CHANNEL_MAX);

    // Summarize the network data
    for (unsigned int x = 0; x < netlist.size(); x++) {
        if (netlist[x]->channel > 0 && netlist[x]->channel < CHANNEL_MAX) {
            int perc = ++channelperc[netlist[x]->channel - 1];
            if (perc > maxch)
                maxch = perc;
        }

        if (netlist[x]->wep)
            wep_count++;
        if (netlist[x]->manuf_score == manuf_max_score)
            vuln_count++;
    }

    snprintf(output, print_width, " Encrypted: %d (%d%%)", wep_count,
             client->FetchNumNetworks() > 0 ?
             (int) (((double) wep_count / client->FetchNumNetworks()) * 100) : 0);
    details_text.push_back(output);

    snprintf(output, print_width, " Default  : %d (%d%%)", vuln_count,
             client->FetchNumNetworks() > 0 ?
             (int) (((double) vuln_count / client->FetchNumNetworks()) * 100) : 0);
    details_text.push_back(output);

    snprintf(output, print_width, "Max. Packet Rate: %d packets/sec",
             max_packet_rate);
    details_text.push_back(output);

    snprintf(output, print_width, "Channel Usage:");
    details_text.push_back(output);
    
    unsigned int graph_height = 7;
    char line[1024];


    // Make a nice graph if we have room
    if (print_width >= 48) {
        snprintf(output, print_width, "  ---------------------------  -----------------------------");
        details_text.push_back(output);

        unsigned int vdraw = 1;
        for (unsigned int x = 0; x < graph_height; x++) {
            memset(line, '\0', print_width);
            line[0] = line[1] = ' ';
            unsigned int draw = 2;

            for (unsigned int y = 0; y < CHANNEL_MAX; y++) {
                if ((((double) channelperc[y] / maxch) * graph_height) >= (graph_height - x))
                    line[draw] = 'X';
                else
                    line[draw] = ' ';

                line[draw+1] = ' ';
                draw += 2;
            }

            snprintf(output, print_width, "%s %02d: %3d (%02d%%) | %02d: %3d (%02d%%)",
                     line, vdraw, channelperc[vdraw-1],
                     client->FetchNumNetworks() > 0 ?
                     (int) (((double) channelperc[vdraw-1] / client->FetchNumNetworks()) * 100) : 0,
                     vdraw+1, channelperc[vdraw],
                     client->FetchNumNetworks() > 0 ?
                     (int) (((double) channelperc[vdraw] / client->FetchNumNetworks()) * 100) : 0);
            vdraw += 2;
            details_text.push_back(output);
        }

        snprintf(output, print_width, "  ---------------------------  -----------------------------");
        details_text.push_back(output);
        snprintf(output, print_width, "  1 2 3 4 5 6 7 8 9 1 1 1 1 1");
        details_text.push_back(output);
        snprintf(output, print_width, "                    0 1 2 3 4");
        details_text.push_back(output);
    } else {
        output[0] = '\0';

        unsigned int netchunk = (unsigned int) ceil((double) print_width / 13);
        if (netchunk > 4)
            netchunk = 4;

        for (unsigned int x = 0; x < CHANNEL_MAX; x++) {
            snprintf(line, print_width, "%s %02d: %3d (%2d%%)",
                     output, x+1, channelperc[x],
                     client->FetchNumNetworks() > 0 ?
                     (int) (((double) channelperc[x] / client->FetchNumNetworks()) * 100) : 0);
            strncpy(output, line, 1024);

            if ((x+1) % netchunk == 0) {
                details_text.push_back(output);
                output[0] = '\0';
            }
        }
        if (strlen(output) > 0)
            details_text.push_back(output);
    }

    kwin->text = details_text;

    // Print out the text with the normal text printer
    return TextPrinter(in_window);
}

int PanelFront::RatePrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    // -Packet History---------------|
    // | Pkts                        |
    // | 1000|XX                     |
    // |     |XXX                 X  |
    // |     |XXX  X              X  |
    // |  500|XXX  X         X    X  |
    // |     |XXX  X         X    X  |
    // |     |XXX  X         X    X  |
    // |    0|XXX  X         X    XX |
    // |     ----------------------- |
    // |      5         2.5        0 |
    // |      Time                   |
    // -------------------------------


    // Tentative width
    unsigned int graph_width = kwin->print_width - 4;
    unsigned int graph_height = kwin->max_display - 4;
    const int unsigned graph_hoffset = 7;
    const int unsigned graph_voffset = 2;

    // Divide it into chunks and average the delta's
    unsigned int chunksize = (unsigned int) ceil((double) packet_history.size() / graph_width);

    // Now resize the graph to fit our sample data cleanly
    graph_width = packet_history.size() / chunksize;

    // Don't bother if we're too small
    if (graph_width <= 20 || graph_height <= 5) {
        return 0;
    }

    vector<unsigned int> averaged_history;
    unsigned int avg_max = 0;

    unsigned int chunk = 0;
    unsigned int chunkcount = 0;
    for (unsigned int x = 1; x < packet_history.size(); x++) {
        if (packet_history[x-1] != 0) {
            unsigned int delta = packet_history[x] - packet_history[x-1];

            if (delta > chunk)
                chunk = delta;
        }
        chunkcount++;

        if (chunkcount >= chunksize || x == packet_history.size() - 1) {
            averaged_history.push_back(chunk);

            if (avg_max < chunk)
                avg_max = chunk;

            chunk = 0;
            chunkcount = 0;
        }
    }

    // convert averaged_history to percentages of height
    for (unsigned int x = 0; x < averaged_history.size(); x++) {
        double perc = (double) averaged_history[x]/avg_max;

        averaged_history[x] = (int) (graph_height * perc);
    }

    // Scan across each row of the graph and draw the columns where needed
    char *graphstring = new char[graph_width+1];

    if (avg_max != 0)
        for (unsigned int x = 0; x < graph_height; x++) {
            memset(graphstring, '\0', graph_width+1);

            for (unsigned int y = 0; y < averaged_history.size() && y < graph_width; y++) {
                if (averaged_history[y] >= (graph_height - x))
                    graphstring[y] = 'X';
                else
                    graphstring[y] = ' ';
            }

            mvwaddstr(kwin->win, graph_voffset+x, graph_hoffset-1, "|");
            mvwaddstr(kwin->win, graph_voffset+x, graph_hoffset, graphstring);
        }

    // Print the framework around the graph
    mvwaddstr(kwin->win, 1, 2, "Pkts");
    snprintf(graphstring, 5, "%4d", avg_max);
    mvwaddstr(kwin->win, graph_voffset, 2, graphstring);
    snprintf(graphstring, 5, "%4d", avg_max/2);
    mvwaddstr(kwin->win, graph_voffset+(graph_height/2), 2, graphstring);
    mvwaddstr(kwin->win, graph_voffset+graph_height, 2, "   0");
    memset(graphstring, '-', graph_width);
    mvwaddstr(kwin->win, graph_voffset+graph_height, graph_hoffset, graphstring);
    mvwaddstr(kwin->win, graph_voffset+graph_height+1, graph_hoffset, "-5");
    mvwaddstr(kwin->win, graph_voffset+graph_height+1,
              graph_hoffset+(graph_width/2)-2, "-2.5");
    mvwaddstr(kwin->win, graph_voffset+graph_height+1,
              graph_hoffset+graph_width-1, "0");
    mvwaddstr(kwin->win, graph_voffset+graph_height+2,
              graph_hoffset+(graph_width/2)-7, "Time (Minutes)");

    delete graphstring;

    return 1;
}


int PanelFront::MainInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;
    char sendbuf[1024];

    switch (in_chr) {
    case 'Q':
        return FE_QUIT;
        break;
    case 'q':
        WriteStatus("Use capital-Q to quit Kismet.");
        break;
    case KEY_UP:
        if (sortby != sort_auto) {
            if (kwin->selected == 0 && kwin->start != 0) {
                kwin->start--;
            } else if (kwin->selected > 0) {
                kwin->selected--;
            }
        } else {
            WriteStatus("Cannot scroll in autofit sort mode.");
        }

        break;
    case KEY_DOWN:
        if (sortby != sort_auto) {
            if (kwin->start + kwin->selected < last_draw_size - 1) {
                if ((kwin->start + kwin->selected >= kwin->end) &&
                    (kwin->start + kwin->selected + 1 < last_draw_size))
                    kwin->start++;
                else
                    kwin->selected++;
            }

        } else {
            WriteStatus("Cannot scroll in autofit sort mode.");
        }
        break;
    case KEY_RIGHT:
    case '+':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            if (last_displayed[kwin->selected]->type == group_bundle)
                last_displayed[kwin->selected]->expanded = 1;
        } else {
            WriteStatus("Cannot expand groups in autofit sort mode.");
        }
        break;
    case KEY_LEFT:
    case '-':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            if (last_displayed[kwin->selected]->type == group_bundle)
                last_displayed[kwin->selected]->expanded = 0;
        } else {
            WriteStatus("Cannot collapse groups in autofit sort mode.");
        }
        break;
    case 'i':
    case 'I':
    case KEY_ENTER:
        if (sortby != sort_auto &&  last_displayed.size() > 0) {
            details_network = last_displayed[kwin->selected];
            SpawnWindow("Network Details",
                        &PanelFront::DetailsPrinter, &PanelFront::DetailsInput);
        } else {
            WriteStatus("Cannot view details in autofit sort mode.");
        }
        break;
    case 't':
    case 'T':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            if (last_displayed[kwin->selected]->tagged)
                last_displayed[kwin->selected]->tagged = 0;
            else
                last_displayed[kwin->selected]->tagged = 1;
        } else {
            WriteStatus("Cannot tag networks in autofit sort mode.");
        }
        break;
    case 'n':
    case 'N':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            details_network = last_displayed[kwin->selected];
            SpawnWindow("Group Name", &PanelFront::GroupNamePrinter, NULL, 3, 30);
        } else {
            WriteStatus("Cannot name groups in autofit sort mode.");
        }
        break;
    case 'g':
    case 'G':
        if (sortby != sort_auto &&  last_displayed.size() > 0) {
            details_network = GroupTagged();
            if (details_network != NULL)
                SpawnWindow("Group Name", &PanelFront::GroupNamePrinter, NULL, 3, 30);
        } else {
            WriteStatus("Cannot create groups in autofit sort mode.");
        }
        break;
    case 'u':
    case 'U':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            if (last_displayed[kwin->selected] != NULL)
                DestroyGroup(last_displayed[kwin->selected]);
        } else {
            WriteStatus("Cannot ungroup in autofit sort mode.");
        }
        break;
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpText);
        //SpawnPopup("Kismet Help", &PanelFront::PrintKismetHelp, HELP_SIZE);
        break;
    case 'z':
    case 'Z':
        ZoomNetworks();
        break;
    case 's':
    case 'S':
        SpawnWindow("Sort Network", &PanelFront::SortPrinter, &PanelFront::SortInput, SORT_SIZE);
        break;
    case 'l':
    case 'L':
        SpawnWindow("Wireless Card Power", &PanelFront::PowerPrinter, &PanelFront::PowerInput, 3);
        break;
    case 'd':
    case 'D':
        snprintf(sendbuf, 1024, "!%u strings \n", (unsigned int) time(0));
        client->Send(sendbuf);
        WriteStatus("Requesting strings from the server");

        SpawnWindow("Data Strings Dump", &PanelFront::DumpPrinter, &PanelFront::DumpInput);
        break;
    case 'r':
    case 'R':
        SpawnWindow("Packet Rate", &PanelFront::RatePrinter, &PanelFront::RateInput);
        break;
    case 'a':
    case 'A':
        SpawnWindow("Statistics", &PanelFront::StatsPrinter, &PanelFront::StatsInput, 18, 65);
        break;
    case 'p':
    case 'P':
        snprintf(sendbuf, 1024, "!%u packtypes \n", (unsigned int) time(0));
        client->Send(sendbuf);
        WriteStatus("Requesting packet types from the server");

        SpawnWindow("Packet Types", &PanelFront::PackPrinter, &PanelFront::PackInput);
        break;
    case 'm':
    case 'M':
        MuteToggle();
        break;
    }

    return 1;
}

int PanelFront::SortInput(void *in_window, int in_chr) {
    switch (in_chr) {
    case 'a':
    case 'A':
        sortby = sort_auto;
        WriteStatus("Autofitting network display");
        break;
    case 'c':
    case 'C':
        sortby = sort_channel;
        WriteStatus("Sorting by channel");
        break;
    case 'f':
        sortby = sort_first;
        WriteStatus("Sorting by time first detected");
        break;
    case 'F':
        sortby = sort_first_dec;
        WriteStatus("Sorting by time first detected (descending)");
        break;
    case 'l':
        sortby = sort_last;
        WriteStatus("Sorting by time most recently active");
        break;
    case 'L':
        sortby = sort_last_dec;
        WriteStatus("Sorting by time most recently active (descending)");
        break;
    case 'b':
        sortby = sort_bssid;
        WriteStatus("Sorting by BSSID");
        break;
    case 'B':
        sortby = sort_bssid_dec;
        WriteStatus("Sorting by BSSID (descending)");
        break;
    case 's':
        sortby = sort_ssid;
        WriteStatus("Sorting by SSID");
        break;
    case 'S':
        sortby = sort_ssid_dec;
        WriteStatus("Sorting by SSID (descending)");
        break;
    case 'w':
    case 'W':
        sortby = sort_wep;
        WriteStatus("Sorting by WEP");
        break;
    case 'p':
        sortby = sort_packets;
        WriteStatus("Sorting by packet counts.");
        break;
    case 'P':
        sortby = sort_packets_dec;
        WriteStatus("Sorting by packet counts (descending)");
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        break;
    default:
        beep();
        return 1;
        break;
    }

    // We don't have anything that doesn't kill the window for the key event
    return 0;
}

int PanelFront::PackInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;
    char sendbuf[1024];

    switch(in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpPack);
        break;

    case 'p':
    case 'P':
        if (kwin->paused)
            kwin->paused = 0;
        else
            kwin->paused = 1;
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        snprintf(sendbuf, 1024, "!%u nopacktypes\n", (unsigned int) time(0));
        client->Send(sendbuf);
        return 0;
        break;
    default:
        break;
    }

    return 1;

}

int PanelFront::DumpInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;
    char sendbuf[1024];

    switch(in_chr) {
    case 'm':
    case 'M':
        MuteToggle();
        break;
    case 'p':
    case 'P':
        // Ignore if we're pending a clear
        if (clear_dump == 1)
            break;

        if (kwin->paused)
            kwin->paused = 0;
        else
            kwin->paused = 1;
        break;

    case 'c':
    case 'C':
        if (!kwin->paused)
            clear_dump = 1;
        break;
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpDump);
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        snprintf(sendbuf, 1024, "!%u nostrings \n", (unsigned int) time(0));
        client->Send(sendbuf);
        return 0;
        break;
    default:
        break;
    }

    return 1;
}

// We don't do anything special here except spawn a help and pass it on to the
// text input handler.  Details is just a slightly special text window.
int PanelFront::DetailsInput(void *in_window, int in_chr) {
    int ret;
    switch (in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpDetails);
        break;
    case 'n':
        // Nasty hack but it works
        ret = (this->*net_win->input)(net_win, KEY_DOWN);
        details_network = last_displayed[net_win->selected];
        return ret;
        break;
    case 'p':
        ret = (this->*net_win->input)(net_win, KEY_UP);
        details_network = last_displayed[net_win->selected];
        return ret;
        break;
    default:
        return TextInput(in_window, in_chr);
        break;
    }

    return 1;
}

int PanelFront::PowerInput(void *in_window, int in_chr) {
    switch (in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpPower);
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        return 0;
        break;
    }

    return 1;
}

int PanelFront::RateInput(void *in_window, int in_chr) {
    switch (in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpRate);
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        return 0;
        break;
    }

    return 1;
}

int PanelFront::StatsInput(void *in_window, int in_chr) {
    switch (in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpStats);
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        return 0;
        break;
    }

    return 1;
}

int PanelFront::TextInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;

    switch (in_chr) {
    case KEY_UP:
    case '-':
        if (kwin->start != 0) {
            kwin->start--;
        }
        break;
    case KEY_DOWN:
    case '+':
        if (kwin->end < (int) kwin->text.size() - 1 && kwin->end != 0) {
            kwin->start++;
        }
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        return 0;
        break;
    default:
        return 1;
        break;
    }

    return 1;
}

int PanelFront::Tick() {
    // We should be getting a 1-second tick - secondary to a draw event, because
    // we can cause our own draw events which wouldn't necessarily be a good thing

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
        FILE *apm;
#ifdef SYS_LINUX
        // Lifted from gkrellm's battery monitor
        char buf[128];

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
#endif
    }

    return 1;
}

void PanelFront::MuteToggle() {
    if (muted) {
        speech = old_speech;
        sound = old_sound;
        muted = 0;
        WriteStatus("Restoring sound");
    } else if (sound != 0 || speech != 0) {
        old_speech = speech;
        old_sound = sound;
        sound = 0;
        speech = 0;
        muted = 1;
        WriteStatus("Muting sound");
    } else if (sound == 0 && speech == 0) {
        WriteStatus("Sound not enabled.");
    }
}

void PanelFront::AddPrefs(map<string, string> in_prefs) {
    prefs = in_prefs;

    SetColumns(prefs["columns"]);

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
    string color = in_color;
    color_pair ret;

    // First, find if theres a hi-
    if (color.substr(0, 3) == "hi-") {
        ret.bold = 1;
        color = color.substr(3, color.length() - 3);
    }

    // Then match all the colors
    if (color == "black")
        ret.index = COLOR_BLACK;
    else if (color == "red")
        ret.index = COLOR_RED;
    else if (color == "green")
        ret.index = COLOR_GREEN;
    else if (color == "yellow")
        ret.index = COLOR_YELLOW;
    else if (color == "blue")
        ret.index = COLOR_BLUE;
    else if (color == "magenta")
        ret.index = COLOR_MAGENTA;
    else if (color == "cyan")
        ret.index = COLOR_CYAN;
    else if (color == "white")
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
