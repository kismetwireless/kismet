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

// This argument list is getting increasingly nasty, hopefully I'll be able to
// come back and clean all this up
void PanelFront::NetLine(string *in_str, wireless_network *net, const char *name, int sub,
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

    time_t idle_time;
    if (sub && net->tcpclient != NULL) {
        if (net->tcpclient->Valid())
            idle_time = net->tcpclient->FetchTime() - net->last_time;
        else
            idle_time = decay + 1;
    } else {
        idle_time = net->idle_time;
    }

    int pos = 2;
    for (unsigned int col = 0; col < column_vec.size(); col++) {
        char element[1024];
        int len = 0;
        main_columns colindex = column_vec[col];

        if (colindex == mcol_decay) {
            if (idle_time < decay)
                snprintf(element, 1024, "!");
            else if (idle_time < (decay * 2))
                snprintf(element, 1024, ".");
            else
                snprintf(element, 1024, " ");
            len = 1;
        } else if (colindex == mcol_name) {
            if (net->cloaked) {
                snprintf(element, 26, "<%s>", name);
            } else {
                snprintf(element, 26, "%s", name);
            }
            len = 25;
        } else if (colindex == mcol_shortname) {
            if (net->cloaked) {
                snprintf(element, 16, "<%s>", name);
            } else {
                snprintf(element, 16, "%s", name);
            }
            len = 15;
        } else if (colindex == mcol_ssid) {
            if (net->cloaked) {
                snprintf(element, 26, "<%s>", net->ssid.c_str());
            } else {
                snprintf(element, 26, "%s", net->ssid.c_str());
            }
            len = 25;
        } else if (colindex == mcol_shortssid) {
            if (net->cloaked) {
                snprintf(element, 16, "<%s>", net->ssid.c_str());
            } else {
                snprintf(element, 16, "%s", net->ssid.c_str());
            }
            len = 15;
        } else if (colindex == mcol_type) {
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
            else if (net->type == network_turbocell)
                snprintf(element, 1024, "T");
            else
                snprintf(element, 1024, "?");

            len = 1;
        } else if (colindex == mcol_wep) {
            if (net->wep)
                snprintf(element, 1024, "Y");
            else
                snprintf(element, 1024, "N");
            len = 1;
        } else if (colindex == mcol_channel) {
            if (net->channel == 0)
                snprintf(element, 3, "--");
            else
                snprintf(element, 3, "%02d", net->channel);
            len = 2;
        } else if (colindex == mcol_data) {
            snprintf(element, 6, "%5d", net->data_packets);
            len = 5;
        } else if (colindex == mcol_llc) {
            snprintf(element, 6, "%5d", net->llc_packets);
            len = 5;
        } else if (colindex == mcol_crypt) {
            snprintf(element, 6, "%5d", net->crypt_packets);
            len = 5;
        } else if (colindex == mcol_weak) {
            snprintf(element, 6, "%5d", net->interesting_packets);
            len = 5;
        } else if (colindex == mcol_packets) {
            snprintf(element, 7, "%6d", net->data_packets + net->llc_packets);
            len = 6;
        } else if (colindex == mcol_bssid) {
            snprintf(element, 18, "%s", net->bssid.Mac2String().c_str());
            len = 17;
        } else if (colindex == mcol_info) {
            snprintf(element, 16, "%s", net->beacon_info.c_str());
            len = 15;
        } else if (colindex == mcol_flags) {
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
        } else if (colindex == mcol_ip) {
            if (net->ipdata.atype == address_none) {
                snprintf(element, 1024, "0.0.0.0");
            } else {
                snprintf(element, 16, "%d.%d.%d.%d",
                         net->ipdata.range_ip[0], net->ipdata.range_ip[1],
                         net->ipdata.range_ip[2], net->ipdata.range_ip[3]);
            }
            len = 15;
        } else if (colindex == mcol_maxrate) {
            snprintf(element, 6, "%2.1f", net->maxrate);
            len = 5;
        } else if (colindex == mcol_manuf) {
            map<mac_addr, manuf *>::const_iterator mitr;
            int found = 0;

            if (net->type == network_adhoc || net->type == network_probe) {
                if ((mitr = client_manuf_map.find(net->manuf_key)) != client_manuf_map.end()) {
                    found = 1;
                }
            } else {
                if ((mitr = ap_manuf_map.find(net->manuf_key)) != ap_manuf_map.end()) {
                    found = 1;
                }
            }

            if (found)
                snprintf(element, 9, "%s", mitr->second->name.c_str());
            else
                snprintf(element, 9, "Unknown");

            len = 8;
        } else if (colindex == mcol_signal) {
            snprintf(element, 4, "%3d", (idle_time < (decay * 2)) ? net->signal : 0);
            len = 3;
        } else if (colindex == mcol_quality) {
            snprintf(element, 4, "%3d", (idle_time < (decay * 2)) ? net->quality : 0);
            len = 3;
        } else if (colindex == mcol_noise) {
            snprintf(element, 4, "%3d", (idle_time < (decay * 2)) ? net->noise : 0);
            len = 3;
        } else if (colindex == mcol_clients) {
            snprintf(element, 5, "%4d", net->client_map.size());
            len = 4;
        } else if (colindex == mcol_datasize) {
            if (net->datasize < 1024) // Less than 1k gets raw bytes
                snprintf(element, 6, "%4ldB", net->datasize);
            else if (net->datasize < 1048576) // Less than 1 meg gets mb
                snprintf(element, 6, "%4ldk", net->datasize/1024);
            else // Display in MB
                snprintf(element, 6, "%4ldM", net->datasize/1024/1024);
            len = 5;
        }

        if (pos + len > print_width)
            break;

//        fprintf(stderr, "%s ... %s\n", retchr, element);

        snprintf(tmpchr, 4096, "%*s %s", (-1) * pos, retchr, element);

        strncpy(retchr, tmpchr, 4096);

        pos += len + 1;
    }

    *in_str = retchr;
}

int PanelFront::MainNetworkPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;
    WINDOW *netwin = kwin->win;

    int drop;

    // One:  Get our new data from the clients we have tagged
    for (unsigned int x = 0; x < context_list.size(); x++) {
        if (context_list[x]->tagged == 1 && context_list[x]->client != NULL)
            PopulateGroups(context_list[x]->client);
    }
    // Two:  Recalculate all our agregate data
    UpdateGroups();
    // Three: Copy it to our own local vector so we can sort it.
    vector<display_network *> display_vector = group_vec;

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
            if (drop > (int) display_vector.size())
                drop = display_vector.size();

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
    case sort_quality:
        snprintf(sortxt, 24, "(Quality)");
        sort(display_vector.begin(), display_vector.end(), DisplaySortQuality());
        break;
    case sort_signal:
        snprintf(sortxt, 24, "(Signal)");
        sort(display_vector.begin(), display_vector.end(), DisplaySortSignal());
        break;
    }

    last_displayed.clear();

    int num = 0;
    int voffset = 2;

    // Print the headers
    int pos = 4;

    for (unsigned int col = 0; col < column_vec.size(); col++) {
        char title[1024];
        int len = 0;
        main_columns colind = column_vec[col];

        if (colind == mcol_decay) {
            snprintf(title, 1024, " ");
            len = 1;
        } else if (colind == mcol_name) {
            snprintf(title, 1024, "Name");
            len = 25;
        } else if (colind == mcol_shortname) {
            snprintf(title, 1024, "Name");
            len = 15;
        } else if (colind == mcol_ssid) {
            snprintf(title, 1024, "SSID");
            len = 25;
        } else if (colind == mcol_shortssid) {
            snprintf(title, 1024, "SSID");
            len = 15;
        } else if (colind == mcol_type) {
            snprintf(title, 1024, "T");
            len = 1;
        } else if (colind == mcol_wep) {
            snprintf(title, 1024, "W");
            len = 1;
        } else if (colind == mcol_channel) {
            snprintf(title, 1024, "Ch");
            len = 2;
        } else if (colind == mcol_data) {
            snprintf(title, 1024, " Data");
            len = 5;
        } else if (colind == mcol_llc) {
            snprintf(title, 1024, "  LLC");
            len = 5;
        } else if (colind == mcol_crypt) {
            snprintf(title, 1024, "Crypt");
            len = 5;
        } else if (colind == mcol_weak) {
            snprintf(title, 1024, " Weak");
            len = 5;
        } else if (colind == mcol_bssid) {
            snprintf(title, 1024, "BSSID");
            len = 17;
        } else if (colind == mcol_flags) {
            snprintf(title, 1024, "Flags");
            len = 5;
        } else if (colind == mcol_ip) {
            snprintf(title, 1024, "IP Range");
            len = 15;
        } else if (colind == mcol_packets) {
            snprintf(title, 1024, "Packts");
            len = 6;
        } else if (colind == mcol_info) {
            snprintf(title, 1024, "Beacon Info");
            len = 15;
        } else if (colind == mcol_maxrate) {
            snprintf(title, 1024, "Rate");
            len = 5;
        } else if (colind == mcol_manuf) {
            snprintf(title, 1024, "Manuf");
            len = 8;
        } else if (colind == mcol_signal) {
            snprintf(title, 1024, "Sgn");
            len = 3;
        } else if (colind == mcol_quality) {
            snprintf(title, 1024, "Qly");
            len = 3;
        } else if (colind == mcol_noise) {
            snprintf(title, 1024, "Nse");
            len = 3;
        } else if (colind == mcol_clients) {
            snprintf(title, 1024, "Clnt");
            len = 4;
        } else if (colind == mcol_datasize) {
            snprintf(title, 1024, " Size");
            len = 5;
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

    if (kwin->selected == -1) {
        int calcnum = 0, calclines = 0;
        for (unsigned int i = kwin->start; (i > 0) && (calclines < kwin->max_display); i--) {
            calcnum++;
            calclines++;

            if (sortby == sort_auto || display_vector[i]->type != group_bundle ||
                display_vector[i]->expanded == 0)
                continue;

            calclines += display_vector[i]->networks.size();
        }
        kwin->start -= calcnum;

    } else if (kwin->selected == -2) {
        kwin->start = kwin->end;
    }

    // Figure out if we need to reposition the selected highlight...
    int calcnum = 0, calclines = 0;
    for (unsigned int i = kwin->start; i < display_vector.size(); i++) {
        calcnum++;
        calclines++;

        if (sortby == sort_auto || display_vector[i]->type != group_bundle ||
            display_vector[i]->expanded == 0)
            continue;

        calclines += display_vector[i]->networks.size();

        if (calclines > kwin->max_display)
            break;
    }

    // Move the selected line to the end of the window if the new display we're
    // about to draw would bump it off the end
    if (kwin->selected < 0)
        kwin->selected = 0;
    if (kwin->selected >= calcnum && calcnum != 0)
        kwin->selected = calcnum - 1;

    for (unsigned int i = kwin->start; i < display_vector.size(); i++) {
        last_displayed.push_back(display_vector[i]);
        wireless_network *net = display_vector[i]->virtnet;

        if (net->manuf_score == manuf_max_score && color)
            wattrset(kwin->win, color_map["factory"].pair);
        else if (net->wep && color)
            wattrset(kwin->win, color_map["wep"].pair);
        else if (color)
            wattrset(kwin->win, color_map["open"].pair);
        else if (color)
            wattrset(kwin->win, color_map["text"].pair);

        if (i == (unsigned) (kwin->start + kwin->selected) && sortby != sort_auto) {
            wattron(netwin, A_REVERSE);
            char bar[1024];
            memset(bar, ' ', 1024);
            int w = kwin->print_width;
            if (w >= 1024)
                w = 1023;
            bar[w] = '\0';
            mvwaddstr(netwin, num+voffset, 2, bar);
        }

        string netline;

        // Build the netline for the group or single host and tag it for expansion if
        // appropriate for this sort and group
        NetLine(&netline, net,
                display_vector[i]->name.length() == 0 ? display_vector[i]->virtnet->ssid.c_str() : display_vector[i]->name.c_str(),
                0,
                display_vector[i]->type == group_host ? 0 : 1,
                sortby == sort_auto ? 0 : display_vector[i]->expanded,
                display_vector[i]->tagged);

        mvwaddstr(netwin, num+voffset, 1, netline.c_str());

        if (i == (unsigned) (kwin->start + kwin->selected) && sortby != sort_auto)
            wattroff(netwin, A_REVERSE);

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
        case sort_quality:
            sort(sortsub.begin(), sortsub.end(), SortQuality());
            break;
        case sort_signal:
            sort(sortsub.begin(), sortsub.end(), SortSignal());
            break;
        }

        for (unsigned int y = 0; y < sortsub.size(); y++) {
            net = display_vector[i]->networks[y];

            NetLine(&netline, net, net->ssid.c_str(), 1, 0, 0, 0);

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

    if (!(lat == 0 && lon == 0 && alt == 0 && spd == 0 && fix == 0)) {

        char fixstr[16];
        float show_alt = alt;
        float show_spd = spd;

        if (metric) {
            show_alt = alt / 3.3;
            show_spd = spd * 1.6093;
        }

        if (fix == -1)
            snprintf(fixstr, 16, "No signal");
        else if (fix == 2)
            snprintf(fixstr, 5, "2D");
        else if (fix == 3)
            snprintf(fixstr, 5, "3D");
        else
            snprintf(fixstr, 5, "NONE");

        // Convert if we're less than a mile/hr or kilom/hr
        int spdslow = 0;
        if (spd < 0.5) {
            spdslow = 1;
            if (metric)
                show_spd = spd * 0.2778;
            else
                show_spd = spd * 1.4667;
        }

        snprintf(gpsdata, 80, "Lat %.3f Lon %.3f Alt %.1f%c Spd %.3f%s Fix %s",
                 lat, lon, show_alt,
                 metric ? 'm' : 'f',
                 show_spd,
                 spdslow ? (metric ? "m/s" : "f/s") : (metric ? "km/h" : "m/h"),
                 fixstr);

        if (color)
            wattrset(kwin->win, color_map["monitor"].pair);
        mvwaddstr(netwin, netwin->_maxy, 2, gpsdata);
        if (color)
            wattrset(kwin->win, color_map["text"].pair);

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
    snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, num_networks);
    mvwaddstr(infowin, 2, 2, info);

    mvwaddstr(infowin, 3, 2, "Pckets");
    snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, num_packets);
    mvwaddstr(infowin, 4, 2, info);

    if (kwin->max_display > 6) {
        mvwaddstr(infowin, 5, 2, "Cryptd");
        snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, num_crypt);
        mvwaddstr(infowin, 6, 2, info);
    }

    if (kwin->max_display > 8) {
        mvwaddstr(infowin, 7, 2, "  Weak");
        snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, num_interesting);
        mvwaddstr(infowin, 8, 2, info);
    }

    if (kwin->max_display > 10) {
        mvwaddstr(infowin, 9, 2, " Noise");
        snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, num_noise);
        mvwaddstr(infowin, 10, 2, info);
    }

    if (kwin->max_display > 12) {
        mvwaddstr(infowin, 11, 2, "Discrd");
        snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, num_dropped);
        mvwaddstr(infowin, 12, 2, info);
    }

    if (kwin->max_display > 14) {
        mvwaddstr(infowin, 13, 2, "Pkts/s");
        snprintf(info, kwin->print_width, "%*d", kwin->print_width-1, packet_rate);
        mvwaddstr(infowin, 14, 2, info);
    }

    if (client->Valid())
        mvwaddstr(infowin, LINES-statheight-2, 2, "Elapsd");
    else
        mvwaddstr(infowin, LINES-statheight-2, 2, "Discon");

    time_t elapsed = server_time - start_time;
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
        delete[] trim;
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

void PanelFront::ClientLine(string *in_str, wireless_client *wclient, int print_width) {
    char retchr[4096];
    char tmpchr[4096];

    memset(retchr, 0, 4096);
    memset(tmpchr, 0, 4096);

    if (print_width > 4096)
        print_width = 4096;

    int pos = 0;
    char element[1024];
    int len = 0;

    time_t idle_time;
    if (wclient->tcpclient != NULL) {
        if (wclient->tcpclient->Valid())
            idle_time = wclient->tcpclient->FetchTime() - wclient->last_time;
        else
            idle_time = decay + 1;
    } else {
        idle_time = decay + 1;
    }


    for (unsigned int col = 0; col < client_column_vec.size(); col++) {
        client_columns colind = client_column_vec[col];

        if (colind == ccol_decay) {
            if (idle_time < decay)
                snprintf(element, 1024, "!");
            else if (idle_time < (decay * 2))
                snprintf(element, 1024, ".");
            else
                snprintf(element, 1024, " ");
            len = 1;
        } else if (colind == ccol_type) {
            if (wclient->type == client_fromds)
                snprintf(element, 2, "F");
            else if (wclient->type == client_tods)
                snprintf(element, 2, "T");
            else if (wclient->type == client_interds)
                snprintf(element, 2, "I");
            else if (wclient->type == client_established)
                snprintf(element, 2, "E");
            else
                snprintf(element, 2, "-");
            len = 1;
        } else if (colind == ccol_mac) {
            snprintf(element, 18, "%s", wclient->mac.Mac2String().c_str());
            len = 17;
        } else if (colind == ccol_manuf) {
            map<mac_addr, manuf *>::const_iterator mitr;
            if ((mitr = client_manuf_map.find(wclient->manuf_key)) != client_manuf_map.end()) {
                snprintf(element, 9, "%s", mitr->second->name.c_str());
            } else {
                snprintf(element, 9, "Unknown");
            }

            len = 8;
        } else if (colind == ccol_data) {
            snprintf(element, 7, "%6d", wclient->data_packets);
            len = 6;
        } else if (colind == ccol_crypt) {
            snprintf(element, 6, "%5d", wclient->crypt_packets);
            len = 5;
        } else if (colind == ccol_weak) {
            snprintf(element, 6, "%5d", wclient->interesting_packets);
            len = 5;
        } else if (colind == ccol_maxrate) {
            snprintf(element, 6, "%2.1f", wclient->maxrate);
            len = 5;
        } else if (colind == ccol_ip) {
            if (wclient->ipdata.atype == address_none) {
                snprintf(element, 1024, "0.0.0.0");
            } else {
                snprintf(element, 16, "%d.%d.%d.%d",
                         wclient->ipdata.ip[0], wclient->ipdata.ip[1],
                         wclient->ipdata.ip[2], wclient->ipdata.ip[3]);
            }
            len = 15;
        } else if (colind == ccol_signal) {
            snprintf(element, 4, "%3d", (idle_time < (decay * 2)) ? wclient->signal : 0);
            len = 3;
        } else if (colind == ccol_quality) {
            snprintf(element, 4, "%3d", (idle_time < (decay * 2)) ? wclient->quality : 0);
            len = 3;
        } else if (colind == ccol_noise) {
            snprintf(element, 4, "%3d", (idle_time < (decay * 2)) ? wclient->noise : 0);
            len = 3;
        } else if (colind == ccol_datasize) {
            if (wclient->datasize < 1024) // Less than 1k gets raw bytes
                snprintf(element, 6, "%4ldB", wclient->datasize);
            else if (wclient->datasize < 1048576) // Less than 1 meg gets mb
                snprintf(element, 6, "%4ldk", wclient->datasize/1024);
            else // Display in MB
                snprintf(element, 6, "%4ldM", wclient->datasize/1024/1024);
            len = 5;
        }

        if (pos + len > print_width - 1)
            break;

        snprintf(tmpchr, 4096, "%*s %s", (-1) * pos, retchr, element);

        strncpy(retchr, tmpchr, 4096);

        pos += len + 1;
    }

    *in_str = retchr;
}

int PanelFront::MainClientPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    client_win = kwin;

    int pos = 2;
    for (unsigned int col = 0; col < client_column_vec.size(); col++) {
        char title[1024];
        int len = 0;
        client_columns colind = client_column_vec[col];

        if (colind == ccol_decay) {
            snprintf(title, 1024, " ");
            len = 1;
        } else if (colind == ccol_type) {
            snprintf(title, 1024, "T");
            len = 1;
        } else if (colind == ccol_mac) {
            snprintf(title, 1024, "MAC");
            len = 17;
        } else if (colind == ccol_manuf) {
            snprintf(title, 1024, "Manuf");
            len = 8;
        } else if (colind == ccol_data) {
            snprintf(title, 1024, "  Data");
            len = 6;
        } else if (colind == ccol_crypt) {
            snprintf(title, 1024, "Crypt");
            len = 5;
        } else if (colind == ccol_weak) {
            snprintf(title, 1024, " Weak");
            len = 5;
        } else if (colind == ccol_maxrate) {
            snprintf(title, 1024, "Rate");
            len = 5;
        } else if (colind == ccol_ip) {
            snprintf(title, 1024, "IP Range");
            len = 15;
        } else if (colind == ccol_signal) {
            snprintf(title, 1024, "Sgn");
            len = 3;
        } else if (colind == ccol_quality) {
            snprintf(title, 1024, "Qly");
            len = 3;
        } else if (colind == ccol_noise) {
            snprintf(title, 1024, "Nse");
            len = 3;
        } else if (colind == ccol_datasize) {
            snprintf(title, 1024, " Size");
            len = 5;
        } else {
            title[0] = '\0';
        }

        if (pos + len >= kwin->print_width)
            break;

        if (color)
            wattrset(kwin->win, color_map["title"].pair);

        mvwaddstr(kwin->win, 1, pos, title);

        if (color)
            wattrset(kwin->win, color_map["text"].pair);

        pos += len + 1;
    }

    char sortxt[24];
    sortxt[0] = '\0';

    vector<wireless_client *> display_vector = details_network->virtnet->client_vec;
    int drop;

    switch (client_sortby) {
    case client_sort_auto:
        // Trim it ourselves for autofit mode.
        // This is really easy because we don't allow groups to be expanded in autofit
        // mode, so we just make it fit.

        snprintf(sortxt, 24, "(Autofit)");

        sort(display_vector.begin(), display_vector.end(), ClientSortLastTimeLT());

        drop = display_vector.size() - kwin->max_display - 1;

        if (drop > 0) {
            if (drop > (int) display_vector.size())
                drop = display_vector.size();

            display_vector.erase(display_vector.begin(), display_vector.begin() + drop);
        }
        sort(display_vector.begin(), display_vector.end(), ClientSortFirstTimeLT());
        kwin->start = 0;

        break;
    case client_sort_channel:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortChannel());
        snprintf(sortxt, 24, "(Channel)");
        break;
    case client_sort_first:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortFirstTime());
        snprintf(sortxt, 24, "(First Seen)");
        break;
    case client_sort_first_dec:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortFirstTimeLT());
        snprintf(sortxt, 24, "(First Seen desc)");
        break;
    case client_sort_last:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortLastTime());
        snprintf(sortxt, 24, "(Latest Seen)");
        break;
    case client_sort_last_dec:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortLastTimeLT());
        snprintf(sortxt, 24, "(Latest Seen desc)");
        break;
    case client_sort_mac:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortMAC());
        snprintf(sortxt, 24, "(MAC)");
        break;
    case client_sort_mac_dec:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortMACLT());
        snprintf(sortxt, 24, "(MAC desc)");
        break;
    case client_sort_wep:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortWEP());
        snprintf(sortxt, 24, "(WEP)");
        break;
    case client_sort_packets:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortPackets());
        snprintf(sortxt, 24, "(Packets)");
        break;
    case client_sort_packets_dec:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortPacketsLT());
        snprintf(sortxt, 24, "(Packets desc)");
        break;
    case client_sort_quality:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortQuality());
        snprintf(sortxt, 24, "(Quality)");
        break;
    case client_sort_signal:
        sort(display_vector.begin(), display_vector.end(),
             ClientSortSignal());
        snprintf(sortxt, 24, "(Signal)");
        break;
    }

    int num = 0;
    int voffset = 2;

    if (kwin->selected > kwin->max_display - voffset) {
        kwin->selected = kwin->max_display - voffset;
    }

    last_client_displayed.clear();
    for (unsigned int i = kwin->start; i < display_vector.size(); i++) {
        last_client_displayed.push_back(display_vector[i]);

        if (color)
            wattrset(kwin->win, color_map["text"].pair);

        if (num == kwin->selected && client_sortby != client_sort_auto) {
            wattron(kwin->win, A_REVERSE);
            char bar[1024];
            memset(bar, ' ', 1024);
            int w = kwin->print_width;
            if (w >= 1024)
                w = 1023;
            bar[w] = '\0';
            mvwaddstr(kwin->win, num+voffset, 1, bar);
        }

        string cliline;

        ClientLine(&cliline, display_vector[i], kwin->print_width);

        mvwaddstr(kwin->win, num+voffset, 1, cliline.c_str());

        if (num == kwin->selected && client_sortby != client_sort_auto)
            wattroff(kwin->win, A_REVERSE);

        num++;
        kwin->end = i;

        if (num > kwin->max_display - voffset)
            break;
    }

    last_client_draw_size = display_vector.size();

    if (color)
        wattrset(kwin->win, color_map["title"].pair);
    mvwaddstr(kwin->win, 0, kwin->title.length() + 4, sortxt);
    if (color)
        wattrset(kwin->win, color_map["text"].pair);

    if (kwin->start != 0 && client_sortby != client_sort_auto) {
        mvwaddstr(kwin->win, 0, kwin->win->_maxx - 10, "(-) Up");
    }

    if (kwin->end < (int) (display_vector.size() - 1) && client_sortby != client_sort_auto) {
        mvwaddstr(kwin->win, kwin->win->_maxy,
                  kwin->win->_maxx - 10, "(+) Down");
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
    delete[] txt;

    kwin->end = x+kwin->start;

    if (kwin->scrollable) {
        if (kwin->start != 0) {
            mvwaddstr(kwin->win, 0, kwin->win->_maxx - 10, "(-) Up");
        }

        if (kwin->end < (int) (kwin->text.size() - 1)) {
            mvwaddstr(kwin->win, kwin->win->_maxy, kwin->win->_maxx - 10, "(+) Down");
        }
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

int PanelFront::SortClientPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    int x = 0;
    while (1) {
        if (KismetClientSortText[x] == NULL)
            break;
        if (kwin->win->_maxx < 64)
            mvwaddstr(kwin->win, 1+x, 2, KismetClientSortTextNarrow[x]);
        else
            mvwaddstr(kwin->win, 1+x, 2, KismetClientSortText[x]);
        x++;
    }

    return 1;
}


int PanelFront::PowerPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    int qual, pwr, nse;

    qual = quality;
    pwr = power;
    nse = noise;

    if (qual == -1 && pwr == -1 && nse == -1) {
        mvwaddstr(kwin->win, 2, 2, "Server did not report card power levels.");
        mvwaddstr(kwin->win, 3, 2, "No card information is available.");
        return 1;
    }

    int width = kwin->win->_maxx - 10;

    if (width <= 5) {
        return 0;
    }

    char *bar = new char[width+1];

    if (qual > LINKQ_MAX)
        qual = LINKQ_MAX;
    if (pwr > LEVEL_MAX)
        pwr = LEVEL_MAX;
    if (nse > NOISE_MAX)
        nse = NOISE_MAX;

    double qperc = 0, pperc = 0, nperc = 0;
    if (qual != 0)
        qperc = (double) qual/LINKQ_MAX;
    if (pwr != 0)
        pperc = (double) pwr/LEVEL_MAX;
    if (nse != 0)
        nperc = (double) nse/NOISE_MAX;

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

    snprintf(bar, width, "%d", qual);
    mvwaddstr(kwin->win, 1, width+6, bar);
    snprintf(bar, width, "%d", pwr);
    mvwaddstr(kwin->win, 2, width+6, bar);
    snprintf(bar, width, "%d", nse);
    mvwaddstr(kwin->win, 3, width+6, bar);

    return 1;
}

// Details
int PanelFront::DetailsPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    kwin->scrollable = 1;

    char output[1024];
    kwin->text.clear();

    int print_width = kwin->print_width;
    if (print_width > 1024)
        print_width = 1023;

    if (details_network->name == "")
        snprintf(output, print_width, "Name    : %s", details_network->virtnet->ssid.c_str());
    else
        snprintf(output, print_width, "Name    : %s", details_network->name.c_str());
    kwin->text.push_back(output);

    if (details_network->networks.size() > 1) {
        snprintf(output, print_width, "Networks: %d", details_network->networks.size());
        kwin->text.push_back(output);

        if (details_network->virtnet->gps_fixed != -1) {
            snprintf(output, print_width, "Min Loc : Lat %f Lon %f Alt %f Spd %f",
                     details_network->virtnet->min_lat, details_network->virtnet->min_lon,
                     metric ? details_network->virtnet->min_alt / 3.3 : details_network->virtnet->min_alt,
                     metric ? details_network->virtnet->min_spd * 1.6093 : details_network->virtnet->min_spd);
            kwin->text.push_back(output);
            snprintf(output, print_width, "Max Loc : Lat %f Lon %f Alt %f Spd %f",
                     details_network->virtnet->max_lat, details_network->virtnet->max_lon,
                     metric ? details_network->virtnet->max_alt / 3.3 : details_network->virtnet->max_alt,
                     metric ? details_network->virtnet->max_spd * 1.6093 : details_network->virtnet->max_spd);
            kwin->text.push_back(output);

            double diagdist = EarthDistance(details_network->virtnet->min_lat,
                                            details_network->virtnet->min_lon,
                                            details_network->virtnet->max_lat,
                                            details_network->virtnet->max_lon);

            if (finite(diagdist)) {
                if (metric) {
                    if (diagdist < 1000)
                        snprintf(output, print_width, "Range    : %f meters", diagdist);
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

        if (details_network->virtnet->carrier_set & (1 << (int) carrier_80211b)) {
            snprintf(output, print_width, "Carrier : IEEE 802.11b");
            kwin->text.push_back(output);
        }
        if (details_network->virtnet->carrier_set & (1 << (int) carrier_80211a)) {
            snprintf(output, print_width, "Carrier : IEEE 802.11a");
            kwin->text.push_back(output);
        }
        if (details_network->virtnet->carrier_set & (1 << (int) carrier_80211g)) {
            snprintf(output, print_width, "Carrier : IEEE 802.11g");
            kwin->text.push_back(output);
        }
        if (details_network->virtnet->carrier_set & (1 << (int) carrier_80211)) {
            snprintf(output, print_width, "Carrier : IEEE 802.11");
            kwin->text.push_back(output);
        }

    }

    kwin->text.push_back("");

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

        snprintf(output, print_width, "Server  : %s:%d", dnet->tcpclient->FetchHost(),
                 dnet->tcpclient->FetchPort());
        kwin->text.push_back(output);

        snprintf(output, print_width, "BSSID   : %s", dnet->bssid.Mac2String().c_str());
        kwin->text.push_back(output);

        if (dnet->carrier_set & (1 << (int) carrier_80211b)) {
            snprintf(output, print_width, "Carrier : IEEE 802.11b");
            kwin->text.push_back(output);
        }
        if (dnet->carrier_set & (1 << (int) carrier_80211a)) {
            snprintf(output, print_width, "Carrier : IEEE 802.11a");
            kwin->text.push_back(output);
        }
        if (dnet->carrier_set & (1 << (int) carrier_80211g)) {
            snprintf(output, print_width, "Carrier : IEEE 802.11g");
            kwin->text.push_back(output);
        }
        if (dnet->carrier_set & (1 << (int) carrier_80211)) {
            snprintf(output, print_width, "Carrier : IEEE 802.11");
            kwin->text.push_back(output);
        }


        map<mac_addr, manuf *>::const_iterator mitr;
        int found = 0;

        if (dnet->type == network_adhoc || dnet->type == network_probe) {
            if ((mitr = client_manuf_map.find(dnet->manuf_key)) != client_manuf_map.end())
                found = 1;
        } else {
            if ((mitr = ap_manuf_map.find(dnet->manuf_key)) != ap_manuf_map.end())
                found = 1;
        }

        if (found) {
            snprintf(output, print_width, "Manuf   : %s",
                     mitr->second->name.c_str());
            kwin->text.push_back(output);
            if (mitr->second->model != "") {
                snprintf(output, print_width, "Model   : %s",
                         mitr->second->model.c_str());
                kwin->text.push_back(output);
            }
            snprintf(output, print_width, "Matched : %s",
                     dnet->manuf_key.Mac2String().c_str());
            kwin->text.push_back(output);
        } else {
            snprintf(output, print_width, "Manuf   : Unknown");
            kwin->text.push_back(output);
        }

        if (dnet->manuf_score == manuf_max_score) {
            snprintf(output, print_width, "     FACTORY CONFIGURATION");
            kwin->text.push_back(output);
        }
    
        snprintf(output, print_width, "Max Rate: %2.1f", dnet->maxrate);
        kwin->text.push_back(output);
    
        snprintf(output, print_width, "First   : %.24s", ctime((const time_t *) &dnet->first_time));
        kwin->text.push_back(output);
    
        snprintf(output, print_width, "Latest  : %.24s", ctime((const time_t *) &dnet->last_time));
        kwin->text.push_back(output);

        snprintf(output, print_width, "Clients : %d", dnet->client_map.size());
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
        case network_turbocell:
            if (dnet->wep)
                snprintf(output, print_width, "Type    : Turbocell (encrypted)");
            else
                snprintf(output, print_width, "Type    : Turbocell");
            break;
        case network_remove:
            break;
        }
        kwin->text.push_back(output);

        if (dnet->type == network_turbocell && dnet->wep == 0) {
            snprintf(output, print_width, "  Net ID  : %d", dnet->turbocell_nid);
            kwin->text.push_back(output);

            switch (dnet->turbocell_mode) {
            case turbocell_ispbase:
                snprintf(output, print_width, "  Mode    : ISP base station");
                break;
            case turbocell_pollbase:
                snprintf(output, print_width, "  Mode    : Polling base station");
                break;
            case turbocell_base:
                snprintf(output, print_width, "  Mode    : Base station");
                break;
            case turbocell_nonpollbase:
                snprintf(output, print_width, "  Mode    : Non-polling base station");
                break;
            default:
                snprintf(output, print_width, "  Mode    : Unknown");
                break;
            }
            kwin->text.push_back(output);

            snprintf(output, print_width, "  Sats    : %s", dnet->turbocell_sat ? "Yes" : "No");
            kwin->text.push_back(output);
        }

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

        // Calculate the bytes
        if (dnet->datasize < 1024) // Less than 1k gets raw bytes
            snprintf(output, print_width, "Data    : %ldB", dnet->datasize);
        else if (dnet->datasize < 1048576) // Less than 1 meg gets mb
            snprintf(output, print_width, "Data    : %ldk (%ldB)",
                     dnet->datasize/1024, dnet->datasize);
        else // Display in MB
            snprintf(output, print_width, "Data    : %ldM (%ldk, %ldB)",
                     dnet->datasize/1024/1024, dnet->datasize/1024, dnet->datasize);
        kwin->text.push_back(output);

        snprintf(output, print_width, "Signal  :");
        kwin->text.push_back(output);
        snprintf(output, print_width, "  Quality : %d (best %d)",
                 dnet->quality, dnet->best_quality);
        kwin->text.push_back(output);
        snprintf(output, print_width, "  Power   : %d (best %d)",
                 dnet->signal, dnet->best_signal);
        kwin->text.push_back(output);
        snprintf(output, print_width, "  Noise   : %d (best %d)",
                 dnet->noise, dnet->best_noise);
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
        }
    
        if (dnet->gps_fixed != -1) {
            snprintf(output, print_width, "Min Loc : Lat %f Lon %f Alt %f Spd %f",
                     dnet->min_lat, dnet->min_lon,
                     metric ? dnet->min_alt / 3.3 : dnet->min_alt,
                     metric ? dnet->min_spd * 1.6093 : dnet->min_spd);
            kwin->text.push_back(output);
            snprintf(output, print_width, "Max Loc : Lat %f Lon %f Alt %f Spd %f",
                     dnet->max_lat, dnet->max_lon,
                     metric ? dnet->max_alt / 3.3 : dnet->max_alt,
                     metric ? dnet->max_spd * 1.6093 : dnet->max_spd);
            kwin->text.push_back(output);


            double diagdist = EarthDistance(dnet->min_lat, dnet->min_lon,
                                            dnet->max_lat, dnet->max_lon);

            if (finite(diagdist)) {
                if (metric) {
                    if (diagdist < 1000)
                        snprintf(output, print_width, "Range    : %f meters", diagdist);
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
    }

    // Now we just use the text printer to handle the rest for us

    return TextPrinter(in_window);
}

int PanelFront::GpsPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    char output[1024];
    kwin->text.clear();

    wireless_network *dnet = details_network->virtnet;

    int print_width = kwin->print_width;
    if (print_width > 1024)
        print_width = 1023;

    if (print_width < 32) {
        kwin->text.push_back("Display not wide enough");
        return TextPrinter(in_window);
    }

    if (dnet->aggregate_points == 0) {
        kwin->text.push_back("No GPS data.");
        return TextPrinter(in_window);
    }

    float center_lat, center_lon;

    // We hijack the "selected" field as a toggle
    if (kwin->selected == 1) {
        center_lat = dnet->best_lat;
        center_lon = dnet->best_lon;
    } else {
        center_lat = dnet->aggregate_lat / dnet->aggregate_points;
        center_lon = dnet->aggregate_lon / dnet->aggregate_points;
    }

    // Try to calculate the bearing and distance to the estimated center
    // Liberally stolen from gpsdrive - math is scary! >:P

    float R = CalcRad(lat);

    float tx = (2 * R * M_PI / 360) * cos(M_PI * lat / 180.0) * (last_lon - lon);
    float ty = (2 * R * M_PI / 360) * (last_lat - lat);

    float base_angle = atan(tx/ty);
    if (finite(base_angle)) {
        if (ty < 0)
            base_angle += M_PI;
        if (base_angle >= (2 * M_PI))
            base_angle -= 2 * M_PI;
        if (base_angle < 0)
            base_angle += 2 * M_PI;
        base_angle = base_angle * 180 / M_PI;
    } else {
        base_angle = 0;
    }

    tx = (2 * R * M_PI / 360) * cos(M_PI * lat / 180.0) * (center_lon - lon);
    ty = (2 * R * M_PI / 360) * (center_lat - lat);
    float center_angle = atan(tx/ty);
    if (finite(center_angle)) {
        if (ty < 0)
            center_angle += M_PI;
        if (center_angle >= (2 * M_PI))
            center_angle -= 2 * M_PI;
        if (center_angle < 0)
            center_angle += 2 * M_PI;
        center_angle = center_angle * 180 / M_PI;
    } else {
        center_angle = 0;
    }

    float difference_angle = base_angle - center_angle;
    if (difference_angle < 0)
        difference_angle += 360;

    double diagdist = EarthDistance(lat, lon, center_lat, center_lon);

    // Now we know everything - where we are, where we are headed, where we SHOULD be headed
    // to get to the supposed center of the network, how far it is, and the orientation on our
    // compass to get to it.  Time to start drawing our output.

    char compass[5][10];
    memset(compass, 0, sizeof(char) * 5 * 10);

    // |  41.12345x-74.12345     .-|-/    |
    // | Bearing:               /  |/ \   |
    // |  123.23 degrees       |   O   |  |
    // |                        \   \ /   |
    // | Estimated center:       '---\    |


    // Find the orientation on our compass:
    if (difference_angle > 330 || difference_angle <= 22) {
        snprintf(compass[0], 10, "  .-|-.  ");
        snprintf(compass[1], 10, " /  |  \\ ");
        snprintf(compass[2], 10, "|   O   |");
        snprintf(compass[3], 10, " \\     / ");
        snprintf(compass[4], 10, "  '---'  ");
    } else if (difference_angle > 22 && difference_angle <= 66) {
        snprintf(compass[0], 10, "  .---/  ");
        snprintf(compass[1], 10, " /   / \\ ");
        snprintf(compass[2], 10, "|   O   |");
        snprintf(compass[3], 10, " \\     / ");
        snprintf(compass[4], 10, "  '---'  ");
    } else if (difference_angle > 66 && difference_angle <= 110) {
        snprintf(compass[0], 10, "  .---.  ");
        snprintf(compass[1], 10, " /     \\ ");
        snprintf(compass[2], 10, "|   O----");
        snprintf(compass[3], 10, " \\     / ");
        snprintf(compass[4], 10, "  '---'  ");
    } else if (difference_angle > 110 && difference_angle <= 154) {
        snprintf(compass[0], 10, "  .---.  ");
        snprintf(compass[1], 10, " /     \\ ");
        snprintf(compass[2], 10, "|   O   |");
        snprintf(compass[3], 10, " \\   \\ / ");
        snprintf(compass[4], 10, "  '---\\  ");
    } else if (difference_angle > 154 && difference_angle <= 198) {
        snprintf(compass[0], 10, "  .---.  ");
        snprintf(compass[1], 10, " /     \\ ");
        snprintf(compass[2], 10, "|   O   |");
        snprintf(compass[3], 10, " \\  |  / ");
        snprintf(compass[4], 10, "  '-|-'  ");
    } else if (difference_angle > 198 && difference_angle <= 242) {
        snprintf(compass[0], 10, "  .---.  ");
        snprintf(compass[1], 10, " /     \\ ");
        snprintf(compass[2], 10, "|   O   |");
        snprintf(compass[3], 10, " \\ /   / ");
        snprintf(compass[4], 10, "  /---'  ");
    } else if (difference_angle > 242 && difference_angle <= 286) {
        snprintf(compass[0], 10, "  .---.  ");
        snprintf(compass[1], 10, " /     \\ ");
        snprintf(compass[2], 10, "----O   |");
        snprintf(compass[3], 10, " \\     / ");
        snprintf(compass[4], 10, "  '---'  ");
    } else if (difference_angle > 286 && difference_angle <= 330) {
        snprintf(compass[0], 10, "  \\---.  ");
        snprintf(compass[1], 10, " / \\   \\ ");
        snprintf(compass[2], 10, "|   O   |");
        snprintf(compass[3], 10, " \\     / ");
        snprintf(compass[4], 10, "  '---'  ");
    } else {
        snprintf(compass[0], 10, "%f\n", difference_angle);
    }


    // - Network GPS ---------------------|
    // | Current:                         |
    // |  41.12345x-74.12345     .-|-.    |
    // | Bearing:               /  |  \   |
    // |  123.23 degrees       |   O   |  |
    // |                        \   \ /   |
    // | Estimated center:       '---\    |
    // | -73.12345x43.12345               |
    // |                        120 feet  |
    // ------------------------------------
    char textfrag[23];

    snprintf(output, print_width, "Current:");
    kwin->text.push_back(output);

    snprintf(textfrag, 23, "%.3f x %.3f", lat, lon);
    snprintf(output, print_width, "%-22s%s", textfrag, compass[0]);
    kwin->text.push_back(output);

    snprintf(textfrag, 23, " Bearing:");
    snprintf(output, print_width, "%-22s%s", textfrag, compass[1]);
    kwin->text.push_back(output);

    snprintf(textfrag, 23, " %.2f*", base_angle);
    snprintf(output, print_width, "%-22s%s", textfrag, compass[2]);
    kwin->text.push_back(output);

    snprintf(textfrag, 23, " ");
    snprintf(output, print_width, "%-22s%s", textfrag, compass[3]);
    kwin->text.push_back(output);

    if (kwin->selected == 1)
        snprintf(textfrag, 23, "Strongest signal:");
    else
        snprintf(textfrag, 23, "Estimated Center:");
    snprintf(output, print_width, "%-22s%s", textfrag, compass[4]);
    kwin->text.push_back(output);

    snprintf(textfrag, 23, "%.3f x %.3f", center_lat, center_lon);
    snprintf(output, print_width, "%-22s%.2f*", textfrag, difference_angle);
    kwin->text.push_back(output);

    if (metric) {
        if (diagdist < 1000)
            snprintf(textfrag, 23, "%.2f m", diagdist);
        else
            snprintf(textfrag, 23, "%.2f km", diagdist / 1000);
    } else {
        diagdist *= 3.3;
        if (diagdist < 5280)
            snprintf(textfrag, 23, "%.2f ft", diagdist);
        else
            snprintf(textfrag, 23, "%.2f mi", diagdist / 5280);
    }

    snprintf(output, print_width, "%-22s%s", "", textfrag);
    kwin->text.push_back(output);

    return TextPrinter(in_window);
}

int PanelFront::PackPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    if (client->GetMaxPackInfos() != ((kwin->max_display / 4) * (kwin->print_width - 2)) / 3)
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
    string ptype;
    char cdata[1024];
    char dsubtype[1024], srcport[12], dstport[12];
    struct servent *srcserv, *dstserv;

    // For as many packets as we can fit in 1/4...
    for (unsigned int x = max(0, (int) packinfo.size() - (((kwin->max_display / 4) * (kwin->print_width - 2)) / 3));
         x < packinfo.size(); x++) {
        switch(packinfo[x].type) {
        case packet_noise:
            data += "N ";
            break;
        case packet_unknown:
            data += "U ";
            break;
        case packet_management:
            data += "M";

            switch (packinfo[x].subtype) {
            case packet_sub_association_req:
                data += "a";
                break;
            case packet_sub_association_resp:
                data += "A";
                break;
            case packet_sub_reassociation_req:
                data += "r";
                break;
            case packet_sub_reassociation_resp:
                data += "R";
                break;
            case packet_sub_probe_req:
                data += "p";
                break;
            case packet_sub_probe_resp:
                data += "P";
                break;
            case packet_sub_beacon:
                data += "B";
                break;
            case packet_sub_atim:
                data += "M";
                break;
            case packet_sub_disassociation:
                data += "D";
                break;
            case packet_sub_authentication:
                data += "t";
                break;
            case packet_sub_deauthentication:
                data += "T";
                break;
            default:
                data += "?";
                break;
            }
            ptype += ")";

            break;
        case packet_phy:
            data += "P";

            switch (packinfo[x].subtype) {
            case packet_sub_rts:
                data += "t";
                break;
            case packet_sub_cts:
                data += "T";
                break;
            case packet_sub_ack:
                data += "A";
                break;
            case packet_sub_cf_end:
                data += "c";
                break;
            case packet_sub_cf_end_ack:
                data += "C";
                break;
            default:
                data += "?";
                break;
            }

            ptype += ")";

            break;
        case packet_data:
            data += "D";
            ptype += "DATA (";

            switch (packinfo[x].subtype) {
            case packet_sub_data:
                data += "D";
                break;
            case packet_sub_data_cf_ack:
                data += "c";
                break;
            case packet_sub_data_cf_poll:
                data += "p";
                break;
            case packet_sub_data_cf_ack_poll:
                data += "P";
                break;
            case packet_sub_data_null:
                data += "N";
                break;
            case packet_sub_cf_ack:
                data += "a";
                break;
            case packet_sub_cf_ack_poll:
                data += "A";
                break;
            default:
                data += "?";
                break;
            }

            break;
        default:
            data += "U ";
            break;
        }

        data += " ";

        if ((int) data.length() >= kwin->print_width - 2) {
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
        start = packinfo.size() - kwin->max_display + (kwin->max_display / 4) + 1;

    for (unsigned int x = start; x < packinfo.size(); x++) {
        switch(packinfo[x].type) {
        case packet_noise:
            ptype = "NOISE";
            break;
        case packet_unknown:
            ptype = "UNKNOWN";
            break;
        case packet_management:
            ptype = "MANAGEMENT (";

            switch (packinfo[x].subtype) {
            case packet_sub_association_req:
                ptype += "Association Request ";
                ptype += packinfo[x].ssid;
                break;
            case packet_sub_association_resp:
                ptype += "Association Response ";
                ptype += packinfo[x].ssid;
                break;
            case packet_sub_reassociation_req:
                ptype += "Reassociation Request ";
                ptype += packinfo[x].ssid;
                break;
            case packet_sub_reassociation_resp:
                ptype += "Reassociation Response ";
                ptype += packinfo[x].ssid;
                break;
            case packet_sub_probe_req:
                ptype += "Probe Request ";
                ptype += packinfo[x].ssid;
                break;
            case packet_sub_probe_resp:
                ptype += "Probe Response ";
                ptype += packinfo[x].ssid;
                break;
            case packet_sub_beacon:
                ptype += "Beacon ";
                ptype += packinfo[x].ssid;
                break;
            case packet_sub_atim:
                ptype += "ATIM";
                break;
            case packet_sub_disassociation:
                ptype += "Disassociation";
                break;
            case packet_sub_authentication:
                ptype += "Authentication";
                break;
            case packet_sub_deauthentication:
                ptype += "Deauthentication";
                break;
            default:
                ptype += "Unknown";
                break;
            }
            ptype += ")";

            break;
        case packet_phy:
            ptype = "PHY (";

            switch (packinfo[x].subtype) {
            case packet_sub_rts:
                ptype += "Ready To Send";
                break;
            case packet_sub_cts:
                ptype += "Clear To Send";
                break;
            case packet_sub_ack:
                ptype += "Data Ack";
                break;
            case packet_sub_cf_end:
                ptype += "CF End";
                break;
            case packet_sub_cf_end_ack:
                ptype += "CF End+Ack";
                break;
            default:
                ptype += "Unknown";
                break;
            }

            ptype += ")";

            break;
        case packet_data:
            ptype = "DATA (";

            switch (packinfo[x].subtype) {
            case packet_sub_data:
                if (packinfo[x].interesting)
                    ptype += "Weak ";
                if (packinfo[x].encrypted)
                    ptype += "Encrypted ";

                switch (packinfo[x].proto.type) {
                case proto_netbios:
                case proto_netbios_tcp:
                    ptype += "NETBIOS ";
                    switch (packinfo[x].proto.nbtype) {
                    case proto_netbios_host:
                        ptype += "HOST ";
                        ptype += packinfo[x].proto.netbios_source;
                        break;
                    case proto_netbios_master:
                        ptype += "MASTER ";
                        ptype += packinfo[x].proto.netbios_source;
                        break;
                    case proto_netbios_domain:
                        ptype += "DOMAIN ";
                        ptype += packinfo[x].proto.netbios_source;
                        break;
                    case proto_netbios_query:
                        ptype += "QUERY ";
                        ptype += packinfo[x].proto.netbios_source;
                        break;
                    case proto_netbios_pdcquery:
                        ptype += "PDC QUERY ";
                        ptype += packinfo[x].proto.netbios_source;
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
                    ptype += dsubtype;
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
                    ptype += dsubtype;
                    break;
                case proto_arp:
                    snprintf(dsubtype, 1024, "ARP %d.%d.%d.%d->%d.%d.%d.%d",
                             packinfo[x].proto.source_ip[0], packinfo[x].proto.source_ip[1],
                             packinfo[x].proto.source_ip[2], packinfo[x].proto.source_ip[3],
                             packinfo[x].proto.dest_ip[0], packinfo[x].proto.dest_ip[1],
                             packinfo[x].proto.dest_ip[2], packinfo[x].proto.dest_ip[3]);
                    ptype += dsubtype;
                    break;
                case proto_ipx_tcp:
                    snprintf(dsubtype, 1024, "IPX");
                    ptype += dsubtype;
                    break;
                default:
                    break;
                }

                break;
            case packet_sub_data_cf_ack:
                ptype += "Data+CF+Ack";
                break;
            case packet_sub_data_cf_poll:
                ptype += "Data+CF+Poll";
                break;
            case packet_sub_data_cf_ack_poll:
                ptype += "Data+CF+Ack+Poll";
                break;
            case packet_sub_data_null:
                ptype += "Data Null";
                break;
            case packet_sub_cf_ack:
                ptype += "CF Ack";
                break;
            case packet_sub_cf_ack_poll:
                ptype += "CF Ack+Poll";
                break;
            default:
                ptype += "Unknown";
                break;
            }

            ptype += ")";

            break;
        default:
            ptype = "UNKNOWN";
            break;
        }

        snprintf(cdata, 1024, "%.8s - %s %s", ctime(&packinfo[x].time)+11,
                 packinfo[x].source_mac.Mac2String().c_str(), ptype.c_str());

        kwin->text.push_back(cdata);
    }

    return TextPrinter(in_window);
}

int PanelFront::DumpPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    vector<TcpClient::string_info> strinf;
    strinf.reserve(100);

    if (kwin->paused != 0) {
        mvwaddstr(kwin->win, 0, kwin->win->_maxx - 10, "Paused");
        return TextPrinter(in_window);
    }

    if (kwin->toggle1 == 0)
        mvwaddstr(kwin->win, 0, kwin->win->_maxx - 10, "All");
    else
        mvwaddstr(kwin->win, 0, kwin->win->_maxx - 10, "Tagged");

    for (unsigned int x = 0; x < context_list.size(); x++) {
        if (context_list[x]->tagged == 1 && context_list[x]->client != NULL) {
            if (clear_dump) {
                client->ClearStrings();
                kwin->text.clear();
            } else {
                vector<TcpClient::string_info> cli_strings = context_list[x]->client->FetchStrings();
                for (unsigned int stng = 0; stng < cli_strings.size(); stng++) {
                    // Only add tagged networks if we care about that.
                    map<mac_addr, display_network *>::iterator gamitr;
                    gamitr = group_assignment_map.find(cli_strings[stng].bssid);
                    if (gamitr == group_assignment_map.end())
                        continue;
                    if (kwin->toggle1 == 1 && gamitr->second->tagged == 0)
                        continue;

                    strinf.push_back(cli_strings[stng]);
                }
            }
        }
    }

    clear_dump = 0;

    // Sort them
    sort(strinf.begin(), strinf.end(), TcpClient::SortStrings());

    kwin->text.clear();

    char output[1024];
    for (unsigned int x = 0; x < strinf.size(); x++) {
        if (kwin->toggle0 == 1) {
            // If we print the date
            snprintf(output, 1024, "%.24s - %s", ctime((const time_t *) &strinf[x].string_ts.tv_sec),
                     strinf[x].text.c_str());
            kwin->text.push_back(output);
        } else {
            kwin->text.push_back(strinf[x].text);
        }
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
        snprintf(gname, print_width - 9, "%s", details_network->virtnet->ssid.c_str());
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

    kwin->scrollable = 1;

    vector<string> details_text;
    char output[1024];

    const int print_width = kwin->print_width;

    snprintf(output, print_width, "Start   : %.24s", ctime((const time_t *) &start_time));
    details_text.push_back(output);

    snprintf(output, print_width, "Servers : %d", context_list.size());
    details_text.push_back(output);

    snprintf(output, print_width, "Networks: %d", num_networks);
    details_text.push_back(output);

    int wep_count = 0, vuln_count = 0;
    int channelperc[CHANNEL_MAX];
    int maxch = 0;

    memset(channelperc, 0, sizeof(int) * CHANNEL_MAX);

    for (unsigned int x = 0; x < context_list.size(); x++) {
        if (context_list[x]->tagged == 1 && context_list[x]->client != NULL) {
            vector<wireless_network *> netlist = context_list[x]->client->FetchNetworkList();

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
        }
    }

    snprintf(output, print_width, " Encrypted: %d (%d%%)", wep_count,
             num_networks > 0 ?
             (int) (((double) wep_count / num_networks) * 100) : 0);
    details_text.push_back(output);

    snprintf(output, print_width, " Default  : %d (%d%%)", vuln_count,
             num_networks > 0 ?
             (int) (((double) vuln_count / num_networks) * 100) : 0);
    details_text.push_back(output);

    snprintf(output, print_width, "Total packets: %d", num_packets);
    details_text.push_back(output);

    snprintf(output, print_width, "Max. Packet Rate: %d packets/sec", max_packet_rate);
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
                     num_networks > 0 ?
                     (int) (((double) channelperc[vdraw-1] / num_networks) * 100) : 0,
                     vdraw+1, channelperc[vdraw],
                     num_networks > 0 ?
                     (int) (((double) channelperc[vdraw] / num_networks) * 100) : 0);
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
                     num_networks > 0 ?
                     (int) (((double) channelperc[x] / num_networks) * 100) : 0);
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

    delete[] graphstring;

    return 1;
}

int PanelFront::AlertPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    kwin->scrollable = 1;

    if (kwin->paused != 0) {
        mvwaddstr(kwin->win, 0, kwin->win->_maxx - 10, "Paused");
        return TextPrinter(in_window);
    }

    vector<TcpClient::alert_info> alerts;
    alerts.reserve(100);

    // Get all the alerts
    for (unsigned int x = 0; x < context_list.size(); x++) {
        if (context_list[x]->tagged == 1 && context_list[x]->client != NULL) {
            vector<TcpClient::alert_info> cli_alerts = context_list[x]->client->FetchAlerts();
            for (unsigned int alrt = 0; alrt < cli_alerts.size(); alrt++)
                alerts.push_back(cli_alerts[alrt]);
        }
    }

    // Sort them
    sort(alerts.begin(), alerts.end(), TcpClient::SortAlerts());

    kwin->text.clear();

    char output[1024];
    for (unsigned int x = 0; x < alerts.size(); x++) {
        if (kwin->toggle0 == 0) {
            // If we print the date
            snprintf(output, 1024, "%.24s - %s", ctime((const time_t *) &alerts[x].alert_ts.tv_sec),
                     alerts[x].alert_text.c_str());
            kwin->text.push_back(output);
        } else {
            kwin->text.push_back(alerts[x].alert_text);
        }
    }

    return TextPrinter(in_window);
}

int PanelFront::DetailsClientPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    kwin->scrollable = 1;

    char output[1024];
    char temp[1024];
    kwin->text.clear();

    int print_width = kwin->print_width;
    if (print_width > 1024)
        print_width = 1023;

    switch (details_client->type) {
    case client_fromds:
        snprintf(temp, print_width, "From Distribution (AP->Wireless)");
        break;
    case client_tods:
        snprintf(temp, print_width, "To Distribution (Wireless->AP)");
        break;
    case client_interds:
        snprintf(temp, print_width, "Intra-distribution (AP->AP)");
        break;
    case client_established:
        snprintf(temp, print_width, "Established (Wireless->AP and AP->Wireless)");
        break;
    case client_unknown:
        snprintf(temp, print_width, "Unknown");
        break;
    }

    snprintf(output, print_width, "Type    : %s", temp);
    kwin->text.push_back(output);

    snprintf(output, print_width, "Server  : %s:%d", details_client->tcpclient->FetchHost(),
             details_client->tcpclient->FetchPort());
    kwin->text.push_back(output);

    snprintf(output, print_width, "MAC     : %s", details_client->mac.Mac2String().c_str());
    kwin->text.push_back(output);

    map<mac_addr, manuf *>::const_iterator mitr;
    if ((mitr = client_manuf_map.find(details_client->manuf_key)) != client_manuf_map.end()) {
        snprintf(output, print_width, "Manuf   : %s",
                 mitr->second->name.c_str());
        kwin->text.push_back(output);
        if (mitr->second->model != "") {
            snprintf(output, print_width, "Model   : %s",
                     mitr->second->model.c_str());
            kwin->text.push_back(output);
        }
        snprintf(output, print_width, "Matched : %s",
                 details_client->manuf_key.Mac2String().c_str());
        kwin->text.push_back(output);
    } else {
        snprintf(output, print_width, "Manuf   : Unknown");
        kwin->text.push_back(output);
    }

    snprintf(output, print_width, "First   : %.24s", ctime((const time_t *) &details_client->first_time));
    kwin->text.push_back(output);
    snprintf(output, print_width, "Latest  : %.24s", ctime((const time_t *) &details_client->last_time));
    kwin->text.push_back(output);
    snprintf(output, print_width, "Max Rate: %2.1f", details_client->maxrate);
    kwin->text.push_back(output);
    snprintf(output, print_width, "Channel : %d", details_client->channel);
    kwin->text.push_back(output);
    snprintf(output, print_width, "WEP     : %s", details_client->wep ? "Yes" : "No");
    kwin->text.push_back(output);
    snprintf(output, print_width, "IP      : %d.%d.%d.%d",
             details_client->ipdata.ip[0], details_client->ipdata.ip[1],
             details_client->ipdata.ip[2], details_client->ipdata.ip[3]);
    kwin->text.push_back(output);

    if (details_client->gps_fixed != -1) {
        kwin->text.push_back("");

        snprintf(output, print_width, "Min Loc : Lat %f Lon %f Alt %f Spd %f",
                 details_client->min_lat, details_client->min_lon,
                 metric ? details_client->min_alt / 3.3 : details_client->min_alt,
                 metric ? details_client->min_spd * 1.6093 : details_client->min_spd);
        kwin->text.push_back(output);
        snprintf(output, print_width, "Max Loc : Lat %f Lon %f Alt %f Spd %f",
                 details_client->max_lat, details_client->max_lon,
                 metric ? details_client->max_alt / 3.3 : details_client->max_alt,
                 metric ? details_client->max_spd * 1.6093 : details_client->max_spd);
        kwin->text.push_back(output);

        double diagdist = EarthDistance(details_client->min_lat,
                                        details_client->min_lon,
                                        details_client->max_lat,
                                        details_client->max_lon);

        if (finite(diagdist)) {
            if (metric) {
                if (diagdist < 1000)
                    snprintf(output, print_width, "Range    : %f meters", diagdist);
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

        kwin->text.push_back("");
    }

    snprintf(output, print_width, "Packets :");
    kwin->text.push_back(output);
    snprintf(output, print_width, "  Data    : %d", details_client->data_packets);
    kwin->text.push_back(output);
    snprintf(output, print_width, "  Crypt   : %d", details_client->crypt_packets);
    kwin->text.push_back(output);
    snprintf(output, print_width, "  Weak    : %d", details_client->interesting_packets);
    kwin->text.push_back(output);

    // Calculate the bytes
    if (details_client->datasize < 1024) // Less than 1k gets raw bytes
        snprintf(output, print_width, "Data    : %ldB", details_client->datasize);
    else if (details_client->datasize < 1048576) // Less than 1 meg gets mb
        snprintf(output, print_width, "Data    : %ldk (%ldB)",
                 details_client->datasize/1024, details_client->datasize);
    else // Display in MB
        snprintf(output, print_width, "Data    : %ldM (%ldk, %ldB)",
                 details_client->datasize/1024/1024, details_client->datasize/1024,
                 details_client->datasize);
    kwin->text.push_back(output);


    snprintf(output, print_width, "Signal  :");
    kwin->text.push_back(output);
    snprintf(output, print_width, "  Quality : %d (best %d)",
             details_client->quality, details_client->best_quality);
    kwin->text.push_back(output);
    snprintf(output, print_width, "  Power   : %d (best %d)",
             details_client->signal, details_client->best_signal);
    kwin->text.push_back(output);
    snprintf(output, print_width, "  Noise   : %d (best %d)",
             details_client->noise, details_client->best_noise);
    kwin->text.push_back(output);

    return TextPrinter(in_window);
}

int PanelFront::ServersPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    if (color)
        wattrset(kwin->win, color_map["title"].pair);
    mvwaddstr(kwin->win, 1, 3, "Server                    Port  Name            Status");
    if (color)
        wattrset(kwin->win, color_map["text"].pair);

    if (kwin->start >= (int) context_list.size())
        kwin->start = 0;
    if (kwin->selected < kwin->start)
        kwin->selected = 0;
    if (kwin->selected > (kwin->max_display - 1))
        kwin->selected = kwin->max_display - 1;

    int voffset = 2;
    int num = 0;

    char line[1024];
    int w = kwin->print_width;
    if (w >= 1024)
        w = 1023;

    for (int x = (int) kwin->start; x < (int) context_list.size() &&
         x < kwin->max_display - 1; x++, num++) {

        if (color)
            wattrset(kwin->win, color_map["text"].pair);

        if ((x - kwin->start) == kwin->selected) {
            wattron(kwin->win, A_REVERSE);
            memset(line, ' ', 1024);
            line[w] = '\0';
            mvwaddstr(kwin->win, num+voffset, 1, line);
        }

        char type;
        if (context_list[x]->primary == 1)
            type = 'P';
        else if (context_list[x]->tagged == 1)
            type = '*';
        else
            type = ' ';

        if (context_list[x]->client) {
            snprintf(line, w, "%c %-25s %-5d %-15s %-12s",
                     type, context_list[x]->client->FetchHost(),
                     context_list[x]->client->FetchPort(),
                     context_list[x]->client->FetchServername().c_str(),
                     context_list[x]->client->Valid() ? "Connected" : "Disconnected");
        } else {
            snprintf(line, w, "- %-25s %-5d %-15s %-12s",
                     "INVALID", 0, "INVALID", "Invalid");
        }

        mvwaddstr(kwin->win, num+voffset, 1, line);

        if ((x - kwin->start) == kwin->selected)
            wattroff(kwin->win, A_REVERSE);

        kwin->end = x;

    }

    return 1;
}

int PanelFront::ServerJoinPrinter(void *in_window) {
    kis_window *kwin = (kis_window *) in_window;

    char targclient[32];
    int print_width = kwin->print_width;

    if (print_width > 31)
        print_width = 31;

    mvwaddstr(kwin->win, 1, 2, "Server (host:port):");

    // The text field is reversed
    wattron(kwin->win, WA_REVERSE);

    memset(targclient, ' ', print_width);
    targclient[print_width] = '\0';

    mvwaddstr(kwin->win, 2, 2, targclient);

    wattroff(kwin->win, WA_REVERSE);

    echo();
    nocbreak();
    nodelay(kwin->win, 0);

    wattron(kwin->win, WA_REVERSE);
    mvwgetnstr(kwin->win, 2, 2, targclient, print_width-1);
    wattroff(kwin->win, WA_REVERSE);

    noecho();
    cbreak();

    // Return 0 to tell them to kill the popup
    if (strlen(targclient) == 0)
        return 0;

    char host[1024];
    int port = -1;
    char msg[1024];

    if (sscanf(targclient, "%1024[^:]:%d", host, &port) != 2) {
        snprintf(msg, 1024, "Illegal server '%s'.", targclient);
        WriteStatus(msg);
        return 0;
    }

    snprintf(msg, 1024, "Connecting to server '%s:%d'.", host, port);
    WriteStatus(msg);

    // Create the new client
    TcpClient *netclient = new TcpClient;
    netclient->Connect(port, host);

    // Add it to our contexts
    AddClient(netclient);

    return 0;

}

#endif
