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
#include "cursesfront.h"

#if defined(HAVE_LIBNCURSES) && defined(BUILD_CURSES)

NCurseFront::NCurseFront() {
    errstr[0] = '\0';

    client = NULL;
}

int NCurseFront::InitDisplay(int in_decay, time_t in_start) {
    start_time = in_start;

    decay = in_decay;

    initscr();

    netborder = subwin(stdscr, LINES-statheight, COLS-infowidth, 0, 0);
    netwin = subwin(netborder, LINES-statheight-3, COLS-infowidth-2, 2, 1);
    infoborder = subwin(stdscr, LINES-statheight, infowidth,
                        0, COLS-infowidth);


    infowin = subwin(stdscr, LINES-statheight-2, infowidth-2,
                     1, COLS-infowidth+1);

    statusborder = subwin(stdscr, statheight, COLS, LINES-statheight, 0);

    statuswin = subwin(stdscr, statheight-2, COLS-2, LINES-statheight+1, 1);
    scrollok(statuswin, 1);

    return 0;
}

// Maybe recode this in the future
int NCurseFront::WriteStatus(string status) {
    winsertln(statuswin);
    mvwaddstr(statuswin, 0, 1, status.substr(0, COLS-4).c_str());

    return 1;
}

int NCurseFront::DrawDisplay() {
    // The status window takes care of itself

    box(netborder, '|', '-');
    mvwaddstr(netborder, 0, 2, "Networks");
    //    mvwaddstr(netborder, 1, 2, "  SSID                        T W Ch BSSID             Pckts");
    if (COLS < 80) {
        // Do a short identifier
        mvwaddstr(netborder, 1, 2, "  SSID          T W Ch Data LLC");
    } else {
        // Do our normal identifier
        mvwaddstr(netborder, 1, 2, "  SSID                        T W Ch  Data   LLC  Crypt  Wk Flags");
    }

    char gpsdata[1024];
//    if (gps != NULL) {
    float lat, lon, alt, spd;
    int mode;

    client->FetchLoc(&lat, &lon, &alt, &spd, &mode);

    if (!(lat == 0 && lon == 0 && alt == 0 && spd == 0 && mode == 0)) {

        char fix[16];

        if (mode == -1)
            snprintf(fix, 16, "No signal");
        else if (mode == 2)
            snprintf(fix, 5, "2D");
        else if (mode == 3)
            snprintf(fix, 5, "3D");
        else
            snprintf(fix, 5, "NONE");

        snprintf(gpsdata, 1024, "Lat %.3f Lon %.3f Alt %.3f Spd %.3f Fix %s",
                 lat, lon, alt, spd, fix);

        mvwaddstr(netborder, LINES-statheight-1, 2, gpsdata);

        // fprintf(stderr, "found: %f %f %f %f\n", lat, lon, alt, spd);

    }

    box(infoborder, '|', '-');
    mvwaddstr(infoborder, 0, 2, "Info");

    mvwaddch(infoborder, LINES-statheight-1, 3, 'H');
    mvwaddch(infoborder, LINES-statheight-1, 5, 'M');
    mvwaddch(infoborder, LINES-statheight-1, 7, 'S');

    box(statusborder, '|', '-');
    mvwaddstr(statusborder, 0, 2, "Status");

    // Now draw the info window
    char info[infowidth-2];
    werase(infowin);

    mvwaddstr(infowin, 0, 1, "Ntwrks");
    snprintf(info, infowidth-2, "%6d", client->FetchNumNetworks());
    mvwaddstr(infowin, 1, 1, info);

    mvwaddstr(infowin, 2, 1, "Pckets");
    snprintf(info, infowidth-2, "%6d", client->FetchNumPackets());
    mvwaddstr(infowin, 3, 1, info);

    mvwaddstr(infowin, 4, 1, "Cryptd");
    snprintf(info, infowidth-2, "%6d", client->FetchNumCrypt());
    mvwaddstr(infowin, 5, 1, info);

    mvwaddstr(infowin, 6, 1, "  Weak");
    snprintf(info, infowidth-2, "%6d", client->FetchNumInteresting());
    mvwaddstr(infowin, 7, 1, info);

    mvwaddstr(infowin, 8, 1, " Noise");
    snprintf(info, infowidth-2, "%6d", client->FetchNumNoise());
    mvwaddstr(infowin, 9, 1, info);

    mvwaddstr(infowin, 10, 1, "Discrd");
    snprintf(info, infowidth-2, "%6d", client->FetchNumDropped());
    mvwaddstr(infowin, 11, 1, info);

    mvwaddstr(infowin, LINES-statheight-4, 1, "Elapsd");
    time_t elapsed = client->FetchTime() - start_time;
    snprintf(info, infowidth-2, "%02d%02d%02d",
             (int) (elapsed / 60) / 60, (int) (elapsed / 60) % 60,
             (int) elapsed % 60);
    mvwaddstr(infowin, LINES-statheight-3, 1, info);

    // Handle trimming the network list
    vector<wireless_network *> network_vector = client->FetchNthRecent(LINES-3-statheight);

    int num = 0;

    werase(netwin);

    for (unsigned int i = 0; i < network_vector.size(); i++) {
        wireless_network *net = network_vector[i];

        char statchar;
        if ((client->FetchTime() - net->last_time) < decay)
            statchar = '!';
        else if ((client->FetchTime() - net->last_time) < (decay * 2))
            statchar = '.';
        else
            statchar = ' ';
        mvwaddch(netwin, num, 1, statchar);

        char statstr[1024];
        memset(statstr, 0, 1024);

        if (COLS < 80) {
            if (net->cloaked)
                snprintf(statstr, 14, "<%s>", net->ssid.c_str());
            else
                snprintf(statstr, 14, "%s", net->ssid.c_str());
        } else {
            if (net->cloaked)
                snprintf(statstr, 28, "<%s>", net->ssid.c_str());
            else
                snprintf(statstr, 28, "%s", net->ssid.c_str());
        }

        mvwaddstr(netwin, num, 3, statstr);

        char type;
        if (net->type == network_ap)
            type = 'A';
        else if (net->type == network_adhoc)
            type = 'H';
        else if (net->type == network_probe)
            type = 'P';
        else if (net->type == network_data)
            type = 'D';
        else if (net->type == network_lor)
            type = 'O';
        else
            type = '?';

        int pos;
        if (COLS < 80) {
            pos = 17;
        } else {
            pos = 31;
        }

        mvwaddch(netwin, num, pos, type);
        pos += 2;

        mvwaddch(netwin, num, pos, (net->wep == 1) ? 'Y' : 'N');
        pos += 2;

        snprintf(statstr, 3, "%02d", net->channel);
        mvwaddstr(netwin, num, pos, statstr);
        pos += 3;

        snprintf(statstr, 6, "%5d", net->data_packets);
        mvwaddstr(netwin, num, pos, statstr);
        pos += 6;

        snprintf(statstr, 6, "%5d", net->llc_packets);
        mvwaddstr(netwin, num, pos, statstr);
        pos += 7;

        if (COLS >= 80) {
            snprintf(statstr, 6, "%5d", net->crypt_packets);
            mvwaddstr(netwin, num, pos, statstr);
            pos += 7;

            snprintf(statstr, 3, "%2d", net->interesting_packets);
            mvwaddstr(netwin, num, pos, statstr);
            pos += 3;

            char atype;
            if (net->ipdata.atype == address_dhcp)
                atype = 'D';
            else if (net->ipdata.atype == address_arp)
                atype = 'A';
            else if (net->ipdata.atype == address_udp)
                atype = 'U';
            else
                atype = ' ';

            snprintf(statstr, 6, "%c%c%c%c%c",
                     atype,
                     net->ipdata.octets != 0 ? net->ipdata.octets + '0' : ' ',
                     net->cisco_equip.size() > 0 ? 'C' : ' ',
                     ' ',
                     ' ');
            mvwaddstr(netwin, num, pos, statstr);

            /*
             mvwaddstr(netwin, num, 38, net->bssid.c_str());

             snprintf(statstr, 5, "%d", (net->data_packets + net->llc_packets));
             mvwaddstr(netwin, num, 56, statstr);
             */
        }

        if (num++ > LINES-3-statheight)
            break;
    }
    wrefresh(netborder);
    wrefresh(infoborder);
    wrefresh(statusborder);
    wrefresh(statuswin);
    wrefresh(netwin);
    wrefresh(infowin);
    refresh();

    return 1;
}

int NCurseFront::EndDisplay() {
    endwin();

    return 1;
}

#endif
