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

#ifndef __NCURSEFRONT_H__
#define __NCURSEFRONT_H__

#include "config.h"

const int infowidth = 10;
const int statheight = 6;

#if defined(HAVE_LIBNCURSES) && defined(BUILD_CURSES)

#ifdef HAVE_LIBCURSES
#include <curses.h>
#else
#include <ncurses.h>
#endif
#undef erase
#undef move
#undef clear

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <string>
#include <vector>

#include "packet.h"
#include "frontend.h"

class NCurseFront : public Frontend {
public:
    NCurseFront();

    void AddClient(TcpClient *in_client) { client = in_client; }

    void FetchClients(vector<TcpClient *> *in_vec) {
        in_vec->clear();
        in_vec->push_back(client);
    }

    TcpClient *FetchPrimaryClient() {
        return client;
    }

    void AddPrefs(map<string, string> in_prefs) { return; }

    int ParseArgs(int argc, char *argv[]) { return 0; }

    int Tick() { return 0; }

    int Poll() { return 0; }

    int InitDisplay(int in_decay, time_t in_start);

    // Draw the screen
    int DrawDisplay();

    // End
    int EndDisplay();

    int WriteStatus(string status);

protected:
    void DelOldest(wireless_network *exclude);

    WINDOW *netborder, *netwin, *infoborder, *infowin,
        *statusborder, *statuswin;

};

#endif

#endif
