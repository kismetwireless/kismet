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

#include "packet.h"
#include "frontend.h"

class NCurseFront : public Frontend {
public:
    NCurseFront();

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
