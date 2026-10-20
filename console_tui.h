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

#ifndef __CONSOLE_TUI_H__
#define __CONSOLE_TUI_H__

#include "config.h"

#include <string>

// Full screen status display for the server console: a banner with the web UI address,
// a packet rate graph per datasource, device and memory graphs, and the server messages.
// Drawn with ANSI escapes and braille dot graphs, without ncurses.
namespace console_tui {
    // Take over the terminal; false if stdout isn't a terminal
    bool start();

    // Restore the terminal and print the most recent messages
    void stop();

    bool active();

    // Record a server message; safe from any thread, with any locks held.  Messages are
    // kept before the display starts so it can show them.
    void add_message(unsigned int flags, const std::string& msg);
}

#endif
