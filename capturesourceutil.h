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

#ifndef __CAPTURESOURCEUTIL_H__
#define __CAPTURESOURCEUTIL_H__

#include "config.h"

#include <string>
#include <vector>
#include <map>

#include "timetracker.h"
#include "packetsource.h"
#include "prism2source.h"
#include "pcapsource.h"
#include "wtapfilesource.h"
#include "wsp100source.h"
#include "vihasource.h"
#include "dronesource.h"

typedef struct capturesource {
    KisPacketSource *source;
    string name;
    string interface;
    string scardtype;
    card_type cardtype;
    packet_parm packparm;
    int childpair[2];
    int servpair[2];
    int textpair[2];
    pid_t childpid;
    int alive;
};

map<string, int> ParseEnableLine(string in_named);
int ParseCardLines(vector<string> *in_lines, vector<capturesource *> *in_capsources);
int BindRootSources(vector<capturesource *> *in_capsources,
                    map<string, int> *in_enable, int filter_enable,
                    Timetracker *in_tracker, GPSD *in_gps);
int BindUserSources(vector<capturesource *> *in_capsources,
                    map<string, int> *in_enable, int filter_enable,
                    Timetracker *in_tracker, GPSD *in_gps);

#endif
