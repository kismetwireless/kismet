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
#include <list>

#include "timetracker.h"
#include "packetsource.h"
#include "prism2source.h"
#include "pcapsource.h"
#include "wtapfilesource.h"
#include "wsp100source.h"
#include "vihasource.h"
#include "dronesource.h"
#include "util.h"
#include "server_globals.h"

// IPC frame.  We define it up here since we need it for the capturesource
// We don't transmit data* but we need it locally
typedef struct capchild_packhdr {
    uint32_t sentinel;
    int8_t packtype;
    int8_t flags;
    int32_t datalen;
    uint8_t *data;
};

typedef struct capturesource {
    KisPacketSource *source;
    string name;
    string interface;
    string scardtype;
    card_type cardtype;
    packet_parm packparm;
    int childpair[2];
    pid_t childpid;
    int alive;
    vector<int> channels;
    int ch_pos;
    int ch_hop;
    list<capchild_packhdr *> cmd_buf;
};

map<string, int> ParseEnableLine(string in_named);
int ParseCardLines(vector<string> *in_lines, vector<capturesource *> *in_capsources);
int BindRootSources(vector<capturesource *> *in_capsources,
                    map<string, int> *in_enable, int filter_enable,
                    Timetracker *in_tracker, GPSD *in_gps);
int BindUserSources(vector<capturesource *> *in_capsources,
                    map<string, int> *in_enable, int filter_enable,
                    Timetracker *in_tracker, GPSD *in_gps);
vector<int> ParseChannelLine(string in_channels);
int ParseSetChannels(vector<string> *in_sourcechanlines, vector<capturesource *> *in_capsources,
                     int in_chsplit, vector<int> *in_80211adefaults, vector<int> *in_80211bdefaults);

// negative numbers are commands, positive numbers are a channel set.  All commands are
// one byte.
#define CAPCMD_NULL      0   // Don't do anything, just something to see if the pipe is still there
#define CAPCMD_ACTIVATE -1   // Start watching the sniffer
#define CAPCMD_FLUSH    -2   // Flush the ring buffer and loose any packets we have
#define CAPCMD_TXTFLUSH -3   // Flush text buffer
#define CAPCMD_SILENT   -4   // Enable silence (no stdout output)
#define CAPCMD_DIE      -5   // Close the source and die
#define CAPCMD_PAUSE    -6   // Pause
#define CAPCMD_RESUME   -7   // Resume

// Sentinel for starting a new packet
#define CAPSENTINEL      0xDECAFBAD

// What type of frame it is in the child datagram
#define CAPPACK_COMMAND  0
#define CAPPACK_PACKET   1
#define CAPPACK_TEXT     2

// What sort of extra info can we carry with the text?
#define CAPFLAG_NONE     0
#define CAPFLAG_FATAL    1

int SpawnCapSourceChild(capturesource *csrc);
int SendChildCommand(capturesource *csrc, int in_cmd);
int FetchChildBlock(int in_fd, kis_packet *packet, uint8_t *data, uint8_t *moddata, string *in_text);

#endif
