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

#ifndef __FRONTEND_H__
#define __FRONTEND_H__

// I tend to think this should be split into a front end and a
// packet tracker

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <string>
#include <vector>

#include "packet.h"
#include "tcpclient.h"
#include "packetracker.h"
#include "manuf.h"

enum sort_type {
    sort_auto, sort_channel, sort_first, sort_first_dec,
    sort_last, sort_last_dec, sort_bssid, sort_bssid_dec,
    sort_ssid, sort_ssid_dec, sort_wep, sort_packets, sort_packets_dec,
    sort_quality, sort_signal,
};

enum group_type {
    group_host, group_bundle, group_sub, group_empty,
};

// What do we actually display
typedef struct display_network {
    // Are we a group or just a single network?
    group_type type;
    // If we're a group, this will hold multiple networks
    vector<wireless_network *> networks;
    // Are we tagged?
    int tagged;
    // Are we expanded?
    int expanded;
    // our virtual wireless network built out of all our members
    wireless_network virtnet;
    // name
    string name;
    // Identifying tag (bssid of the origional network most likely)
    string tag;
};


// Front end events
#define FE_QUIT -100

class Frontend {
public:
    virtual ~Frontend() {}

    virtual void AddPrefs(map<string, string> in_prefs) = 0;

    void AddClient(TcpClient *in_client) { client = in_client; }

    // Handle consistent tick operations
    virtual int Tick() = 0;

    virtual int Poll() = 0;

    // Handle anything special in the arguments
    virtual int ParseArgs(int argc, char *argv[]) = 0;

    // Init the screen
    virtual int InitDisplay(int in_decay, time_t in_start) = 0;

    // Draw the screen
    virtual int DrawDisplay() = 0;

    // End
    virtual int EndDisplay() = 0;

    virtual int WriteStatus(string status) = 0;

    // Get the error
    char *FetchError() { return errstr; }

    // Load group data from the stored groupfile
    void ReadGroupMap(FILE *in_file);
    void WriteGroupMap(FILE *in_file);

    void RemoveGroup(string in_bssid);

protected:
    int decay;
    char errstr[1024];

    time_t start_time;

    TcpClient *client;

    string Mac2String(uint8_t *mac, char seperator);

    // Populate groups with data from the client -- fetch all the networks and put
    // them in the groups they should be in
    void PopulateGroups();
    // Update our groups.  This controls how group aggregate data gets generated.
    void UpdateGroups();
    // Group all the tagged networks
    display_network *GroupTagged();
    // Destroy a group
    void DestroyGroup(display_network *in_group);

    double CalcRad(double lat);
    double EarthDistance(double lat1, double lon1, double lat2, double lon2);
    double Rad2Deg(double x);

    // Tracking groups is a real pain.  We need to know all our active groups,
    // then we need all the bssid to group names that we have stored, then we need
    // all the names to group structures to find a group when we create it,
    // and THEN we need all the BSSID's to group structures.

    // All of this looks really ugly, but it means we never do more than a tree
    // search for a network, and a lot of it is pointers so we don't loose as much
    // memory as it sounds like.

    // List of display groups and single networks
    vector<display_network *> group_vec;

    // Mapping of potential BSSID's to group tags so we know WHERE to put someone
    map<uint8_t *, string, STLMacComp> bssid_group_map;

    // Map of group tag to group name
    map<string, string> group_name_map;

    // Mapping of group names to actual groups
    map<string, display_network *> group_tag_map;

    // Mapping of BSSID's to groups we've assigned them to, so we can quickly
    // add someone to a group if they're not there yet
    map<uint8_t *, display_network *, STLMacComp> group_assignment_map;

    map<string, string> prefs;

};

#endif

