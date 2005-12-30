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

#ifndef __GLOBALREGISTRY_H__
#define __GLOBALREGISTRY_H__

#include "config.h"

#include "version.h"
#include "util.h"
#include "macaddr.h"
// #include "packet.h"

// Pre-defs for all the things we point to
class MessageBus;
class Packetsourcetracker;
class Netracker;
class Packetchain;
class Alertracker;
class Timetracker;
class KisNetFramework;
class KisDroneFramework;
class ConfigFile;
class GroupConfigFile;
class SpeechControl;
class SoundControl;
class Plugintracker;
class KisBuiltinDissector;
// We need these for the vectors of subservices to poll
class Pollable;
// Vector of dumpfiles to destroy
class Dumpfile;
class Dumpfile_Runstate;
// Root-level ipc system
class IPCRemote;

// These are the offsets into the array of protocol references, not
// the reference itself.
// tcpserver protocol numbers for all the builtin protocols kismet
// uses and needs to refer to internally.  Modules are on their own
// for tracking this.
#define PROTO_REF_KISMET		0
#define PROTO_REF_ERROR			1
#define PROTO_REF_ACK			2
#define PROTO_REF_PROTOCOL		3
#define PROTO_REF_CAPABILITY	4
#define PROTO_REF_TERMINATE		5
#define PROTO_REF_TIME			6
#define PROTO_REF_NETWORK		7
#define PROTO_REF_CLIENT		8
#define PROTO_REF_CARD			9
#define PROTO_REF_GPS			10
#define PROTO_REF_ALERT			11
#define PROTO_REF_STATUS		12
#define PROTO_REF_INFO			13
#define PROTO_REF_REMOVE		14
#define PROTO_REF_PACKET		15
#define PROTO_REF_STRING		16
#define PROTO_REF_WEPKEY		17
#define PROTO_REF_MAX			18

// Same game, packet component references
#define PACK_COMP_80211			0
#define PACK_COMP_TURBOCELL		1
#define PACK_COMP_RADIODATA		2
#define PACK_COMP_GPS			3
#define PACK_COMP_LINKFRAME		4
#define PACK_COMP_80211FRAME	5
#define PACK_COMP_MANGLEFRAME	6
#define PACK_COMP_TRACKERNET	7
#define PACK_COMP_TRACKERCLIENT	8
#define PACK_COMP_KISCAPSRC		9
#define PACK_COMP_ALERT			10
#define PACK_COMP_BASICDATA		11
#define PACK_COMP_STRINGS		12
#define PACK_COMP_MAX			13

// Same game again, with alerts that internal things need to generate
#define ALERT_REF_KISMET		0
#define ALERT_REF_MAX			1

// Define some macros (ew) to shortcut into the vectors we had to build for
// fast access.  Kids, don't try this at home.
#define _PCM(x)		globalreg->packetcomp_map[(x)]
#define _NPM(x)		globalreg->netproto_map[(x)]
#define _ARM(x)		globalreg->alertref_map[(x)]
#define _ALERT(x, y, z, a)	globalreg->alertracker->RaiseAlert((x), (y), \
	(z)->bssid_mac, (z)->source_mac, (z)->dest_mac, (z)->other_mac, \
	(z)->channel, (a))

// Send a msg via gloablreg msgbus
#define _MSG(x, y)	globalreg->messagebus->InjectMessage((x), (y))

// Global registry of references to tracker objects and preferences.  This 
// should supplant the masses of globals and externs we'd otherwise need.
// 
// Really this just just a big ugly hack to do globals without looking like
// we're doing globals, but it's a lot nicer for maintenance at least.
class GlobalRegistry {
public:
	// argc and argv for modules to allow overrides
	int argc;
	char **argv;
	char **envp;

	// getopt-long number for arguments that don't take a short letter
	// Anything using a getopt long should grab this and increment it
	int getopt_long_num;
	
    // Fatal terminate condition, as soon as we detect this in the main code we
    // should initiate a shutdown
    int fatal_condition;
	// Are we in "spindown" mode, where we're giving components a little time
	// to clean up their business with pollables and shut down
	int spindown;
    
    MessageBus *messagebus;
	Plugintracker *plugintracker;
    Packetsourcetracker *sourcetracker;
    Netracker *netracker;
    Packetchain *packetchain;
    Alertracker *alertracker;
    Timetracker *timetracker;
    KisNetFramework *kisnetserver;
    KisDroneFramework *kisdroneserver;
    ConfigFile *kismet_config;
	GroupConfigFile *runstate_config;
    ConfigFile *kismetui_config;
    SpeechControl *speechctl;
    SoundControl *soundctl;
	KisBuiltinDissector *builtindissector;
	IPCRemote *rootipc;
	Dumpfile_Runstate *runstate_dumper;

	string version_major;
	string version_minor;
	string version_tiny;

	// Vector of pollable subservices for main()...  You should use the util 
	// functions for this, but main needs to be able to see it directly
	vector<Pollable *> subsys_pollable_vec;

	// Vector of dumpfiles to close cleanly
	vector<Dumpfile *> subsys_dumpfile_vec;
	
    time_t start_time;
    string servername;
	struct timeval timestamp;

    unsigned int metric;

    // Protocol references we don't want to keep looking up
	int netproto_map[PROTO_REF_MAX];

    // Filter maps for the various filter types
    int filter_tracker;
    macmap<int> filter_tracker_bssid;
    macmap<int> filter_tracker_source;
    macmap<int> filter_tracker_dest;
    int filter_tracker_bssid_invert, filter_tracker_source_invert,
        filter_tracker_dest_invert;

    int filter_dump;
    macmap<int> filter_dump_bssid;
    macmap<int> filter_dump_source;
    macmap<int> filter_dump_dest;
    int filter_dump_bssid_invert, filter_dump_source_invert,
        filter_dump_dest_invert;

    int filter_export;
    macmap<int> filter_export_bssid;
    macmap<int> filter_export_source;
    macmap<int> filter_export_dest;
    int filter_export_bssid_invert, filter_export_source_invert,
        filter_export_dest_invert;
   
    mac_addr broadcast_mac;

    int alert_backlog;

    // Packet component references we use internally and don't want to keep looking up
	int packetcomp_map[PACK_COMP_MAX];

	// Alert references
	int alertref_map[ALERT_REF_MAX];
    
    GlobalRegistry() { 
		version_major = VERSION_MAJOR;
		version_minor = VERSION_MINOR;
		version_tiny = VERSION_TINY;

        fatal_condition = 0;
		spindown = 0;

		argc = 0;
		argv = NULL;
		envp = NULL;

		getopt_long_num = 127;

        next_ext_ref = 0;

        messagebus = NULL;
		plugintracker = NULL;
        sourcetracker = NULL;
		netracker = NULL;
		packetchain = NULL;
        alertracker = NULL;
        timetracker = NULL;
        kisnetserver = NULL;
        kisdroneserver = NULL;
        kismet_config = NULL;
		runstate_config = NULL;
		runstate_dumper = NULL;
        kismetui_config = NULL;
        speechctl = NULL;
        soundctl = NULL;
		builtindissector = NULL;
		rootipc = NULL;

        start_time = 0;

        metric = 0;

		for (int x = 0; x < PROTO_REF_MAX; x++)
			netproto_map[x] = -1;

        filter_tracker = 0;
        filter_tracker_bssid_invert = -1;
        filter_tracker_source_invert = -1;
        filter_tracker_dest_invert = -1;

        filter_dump = 0;
        filter_dump_bssid_invert = -1;
        filter_dump_source_invert = -1;
        filter_dump_dest_invert = -1;

        filter_export = 0;
        filter_export_bssid_invert = -1;
        filter_export_source_invert = -1;
        filter_export_dest_invert = -1;

        broadcast_mac = mac_addr("FF:FF:FF:FF:FF:FF");

        alert_backlog = 0;

		for (unsigned int x = 0; x < PACK_COMP_MAX; x++)
			packetcomp_map[x] = -1;

		for (unsigned int x = 0; x < ALERT_REF_MAX; x++)
			alertref_map[x] = -1;

    }

    // External globals -- allow other things to tie structs to us
    int RegisterExternalGlobal(string in_name) {
        if (ext_name_map.find(StrLower(in_name)) != ext_name_map.end())
            return -1;
        
        ext_name_map[StrLower(in_name)] = next_ext_ref++;
    }

    int FetchExternalGlobalRef(string in_name) {
        if (ext_name_map.find(StrLower(in_name)) != ext_name_map.end())
            return -1;

        return ext_name_map[StrLower(in_name)];
    }

    void *FetchExternalGlobal(int in_ref) {
        if (ext_data_map.find(in_ref) == ext_data_map.end())
            return NULL;

        return ext_data_map[in_ref];
    }

    int InsertExternalGlobal(int in_ref, void *in_data) {
        if (ext_data_map.find(in_ref) == ext_data_map.end())
            return -1;

        ext_data_map[in_ref] = in_data;

        return 1;
    }

	int RegisterPollableSubsys(Pollable *in_subcli) {
		subsys_pollable_vec.push_back(in_subcli);
		return 1;
	}

	int RemovePollableSubsys(Pollable *in_subcli) {
		for (unsigned int x = 0; x < subsys_pollable_vec.size(); x++) {
			if (subsys_pollable_vec[x] == in_subcli) {
				subsys_pollable_vec.erase(subsys_pollable_vec.begin() + x);
				return 1;
			}
		}
		return 0;
	}

	void RegisterDumpFile(Dumpfile *in_dump) {
		subsys_dumpfile_vec.push_back(in_dump);
	}

	int RemoveDumpFile(Dumpfile *in_dump) {
		for (unsigned int x = 0; x < subsys_pollable_vec.size(); x++) {
			if (subsys_dumpfile_vec[x] == in_dump) {
				subsys_dumpfile_vec.erase(subsys_dumpfile_vec.begin() + x);
				return 1;
			}
		}
		return 0;
	}

protected:
    // Exernal global references, string to intid
    map<string, int> ext_name_map;
    // External globals
    map<int, void *> ext_data_map;
    int next_ext_ref;
};

#endif

