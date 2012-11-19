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

#include <unistd.h>
#include "util.h"
#include "macaddr.h"
// #include "packet.h"

// Pre-defs for all the things we point to
class MessageBus;
class Packetsourcetracker;

// Old network tracking core due to be removed
class Netracker;
// new multiphy tracking core
class Devicetracker;

class Packetchain;
class Alertracker;
class Timetracker;
class KisNetFramework;
class KisDroneFramework;
class ConfigFile;
class GroupConfigFile;
class SoundControl;
class Plugintracker;
class KisBuiltinDissector;
// We need these for the vectors of subservices to poll
class Pollable;
// Vector of dumpfiles to destroy
class Dumpfile;
// ipc system
class IPCRemote;
class RootIPCRemote;
class KisPanelInterface;
// Manuf db
class Manuf;
// Pcap dump (only built-in dumpfile which supports plugin hooks currently)
class Dumpfile_Pcap;

#define KISMET_INSTANCE_SERVER	0
#define KISMET_INSTANCE_DRONE	1
#define KISMET_INSTANCE_CLIENT	2

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
#define PROTO_REF_BSSID			7
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
#define PROTO_REF_SSID			18
#define PROTO_REF_MAX			19

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
#define PACK_COMP_FCSBYTES		13
#define PACK_COMP_DEVICE		14
#define PACK_COMP_COMMON		15
#define PACK_COMP_CHECKSUM		16
#define PACK_COMP_DECAP			17
#define PACK_COMP_MAX			18

// Same game again, with alerts that internal things need to generate
#define ALERT_REF_KISMET		0
#define ALERT_REF_MAX			1

// Define some macros (ew) to shortcut into the vectors we had to build for
// fast access.  Kids, don't try this at home.

// DEPRECATED... Trying to switch to each component registering by name
// and finding related component by name.  Try to avoid using _PCM etc
// in future code
#define _PCM(x)		globalreg->packetcomp_map[(x)]
#define _NPM(x)		globalreg->netproto_map[(x)]
#define _ARM(x)		globalreg->alertref_map[(x)]
#define _ALERT(x, y, z, a)	globalreg->alertracker->RaiseAlert((x), (y), \
	(z)->bssid_mac, (z)->source_mac, (z)->dest_mac, (z)->other_mac, \
	(z)->channel, (a))
#define _COMMONALERT(t, p, c, a)  globalreg->alertracker->RaiseAlert((t), (p), \
	(c)->device, (c)->source, (c)->dest, mac_addr(0), (c)->channel, (a))

// Send a msg via gloablreg msgbus
#define _MSG(x, y)	globalreg->messagebus->InjectMessage((x), (y))

// Record how a pid died
struct pid_fail {
	pid_t pid;
	int status;
};

// Record of how we failed critically.  We want to spin a critfail message out
// to the client so it can do something intelligent.  A critical fail is something
// like the root IPC process failing to load, or dropping dead.
struct critical_fail {
	time_t fail_time;
	string fail_msg;
};

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

	// What are we? server, drone, client
	int kismet_instance;

	// getopt-long number for arguments that don't take a short letter
	// Anything using a getopt long should grab this and increment it
	int getopt_long_num;
	
    // Fatal terminate condition, as soon as we detect this in the main code we
    // should initiate a shutdown
    int fatal_condition;
	// Are we in "spindown" mode, where we're giving components a little time
	// to clean up their business with pollables and shut down
	int spindown;

	// Did we receive a SIGWINCH that hasn't been dealt with yet?
	bool winch;
    
    MessageBus *messagebus;
	Plugintracker *plugintracker;
    Packetsourcetracker *sourcetracker;
	
	// Old network tracker due to be removed
    Netracker *netracker;
	// New multiphy tracker
	Devicetracker *devicetracker;

    Packetchain *packetchain;
    Alertracker *alertracker;
    Timetracker *timetracker;
    KisNetFramework *kisnetserver;
    KisDroneFramework *kisdroneserver;
    ConfigFile *kismet_config;
    ConfigFile *kismetui_config;
    SoundControl *soundctl;
	KisBuiltinDissector *builtindissector;
	RootIPCRemote *rootipc;
	KisPanelInterface *panel_interface;
	Manuf *manufdb;

	string log_prefix;

	string version_major;
	string version_minor;
	string version_tiny;
	string revision;
	string revdate;

	// Map of named file pipes that sub-components should use
	map<string, int> namedfd_map;

	// Vector of pollable subservices for main()...  You should use the util 
	// functions for this, but main needs to be able to see it directly
	vector<Pollable *> subsys_pollable_vec;

	// Vector of dumpfiles to close cleanly
	vector<Dumpfile *> subsys_dumpfile_vec;

	// Vector of child signals
	vector<pid_fail> sigchild_vec;
	
    time_t start_time;
    string servername;
	struct timeval timestamp;

	string homepath;

	string logname;

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
   
    mac_addr broadcast_mac, empty_mac;

    int alert_backlog;

    // Packet component references we use internally and don't want to keep looking up
	int packetcomp_map[PACK_COMP_MAX];

	// Alert references
	int alertref_map[ALERT_REF_MAX];

	unsigned int crc32_table[256];

	Dumpfile_Pcap *pcapdump;

	// global netlink reference 
	void *nlhandle;

	// Critical failure elements
	vector<critical_fail> critfail_vec;
    
    GlobalRegistry();

    // External globals -- allow other things to tie structs to us
    int RegisterGlobal(string in_name);
    int FetchGlobalRef(string in_name);

    void *FetchGlobal(int in_ref);
	void *FetchGlobal(string in_name);

    int InsertGlobal(int in_ref, void *in_data);
	int InsertGlobal(string in_name, void *in_data);

	// Add something to the poll() main loop
	int RegisterPollableSubsys(Pollable *in_subcli);
	int RemovePollableSubsys(Pollable *in_subcli);

	// Add a log file
	void RegisterDumpFile(Dumpfile *in_dump);
	int RemoveDumpFile(Dumpfile *in_dump);
	Dumpfile *FindDumpFileType(string in_type);

	// Are we supposed to start checksumming packets?  (ie multiple sources, 
	// whatever other conditions we use)
	int checksum_packets;

	// Add & retreive a named FD
	void AddNamedFd(string name, int fd);
	int GetNamedFd(string name);

protected:
    // Exernal global references, string to intid
    map<string, int> ext_name_map;
    // External globals
    map<int, void *> ext_data_map;
    int next_ext_ref;
};

#endif

// vim: ts=4:sw=4
