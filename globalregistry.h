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

#include <atomic>
#include <unistd.h>
#include <memory>

#include "util.h"
#include "kis_mutex.h"
#include "macaddr.h"
#include "uuid.h"

#include "fmt.h"

class GlobalRegistry;

// Pre-defs for all the things we point to
class MessageBus;

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
class SoundControl;
class Plugintracker;
class KisBuiltinDissector;
// We need these for the vectors of subservices to poll
class Pollable;
// ipc system
class IPCRemote;
class RootIPCRemote;
class KisPanelInterface;
// Manuf db
class Manuf;
// Field name resolver
class EntryTracker;
// HTTP server
class Kis_Net_Httpd;

#define KISMET_INSTANCE_SERVER	0
#define KISMET_INSTANCE_DRONE	1
#define KISMET_INSTANCE_CLIENT	2

// TODO remove these when netserver is fully removed
//
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
#define _ALERT(x, y, z, a)	Globalreg::globalreg->alertracker->RaiseAlert((x), (y), \
	(z)->bssid_mac, (z)->source_mac, (z)->dest_mac, (z)->other_mac, \
	(z)->channel, (a))
#define _COMMONALERT(t, p, c, b, a)  Globalreg::globalreg->alertracker->RaiseAlert((t), (p), \
	(b), (c)->source, (c)->dest, mac_addr(0), (c)->channel, (a))

// Send a msg via gloablreg msgbus
#define _MSG(x, y)	Globalreg::globalreg->messagebus->InjectMessage((x), (y))

// fmt-enabled msgbus
#define _MSG_DEBUG(...) \
    Globalreg::globalreg->messagebus->InjectMessage(fmt::format(__VA_ARGS__), MSGFLAG_DEBUG)

#define _MSG_INFO(...) \
    Globalreg::globalreg->messagebus->InjectMessage(fmt::format(__VA_ARGS__), MSGFLAG_INFO)

#define _MSG_ERROR(...) \
    Globalreg::globalreg->messagebus->InjectMessage(fmt::format(__VA_ARGS__), MSGFLAG_ERROR)

#define _MSG_ALERT(...) \
    Globalreg::globalreg->messagebus->InjectMessage(fmt::format(__VA_ARGS__), MSGFLAG_ALERT)

#define _MSG_FATAL(...) \
    Globalreg::globalreg->messagebus->InjectMessage(fmt::format(__VA_ARGS__), MSGFLAG_FATAL)

// Record of how we failed critically.  We want to spin a critfail message out
// to the client so it can do something intelligent.  A critical fail is something
// like the root IPC process failing to load, or dropping dead.
struct critical_fail {
	time_t fail_time;
    std::string fail_msg;
};

// Stub class for global data
class SharedGlobalData {
public:
    virtual ~SharedGlobalData() { }
};

// Stub class for lifetime globals to inherit from to get auto-destroyed on exit
class LifetimeGlobal : public SharedGlobalData {
public:
    virtual ~LifetimeGlobal() { }
};

// Stub class for async objects that need to be triggered after the rest of the
// system has started up, such as the datasourcetracker and the log tracker
class DeferredStartup {
public:
    virtual ~DeferredStartup() { }

    virtual void Deferred_Startup() = 0;
    virtual void Deferred_Shutdown() = 0;
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

    uuid server_uuid;
    uint64_t server_uuid_hash;

	// getopt-long number for arguments that don't take a short letter
	// Anything using a getopt long should grab this and increment it
	int getopt_long_num;
	
    // Fatal terminate condition, as soon as we detect this in the main code we
    // should initiate a shutdown
    std::atomic<int> fatal_condition;
	// Are we in "spindown" mode, where we're giving components a little time
	// to clean up their business with pollables and shut down
    std::atomic<int> spindown;

	// Did we receive a SIGWINCH that hasn't been dealt with yet?
	bool winch;
    
    MessageBus *messagebus;

    // Globals which should be deprecated in favor of named globals; all code should
    // be migrated to the shared pointer references

	// New multiphy tracker
	Devicetracker *devicetracker;

    Packetchain *packetchain;
    Alertracker *alertracker;
    Timetracker *timetracker;
    ConfigFile *kismet_config;
	KisBuiltinDissector *builtindissector;
	Manuf *manufdb;

    std::string log_prefix;

    std::string version_major;
	std::string version_minor;
	std::string version_tiny;
    std::string version_git_rev;
    std::string build_date;

	// Vector of child signals
    pid_t sigchild_vec[1024];
    std::atomic<unsigned int> sigchild_vec_pos;
	
    time_t start_time;
    std::string servername;
	struct timeval timestamp;

    std::string etc_dir;
    std::string data_dir;
    std::string homepath;

    std::string logname;
   
    mac_addr broadcast_mac, empty_mac, multicast_mac;

    int alert_backlog;

    // Packet component references we use internally and don't want to keep looking up
	int packetcomp_map[PACK_COMP_MAX];

	// Alert references
	int alertref_map[ALERT_REF_MAX];

	unsigned int crc32_table[256];

	// Critical failure elements
    std::vector<critical_fail> critfail_vec;

    // Field name tracking
    EntryTracker *entrytracker;
    
    GlobalRegistry();

    // External globals -- allow other things to tie structs to us
    int RegisterGlobal(std::string in_name);
    int FetchGlobalRef(std::string in_name);

    std::shared_ptr<void> FetchGlobal(int in_ref);
	std::shared_ptr<void> FetchGlobal(std::string in_name);

    int InsertGlobal(int in_ref, std::shared_ptr<void> in_data);
	int InsertGlobal(std::string in_name, std::shared_ptr<void> in_data);
    void RemoveGlobal(int in_ref);
    void RemoveGlobal(std::string in_name);

    // Add a CLI extension
    typedef void (*usage_func)(const char *);
    void RegisterUsageFunc(usage_func in_cli);
    void RemoveUsageFunc(usage_func in_cli);
    std::vector<usage_func> usage_func_vec;

	// Are we supposed to start checksumming packets?  (ie multiple sources, 
	// whatever other conditions we use)
	int checksum_packets;

    void RegisterLifetimeGlobal(std::shared_ptr<LifetimeGlobal> in_g);
    void RemoveLifetimeGlobal(std::shared_ptr<LifetimeGlobal> in_g);
    void DeleteLifetimeGlobals();

    void RegisterDeferredGlobal(std::shared_ptr<DeferredStartup> in_d);
    void RemoveDeferredGlobal(std::shared_ptr<DeferredStartup> in_d);
    void Start_Deferred();
    void Shutdown_Deferred();

protected:
    kis_recursive_timed_mutex ext_mutex;
    // Exernal global references, string to intid
    std::map<std::string, int> ext_name_map;
    // External globals
    std::map<int, std::shared_ptr<void> > ext_data_map;
    std::atomic<int> next_ext_ref;

    kis_recursive_timed_mutex lifetime_mutex;
    std::vector<std::shared_ptr<LifetimeGlobal> > lifetime_vec;

    kis_recursive_timed_mutex deferred_mutex;
    bool deferred_started;
    std::vector<std::shared_ptr<DeferredStartup> > deferred_vec;
};

namespace Globalreg {
    extern GlobalRegistry *globalreg;

    template<typename T> 
    std::shared_ptr<T> FetchGlobalAs(GlobalRegistry *in_globalreg, int in_ref) {
        return std::static_pointer_cast<T>(in_globalreg->FetchGlobal(in_ref));
    }

    template<typename T> 
    std::shared_ptr<T> FetchGlobalAs(int in_ref) {
        return FetchGlobalAs<T>(Globalreg::globalreg, in_ref);
    }

    template<typename T> 
    std::shared_ptr<T> FetchGlobalAs(GlobalRegistry *in_globalreg, const std::string& in_name) {
        return std::static_pointer_cast<T>(in_globalreg->FetchGlobal(in_name));
    }

    template<typename T> 
    std::shared_ptr<T> FetchGlobalAs(const std::string& in_name) {
        return FetchGlobalAs<T>(globalreg, in_name);
    }

    template<typename T>
    std::shared_ptr<T> FetchGlobalAs() {
        return FetchGlobalAs<T>(globalreg, T::global_name());
    }

    template<typename T> 
    std::shared_ptr<T> FetchMandatoryGlobalAs(GlobalRegistry *in_globalreg, 
            const std::string& in_name) {
        std::shared_ptr<T> r = std::static_pointer_cast<T>(in_globalreg->FetchGlobal(in_name));

        if (r == nullptr) 
            throw std::runtime_error(fmt::format("Unable to find '{}' in the global registry, "
                        "code initialization may be out of order.", in_name));

        return r;
    }

    template<typename T> 
    std::shared_ptr<T> FetchMandatoryGlobalAs(const std::string& in_name) {
        return FetchMandatoryGlobalAs<T>(Globalreg::globalreg, in_name);
    }

    template<typename T>
    std::shared_ptr<T> FetchMandatoryGlobalAs() {
        return FetchMandatoryGlobalAs<T>(Globalreg::globalreg, T::global_name());
    }
}


#endif

