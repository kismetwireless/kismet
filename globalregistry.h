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

#include "boost/asio.hpp"

class global_registry;

// Pre-defs for all the things we point to
class message_bus;

// new multiphy tracking core
class device_tracker;

class packet_chain;
class alert_tracker;
class time_tracker;
class config_file;
class plugin_tracker;
class KisBuiltinDissector;
// We need these for the vectors of subservices to poll
class kis_pollable;
// kis_manuf db
class kis_manuf;
// Field name resolver
class entry_tracker;
// HTTP server
class kis_net_httpd;

#define KISMET_INSTANCE_SERVER	0
#define KISMET_INSTANCE_DRONE	1
#define KISMET_INSTANCE_CLIENT	2

// Same game again, with alerts that internal things need to generate
#define ALERT_REF_KISMET		0
#define ALERT_REF_MAX			1

// Maximum number of packet components we can track
#define PACK_COMP_MAX 128

// Define some macros (ew) to shortcut into the vectors we had to build for
// fast access.  Kids, don't try this at home.

// DEPRECATED... Trying to switch to each component registering by name
// and finding related component by name.  Try to avoid using _PCM etc
// in future code
#define _ALERT(x, y, z, a)	Globalreg::globalreg->alertracker->raise_alert((x), (y), \
	(z)->bssid_mac, (z)->source_mac, (z)->dest_mac, (z)->other_mac, \
	(z)->channel, (a))
#define _COMMONALERT(t, p, c, b, a)  Globalreg::globalreg->alertracker->raise_alert((t), (p), \
	(b), (c)->source, (c)->dest, mac_addr(0), (c)->channel, (a))

// Send a msg via gloablreg msgbus
#define _MSG(x, y)	Globalreg::globalreg->messagebus->inject_message((x), (y))

// fmt-enabled msgbus
#define _MSG_DEBUG(...) \
    Globalreg::globalreg->messagebus->inject_message(fmt::format(__VA_ARGS__), MSGFLAG_DEBUG)

#define _MSG_INFO(...) \
    Globalreg::globalreg->messagebus->inject_message(fmt::format(__VA_ARGS__), MSGFLAG_INFO)

#define _MSG_ERROR(...) \
    Globalreg::globalreg->messagebus->inject_message(fmt::format(__VA_ARGS__), MSGFLAG_ERROR)

#define _MSG_ALERT(...) \
    Globalreg::globalreg->messagebus->inject_message(fmt::format(__VA_ARGS__), MSGFLAG_ALERT)

#define _MSG_FATAL(...) \
    Globalreg::globalreg->messagebus->inject_message(fmt::format(__VA_ARGS__), MSGFLAG_FATAL)

// Record of how we failed critically.  We want to spin a critfail message out
// to the client so it can do something intelligent.  A critical fail is something
// like the root IPC process failing to load, or dropping dead.
struct critical_fail {
	time_t fail_time;
    std::string fail_msg;
};

// Stub class for global data
class shared_global_data {
public:
    virtual ~shared_global_data() { }
};

// Stub class for lifetime globals to inherit from to get auto-destroyed on exit
class lifetime_global : public shared_global_data {
public:
    virtual ~lifetime_global() { }
};

// Stub class for async objects that need to be triggered after the rest of the
// system has started up, such as the datasourcetracker and the log tracker
class deferred_startup {
public:
    virtual ~deferred_startup() { }

    virtual void trigger_deferred_startup() { };
    virtual void trigger_deferred_shutdown() { };
};

// Global registry of references to tracker objects and preferences.  This 
// should supplant the masses of globals and externs we'd otherwise need.
// 
// Really this just just a big ugly hack to do globals without looking like
// we're doing globals, but it's a lot nicer for maintenance at least.
class global_registry {
public:
	// argc and argv for modules to allow overrides
	int argc;
	char **argv;
	char **envp;

    uuid server_uuid;
    std::size_t server_uuid_hash;

	// getopt-long number for arguments that don't take a short letter
	// Anything using a getopt long should grab this and increment it
	int getopt_long_num;
	
    // Fatal terminate condition, as soon as we detect this in the main code we
    // should initiate a shutdown
    std::atomic<bool> fatal_condition;
	// Are we in "spindown" mode, where we're giving components a little time
	// to clean up their business with pollables and shut down
    std::atomic<bool> spindown;
    // We're done; shut down; service threads should also use this as a final, absolute
    // termination clause
    std::atomic<bool> complete;

    // Signal service thread that gets cleaned up at exit
    std::thread signal_service_thread;
    
    message_bus *messagebus;

    // Globals which should be deprecated in favor of named globals; all code should
    // be migrated to the shared pointer references

	// New multiphy tracker
	device_tracker *devicetracker;

    packet_chain *packetchain;
    alert_tracker *alertracker;
    time_tracker *timetracker;
    config_file *kismet_config;
	KisBuiltinDissector *builtindissector;
	kis_manuf *manufdb;

    std::string log_prefix;

    std::string version_major;
	std::string version_minor;
	std::string version_tiny;
    std::string version_git_rev;
    std::string build_date;

    std::atomic<bool> reap_child_procs;
	
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
    entry_tracker *entrytracker;
    
    global_registry();

    // External globals -- allow other things to tie structs to us
    int RegisterGlobal(std::string in_name);
    int FetchGlobalRef(std::string in_name);

    std::shared_ptr<void> FetchGlobal(int in_ref);
	std::shared_ptr<void> FetchGlobal(std::string in_name);

    int insert_global(int in_ref, std::shared_ptr<void> in_data);
	int insert_global(std::string in_name, std::shared_ptr<void> in_data);
    void remove_global(int in_ref);
    void remove_global(std::string in_name);

    // Add a CLI extension
    typedef void (*usage_func)(const char *);
    void RegisterUsageFunc(usage_func in_cli);
    void RemoveUsageFunc(usage_func in_cli);
    std::vector<usage_func> usage_func_vec;

	// Are we supposed to start checksumming packets?  (ie multiple sources, 
	// whatever other conditions we use)
	int checksum_packets;

    void register_lifetime_global(std::shared_ptr<lifetime_global> in_g);
    void Removelifetime_global(std::shared_ptr<lifetime_global> in_g);
    void delete_lifetime_globals();

    void register_deferred_global(std::shared_ptr<deferred_startup> in_d);
    void remove_deferred_global(std::shared_ptr<deferred_startup> in_d);
    void start_deferred();
    void shutdown_deferred();

    // Global ASIO contexts and IO threads
    const int n_io_threads = static_cast<int>(std::thread::hardware_concurrency() * 4);
    boost::asio::io_context io{n_io_threads};

protected:
    kis_recursive_timed_mutex ext_mutex;
    // Exernal global references, string to intid
    std::map<std::string, int> ext_name_map;
    // External globals
    std::map<int, std::shared_ptr<void> > ext_data_map;
    std::atomic<int> next_ext_ref;

    kis_recursive_timed_mutex lifetime_mutex;
    std::vector<std::shared_ptr<lifetime_global> > lifetime_vec;

    kis_recursive_timed_mutex deferred_mutex;
    bool deferred_started;
    std::vector<std::shared_ptr<deferred_startup> > deferred_vec;
};

namespace Globalreg {
    extern std::atomic<unsigned long> n_tracked_fields;
    extern std::atomic<unsigned long> n_tracked_components;

    extern global_registry *globalreg;

    template<typename T> 
    std::shared_ptr<T> fetch_global_as(global_registry *in_globalreg, int in_ref) {
        return std::static_pointer_cast<T>(in_globalreg->FetchGlobal(in_ref));
    }

    template<typename T> 
    std::shared_ptr<T> fetch_global_as(int in_ref) {
        return fetch_global_as<T>(Globalreg::globalreg, in_ref);
    }

    template<typename T> 
    std::shared_ptr<T> fetch_global_as(global_registry *in_globalreg, const std::string& in_name) {
        return std::static_pointer_cast<T>(in_globalreg->FetchGlobal(in_name));
    }

    template<typename T> 
    std::shared_ptr<T> fetch_global_as(const std::string& in_name) {
        return fetch_global_as<T>(globalreg, in_name);
    }

    template<typename T>
    std::shared_ptr<T> fetch_global_as() {
        return fetch_global_as<T>(globalreg, T::global_name());
    }

    template<typename T> 
    std::shared_ptr<T> fetch_mandatory_global_as(global_registry *in_globalreg, 
            const std::string& in_name) {
        std::shared_ptr<T> r = std::static_pointer_cast<T>(in_globalreg->FetchGlobal(in_name));

        if (r == nullptr) 
            throw std::runtime_error(fmt::format("Unable to find '{}' in the global registry, "
                        "code initialization may be out of order.", in_name));

        return r;
    }

    template<typename T> 
    std::shared_ptr<T> fetch_mandatory_global_as(const std::string& in_name) {
        return fetch_mandatory_global_as<T>(Globalreg::globalreg, in_name);
    }

    template<typename T>
    std::shared_ptr<T> fetch_mandatory_global_as() {
        return fetch_mandatory_global_as<T>(Globalreg::globalreg, T::global_name());
    }
}


#endif

