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

#include "config.h"

#include <unistd.h>
#include "globalregistry.h"
#include "util.h"
#include "macaddr.h"

global_registry *Globalreg::globalreg = NULL;

global_registry::global_registry() { 
    ext_mutex.set_name("globalreg_ext_mutex");
    lifetime_mutex.set_name("globalreg_lifetime_mutex");
    deferred_mutex.set_name("globalreg_deferred_mutex");

	fatal_condition = false;
	spindown = false;
    complete = false;

	argc = 0;
	argv = NULL;
	envp = NULL;

	getopt_long_num = 127;

	next_ext_ref = 0;

	messagebus = NULL;
	packetchain = NULL;
	alertracker = NULL;
	timetracker = NULL;
	kismet_config = NULL;
	builtindissector = NULL;
	manufdb = NULL;

    etc_dir = std::string(SYSCONF_LOC);
    data_dir = std::string(DATA_LOC);

	start_time = 0;

	broadcast_mac = mac_addr("FF:FF:FF:FF:FF:FF");
    multicast_mac = mac_addr("01:00:00:00:00:00");
	empty_mac = mac_addr(0);

	alert_backlog = 0;

	for (unsigned int x = 0; x < PACK_COMP_MAX; x++)
		packetcomp_map[x] = -1;

	for (unsigned int x = 0; x < ALERT_REF_MAX; x++)
		alertref_map[x] = -1;

	checksum_packets = 0;

    deferred_started = false;
}

// External globals -- allow other things to tie structs to us
int global_registry::RegisterGlobal(std::string in_name) {
    local_locker lock(&ext_mutex);

    std::map<std::string, int>::iterator i;

	if ((i = ext_name_map.find(str_lower(in_name))) != ext_name_map.end())
		return i->second;

	next_ext_ref++;

	ext_name_map[str_lower(in_name)] = next_ext_ref;

	return next_ext_ref;
}

int global_registry::FetchGlobalRef(std::string in_name) {
    local_shared_locker lock(&ext_mutex);

    auto extref = ext_name_map.find(str_lower(in_name));

    if (extref == ext_name_map.end())
        return -1;

    return extref->second;
}

std::shared_ptr<void> global_registry::FetchGlobal(int in_ref) {
    local_shared_locker lock(&ext_mutex);

	if (ext_data_map.find(in_ref) == ext_data_map.end())
		return NULL;

	return ext_data_map[in_ref];
}

std::shared_ptr<void> global_registry::FetchGlobal(std::string in_name) {
    local_shared_locker lock(&ext_mutex);

	int ref;

	if ((ref = FetchGlobalRef(in_name)) < 0) {
		return NULL;
	}

	return ext_data_map[ref];
}

int global_registry::insert_global(int in_ref, std::shared_ptr<void> in_data) {
    local_locker lock(&ext_mutex);

	ext_data_map[in_ref] = in_data;

	return 1;
}

void global_registry::remove_global(int in_ref) {
    local_locker lock(&ext_mutex);

    if (ext_data_map.find(in_ref) != ext_data_map.end()) {
        ext_data_map.erase(ext_data_map.find(in_ref));
    }
}

int global_registry::insert_global(std::string in_name, std::shared_ptr<void> in_data) {
	int ref = RegisterGlobal(in_name);

	return insert_global(ref, in_data);
}

void global_registry::remove_global(std::string in_name) {
    int ref = FetchGlobalRef(in_name);
    remove_global(ref);
}

void global_registry::RegisterUsageFunc(usage_func in_cli) {
    usage_func_vec.push_back(in_cli);
}

void global_registry::RemoveUsageFunc(usage_func in_cli) {
    for (std::vector<usage_func>::iterator i = usage_func_vec.begin();
            i != usage_func_vec.end(); ++i) {
        if ((*i) == in_cli) {
            usage_func_vec.erase(i);
            return;
        }
    }
}

void global_registry::register_lifetime_global(std::shared_ptr<lifetime_global> in_g) {
    local_locker lock(&lifetime_mutex);

    lifetime_vec.insert(lifetime_vec.begin(), in_g);
}

void global_registry::Removelifetime_global(std::shared_ptr<lifetime_global> in_g) {
    local_locker lock(&lifetime_mutex);

    for (auto i = lifetime_vec.begin(); i != lifetime_vec.end(); ++i) {
        if (*i == in_g) {
            lifetime_vec.erase(i);
            break;
        }
    }
}

void global_registry::delete_lifetime_globals() {
    local_locker lock(&lifetime_mutex);

    lifetime_vec.clear();
}

void global_registry::register_deferred_global(std::shared_ptr<deferred_startup> in_d) {
    local_locker lock(&deferred_mutex);

    deferred_vec.push_back(in_d);

    if (deferred_started)
        in_d->trigger_deferred_startup();
}

void global_registry::remove_deferred_global(std::shared_ptr<deferred_startup> in_d) {
    local_locker lock(&deferred_mutex);

    for (auto i = deferred_vec.begin(); i != deferred_vec.end(); ++i) {
        if ((*i) == in_d) {
            deferred_vec.erase(i);
            break;
        }
    }
}

void global_registry::start_deferred() {
    local_locker lock(&deferred_mutex);

    deferred_started = true;
    
    for (auto i : deferred_vec) {
        i->trigger_deferred_startup();
    }
}

void global_registry::shutdown_deferred() {
    local_locker lock(&deferred_mutex);

    for (auto i : deferred_vec)
        i->trigger_deferred_shutdown();

    deferred_vec.clear();
}

std::atomic<unsigned long> Globalreg::n_tracked_fields;
std::atomic<unsigned long> Globalreg::n_tracked_components;
std::atomic<unsigned long> Globalreg::n_tracked_http_connections;

