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

GlobalRegistry *Globalreg::globalreg = NULL;

GlobalRegistry::GlobalRegistry() { 
	fatal_condition = 0;
	spindown = 0;

	winch = false;

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

    for (int x = 0; x < 1024; x++)
        sigchild_vec[x] = 0;
    sigchild_vec_pos = 0;
}

// External globals -- allow other things to tie structs to us
int GlobalRegistry::RegisterGlobal(std::string in_name) {
    local_locker lock(&ext_mutex);

    std::map<std::string, int>::iterator i;

	if ((i = ext_name_map.find(StrLower(in_name))) != ext_name_map.end())
		return i->second;

	next_ext_ref++;

	ext_name_map[StrLower(in_name)] = next_ext_ref;

	return next_ext_ref;
}

int GlobalRegistry::FetchGlobalRef(std::string in_name) {
    local_shared_locker lock(&ext_mutex);

    auto extref = ext_name_map.find(StrLower(in_name));

    if (extref == ext_name_map.end())
        return -1;

    return extref->second;
}

std::shared_ptr<void> GlobalRegistry::FetchGlobal(int in_ref) {
    local_shared_locker lock(&ext_mutex);

	if (ext_data_map.find(in_ref) == ext_data_map.end())
		return NULL;

	return ext_data_map[in_ref];
}

std::shared_ptr<void> GlobalRegistry::FetchGlobal(std::string in_name) {
    local_shared_locker lock(&ext_mutex);

	int ref;

	if ((ref = FetchGlobalRef(in_name)) < 0) {
		return NULL;
	}

	return ext_data_map[ref];
}

int GlobalRegistry::InsertGlobal(int in_ref, std::shared_ptr<void> in_data) {
    local_locker lock(&ext_mutex);

	ext_data_map[in_ref] = in_data;

	return 1;
}

void GlobalRegistry::RemoveGlobal(int in_ref) {
    local_locker lock(&ext_mutex);

    if (ext_data_map.find(in_ref) != ext_data_map.end()) {
        ext_data_map.erase(ext_data_map.find(in_ref));
    }
}

int GlobalRegistry::InsertGlobal(std::string in_name, std::shared_ptr<void> in_data) {
	int ref = RegisterGlobal(in_name);

	return InsertGlobal(ref, in_data);
}

void GlobalRegistry::RemoveGlobal(std::string in_name) {
    int ref = FetchGlobalRef(in_name);
    RemoveGlobal(ref);
}

void GlobalRegistry::RegisterUsageFunc(usage_func in_cli) {
    usage_func_vec.push_back(in_cli);
}

void GlobalRegistry::RemoveUsageFunc(usage_func in_cli) {
    for (std::vector<usage_func>::iterator i = usage_func_vec.begin();
            i != usage_func_vec.end(); ++i) {
        if ((*i) == in_cli) {
            usage_func_vec.erase(i);
            return;
        }
    }
}

void GlobalRegistry::RegisterLifetimeGlobal(std::shared_ptr<LifetimeGlobal> in_g) {
    local_locker lock(&lifetime_mutex);

    lifetime_vec.insert(lifetime_vec.begin(), in_g);
}

void GlobalRegistry::RemoveLifetimeGlobal(std::shared_ptr<LifetimeGlobal> in_g) {
    local_locker lock(&lifetime_mutex);

    for (auto i = lifetime_vec.begin(); i != lifetime_vec.end(); ++i) {
        if (*i == in_g) {
            lifetime_vec.erase(i);
            break;
        }
    }
}

void GlobalRegistry::DeleteLifetimeGlobals() {
    local_locker lock(&lifetime_mutex);

    lifetime_vec.clear();
}

void GlobalRegistry::RegisterDeferredGlobal(std::shared_ptr<DeferredStartup> in_d) {
    local_locker lock(&deferred_mutex);

    deferred_vec.push_back(in_d);

    if (deferred_started)
        in_d->Deferred_Startup();
}

void GlobalRegistry::RemoveDeferredGlobal(std::shared_ptr<DeferredStartup> in_d) {
    local_locker lock(&deferred_mutex);

    for (auto i = deferred_vec.begin(); i != deferred_vec.end(); ++i) {
        if ((*i) == in_d) {
            deferred_vec.erase(i);
            break;
        }
    }
}

void GlobalRegistry::Start_Deferred() {
    local_locker lock(&deferred_mutex);

    deferred_started = true;
    
    for (auto i : deferred_vec) {
        i->Deferred_Startup();
    }
}

void GlobalRegistry::Shutdown_Deferred() {
    local_locker lock(&deferred_mutex);

    for (auto i : deferred_vec)
        i->Deferred_Shutdown();

    deferred_vec.clear();
}

