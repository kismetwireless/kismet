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

#ifndef __ANTENNATRACKER_H__
#define __ANTENNATRACKER_H__

#include "config.h"
#include "kis_net_microhttpd.h"
#include "globalregistry.h"
#include "trackedcomponent.h"
#include "kis_mutex.h"

/* Antenna tracker
 *
 * Map per-source antennas to a common antenna ID number for fast grouping across sources.
 * 
 * Sources should register antennas with the antenna mapping system and use those simple
 * IDs for mapping to per-antenna signals.
 *
 * Other mechanisms, such as SDOA, can use these groupings for fast analysis
 */

class tracked_antenna : public tracker_component {
public:
    tracked_antenna() :
        tracker_component(0) {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_antenna(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_antenna(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("tracked_antenna");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(antenna_id, uint32_t, unsigned int, unsigned int, antenna_id);
    __Proxy(antenna_uuid, uuid, uuid, uuid, antenna_uuid);
    __Proxy(source_uuid, uuid, uuid, uuid, source_uuid);
    __Proxy(source_antnum, int32_t, int32_t, int32_t, source_antnum);
    __Proxy(power_adjust, int32_t, int32_t, int32_t, power_adjust);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("kismet.antenna.id", "Antenna ID for fast lookup", &antenna_id);
        RegisterField("kismet.antenna.uuid", "Antenna UUID", &antenna_uuid);
        RegisterField("kismet.antenna.source_uuid", "UUID of antenna source", &source_uuid);
        RegisterField("kismet.antenna.source_antnum", "Antenna number on source", &source_antnum);
        RegisterField("kismet.antenna.power_adjust", "Optional power adjustment", &power_adjust);
    }

    std::shared_ptr<TrackerElementInt32> antenna_id;
    std::shared_ptr<TrackerElementUUID> antenna_uuid;
    std::shared_ptr<TrackerElementUUID> source_uuid;
    std::shared_ptr<TrackerElementInt32> power_adjust;
    std::shared_ptr<TrackerElementInt32> source_antnum;

};

class Antennatracker : public LifetimeGlobal {
public:
    static std::shared_ptr<Antennatracker> create_at() {
        auto mon = std::make_shared<Antennatracker>();
        Globalreg::globalreg->RegisterLifetimeGlobal(mon);
        Globalreg::globalreg->InsertGlobal("ANTENNATRACKER", mon);

        return mon;
    }

    Antennatracker();
    virtual ~Antennatracker();

    // Add a new antenna
    int add_antenna(uuid in_src, int in_srcnum, int adjustment);
    int add_antenna(uuid in_src, int in_srcnum, int adjustment, uuid in_ant_uuid);

    // Adjust an existing antenna
    int set_antenna_adjustment(int in_antnum, int adjustment);

    // Retreive antenna
    std::shared_ptr<tracked_antenna> get_antenna(int in_antnum);

protected:
    kis_recursive_timed_mutex mutex;

    int next_ant_id;
    
    std::shared_ptr<TrackerElementIntMap> antenna_id_map;

    std::shared_ptr<Kis_Net_Httpd_Simple_Tracked_Endpoint> antenna_endp;

};

#endif

