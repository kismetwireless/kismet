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
#include "kis_net_beast_httpd.h"
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

    tracked_antenna(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_antenna");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(antenna_id, uint32_t, unsigned int, unsigned int, antenna_id);
    __Proxy(antenna_uuid, uuid, uuid, uuid, antenna_uuid);
    __Proxy(source_uuid, uuid, uuid, uuid, source_uuid);
    __Proxy(source_antnum, int32_t, int32_t, int32_t, source_antnum);
    __Proxy(power_adjust, int32_t, int32_t, int32_t, power_adjust);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.antenna.id", "Antenna ID for fast lookup", &antenna_id);
        register_field("kismet.antenna.uuid", "Antenna UUID", &antenna_uuid);
        register_field("kismet.antenna.source_uuid", "UUID of antenna source", &source_uuid);
        register_field("kismet.antenna.source_antnum", "Antenna number on source", &source_antnum);
        register_field("kismet.antenna.power_adjust", "Optional power adjustment", &power_adjust);
    }

    std::shared_ptr<tracker_element_int32> antenna_id;
    std::shared_ptr<tracker_element_uuid> antenna_uuid;
    std::shared_ptr<tracker_element_uuid> source_uuid;
    std::shared_ptr<tracker_element_int32> power_adjust;
    std::shared_ptr<tracker_element_int32> source_antnum;

};

class antenna_tracker : public lifetime_global {
public:
    static std::shared_ptr<antenna_tracker> create_at() {
        auto mon = std::make_shared<antenna_tracker>();
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global("ANTENNATRACKER", mon);

        return mon;
    }

    antenna_tracker();
    virtual ~antenna_tracker();

    // Add a new antenna
    int add_antenna(uuid in_src, int in_srcnum, int adjustment);
    int add_antenna(uuid in_src, int in_srcnum, int adjustment, uuid in_ant_uuid);

    // Adjust an existing antenna
    int set_antenna_adjustment(int in_antnum, int adjustment);

    // Retrieve antenna
    std::shared_ptr<tracked_antenna> get_antenna(int in_antnum);

protected:
    kis_mutex mutex;

    int next_ant_id;
    
    std::shared_ptr<tracker_element_int_map> antenna_id_map;
};

#endif

