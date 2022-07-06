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

#ifndef __GPSTRACKER_H__
#define __GPSTRACKER_H__

#include "config.h"

#include "eventbus.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "kis_net_beast_httpd.h"
#include "packet.h"
#include "packetchain.h"
#include "timetracker.h"
#include "trackedlocation.h"

class kis_gps_builder;
typedef std::shared_ptr<kis_gps_builder> shared_gps_builder;

class kis_gps;
typedef std::shared_ptr<kis_gps> shared_gps;

// Packet info attached to each packet, if there isn't already GPS info present

// Optional merge flags for partial records
#define GPS_PACKINFO_MERGE_LOC      (1 << 1)
#define GPS_PACKINFO_MERGE_ALT      (1 << 2)
#define GPS_PACKINFO_MERGE_SPEED    (1 << 3)
#define GPS_PACKINFO_MERGE_HEADING  (1 << 4)
#define GPS_PACKINFO_MERGE_REST     (1 << 128)

class kis_gps_packinfo : public packet_component {
public:
    kis_gps_packinfo() {
        reset();
    }

    virtual bool unique() override { return true; }

    void set(std::shared_ptr<kis_gps_packinfo> src) {
        merge_partial = src->merge_partial;
        merge_flags = src->merge_flags;

        lat = src->lat;
        lon = src->lon;
        alt = src->alt;
        speed = src->speed;
        heading = src->heading;
        magheading = src->magheading;
        precision = src->precision;
        fix = src->fix;
        tv.tv_sec = src->tv.tv_sec;
        tv.tv_usec = src->tv.tv_usec;
        gpsuuid = src->gpsuuid;
        gpsname = src->gpsname;
    }

    void reset() {
        merge_partial = false;
        merge_flags = 0;

        lat = lon = alt = speed = heading = magheading = 0;
        precision = 0;
        fix = 0;
        tv.tv_sec = 0;
        tv.tv_usec = 0;
        error_x = 0;
        error_y = 0;
        error_v = 0;
    }

    std::shared_ptr<kis_tracked_location_full> as_tracked_full() {
        auto r = std::make_shared<kis_tracked_location_full>();

        r->set_location(lat, lon);
        r->set_alt(alt);

        if (speed != 0)
            r->set_speed(speed);

        if (heading != 0)
            r->set_heading(heading);

        if (magheading != 0)
            r->set_magheading(magheading);

        r->set_fix(fix);
        r->set_time_sec(tv.tv_sec);
        r->set_time_usec(tv.tv_usec);

        return r;
    }

    double lat;
    double lon;
    double alt;
    double speed;
    double heading;
    double magheading;

    // If we know it, how accurate our location is, in meters
    double precision;

    // Should handlers merge partial info (speed and alt) without 
    // location info?  Used for sources like adsb which receive location
    // in multiple records
    bool merge_partial;
    uint8_t merge_flags;

    // If we know it, 2d vs 3d fix
    int fix;

    // If we know error values...
    double error_x, error_y, error_v;

    struct timeval tv;

    // GPS that created us
    uuid gpsuuid;

    // Name of GPS that created us
    std::string gpsname;
};

// Packet component used to tell other components NOT to include gps info
// from the live GPS
class kis_no_gps_packinfo : public packet_component {
public:
    kis_no_gps_packinfo() { }

    void reset() {  }
};

/* GPS manager which handles configuring GPS sources and deciding which one
 * is going to be used */
class gps_tracker : public lifetime_global, public deferred_startup {
public:
    static std::string global_name() { return "GPSTRACKER"; }

    static std::shared_ptr<gps_tracker> create_gpsmanager() {
        std::shared_ptr<gps_tracker> mon(new gps_tracker());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        Globalreg::globalreg->register_deferred_global(mon);
        return mon;
    }

private:
    gps_tracker();

public:
    virtual ~gps_tracker();

    virtual void trigger_deferred_startup() override;

    // Register a gps builer prototype
    void register_gps_builder(shared_gps_builder in_builder);

    // Create a GPS from a definition string
    std::shared_ptr<kis_gps> create_gps(std::string in_definition);

    // Find the next available name for a gps, named interface style as 
    // name, name1, name2, etc
    std::string find_next_name(const std::string& in_name);

    // Remove a GPS by UUID
    bool remove_gps(uuid in_uuid);

    std::shared_ptr<kis_gps> find_gps(uuid in_uuid);
    std::shared_ptr<kis_gps> find_gps_by_name(const std::string& in_name);

    // Set a primary GPS
    bool set_primary_gps(uuid in_uuid);

    // get the best location (as in the 'best' gps devices first)
    std::shared_ptr<kis_gps_packinfo> get_best_location();

    // Populate packets that don't have a GPS location
    static int kis_gpspack_hook(CHAINCALL_PARMS);

    static std::string event_gps_location() { return "GPS_LOCATION"; }

protected:
    kis_mutex gpsmanager_mutex;

    std::shared_ptr<tracker_element_vector> gps_prototypes_vec;

    // GPS instances, as a vector, sorted by priority; we don't mind doing a 
    // linear search because we'll typically have very few GPS devices
    std::shared_ptr<tracker_element_vector> gps_instances_vec;

    // Extra field we insert into a location record
    int tracked_uuid_addition_id;

    // Logging function
    void log_snapshot_gps();

    // Do we log to the Kismet log?
    bool database_logging;
    // Timer for logging GPS path as a snapshot
    int log_snapshot_timer;

    int pack_comp_gps, pack_comp_no_gps;

    std::shared_ptr<time_tracker> timetracker;
    int event_timer_id;
    std::shared_ptr<event_bus> eventbus;
};

#endif

