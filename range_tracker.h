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

#ifndef __RANGE_TRACKER_H__
#define __RANGE_TRACKER_H__

#include "config.h"

#include <array>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "kis_net_beast_httpd.h"
#include "packet.h"
#include "trackedelement.h"
#include "uuid.h"

// Receiver range: for devices that report their own position (aircraft, vessels, drones,
// mesh nodes), how far each one was from Kismet when a packet from it was heard, kept as
// the furthest distance in each degree of bearing.  Kept for each kind of device, for
// each data source and for all of them together, over all time and over the last day,
// and for aircraft by altitude.  Positions heard while Kismet's own location is unknown
// go into a convex hull instead, the area the devices were heard over.

class range_tracker : public lifetime_global, public deferred_startup {
public:
    static std::string global_name() { return "RANGETRACKER"; }

    static std::shared_ptr<range_tracker> create_range_tracker() {
        std::shared_ptr<range_tracker> mon(new range_tracker());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->register_deferred_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

    static constexpr size_t bins = 360;
    static constexpr size_t day_slots = 24;
    // Upper altitude of each band but the last, in meters
    static constexpr std::array<double, 2> band_tops{{3000, 7500}};
    static constexpr size_t bands = band_tops.size() + 1;
    static constexpr size_t max_hull = 1024;

private:
    range_tracker();

public:
    virtual ~range_tracker();

    virtual void trigger_deferred_startup() override;
    virtual void trigger_deferred_shutdown() override;

    // A packet from a device at reported, heard by Kismet at heard (which may have no
    // location).  prev is the device's
    // reported position before this packet, and prev_time when it was; a position only
    // counts when it moved from that one, plausibly, so repeats and bad decodes don't.
    // The caller holds the device lock.
    void add(const std::string& kind, const std::shared_ptr<kis_packet>& in_pack,
            const kis_gps_packinfo& heard, const kis_gps_packinfo& reported,
            double prev_lat, double prev_lon, time_t prev_time);

    struct band_bins {
        std::array<float, bins> dist{};
    };

    struct range_record {
        std::string kind;
        uuid source;                    // unset for every source together
        std::string source_key;         // the UUID as text, empty for every source
        std::string source_name;

        uint64_t samples = 0;
        uint64_t rejected = 0;
        time_t first_time = 0;
        time_t last_time = 0;

        // Running average of where Kismet was, and how far it has strayed from it
        double center_lat = 0, center_lon = 0;
        uint64_t center_n = 0;
        double moved = 0;

        // All time: the furthest distance in each degree, and the altitude, time and
        // signal of the position that set it
        std::array<float, bins> dist{};
        std::array<float, bins> alt{};
        std::array<time_t, bins> time{};
        std::array<float, bins> signal{};

        // The last day, an hour to a slot; stamps are the hour each slot holds
        std::array<band_bins, day_slots> day{};
        std::array<time_t, day_slots> day_hour{};

        // All time, by altitude band, for positions with an altitude
        std::array<band_bins, bands> band{};

        // Convex hull, counterclockwise as [lat, lon], of positions heard while Kismet's
        // location was unknown
        std::vector<std::pair<double, double>> hull;
        uint64_t hull_samples = 0;
    };

protected:
    using record_key = std::pair<std::string, std::string>;

    range_record *record_for(const std::string& kind, const std::string& source_key, const uuid& source,
            const std::string& name);
    void add_to(range_record& rec, size_t bin, double dist, const kis_gps_packinfo& heard,
            const kis_gps_packinfo& reported, double sig, time_t now);
    void add_hull(range_record& rec, double lat, double lon, time_t now);

    double limit_for(const std::string& kind) const;
    double speed_for(const std::string& kind) const;

    std::shared_ptr<tracker_element> summary(const range_record& rec, time_t now);
    std::shared_ptr<tracker_element> detail(const range_record& rec, time_t now);
    std::shared_ptr<tracker_element> all_endpoint();
    std::shared_ptr<tracker_element> kind_endpoint(const std::string& kind, const std::string& source_key);
    void reset_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con);

    bool save(std::string& err);
    void load();

    kis_mutex mutex;
    std::map<record_key, std::unique_ptr<range_record>> records;
    bool dirty = false;

    bool enabled = true;
    bool save_enabled = true;
    std::string save_file;
    std::map<std::string, double> limits;     // m, by kind
    int timer_id = -1;
    int pack_comp_datasrc;

    int f_records, f_kind, f_source, f_source_name, f_samples, f_rejected, f_first, f_last,
        f_center, f_moved, f_bin_deg, f_furthest, f_furthest_bearing, f_dist, f_alt, f_time,
        f_signal, f_day, f_bands, f_band_min, f_band_max, f_band_dist, f_hull, f_hull_point,
        f_hull_samples;
};

#endif
