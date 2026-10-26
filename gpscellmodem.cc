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

#include "gpscellmodem.h"
#include "messagebus.h"

kis_gps_cellmodem::kis_gps_cellmodem(shared_gps_builder in_builder, uint64_t in_id) :
    kis_gps(in_builder, in_id),
    warned_other_source{false},
    last_feed_time{0} { }

bool kis_gps_cellmodem::open_gps(std::string in_opts) {
    kis_lock_guard<kis_mutex> lk(gps_mutex, "gps_cellmodem open_gps");

    if (!kis_gps::open_gps(in_opts))
        return false;

    set_int_gps_description("cell modem GNSS, idle until its cellat source opens");
    return true;
}

bool kis_gps_cellmodem::valid_name(const std::string& in_name) {
    if (in_name.empty() || in_name.length() > 64)
        return false;

    for (auto c : in_name) {
        if (!(isalnum(static_cast<unsigned char>(c)) || c == '-' || c == '_' || c == '.'))
            return false;
    }

    return true;
}

void kis_gps_cellmodem::feed_nmea(const std::string& in_source,
        const std::vector<std::string>& in_sentences) {
    kis_lock_guard<kis_mutex> lk(gps_mutex, "gps_cellmodem feed_nmea");

    // One receiver per GPS: a second source naming the same GPS would interleave
    // two modems' positions
    if (!attached_source.empty() && attached_source != in_source) {
        if (!warned_other_source) {
            warned_other_source = true;
            _MSG_ERROR("(GPS) Cell modem GPS {} is fed by source {}; ignoring the GNSS of "
                    "source {}, which names the same GPS.  Give each modem its own gps= name.",
                    get_gps_name(), attached_source, in_source);
        }
        return;
    }

    if (attached_source.empty()) {
        attached_source = in_source;
        gsv.reset();
        set_int_gps_description(fmt::format("GNSS of cell source {}", in_source));
        _MSG_INFO("(GPS) Cell modem GPS {} is receiving the GNSS of source {}",
                get_gps_name(), in_source);
    }

    set_int_device_connected(true);

    for (const auto& s : in_sentences) {
        gps_fix_update update;

        switch (gps_nmea::parse(s, update, &gsv)) {
            case gps_nmea::result::update:
                apply_fix(update);
                last_feed_time = time(0);
                break;
            case gps_nmea::result::ignored:
                set_int_gps_data_time(time(0));
                last_feed_time = time(0);
                break;
            default:
                break;
        }
    }
}

void kis_gps_cellmodem::detach(const std::string& in_source) {
    kis_lock_guard<kis_mutex> lk(gps_mutex, "gps_cellmodem detach");

    if (attached_source != in_source)
        return;

    attached_source.clear();
    warned_other_source = false;
    set_int_device_connected(false);
    last_feed_time = 0;
    gsv.reset();
    clear_quality();
    set_int_gps_description("cell modem GNSS, idle until its cellat source opens");
}

bool kis_gps_cellmodem::get_location_valid() {
    kis_lock_guard<kis_mutex> lk(data_mutex, "gps_cellmodem get_location_valid");

    if (gps_location == nullptr || !gps_location->gps_info_ok || gps_location->fix < 2)
        return false;

    if (time(0) - gps_location->tv.tv_sec > location_expire)
        return false;

    return true;
}

bool kis_gps_cellmodem::get_device_connected() {
    const time_t t = last_feed_time;
    return t != 0 && time(0) - t <= location_expire;
}
