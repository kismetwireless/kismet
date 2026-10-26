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

#ifndef __GPS_CELLMODEM_H__
#define __GPS_CELLMODEM_H__

#include "config.h"

#include <atomic>
#include <string>
#include <vector>

#include "kis_gps.h"
#include "gpsnmea_v3.h"

// A cell modem's own GNSS receiver.  It reads nothing itself: the cellat
// source that holds the modem opens the modem's NMEA port in its helper and
// forwards the sentences, so the GPS is idle until that source opens and goes
// idle again when it closes.  Declared in kismet.conf (gps=cellmodem:name=...)
// it exists before the source does; a source naming one that does not exist
// creates it.
class kis_gps_cellmodem : public kis_gps {
public:
    kis_gps_cellmodem(shared_gps_builder in_builder, uint64_t in_id);
    virtual ~kis_gps_cellmodem() { }

    virtual bool open_gps(std::string in_opts) override;

    virtual bool get_location_valid() override;
    virtual bool get_device_connected() override;

    // Sentences from the source named in_source; called from its packet handler
    void feed_nmea(const std::string& in_source, const std::vector<std::string>& in_sentences);

    // The source closed; the GPS has no data until it opens again
    void detach(const std::string& in_source);

    // A GPS name a source definition may use: it becomes part of a GPS definition,
    // so nothing that could add an option
    static bool valid_name(const std::string& in_name);

protected:
    // Location older than this is not current; the modem sends a fix every second
    static constexpr time_t location_expire = 10;

    // Guarded by gps_mutex
    gps_nmea::gsv_collector gsv;
    std::string attached_source;
    bool warned_other_source;

    // Read without gps_mutex, which is taken before data_mutex
    std::atomic<time_t> last_feed_time;
};

class gps_cellmodem_builder : public kis_gps_builder {
public:
    gps_cellmodem_builder() : kis_gps_builder() {
        initialize();
    }

    virtual void initialize() override {
        set_int_gps_class("cellmodem");
        set_int_gps_class_description("GNSS of a cell modem, fed by its cellat source");
        // Behind a dedicated receiver, ahead of the web and meta GPS
        set_int_gps_priority(-500);
        set_int_default_name("cellmodem");
        set_int_singleton(false);
    }

    virtual shared_gps build_gps(shared_gps_builder in_builder, uint64_t in_id) override {
        return shared_gps(new kis_gps_cellmodem(in_builder, in_id));
    }
};

#endif
