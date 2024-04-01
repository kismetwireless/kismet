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

#ifndef __PHY_RADIATION_H__
#define __PHY_RADIATION_H__

#include "config.h"
#include "globalregistry.h"
#include "phyhandler.h"
#include "configfile.h"

class geiger_device : public tracker_component {
public:
    geiger_device() :
        tracker_component() {
            register_fields();
            reserve_fields(nullptr);

            rolling_sz = 
                Globalreg::globalreg->kismet_config->fetch_opt_uint("geiger_spectrum_history", 4096);
        }

    geiger_device(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(nullptr);

            rolling_sz = 
                Globalreg::globalreg->kismet_config->fetch_opt_uint("geiger_spectrum_history", 4096);
        }

    geiger_device(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(e);

            rolling_sz = 
                Globalreg::globalreg->kismet_config->fetch_opt_uint("geiger_spectrum_history", 4096);
        }

    geiger_device(const geiger_device *p):
        tracker_component(p) {
            rolling_sz = p->rolling_sz;

            __ImportField(aggregate_spectrum, p);
            __ImportField(detector_uuid, p);
            __ImportField(cps_rrd, p);
            __ImportField(usv_rrd, p);
        }

    void insert_cps_record(time_t ts, double cps, const std::vector<double>& spectrum) {
        cps_rrd->add_sample(cps, ts);

        std::vector<double> del_vec;
        bool del = false;

        if (aggregate_spectrum->size() == 0) {
            aggregate_spectrum->set(spectrum);
            spectrum_rolling_log.push_back(spectrum);
            return;
        }

        if (spectrum_rolling_log.size() >= rolling_sz) {
            del = true;
            del_vec = spectrum_rolling_log.front();
            spectrum_rolling_log.pop_front();
        }
        spectrum_rolling_log.push_back(spectrum);

        for (unsigned int x = 0; x < spectrum.size(); x++) {
            if (x >= aggregate_spectrum->size()) {
                break;
            }

            if (del && x >= del_vec.size()) {
                break;
            }
        
            // Add new, remove last if it rolls off the back
            (*aggregate_spectrum)[x] += spectrum[x] - (del ? del_vec[x] : 0);
        }

    }

    __Proxy(detector_uuid, uuid, uuid, uuid, detector_uuid);
    __Proxy(detector_type, std::string, std::string, std::string, detector_type);

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("radiation.sensor.aggregate_spectrum", "Aggregated spectrum over time", &aggregate_spectrum);
        register_field("radiation.sensor.uuid", "Detector UUID", &detector_uuid);
        register_field("radiation.sensor.cps_rrd", "Counts-per-second RRD", &cps_rrd);
        register_field("radiation.sensor.usv_rrd", "uSV dosage RRD (if available)", &usv_rrd);
        register_field("radiation.sensor.type", "Detector type/brand", &detector_type);

    }

    std::shared_ptr<tracker_element_vector_double> aggregate_spectrum;
    std::shared_ptr<tracker_element_uuid> detector_uuid;
    std::shared_ptr<tracker_element_string> detector_type;
    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>> cps_rrd;
    std::shared_ptr<kis_tracked_rrd<kis_tracked_rrd_extreme_aggregator>> usv_rrd;

    std::list<std::vector<double>> spectrum_rolling_log;

    unsigned int rolling_sz;
};

class kis_radiation_phy : public kis_phy_handler {
public:
    virtual ~kis_radiation_phy();

    kis_radiation_phy() :
        kis_phy_handler() {
            indexed = false;
        };

    virtual kis_phy_handler *create_phy_handler(int in_phyid) override {
        return new kis_radiation_phy(in_phyid);
    }

    kis_radiation_phy(int in_phyid);

    static int packet_handler(CHAINCALL_PARMS);

protected:
    kis_mutex rad_mutex;

    std::shared_ptr<packet_chain> packetchain;
    std::shared_ptr<device_tracker> devicetracker;

    std::shared_ptr<tracker_element_uuid_map> geiger_counters;

    int pack_comp_common, pack_comp_json, pack_comp_meta, pack_comp_radiodata, 
        pack_comp_datasrc;

    uint16_t geiger_device_id;
};


#endif

