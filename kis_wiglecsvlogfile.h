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

#ifndef __KIS_WIGLECSV_LOGFILE_H__
#define __KIS_WIGLECSV_LOGFILE_H__ 

#include "config.h"

#include "configfile.h"
#include "globalregistry.h"
#include "logtracker.h"
#include "packetchain.h"
#include "phy_80211.h"
#include "phy_btle.h"
#include "phy_bluetooth.h"
#include "phy_cell.h"

class kis_phy_handler;

class kis_wiglecsv_logfile : public kis_logfile {
public:
    kis_wiglecsv_logfile(shared_log_builder in_builder);
    virtual ~kis_wiglecsv_logfile();

    virtual bool open_log(const std::string& in_template, const std::string& in_path) override;
    virtual void close_log() override;

protected:
    static int packet_handler(CHAINCALL_PARMS);

    // One Wi-Fi AP row; caller holds the log mutex and the device lock
    void print_wifi_row(const std::shared_ptr<kis_tracked_device_base>& dev,
            const std::shared_ptr<dot11_tracked_device>& dot11,
            const std::shared_ptr<kis_packet>& in_pack, int signal);

    // Rows for the BSSs the transmitter of this frame advertises in its multiple BSSID
    // element; caller holds the log mutex and no device lock
    void log_mbssid_hosted(const std::shared_ptr<kis_packet>& in_pack,
            const std::shared_ptr<kis_tracked_device_info>& devs, const mac_addr& transmitter,
            int signal);

    FILE *csvfile;

    int pack_comp_80211, pack_comp_device;

    unsigned int throttle_seconds;

    // Per-device throttle; written by any packet thread
    kis_mutex timer_mutex;
    std::unordered_map<device_key, time_t> timer_map;

    std::shared_ptr<device_tracker> devicetracker;
    kis_80211_phy *dot11_phy;
    kis_bluetooth_phy *bt_phy;
    kis_btle_phy *btle_phy;
    kis_cellular_phy *cell_phy;
};

class wiglecsv_logfile_builder : public kis_logfile_builder {
public:
    wiglecsv_logfile_builder() :
        kis_logfile_builder() {
            register_fields();
            reserve_fields(nullptr);
            initialize();
        }

    wiglecsv_logfile_builder(int in_id) :
        kis_logfile_builder(in_id) {
            register_fields();
            reserve_fields(nullptr);
            initialize();
        }

    wiglecsv_logfile_builder(int in_id, std::shared_ptr<tracker_element_map> e) :
        kis_logfile_builder(in_id, e) {
            register_fields();
            reserve_fields(e);
            initialize();
        }

    virtual ~wiglecsv_logfile_builder() { }

    virtual shared_logfile build_logfile(shared_log_builder builder) override {
        return shared_logfile(new kis_wiglecsv_logfile(builder));
    }

    virtual void initialize() override {
        set_log_class("wiglecsv");
        set_log_name("Wigle CSV");
        set_stream(true);
        set_singleton(false);
        set_log_description("CSV log of Access Points, Bluetooth, and Cellular cells for uploading to Wigle");
    }
};


#endif /* ifndef KIS_WIGLECSV_LOGFILE_H */
