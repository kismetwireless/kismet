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

#include "kis_wiglecsvlogfile.h"

#include "devicetracker.h"
#include "phy_80211.h"
#include "phy_bluetooth.h"
#include "phy_btle.h"
#include "version.h"

// Aggressive additional mangle of text to handle converting ',' and '"' to
// hexcode for CSV
std::string munge_for_csv(const std::string& in_data) {
	std::string ret;

	for (size_t i = 0; i < in_data.length(); i++) {
		if ((unsigned char) in_data[i] >= 32 && (unsigned char) in_data[i] <= 126 &&
				in_data[i] != ',' && in_data[i] != '\"' ) {
			ret += in_data[i];
		} else {
			ret += '\\';
			ret += ((in_data[i] >> 6) & 0x03) + '0';
			ret += ((in_data[i] >> 3) & 0x07) + '0';
			ret += ((in_data[i] >> 0) & 0x07) + '0';
		}
	}

	return ret;
}

std::string wifi_crypt_to_string(unsigned long cryptset) {
    std::stringstream ss;

    if (cryptset & dot11_crypt_akm_wps)
        ss << "[WPS] ";

    if (cryptset & dot11_crypt_general_wep)
        ss << "[WEP] ";

    if (cryptset & dot11_crypt_general_wpa) {

        std::string cryptver = "";

        if ((cryptset & dot11_crypt_pairwise_tkip) || (cryptset & dot11_crypt_group_tkip)) {
            if ((cryptset & dot11_crypt_pairwise_ccmp128) || (cryptset & dot11_crypt_group_ccmp128)) {
                cryptver = "CCMP+TKIP";
            } else {
                cryptver = "TKIP";
            }
        } else if (cryptset & dot11_crypt_pairwise_ccmp128) {
            cryptver = "CCMP";
        }

        std::string authver = "";

        if (cryptset & dot11_crypt_akm_psk) {
            authver = "PSK";
        } else if (cryptset & dot11_crypt_akm_1x) {
            authver = "EAP";
        } else if (cryptset & dot11_crypt_akm_owe) {
            authver = "OWE";
        } else {
            authver = "UNKNOWN";
        }

        if ((cryptset & dot11_crypt_general_wpa2) && (cryptset & dot11_crypt_general_wpa1)) {
            ss << "[WPA-" << authver << "-" << cryptver << "] ";
            ss << "[WPA2-" << authver << "-" << cryptver << "] ";
        } else if (cryptset & dot11_crypt_general_wpa2) {
            ss << "[WPA2-" << authver << "-" << cryptver << "] ";
        } else if ((cryptset & dot11_crypt_general_wpa3) || (cryptset & dot11_crypt_akm_owe)) {
            ss << "[WPA3-" << authver << "-" << cryptver << "] ";
        } else {
            ss << "[WPA-" << authver << "-" << cryptver << "] ";
        }
    }

    auto retstr = ss.str();

    if (retstr.length() > 0)
        return retstr.substr(0, retstr.length() - 1);

    return "";
}

int frequency_to_wifi_channel(double in_freq) {
    if (in_freq == 0)
        return 0;

    in_freq = in_freq / 1000;

    if (in_freq == 2484)
        return 14;
    else if (in_freq < 2484)
        return (in_freq - 2407) / 5;
    else if (in_freq >= 4910 && in_freq <= 4980)
        return (in_freq - 4000) / 5;
    else if (in_freq <= 45000)
        return (in_freq - 5000) / 5;
    else if (in_freq >= 58320 && in_freq <= 64800)
        return (in_freq - 56160) / 2160;
    else
        return in_freq;
}

kis_wiglecsv_logfile::kis_wiglecsv_logfile(shared_log_builder in_builder) :
    kis_logfile(in_builder) {

    csvfile = nullptr;

    devicetracker = Globalreg::fetch_mandatory_global_as<device_tracker>();

    auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();

    pack_comp_l1info = packetchain->register_packet_component("RADIODATA");
    pack_comp_gps = packetchain->register_packet_component("GPS");
	pack_comp_device = packetchain->register_packet_component("DEVICE");
	pack_comp_common = packetchain->register_packet_component("COMMON");

    throttle_seconds =
        Globalreg::globalreg->kismet_config->fetch_opt_uint("wigle_log_throttle", 1);

    auto devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    dot11_phy =
        static_cast<kis_80211_phy *>(devicetracker->fetch_phy_handler_by_name("IEEE802.11"));
    bt_phy =
        static_cast<kis_bluetooth_phy *>(devicetracker->fetch_phy_handler_by_name("Bluetooth"));
    btle_phy =
        static_cast<kis_btle_phy *>(devicetracker->fetch_phy_handler_by_name("BTLE"));

    if (dot11_phy == nullptr || bt_phy == nullptr || btle_phy == nullptr) {
        _MSG_FATAL("Could not initialize wigle log, phys not available");
        Globalreg::globalreg->fatal_condition = true;
        return;
    }

}

kis_wiglecsv_logfile::~kis_wiglecsv_logfile() {
    close_log();
}

bool kis_wiglecsv_logfile::open_log(const std::string& in_template, const std::string& in_path) {
    kis_unique_lock<kis_mutex> lk(log_mutex, "open_log");

    set_int_log_open(false);
    set_int_log_path(in_path);
    set_int_log_template(in_template);

    auto packetchain = Globalreg::fetch_mandatory_global_as<packet_chain>();

    csvfile = fopen(in_path.c_str(), "wa");
    if (csvfile == NULL) {
        _MSG_ERROR("Failed to open wiglecsv log '{}': {}", in_path,
                kis_strerror_r(errno));
        return false;
    }

    _MSG_INFO("Opened wiglecsv log file '{}'", in_path);

    // CSV headers
    fmt::print(csvfile, "WigleWifi-1.6,appRelease=Kismet{0}{1}{2}-{3},model=Kismet,"
            "release={0}.{1}.{2}-{3},device=kismet,display=kismet,board=kismet,brand=Kismet,"
            "star=Sol,body=3,subBody=0\n",
            VERSION_MAJOR, VERSION_MINOR, VERSION_TINY, VERSION_GIT_COMMIT);
    fmt::print(csvfile, "MAC,SSID,AuthMode,FirstSeen,Channel,Frequency,RSSI,CurrentLatitude,CurrentLongitude,"
            "AltitudeMeters,AccuracyMeters,RCOIs,MfgrId,Type\n");


    set_int_log_open(true);

    fflush(csvfile);

    lk.unlock();

    packetchain->register_handler(&kis_wiglecsv_logfile::packet_handler, this, CHAINPOS_LOGGING, -100);

    return true;
}

void kis_wiglecsv_logfile::close_log() {
    kis_lock_guard<kis_mutex> lk(log_mutex);

    set_int_log_open(false);

    if (csvfile != nullptr)
        fclose(csvfile);

    csvfile = nullptr;

    auto packetchain =
        Globalreg::fetch_global_as<packet_chain>();
    if (packetchain != nullptr) {
        packetchain->remove_handler(&kis_wiglecsv_logfile::packet_handler, CHAINPOS_LOGGING);
    }
}

int kis_wiglecsv_logfile::packet_handler(CHAINCALL_PARMS) {
    if (in_pack->filtered)
        return 1;

    if (in_pack->duplicate)
        return 1;

    kis_wiglecsv_logfile *wigle = static_cast<kis_wiglecsv_logfile *>(auxdata);

    kis_lock_guard<kis_mutex> lk(wigle->log_mutex);

    if (!wigle->get_log_open())
        return 1;

    if (wigle->stream_paused)
        return 1;

    auto l1info = in_pack->fetch<kis_layer1_packinfo>(wigle->pack_comp_l1info);
    auto commoninfo = in_pack->fetch<kis_common_info>(wigle->pack_comp_common);
    auto gps = in_pack->fetch<kis_gps_packinfo>(wigle->pack_comp_gps);
    auto devs = in_pack->fetch<kis_tracked_device_info>(wigle->pack_comp_device);

    if (commoninfo == nullptr || gps == nullptr || devs == nullptr)
        return 1;

    if (gps->lat == 0 || gps->lon == 0)
        return 1;

    int signal = 0;

    if (l1info != nullptr) {
        if (l1info->signal_type == kis_l1_signal_type_dbm)
            signal = l1info->signal_dbm;
        else
            signal = l1info->signal_rssi;
    }

    // Ignore all but management packets; we don't wigle-log data frames
    if (commoninfo->type != packet_basic_mgmt)
        return 1;

    // Find the record for the origin device, the only one we care about
    const auto& d_k = devs->devrefs.find(commoninfo->source);
    if (d_k == devs->devrefs.end())
        return 1;

    auto dev = d_k->second;

    // Stop looking at all if we're w/in the timeout for logging this device
    const auto& time_k = wigle->timer_map.find(dev->get_key());

    if (time_k != wigle->timer_map.end()) {
        if (time(0) < time_k->second)
            return 1;
    }

    // Lock the device tracker while we log this packet because we need to interact
    // with the device internals

    kis_lock_guard<kis_mutex> device_lk(wigle->devicetracker->get_devicelist_mutex());

    // Break into per-phy handling
    if (wigle->dot11_phy->device_is_a(dev)) {
        auto dot11 = wigle->dot11_phy->fetch_dot11_record(dev);
        if (dot11 == nullptr)
            return 1;

        auto timestamp = dev->get_first_time();
        auto name = std::string("");
        auto crypt = std::string("");

        if (dot11->has_last_beaconed_ssid_record()) {
            auto last_ssid_a = dot11->get_last_beaconed_ssid_record();
            auto last_ssid = last_ssid_a->get_as<dot11_advertised_ssid>();

            if (last_ssid != nullptr) {
                name = munge_for_csv(last_ssid->get_ssid());
                crypt = wifi_crypt_to_string(last_ssid->get_crypt_set());
            }

        }

        crypt += "[ESS]";

        std::time_t timet(timestamp);
        std::tm tm;
        std::stringstream ts;

        gmtime_r(&timet, &tm);

        char tmstr[256];
        strftime(tmstr, 255, "%Y-%m-%d %H:%M:%S", &tm);
        ts << tmstr;

        auto channel = frequency_to_wifi_channel(dev->get_frequency());

        // [BSSID],[SSID],[Capabilities],[First timestamp seen],[Channel],[Frequency],[RSSI],
        //    [Latitude],[Longitude],[Altitude],[Accuracy],[RCOIs],[MfgrId],[Type]
        fmt::print(wigle->csvfile, "{},{},{},{},{},{},{},{:3.6f},{:3.6f},{:f},{},{}\n",
                dev->get_macaddr(),
                name,
                crypt,
                ts.str(),
                (int) channel,
                dev->get_frequency(),
                signal,
                gps->lat, gps->lon, gps->alt,
                0, // TODO - dereive a gps accuracy
                "WIFI");

    } else if (wigle->bt_phy->device_is_a(dev)) {
        auto bt = wigle->bt_phy->fetch_bluetooth_record(dev);

        if (bt == nullptr)
            return 1;

        auto timestamp = dev->get_first_time();
        auto name = munge_for_csv(dev->get_commonname());
        auto crypt = std::string("");

        std::time_t timet(timestamp);
        std::tm tm;
        std::stringstream ts;

        gmtime_r(&timet, &tm);

        char tmstr[256];
        strftime(tmstr, 255, "%Y-%m-%d %H:%M:%S", &tm);
        ts << tmstr;

        std::string type;

        switch (static_cast<bt_device_type>(bt->get_bt_device_type())) {
            case bt_device_type::btle:
                crypt = "Misc [LE]";
                type = "BLE";
                break;
            default:
                crypt = "Misc [BT]";
                type = "BT";
                break;
        }

        // [bd_addr],[device name],[capabilities],[first timestamp seen],[channel],
        //   [frequency],[rssi],[latitude],[longitude],[altitude],[accuracy],[rcois],
        //   [mfgrid],[type]

        fmt::print(wigle->csvfile, "{},{},{},{},{},{},{},{:3.10f},{:3.10f},{:f},{},{},{},{}\n",
                dev->get_macaddr(),
                name,
                crypt,
                ts.str(),
                0, // no channel for bluetooth
                "", // todo - fill in device type code
                signal,
                gps->lat, gps->lon, gps->alt,
                0, // todo - derive accuracy from gps
                "", // rcoi blank
                "", // todo - fill bt mfgr id
                type);

    } else if (wigle->btle_phy->device_is_a(dev)) {
        auto bt = wigle->btle_phy->fetch_btle_record(dev);

        if (bt == nullptr)
            return 1;

        auto timestamp = dev->get_first_time();
        auto name = munge_for_csv(dev->get_commonname());

        std::time_t timet(timestamp);
        std::tm tm;
        std::stringstream ts;

        gmtime_r(&timet, &tm);

        char tmstr[256];
        strftime(tmstr, 255, "%Y-%m-%d %H:%M:%S", &tm);
        ts << tmstr;

        const auto type = std::string{"BLE"};
        const auto crypt = std::string{"Misc [LE]"};

        // [bd_addr],[device name],[capabilities],[first timestamp seen],[channel],
        //   [frequency],[rssi],[latitude],[longitude],[altitude],[accuracy],[rcois],
        //   [mfgrid],[type]

        fmt::print(wigle->csvfile, "{},{},{},{},{},{},{},{:3.10f},{:3.10f},{:f},{},{},{},{}\n",
                dev->get_macaddr(),
                name,
                crypt,
                ts.str(),
                0,
                "", // todo - fill in device type code
                signal,
                gps->lat, gps->lon, gps->alt,
                0, // todo - derive accuracy from gps
                "", // rcoi blank
                "", // todo - fill bt mfgr id
                type);
    }

    wigle->timer_map[dev->get_key()] = time(0) + wigle->throttle_seconds;

    fflush(wigle->csvfile);

    return 1;
}
