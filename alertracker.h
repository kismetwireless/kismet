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

#ifndef __ALERTRACKER_H__
#define __ALERTRACKER_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>

#include "globalregistry.h"
#include "kis_mutex.h"
#include "messagebus.h"
#include "packetchain.h"
#include "timetracker.h"
#include "kis_net_microhttpd.h"
#include "kis_gps.h"

#ifdef PRELUDE
#include <libprelude/prelude.hxx>
#define PRELUDE_ANALYZER_MODEL "Kismet"
#define PRELUDE_ANALYZER_CLASS "Wireless Monitor"
#define PRELUDE_ANALYZER_MANUFACTURER "https://www.kismetwireless.net/"
#endif

// TODO:
// - move packet_component to a tracked system & just use the converted
//   kis_alert_info in the future...
// - Move alert_ref into a tracked component and return via rest
// - Add description to alerts

class kis_alert_info : public packet_component {
public:
	kis_alert_info() {
		tm.tv_sec = 0;
		tm.tv_usec = 0;
		channel = "0";

        gps = NULL;

		// We do NOT self-destruct because we get cached in the alertracker
		// for playbacks.  It's responsible for discarding us
		self_destruct = 0;
	}

    virtual ~kis_alert_info() {
        if (gps != NULL)
            delete(gps);
    }

    device_key devicekey;

    std::string header;
	int phy;
	struct timeval tm;
	mac_addr bssid;
	mac_addr source;
	mac_addr dest;
	mac_addr other;
    std::string channel;
    std::string text;

    kis_gps_packinfo *gps;
};

class kis_alert_component : public packet_component {
public:
	kis_alert_component() {
		// We can self destruct because we won't clear out the vector
		// of actual alert info
		self_destruct = 1;
	}

    std::vector<kis_alert_info *> alert_vec;
};

class tracked_alert : public tracker_component {
public:
    tracked_alert() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_alert(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_alert(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("tracked_alert");
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

    __Proxy(devicekey, device_key, device_key, device_key, devicekey);

    __Proxy(header, std::string, std::string, std::string, header);
    __Proxy(phy, uint32_t, uint32_t, uint32_t, phy);
    __Proxy(timestamp, double, double, double, timestamp);

    __Proxy(transmitter_mac, mac_addr, mac_addr, mac_addr, transmitter_mac);
    __Proxy(source_mac, mac_addr, mac_addr, mac_addr, source_mac);
    __Proxy(dest_mac, mac_addr, mac_addr, mac_addr, dest_mac);
    __Proxy(other_mac, mac_addr, mac_addr, mac_addr, other_mac);

    __Proxy(channel, std::string, std::string, std::string, channel);
    __Proxy(frequency, double, double, double, frequency);

    __Proxy(text, std::string, std::string, std::string, text);

    __ProxyTrackable(location, kis_tracked_location_triplet, location);

    void from_alert_info(kis_alert_info *info) {
        set_devicekey(info->devicekey);
        set_header(info->header);
        set_phy(info->phy);
        set_timestamp(ts_to_double(info->tm));
        set_transmitter_mac(info->bssid);
        set_source_mac(info->source);
        set_dest_mac(info->dest);
        set_other_mac(info->other);
        set_channel(info->channel);
        set_text(info->text);

        if (info->gps != NULL)
            location->set(info->gps);
    }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("kismet.alert.device_key", "Device key of linked device", &devicekey);
        RegisterField("kismet.alert.header", "Alert type", &header);
        RegisterField("kismet.alert.phy_id", "ID of phy generating alert", &phy);
        RegisterField("kismet.alert.timestamp", "Timestamp (sec.ms)", &timestamp);
        RegisterField("kismet.alert.transmitter_mac", "Transmitter MAC address", &transmitter_mac);
        RegisterField("kismet.alert.source_mac", "Source MAC address", &source_mac);
        RegisterField("kismet.alert.dest_mac", "Destination MAC address", &dest_mac);
        RegisterField("kismet.alert.other_mac", "Other / Extra MAC address", &other_mac);
        RegisterField("kismet.alert.channel", "Phy-specific channel", &channel);
        RegisterField("kismet.alert.frequency", "Frequency (khz)", &frequency);
        RegisterField("kismet.alert.text", "Alert text", &text);
        RegisterField("kismet.alert.location", "location", &location);
    }

    std::shared_ptr<TrackerElementDeviceKey> devicekey;
    std::shared_ptr<TrackerElementString> header;
    std::shared_ptr<TrackerElementUInt32> phy;
    std::shared_ptr<TrackerElementDouble> timestamp;
    std::shared_ptr<TrackerElementMacAddr> transmitter_mac;
    std::shared_ptr<TrackerElementMacAddr> source_mac;
    std::shared_ptr<TrackerElementMacAddr> dest_mac;
    std::shared_ptr<TrackerElementMacAddr> other_mac;
    std::shared_ptr<TrackerElementString> channel;
    std::shared_ptr<TrackerElementDouble> frequency;
    std::shared_ptr<TrackerElementString> text;
    std::shared_ptr<kis_tracked_location_triplet> location;
};


static const int alert_time_unit_conv[] = {
    1, 60, 3600, 86400
};

enum alert_time_unit {
    sat_second, sat_minute, sat_hour, sat_day
};

class tracked_alert_definition : public tracker_component {
public:
    tracked_alert_definition() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_alert_definition(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    tracked_alert_definition(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("tracked_alert_definition");
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

    __Proxy(header, std::string, std::string, std::string, header);
    __Proxy(description, std::string, std::string, std::string, description);
    __Proxy(phy, int64_t, int64_t, int64_t, phy);

    __Proxy(limit_unit, uint64_t, alert_time_unit, alert_time_unit, limit_unit);
    __Proxy(limit_rate, uint64_t, uint64_t, uint64_t, limit_rate);

    __Proxy(burst_unit, uint64_t, alert_time_unit, alert_time_unit, burst_unit);
    __Proxy(limit_burst, uint64_t, uint64_t, uint64_t, limit_burst);

    __Proxy(burst_sent, uint64_t, uint64_t, uint64_t, burst_sent);
    __ProxyIncDec(burst_sent, uint64_t, uint64_t, burst_sent);

    __Proxy(total_sent, uint64_t, uint64_t, uint64_t, total_sent);
    __ProxyIncDec(total_sent, uint64_t, uint64_t, total_sent);

    __Proxy(time_last, double, double, double, time_last);

    int get_alert_ref() { return alert_ref; }
    void set_alert_ref(int in_ref) { alert_ref = in_ref; }

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("kismet.alert.definition.header", "Alert type", &header);
        RegisterField("kismet.alert.definition.description", "Alert description", &description);
        RegisterField("kismet.alert.definition.phyid", "Alert phy type", &phy);
        RegisterField("kismet.alert.definition.limit_unit", 
                "Alert limit time unit (defined in alertracker.h)", &limit_unit);
        RegisterField("kismet.alert.definition.limit_rate", "Alert rate limit", &limit_rate);
        RegisterField("kismet.alert.definition.burst_unit", 
                "Burst limit time unit (defined in alertracker.h)", &burst_unit);
        RegisterField("kismet.alert.definition.limit_burst", "Burst rate limit", &limit_burst);
        RegisterField("kismet.alert.definition.burst_sent", "Alerts sent in burst", &burst_sent);
        RegisterField("kismet.alert.definition.total_sent", "Total alerts sent", &total_sent);
        RegisterField("kismet.alert.definition.time_last", 
                "Timestamp of last alert (sec.us)", &time_last);
    }

    // Non-exposed internal reference
    int alert_ref;

    // Alert type and description
    std::shared_ptr<TrackerElementString> header;
    std::shared_ptr<TrackerElementString> description;
    // Phynum this is linked to
    std::shared_ptr<TrackerElementInt64> phy;

    // Units, rate limit, burst, and burst rate
    std::shared_ptr<TrackerElementUInt64> limit_unit;
    std::shared_ptr<TrackerElementUInt64> limit_rate;
    std::shared_ptr<TrackerElementUInt64> burst_unit;
    std::shared_ptr<TrackerElementUInt64> limit_burst;

    // Number of burst and total alerts we've sent of this type
    std::shared_ptr<TrackerElementUInt64> burst_sent;
    std::shared_ptr<TrackerElementUInt64> total_sent;

    // Timestamp of the last time
    std::shared_ptr<TrackerElementDouble> time_last;

};

typedef std::shared_ptr<tracked_alert_definition> shared_alert_def;

class Alertracker : public Kis_Net_Httpd_CPPStream_Handler, public LifetimeGlobal {
public:
	// Simple struct from reading config lines
	struct alert_conf_rec {
        std::string header;
        alert_time_unit limit_unit;
        int limit_rate;
		alert_time_unit burst_unit;
        int limit_burst;
	};

    static std::string global_name() { return "ALERTTRACKER"; }

    static std::shared_ptr<Alertracker> create_alertracker() {
        std::shared_ptr<Alertracker> mon(new Alertracker());
        Globalreg::globalreg->alertracker = mon.get();
        Globalreg::globalreg->RegisterLifetimeGlobal(mon);
        Globalreg::globalreg->InsertGlobal(global_name(), mon);
        return mon;
    }

private:
    Alertracker();

    // Raise an Prelude alert (requires prelude support compiled in)
    int RaisePreludeAlert(int in_ref, kis_packet *in_pack, mac_addr bssid, mac_addr source,
            mac_addr dest, mac_addr other, std::string in_channel, std::string in_text);
    int RaisePreludeOneShot(std::string in_header, std::string in_text);

    // Initialize Prelude Client (requires prelude support compiled in)
    void PreludeInitClient(const char *analyzer_name);

public:
    virtual ~Alertracker();

    // Register an alert and get an alert reference number back.
    int RegisterAlert(std::string in_header, std::string in_desc, 
            alert_time_unit in_unit, int in_rate, alert_time_unit in_burstunit, 
            int in_burst, int in_phy);

    // Find a reference from a name
    int FetchAlertRef(std::string in_header);

    // Will an alert succeed?
    int PotentialAlert(int in_ref);

    // Raise an alert ...
    int RaiseAlert(int in_ref, kis_packet *in_pack,
                   mac_addr bssid, mac_addr source, mac_addr dest, mac_addr other,
                   std::string in_channel, std::string in_text);

    // Raise a one-shot communications alert
    int RaiseOneShot(std::string in_header, std::string in_text, int in_phy);

    // parse an alert config string
	int ParseAlertStr(std::string alert_str, std::string *ret_name, 
					  alert_time_unit *ret_limit_unit, int *ret_limit_rate,
					  alert_time_unit *ret_limit_burst, int *ret_burst_rate);

	// Load alert rates from a config file
	int ParseAlertConfig(ConfigFile *in_conf);

    // Define an alert and limits
    int DefineAlert(std::string name, alert_time_unit limit_unit, int limit_rate,
            alert_time_unit limit_burst, int burst_rate);

	// Activate a preconfigured alert from a file
	int ActivateConfiguredAlert(std::string in_header, std::string in_desc);
	int ActivateConfiguredAlert(std::string in_header, std::string in_desc, int in_phy);

    // Find an activated alert
    int FindActivatedAlert(std::string in_header);

    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *concls);

protected:
    kis_recursive_timed_mutex alert_mutex;

    std::shared_ptr<Packetchain> packetchain;
    std::shared_ptr<EntryTracker> entrytracker;

    int alert_vec_id, alert_entry_id, alert_timestamp_id, alert_def_id;

    // Check and age times
    int CheckTimes(shared_alert_def arec);

	// Parse a foo/bar rate/unit option
	int ParseRateUnit(std::string in_ru, alert_time_unit *ret_unit, int *ret_rate);

    int pack_comp_alert;
    int alert_ref_kismet;

    int next_alert_id;

    // Internal C++ mapping
    std::map<std::string, int> alert_name_map;
    std::map<int, shared_alert_def> alert_ref_map;

    // Tracked mapping for export
    std::shared_ptr<TrackerElementVector> alert_defs_vec;

    int num_backlog;

    // Backlog of alerts to be sent
    std::vector<kis_alert_info *> alert_backlog;

    // Alert configs we read before we know the alerts themselves
	std::map<std::string, alert_conf_rec *> alert_conf_map;

#ifdef PRELUDE
    // Prelude client
    Prelude::ClientEasy *prelude_client;
#endif

    // Do we log alerts to the kismet database?
    bool log_alerts;

};

#endif
