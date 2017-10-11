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

/* The new grand, unified Kismet logging system.
 *
 * The new logfile system combines all the previous Kismet logs into a single entity
 * which can later be extrapolated into the original data types (or all new data types).
 *
 * The new log is based on sqlite3 and is, itself, a database.  It borrows from the nosql
 * methodology by, in general, defining the minimum number of normalized fields and 
 * storing data in traditional JSON format whenever possible.
 *
 * The new log format synergizes with the REST UI to provide dynamic access to 
 * historical data.
 *
 * The log file is divided into several core record groups:
 *
 * DEVICES  -   A raw dump of the device record, as JSON.  This is the same data as what
 *              is exported via the REST UI.  Devices are snapshotted at regular intervals.
 *              The entire known tracked device object in Kismet will be serialized to
 *              the database.
 *
 * PACKET   -   Location-tagged data record which includes raw pcap data in the original
 *              DLT format of the datasource, suitable for conversion to pcap files
 *
 * DATA     -   Arbitrary non-pcap data in JSON format, and similar instant records tied
 *              to an event or device
 *
 * MESSAGES -   Kismet message text (traditionally shown on the server console and the
 *              'Messages' panel of the UI)
 *
 * SNAPSHOT -   Snapshots of various state types, such as datasource performance, 
 *              channel usage, and other non-packet/non-device time-based records
 *
 *
 * Storage notes
 *
 * - Normalized floating point fields (such as GPS coordinates) are stored as integers
 *   instead of doubles.  The original value can be obtained by dividing by 100000.
 *
 * - Devices are stored by phy name and mac address.  The 'kismet.device.base.key' field
 *   is only meaningful during an active Kismet session.
 *
 */

#ifndef __KISLOGFILE_H__
#define __KISLOGFILE_H__

#include "config.h"

#include <memory>
#include <mutex>
#include <string>

#include "globalregistry.h"
#include "kis_database.h"
#include "devicetracker.h"
#include "alertracker.h"

class KisLogfile : public KisDatabase {
public:
    KisLogfile(GlobalRegistry *in_globalreg, std::string in_logname);
    virtual ~KisLogfile();

    virtual int Database_UpgradeDB();

    // Log a vector of multiple devices, replacing any old device records
    virtual int log_devices(TrackerElementVector in_devices);

    // Device logs are non-streaming; we need to know the last time we generated
    // device logs so that we can update just the logs we need.
    virtual time_t get_last_device_log_ts() { return last_device_log; }

    // Log a packet
    virtual int log_packet(kis_packet *in_packet);

    // Log data that isn't a packet; this is a slightly more clunky API because we 
    // can't derive the data from the simple packet interface.  GPS may be null,
    // and other attributes may be empty, if that data is not available
    virtual int log_data(kis_gps_packinfo *gps, struct timeval tv, 
            std::string phystring, mac_addr devmac, uuid datasource_uuid, 
            std::string json);

    // Log an alert; takes a standard tracked_alert element
    virtual int log_alert(std::shared_ptr<tracked_alert> in_alert);

    // Log snapshotted data; Slightly clunkier API since it has to allow for
    // entirely generic data
    virtual int log_snapshot(kis_gps_packinfo *gps, struct timeval tv,
            std::string snaptype, std::string json);

protected:
    // Per-table mutexes to prevent clobbering prepared statements
    std::recursive_timed_mutex device_mutex, packet_mutex, data_mutex,
        alert_mutex, msg_mutex, snapshot_mutex;

    std::shared_ptr<Devicetracker> devicetracker;

    int pack_comp_linkframe, pack_comp_gps, pack_comp_radiodata,
        pack_comp_device, pack_comp_datasource;

    time_t last_device_log;

    // Prebaked parameterized statements
    sqlite3_stmt *device_stmt;
    const char *device_pz;

    sqlite3_stmt *packet_stmt;
    const char *packet_pz;

    sqlite3_stmt *data_stmt;
    const char *data_pz;
    
    sqlite3_stmt *alert_stmt;
    const char *alert_pz;

    sqlite3_stmt *msg_stmt;
    const char *msg_pz;
    
    sqlite3_stmt *snapshot_stmt;
    const char *snapshot_pz;
};

#endif

