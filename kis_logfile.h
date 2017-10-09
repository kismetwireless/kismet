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
 * DATA     -   Location-tagged data record which can include raw pcap data in the original
 *              DLT format of the datasource, arbitrary non-pcap data in JSON format,
 *              and similar instant records
 * 
 * ALERTS   -   Alert information from the Kismet WIDS subsystem
 *
 * MESSAGES -   Kismet message text (traditionally shown on the server console and the
 *              'Messages' panel of the UI)
 *
 * SNAPSHOT -   Snapshots of various state types, such as datasource performance, 
 *              channel usage, and other non-packet time-based records
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

class KisLogfile : public KisDatabase {
public:
    KisLogfile(GlobalRegistry *in_globalreg, std::string in_logname);
    virtual ~KisLogfile();

    virtual int Database_UpgradeDB();

protected:

};

#endif

