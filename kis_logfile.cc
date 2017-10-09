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
#include "kis_logfile.h"

KisLogfile::KisLogfile(GlobalRegistry *in_globalreg, std::string in_logname) :
    KisDatabase(in_globalreg, "kismetlog", in_logname) {


    Database_UpgradeDB();
}

int KisLogfile::Database_UpgradeDB() {
    local_locker dblock(&ds_mutex);

    unsigned int dbv = Database_GetDBVersion();
    std::string sql;
    int r;
    char *sErrMsg = NULL;

    if (dbv < 1) {
        sql =
            "CREATE TABLE devices ("
            
            "first_time INT, " // Time seen
            "last_time INT, "

            "phyname TEXT, " // Phy records
            "devmac TEXT, "

            "strongest_signal INT, " // Strongest signal

            "min_lat INT, " // Locational bounding rectangle
            "min_lon INT, "
            "max_lat INT, "
            "max_lon INT, "

            "strongest_lat INT, " // Strongest location
            "strongest_lon INT, "

            "bytes_data INT, " // Amount of data seen on device

            "type TEXT" // PHY specific type

            "device BLOB" // Actual device
            
            "UNIQUE(phyname, devmac) ON CONFLICT REPLACE)";


    }

    return 1;
}

