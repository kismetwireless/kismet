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

#ifndef __BLUETOOTH_SCAN_SOURCE_H__
#define __BLUETOOTH_SCAN_SOURCE_H__ 

#include "config.h"

#include "datasource_scan.h"
#include "globalregistry.h"
#include "kis_datasource.h"

class bluetooth_scan_source : public datasource_scan_source, public lifetime_global {
public:
    static std::string global_name() { return "bluetooth_scan_source"; }

    static std::shared_ptr<bluetooth_scan_source> create_bluetooth_scan_source() {
        std::shared_ptr<bluetooth_scan_source> bsrc(new bluetooth_scan_source());
        Globalreg::globalreg->register_lifetime_global(bsrc);
        Globalreg::globalreg->insert_global(global_name(), bsrc);
        return bsrc;
    }

private:
    bluetooth_scan_source() :
        datasource_scan_source("/phy/phybluetooth/scan/scan_report",
                "Bluetooth/BTLE Scan",
                "BLUETOOTHSCAN"),
        lifetime_global() { }

public:
    virtual ~bluetooth_scan_source() { };

};

#endif /* ifndef BLUETOOTH_SCAN_SOURCE_H */
