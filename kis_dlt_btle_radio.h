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

#ifndef __KIS_DLT_BT_RADIO_H__
#define __KIS_DLT_BT_RADIO_H__

#include "config.h"

#include "globalregistry.h"
#include "packet.h"
#include "packetchain.h"
#include "kis_dlt.h"

#ifndef KDLT_BLUETOOTH_LE_LL
#define KDLT_BLUETOOTH_LE_LL        251
#endif

#ifndef KDLT_BTLE_RADIO
#define KDLT_BTLE_RADIO             256
#endif

class kis_dlt_btle_radio : public kis_dlt_handler {
public:
    static std::string global_name() { return "DLT_BTLE_RADIO"; }

    static std::shared_ptr<kis_dlt_btle_radio> create_dlt() {
        std::shared_ptr<kis_dlt_btle_radio> mon(new kis_dlt_btle_radio());
        Globalreg::globalreg->register_lifetime_global(mon);
        Globalreg::globalreg->insert_global(global_name(), mon);
        return mon;
    }

private:
	kis_dlt_btle_radio();

public:
	virtual ~kis_dlt_btle_radio() { };

protected:
	virtual int handle_packet(const std::shared_ptr<kis_packet>& in_pack) override;
};

#endif

