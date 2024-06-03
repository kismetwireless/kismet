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

/* DLT handler framework */

#ifndef __KIS_DLT_H__
#define __KIS_DLT_H__

#include "config.h"

#include "globalregistry.h"
#include "packet.h"
#include "packetchain.h"

class kis_dlt_handler : public lifetime_global {
public:
	kis_dlt_handler();
	virtual ~kis_dlt_handler();

	virtual int fetch_dlt() { return dlt; }
	virtual std::string fetch_dlt_name() { return dlt_name; }

protected:
	virtual int handle_packet(const std::shared_ptr<kis_packet>& in_pack) = 0;

	std::string dlt_name;
	int dlt;
	int chainid;
	int pack_comp_linkframe, pack_comp_decap, pack_comp_datasrc,
		pack_comp_radiodata, pack_comp_l1_agg, pack_comp_gps, pack_comp_checksum,
        pack_comp_l1data;
    std::shared_ptr<packet_chain> packetchain;
};

#endif

