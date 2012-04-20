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

#ifndef __KIS_DISSECTOR_IPDATA_H__
#define __KIS_DISSECTOR_IPDATA_H__

#include "config.h"

#include "globalregistry.h"
#include "packet.h"
#include "packetchain.h"

class Kis_Dissector_IPdata {
public:
	Kis_Dissector_IPdata() { 
		fprintf(stderr, "FATAL OOPS: Kis_Dissector_IPdata()\n"); 
		exit(1); 
	}

	Kis_Dissector_IPdata(GlobalRegistry *in_globalreg);

	virtual int HandlePacket(kis_packet *in_pack);

	~Kis_Dissector_IPdata();

protected:
	GlobalRegistry *globalreg;

	int pack_comp_datapayload, pack_comp_basicdata, pack_comp_common;
	int alert_dhcpclient_ref;
};

#endif

