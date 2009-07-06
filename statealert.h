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

#ifndef __STATEALERT_H__
#define __STATEALERT_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globalregistry.h"
#include "packetchain.h"
#include "alertracker.h"

class StateAlert {
public:
	StateAlert() { fprintf(stderr, "FATAL OOPS:  StateAlert()\n"); exit(1); }
	StateAlert(GlobalRegistry *in_globalreg) {
		globalreg = in_globalreg;
	}

	virtual ~StateAlert() { }

	virtual int ProcessPacket(kis_packet *in_pack) = 0;

protected:
	GlobalRegistry *globalreg;

};

class BSSTSStateAlert : public StateAlert {
public:
	typedef struct {
		int incident;
		uint64_t bss_timestamp;
		struct timeval ts;
	} bss_rec;

	BSSTSStateAlert() { 
		fprintf(stderr, "FATAL OOPS: BSSTimestampStateAlert()\n");
		exit(1);
	}
	BSSTSStateAlert(GlobalRegistry *in_globalreg);
	virtual ~BSSTSStateAlert();

	virtual int ProcessPacket(kis_packet *in_pack);

protected:
	map<mac_addr, bss_rec *> state_map;

	int alert_bss_ts_ref;

};

#endif

