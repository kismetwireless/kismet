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

#ifndef __GPSDLIBGPS_H__
#define __GPSDLIBGPS_H__

#include "config.h"

#ifdef HAVE_LIBGPS

#include <gps.h>

#include "clinetframework.h"
#include "serialclient.h"
#include "kis_netframe.h"
#include "packetchain.h"
#include "gpscore.h"

class GPSLibGPS : public GPSCore {
public:
    GPSLibGPS();
    GPSLibGPS(GlobalRegistry *in_globalreg);
    virtual ~GPSLibGPS();

	virtual int Timer();

    virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset);
    virtual int Poll(fd_set& in_rset, fd_set& in_wset);
    
    virtual int ParseData();
    
    virtual int Shutdown();

    virtual int Reconnect();
protected:
	struct gps_data_t *lgpst;
	int lgpst_started;

	string host, port;

	int gpseventid;

	int last_mode;

	time_t last_hed_time;
};

#endif

#endif

