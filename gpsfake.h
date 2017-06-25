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

#ifndef __GPSFAKE_V2_H__
#define __GPSFAKE_V2_H__

#include "config.h"

#include "kis_gps.h"
#include "timetracker.h"
#include "globalregistry.h"

// New fake GPS
//
// Always sets a fixed location and optional altitude.

class GPSFake : public Kis_Gps {
public:
    GPSFake(GlobalRegistry *in_globalreg);
    virtual ~GPSFake();

    // Kis_GPS Api
    virtual Kis_Gps *BuildGps(string in_opts);

    virtual int OpenGps(string in_opts);

    virtual string FetchGpsDescription();

    virtual bool FetchGpsLocationValid();

    virtual bool FetchGpsConnected();

    virtual kis_gps_packinfo *FetchGpsLocation();

protected:
    GlobalRegistry *globalreg;

};

#endif

