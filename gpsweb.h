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

#ifndef __GPSWEB_H__
#define __GPSWEB_H__

#include "config.h"

#include "kis_gps.h"
#include "timetracker.h"
#include "globalregistry.h"
#include "kis_net_microhttpd.h"

// GPS WEB
//
// Accept GPS location from HTTP POST, allows using a phone browser as a
// GPS source
//
// Ranked between fixed GPS

class GPSWeb : public Kis_Gps, public Kis_Net_Httpd_Stream_Handler {
public:
    GPSWeb(GlobalRegistry *in_globalreg);
    virtual ~GPSWeb();

    // Kis_GPS Api
    virtual Kis_Gps *BuildGps(string in_opts);

    virtual int OpenGps(string in_opts);

    virtual string FetchGpsDescription();

    virtual bool FetchGpsLocationValid();

    virtual bool FetchGpsConnected();

    virtual kis_gps_packinfo *FetchGpsLocation();

    // HTTP api
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

    virtual int Httpd_PostIterator(void *coninfo_cls, enum MHD_ValueKind kind, 
            const char *key, const char *filename, const char *content_type,
            const char *transfer_encoding, const char *data, 
            uint64_t off, size_t size);

protected:
    GlobalRegistry *globalreg;

    // Last time we calculated the heading, don't do it more than once every 
    // few seconds or we get nasty noise
    time_t last_heading_time;

};

#endif

