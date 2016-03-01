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

#ifndef __KIS_NET_WEBSESSION_H__
#define __KIS_NET_WEBSESSION_H__

#include "config.h"

#include <string>
#include "trackedelement.h"
#include "kis_net_microhttpd.h"

// We need to subclass the HTTPD handler directly because even though we can
// generally act like a stream, we need to be able to directly manipulate the
// response header
class Kis_Net_Websession : public Kis_Net_Httpd_Handler {
public:
    Kis_Net_Websession(GlobalRegistry *in_globalreg);
    ~Kis_Net_Websession();

    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual int Httpd_HandleRequest(Kis_Net_Httpd *httpd, 
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size);

protected:
    GlobalRegistry *globalreg;

};

#endif

