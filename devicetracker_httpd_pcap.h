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

#ifndef __DEVICETRACKER_HTTPD_PCAP__
#define __DEVICETRACKER_HTTPD_PCAP__

#include "config.h"

#include "kis_net_microhttpd.h"

/* This implements a devicetracker-wide pcapng stream, with optional
 * filtering per specific device key */

class Devicetracker_Httpd_Pcap : public Kis_Net_Httpd_Ringbuf_Stream_Handler {
public:
    Devicetracker_Httpd_Pcap() : Kis_Net_Httpd_Ringbuf_Stream_Handler() {
        devicetracker = 
            Globalreg::FetchMandatoryGlobalAs<Devicetracker>();

        Bind_Httpd_Server();
    }

    virtual ~Devicetracker_Httpd_Pcap() { };

    // HandleGetRequest handles generating a stream so we don't need to implement that
    // Same for HandlePostRequest
   
    // Standard path validation
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    // We use this to attach the pcap stream
    virtual int Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size); 

    virtual int Httpd_PostComplete(Kis_Net_Httpd_Connection *con __attribute__((unused))) {
        return 0;
    }

protected:
    std::shared_ptr<Devicetracker> devicetracker;
    
};


#endif

