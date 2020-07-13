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

class device_tracker_httpd_pcap : public kis_net_httpd_ringbuf_stream_handler {
public:
    device_tracker_httpd_pcap() : kis_net_httpd_ringbuf_stream_handler() {
        devicetracker = 
            Globalreg::fetch_mandatory_global_as<device_tracker>();

        bind_httpd_server();
    }

    virtual ~device_tracker_httpd_pcap() { };

    // HandleGetRequest handles generating a stream so we don't need to implement that
    // Same for HandlePostRequest
   
    // Standard path validation
    virtual bool httpd_verify_path(const char *path, const char *method) override;

    // We use this to attach the pcap stream
    virtual KIS_MHD_RETURN httpd_create_stream_response(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) override; 

    virtual KIS_MHD_RETURN httpd_post_complete(kis_net_httpd_connection *con __attribute__((unused))) override {
        return MHD_YES;
    }

protected:
    std::shared_ptr<device_tracker> devicetracker;
    
};


#endif

