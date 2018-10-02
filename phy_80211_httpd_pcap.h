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

#ifndef __PHY_80211_HTTPD_PCAP__
#define __PHY_80211_HTTPD_PCAP__

#include "config.h"

#include "kis_net_microhttpd.h"

/* An 802.11-aware pcap-ng streamer */

class Phy_80211_Httpd_Pcap : public Kis_Net_Httpd_Ringbuf_Stream_Handler {
public:
    Phy_80211_Httpd_Pcap() : Kis_Net_Httpd_Ringbuf_Stream_Handler() { 
        Bind_Httpd_Server();
    }

    virtual ~Phy_80211_Httpd_Pcap() { };

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
    
};


#endif

