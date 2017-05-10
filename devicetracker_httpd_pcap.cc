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

#include "config.hpp"

#include "kis_net_microhttpd.h"
#include "devicetracker_httpd_pcap.h"
#include "pcapng_stream_ringbuf.h"

bool Devicetracker_Httpd_Pcap::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {
        // Total pcap of all data
        if (strcmp(path, "/data/all_packets.pcapng") == 0) {
            return true;
        }

        // TODO device key lookup
    }

    return false;

}

void Devicetracker_Httpd_Pcap::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (strcmp(method, "GET") != 0) {
        return;
    }

    if (strcmp(url, "/data/all_packets.pcapng") == 0) {
        if (!httpd->HasValidSession(connection)) {
            connection->httpcode = 503;
            return;
        }

        // At this point we're logged in and have an aux pointer for the
        // ringbuf aux; We can create our pcap ringbuf stream and attach it.
        // We need to close down the pcapringbuf during teardown.
        
        Kis_Net_Httpd_Ringbuf_Stream_Aux *saux = 
            (Kis_Net_Httpd_Ringbuf_Stream_Aux *) connection->custom_extension;
        
        Pcap_Stream_Ringbuf *psrb = new Pcap_Stream_Ringbuf(http_globalreg,
                saux->get_rbhandler(), NULL, NULL);

        saux->set_aux(psrb, [](Kis_Net_Httpd_Ringbuf_Stream_Aux *aux) {
            if (aux->aux != NULL)
                delete (Kis_Net_Httpd_Ringbuf_Stream_Aux *) (aux->aux);
        });

    }


}

