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
#include "devicetracker.h"

bool Devicetracker_Httpd_Pcap::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {
        // /devices/by-key/[key]/pcap/[key].pcapng
        
        shared_ptr<Devicetracker> devicetracker =
            static_pointer_cast<Devicetracker>(http_globalreg->FetchGlobal("DEVICE_TRACKER"));

        vector<string> tokenurl = StrTokenize(path, "/");
        if (tokenurl.size() < 6)
            return false;

        if (tokenurl[1] != "devices")
            return false;

        if (tokenurl[2] != "by-key")
            return false;

        if (tokenurl[4] != "pcap")
            return false;


        uint64_t key = 0;
        std::stringstream ss(tokenurl[3]);
        ss >> key;

        if (devicetracker->FetchDevice(key) == NULL)
            return false;

        return true;

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

    shared_ptr<Packetchain> packetchain = 
        static_pointer_cast<Packetchain>(http_globalreg->FetchGlobal("PACKETCHAIN"));
    int pack_comp_device = packetchain->RegisterPacketComponent("DEVICE");

    // /devices/by-key/[key]/pcap/[key].pcapng

    shared_ptr<Devicetracker> devicetracker =
        static_pointer_cast<Devicetracker>(http_globalreg->FetchGlobal("DEVICE_TRACKER"));

    vector<string> tokenurl = StrTokenize(url, "/");
    if (tokenurl.size() < 6)
        return;

    if (tokenurl[1] != "devices")
        return;

    if (tokenurl[2] != "by-key")
        return;

    if (tokenurl[4] != "pcap")
        return;

    uint64_t key = 0;
    std::stringstream ss(tokenurl[3]);
    ss >> key;

    if (devicetracker->FetchDevice(key) == NULL)
        return;


    if (!httpd->HasValidSession(connection)) {
        connection->httpcode = 503;
        return;
    }

    Kis_Net_Httpd_Ringbuf_Stream_Aux *saux = 
        (Kis_Net_Httpd_Ringbuf_Stream_Aux *) connection->custom_extension;
      
    // Filter based on the device key
    Pcap_Stream_Ringbuf *psrb = new Pcap_Stream_Ringbuf(http_globalreg,
            saux->get_rbhandler(), 
            [key, pack_comp_device](kis_packet *packet) -> bool {
                kis_tracked_device_info *devinfo = 
                    (kis_tracked_device_info *) packet->fetch(pack_comp_device);

                if (devinfo == NULL) {
                    return false;
                }

                if (devinfo->devref->get_key() == key) {
                    return true;
                }

                return false;
            }, NULL);

    saux->set_aux(psrb, [](Kis_Net_Httpd_Ringbuf_Stream_Aux *aux) {
            if (aux->aux != NULL)
                delete (Kis_Net_Httpd_Ringbuf_Stream_Aux *) (aux->aux);
            });

}

