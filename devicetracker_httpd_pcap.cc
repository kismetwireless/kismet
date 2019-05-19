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

#include "config.h"

#include "kis_net_microhttpd.h"
#include "devicetracker_httpd_pcap.h"
#include "pcapng_stream_ringbuf.h"
#include "devicetracker.h"

bool Devicetracker_Httpd_Pcap::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {
        // /devices/by-key/[key]/pcap/[key].pcapng
       
        std::vector<std::string> tokenurl = StrTokenize(path, "/");
        if (tokenurl.size() < 6)
            return false;

        if (tokenurl[1] != "devices")
            return false;

        if (tokenurl[2] != "by-key")
            return false;

        if (tokenurl[4] != "pcap")
            return false;

        device_key key(tokenurl[3]);
        if (key.get_error())
            return false;

        if (devicetracker->FetchDevice(key) == NULL)
            return false;

        std::string keyurl = tokenurl[3] + ".pcapng";

        if (tokenurl[5] != keyurl)
            return false;

        return true;

    }

    return false;

}

int Devicetracker_Httpd_Pcap::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (strcmp(method, "GET") != 0) {
        return MHD_YES;
    }

    auto packetchain = Globalreg::FetchMandatoryGlobalAs<Packetchain>("PACKETCHAIN");
    int pack_comp_device = packetchain->RegisterPacketComponent("DEVICE");

    // /devices/by-key/[key]/pcap/[key].pcapng

    std::vector<std::string> tokenurl = StrTokenize(url, "/");
    if (tokenurl.size() < 6)
        return MHD_YES;

    if (tokenurl[1] != "devices")
        return MHD_YES;

    if (tokenurl[2] != "by-key")
        return MHD_YES;

    if (tokenurl[4] != "pcap")
        return MHD_YES;

    device_key key(tokenurl[3]);
    if (key.get_error())
        return MHD_YES;

    std::shared_ptr<kis_tracked_device_base> dev = devicetracker->FetchDevice(key);
    if (dev == NULL)
        return MHD_YES;

    if (!httpd->HasValidSession(connection)) {
        connection->httpcode = 503;
        return MHD_YES;
    }

    Kis_Net_Httpd_Buffer_Stream_Aux *saux = 
        (Kis_Net_Httpd_Buffer_Stream_Aux *) connection->custom_extension;
      
    // Filter based on the device key
    auto *psrb = new Pcap_Stream_Packetchain(Globalreg::globalreg,
            saux->get_rbhandler(), 
            [key, pack_comp_device](kis_packet *packet) -> bool {
                kis_tracked_device_info *devinfo = 
                    (kis_tracked_device_info *) packet->fetch(pack_comp_device);

                if (devinfo == NULL) {
                    return false;
                }

                for (auto dri : devinfo->devrefs) {
                    if (dri.second->get_key() == key)
                        return true;
                }

                return false;
            }, NULL);

    auto streamtracker = Globalreg::FetchMandatoryGlobalAs<StreamTracker>("STREAMTRACKER");

    saux->set_aux(psrb, 
        [psrb, streamtracker](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            streamtracker->remove_streamer(psrb->get_stream_id());
            if (aux->aux != NULL) {
                delete (Kis_Net_Httpd_Buffer_Stream_Aux *) (aux->aux);
            }
        });

    streamtracker->register_streamer(psrb, dev->get_macaddr().Mac2String() + ".pcapng",
            "pcapng", "httpd", 
            "pcapng of all packets for device " + dev->get_macaddr().Mac2String());

    return MHD_NO;
}

