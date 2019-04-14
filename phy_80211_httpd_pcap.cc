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
#include "phy_80211_httpd_pcap.h"
#include "pcapng_stream_ringbuf.h"
#include "devicetracker.h"
#include "phy_80211.h"

bool Phy_80211_Httpd_Pcap::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "GET") == 0) {
        std::vector<std::string> tokenurl = StrTokenize(path, "/");

        // /phy/phy80211/by-bssid/[mac]/pcap/[mac].pcapng
        if (tokenurl.size() < 7)
            return false;

        if (tokenurl[1] != "phy")
            return false;

        if (tokenurl[2] != "phy80211")
            return false;

        if (tokenurl[3] != "by-bssid")
            return false;

        mac_addr dmac(tokenurl[4]);
        if (dmac.error) {
            fprintf(stderr, "debug - invalid dmac %s\n", tokenurl[4].c_str());
            return false;
        }

        if (tokenurl[5] != "pcap")
            return false;

        // Valid requested file?
        if (tokenurl[6] != tokenurl[4] + ".pcapng")
            return false;

        auto devicetracker =
            Globalreg::FetchMandatoryGlobalAs<Devicetracker>("DEVICETRACKER");

        Kis_Phy_Handler *dot11phy = 
            devicetracker->FetchPhyHandlerByName("IEEE802.11");

        if (dot11phy == NULL) {
            fprintf(stderr, "debug - couldn't find dot11phy\n");
            return false;
        }


        // Does it exist?
        device_key targetkey(dot11phy->FetchPhynameHash(), dmac);

        if (devicetracker->FetchDevice(targetkey) != NULL)
            return true;
    }

    return false;
}

int Phy_80211_Httpd_Pcap::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    if (strcmp(method, "GET") != 0) {
        return MHD_YES;
    }

    auto devicetracker =
        Globalreg::FetchMandatoryGlobalAs<Devicetracker>("DEVICETRACKER");

    Kis_Phy_Handler *dot11phy = 
        devicetracker->FetchPhyHandlerByName("IEEE802.11");

    if (dot11phy == NULL)
        return MHD_YES;

    std::vector<std::string> tokenurl = StrTokenize(url, "/");

    // /phy/phy80211/by-bssid/[mac]/pcap/[mac].pcapng
    if (tokenurl.size() < 7)
        return MHD_YES;

    if (tokenurl[1] != "phy")
        return MHD_YES;

    if (tokenurl[2] != "phy80211")
        return MHD_YES;

    if (tokenurl[3] != "by-bssid")
        return MHD_YES;

    mac_addr dmac(tokenurl[4]);
    if (dmac.error)
        return MHD_YES;

    if (tokenurl[5] != "pcap")
        return MHD_YES;

    // Valid requested file?
    if (tokenurl[6] != tokenurl[4] + ".pcapng")
        return MHD_YES;

    // Does it exist?
    device_key targetkey(dot11phy->FetchPhynameHash(), dmac);

    std::shared_ptr<kis_tracked_device_base> dev;
    if ((dev = devicetracker->FetchDevice(targetkey)) == NULL)
        return MHD_YES;

    if (!httpd->HasValidSession(connection, true)) {
        connection->httpcode = 503;
        return MHD_YES;
    }

    auto streamtracker = Globalreg::FetchMandatoryGlobalAs<StreamTracker>("STREAMTRACKER");
    auto packetchain = Globalreg::FetchMandatoryGlobalAs<Packetchain>("PACKETCHAIN");
    int pack_comp_dot11 = packetchain->RegisterPacketComponent("PHY80211");

    Kis_Net_Httpd_Buffer_Stream_Aux *saux = 
        (Kis_Net_Httpd_Buffer_Stream_Aux *) connection->custom_extension;
      
    // Filter based on the device key
    auto *psrb = new Pcap_Stream_Packetchain(Globalreg::globalreg,
            saux->get_rbhandler(), 
            [dmac, pack_comp_dot11](kis_packet *packet) -> bool {
                dot11_packinfo *dot11info =
                    (dot11_packinfo *) packet->fetch(pack_comp_dot11);

                if (dot11info == NULL) {
                    return false;
                }

                if (dot11info->bssid_mac == dmac) {
                    return true;
                }

                return false;
            }, NULL);

    saux->set_aux(psrb, 
        [psrb, streamtracker](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            streamtracker->remove_streamer(psrb->get_stream_id());
            if (aux->aux != NULL) {
                delete (Pcap_Stream_Packetchain *) (aux->aux);
            }
        });

    streamtracker->register_streamer(psrb, "phy80211-" + dmac.Mac2String() + " .pcapng",
            "pcapng", "httpd", 
            "pcapng of all packets on phy80211 BSSID " + dmac.Mac2String());

    return MHD_NO;
}

