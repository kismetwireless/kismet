
#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <memory>

#include "globalregistry.h"
#include "packetchain.h"
#include "timetracker.h"
#include "phy_nrf_51822.h"
#include "kis_httpd_registry.h"
#include "devicetracker.h"
#include "dlttracker.h"
#include "manuf.h"

Kis_NRF51822_Phy::Kis_NRF51822_Phy(global_registry *in_globalreg, int in_phyid) :
    kis_phy_handler(in_globalreg, in_phyid) {

    //globalreg = in_globalreg;

    set_phy_name("NRF51822");

    packetchain = 
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker = 
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    nrf51822_device_entry_id =
        entrytracker->register_field("nrf51822.device",
                tracker_element_factory<nrf51822_tracked_device>(),
                "NRF 51822 device");

    pack_comp_common = packetchain->register_packet_component("COMMON");
	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");

    // Extract the dynamic DLT
    auto dltt = 
        Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");
    dlt = dltt->register_linktype("NRF51822");

    /*
    auto httpregistry = 
        Globalreg::FetchMandatoryGlobalAs<Kis_Httpd_Registry>("WEBREGISTRY");
        */

    // Make the manuf string
    //mj_manuf_amazon = Globalreg::globalreg->manufdb->MakeManuf("Amazon");
    //mj_manuf_logitech = Globalreg::globalreg->manufdb->MakeManuf("Logitech");
    //mj_manuf_microsoft = Globalreg::globalreg->manufdb->MakeManuf("Microsoft");
    mj_manuf_ti = Globalreg::globalreg->manufdb->MakeManuf("Texas Instruments");

    packetchain->register_handler(&DissectorNRF51822, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&CommonClassifierNRF51822, this, CHAINPOS_CLASSIFIER, -100);
}

Kis_NRF51822_Phy::~Kis_NRF51822_Phy() {
    packetchain->remove_handler(&CommonClassifierNRF51822, CHAINPOS_CLASSIFIER);
}

int Kis_NRF51822_Phy::DissectorNRF51822(CHAINCALL_PARMS) {
    auto mphy = static_cast<Kis_NRF51822_Phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == NULL)
        return 0;

    // Is it a packet we care about?
    if (packdata->dlt != mphy->dlt)
        return 0;

    // Do we have enough data for an OUI?
    if (packdata->length < 6)
        return 0;

    //get the mac address
    unsigned char l_mac[6];memset(l_mac,0x00,6);
    l_mac[0] = packdata->data[11];
    l_mac[1] = packdata->data[10];
    l_mac[2] = packdata->data[9];
    l_mac[3] = packdata->data[8];
    l_mac[4] = packdata->data[7];
    l_mac[5] = packdata->data[6];
    // Did something already classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common != NULL)
        return 0;

    common = new kis_common_info;

    //printf("chan :%d\n",(packdata->data[packdata->length-1] & 0x7f));

    common->phyid = mphy->fetch_phy_id();
    common->channel = int_to_string(packdata->data[packdata->length-1] & 0x7f);
    common->basic_crypt_set = crypt_none;
    common->type = packet_basic_mgmt;
    common->source = mac_addr(l_mac, 6);//mac_addr(packdata->data, 6);
    common->transmitter = mac_addr(l_mac, 6);//mac_addr(packdata->data, 6);

    in_pack->insert(mphy->pack_comp_common, common);

    return 1;
}

int Kis_NRF51822_Phy::CommonClassifierNRF51822(CHAINCALL_PARMS) {
    auto mphy = static_cast<Kis_NRF51822_Phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == nullptr)
        return 0;

    // Is it a packet we care about?
    if (packdata->dlt != mphy->dlt)
        return 0;
/**/
    // Did we classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common == NULL)
        return 0;

    // Update with all the options in case we can add signal and frequency
    // in the future
    auto device = 
        mphy->devicetracker->update_common_device(common,
                common->source, mphy, in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                "TI");
    auto nrf51822 =
        device->get_sub_as<nrf51822_tracked_device>(mphy->nrf51822_device_entry_id);

    if (nrf51822 == NULL) {
        _MSG_INFO("Detected new NRF 51822 device {}",
                common->source.mac_to_string());
        nrf51822 = std::make_shared<nrf51822_tracked_device>(mphy->nrf51822_device_entry_id);
        device->insert(nrf51822);
    }
/**/
    return 1;
}

void Kis_NRF51822_Phy::load_phy_storage(shared_tracker_element in_storage,
        shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto nrfdevi = storage->find(nrf51822_device_entry_id);

    if (nrfdevi != storage->end()) {
        auto nrfdev =
            std::make_shared<nrf51822_tracked_device>(nrf51822_device_entry_id,
                    std::static_pointer_cast<tracker_element_map>(nrfdevi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(nrfdev);
    }
}

