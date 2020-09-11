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
#include "kis_httpd_registry.h"
#include "devicetracker.h"
#include "dlttracker.h"
#include "manuf.h"

#include "phy_802154.h"

typedef struct {
    uint16_t type; //type identifier
    uint16_t length; // number of octets for type in value field (not including padding
    uint32_t value; // data for type
} tap_tlv;

typedef struct {
    uint8_t version; // currently zero
    uint8_t reserved; // must be zero
    uint16_t length; // total length of header and tlvs in octets, min 4 and must be multiple of 4
    tap_tlv tlv[3];//tap tlvs 3 if we get channel later
    uint8_t payload[0];	        
    ////payload + fcs per fcs type
} zigbee_tap;
zigbee_tap * tap_header;

uint8_t chan = 0;
uint8_t sigstr = 0;

//802.15.4 header
struct _802_15_4_fcf{
    unsigned char type : 3;
    unsigned char security : 1;
    unsigned char pending : 1;
    unsigned char ack_req : 1;
    unsigned char pan_id_comp : 1;
    unsigned char reserved : 1;
    unsigned char sns : 1;
    unsigned char iep : 1;
    unsigned char dest_addr_mode : 2;
    unsigned char frame_ver : 2;
    unsigned char src_addr_mode : 2;
};
_802_15_4_fcf * hdr_802_15_4_fcf;

uint8_t dest[2] = {0x00,0x00};
uint8_t dest_pan[2] = {0x00,0x00};
uint8_t src[2] = {0x00,0x00};
uint8_t src_pan[2] = {0x00,0x00};

uint8_t ext_dest[8];
uint8_t ext_source[8];

kis_802154_phy::kis_802154_phy(global_registry *in_globalreg, int in_phyid) :
    kis_phy_handler(in_globalreg, in_phyid) {

    set_phy_name("802.15.4");

    packetchain = 
        Globalreg::fetch_mandatory_global_as<packet_chain>();
    entrytracker = 
        Globalreg::fetch_mandatory_global_as<entry_tracker>();
    devicetracker =
        Globalreg::fetch_mandatory_global_as<device_tracker>();

    kis_802154_device_entry_id =
        entrytracker->register_field("802154.device",
                tracker_element_factory<kis_802154_tracked_device>(),
                "802.15.4 device");

    pack_comp_common = packetchain->register_packet_component("COMMON");
	pack_comp_linkframe = packetchain->register_packet_component("LINKFRAME");
    pack_comp_l1info = packetchain->register_packet_component("RADIODATA");

    // Extract the dynamic DLT
    auto dltt = 
        Globalreg::fetch_mandatory_global_as<dlt_tracker>("DLTTRACKER");
    dlt = KDLT_IEEE802_15_4_NOFCS;

    /*
    auto httpregistry = 
        Globalreg::fetch_mandatory_global_as<kis_httpd_registry>("WEBREGISTRY");
        */

    packetchain->register_handler(&dissector802154, this, CHAINPOS_LLCDISSECT, -100);
    packetchain->register_handler(&commonclassifier802154, this, CHAINPOS_CLASSIFIER, -100);
}

kis_802154_phy::~kis_802154_phy() {
    packetchain->remove_handler(&commonclassifier802154, CHAINPOS_CLASSIFIER);
}

int kis_802154_phy::dissector802154(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_802154_phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    if (packdata == NULL)
        return 0;

    // Is it a packet we care about?
    if (packdata == NULL || (packdata != NULL && (packdata->dlt != KDLT_IEEE802_15_4_NOFCS && packdata->dlt != KDLT_IEEE802_15_4_TAP)))
    {
        printf("not a packet we care about\n");
        return 0;
    }

    // Do we have enough data for an OUI?
    if (packdata->length < 6)
        return 0;

    // Did something already classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common != NULL)
        return 0;

    //process the packet
    printf("process a packet from within the phy_802154\n");
    //hurray we make it here

    uint8_t pkt_ctr = 0;
    if(packdata->dlt == KDLT_IEEE802_15_4_TAP)
    {
        printf("KDLT_IEEE802_15_4_TAP\n");
        uint64_t tap_header_size = sizeof(zigbee_tap);
        printf("tap_header_size:%d\n",tap_header_size);

        uint8_t tmp_header[32];memset(tmp_header,0x00,32);
        printf("copy over the tmp data\n");
        memcpy(tmp_header, &packdata->data[pkt_ctr], tap_header_size);
        printf("set the header\n");
        tap_header = (zigbee_tap *)&tmp_header;

        //realy we are going to want to iterate through them to pull them correctly.

        printf("pull out the channel\n");
        chan = tap_header->tlv[2].value;

        printf("pull out the signal\n");
        sigstr = tap_header->tlv[1].value;

        //printf("change the dtl\n");
        //packdata->dlt = KDLT_IEEE802_15_4_NOFCS;
        printf("advance the pkt_ctr\n");
        pkt_ctr += tap_header_size;
    }

    printf("pkt_ctr:%d\n",pkt_ctr);

    if(packdata->dlt == KDLT_IEEE802_15_4_NOFCS || packdata->dlt == KDLT_IEEE802_15_4_TAP)
    {
        //printf("parse a 802154 packet of dlt KDLT_IEEE802_15_4_NOFCS\n");
        //printf("print the packet that we got\n");
        //for(int xp=0;xp<(int)packdata->length;xp++)
        //{
            //printf("%02X",packdata->data[xp]);
        //}
        //printf("\n");
        //get the fcf first

        unsigned short fcf = (((short)packdata->data[pkt_ctr+1]) << 8) | (0x00ff & packdata->data[pkt_ctr]);
        pkt_ctr+=2;
        //we need to take a look at what flags are set
        hdr_802_15_4_fcf = (_802_15_4_fcf* )&fcf;

        //printf("struct\n");
//        printf("type:%02X\n",hdr_802_15_4_fcf->type);
//        printf("security:%02X\n",hdr_802_15_4_fcf->security);
        //printf("pending:%02X\n",hdr_802_15_4_fcf->pending);
        //printf("ack_req:%02X\n",hdr_802_15_4_fcf->ack_req);
        //printf("pan_id_comp:%02X\n",hdr_802_15_4_fcf->pan_id_comp);
        //printf("reserved:%02X\n",hdr_802_15_4_fcf->reserved);
        //printf("sns:%02X\n",hdr_802_15_4_fcf->sns);
        //printf("iep:%02X\n",hdr_802_15_4_fcf->iep);
//        printf("dest_addr_mode:%02X\n",hdr_802_15_4_fcf->dest_addr_mode);
//        printf("frame_ver:%02X\n",hdr_802_15_4_fcf->frame_ver);
//        printf("src_addr_mode:%02X\n",hdr_802_15_4_fcf->src_addr_mode);

        //we should be able to handle whichever correctly
        //0x01 - data,  0x03 - cmd, 0x04 - reserved
        //hdr_802_15_4_fcf->type == 0x01 || hdr_802_15_4_fcf->type == 0x03 || hdr_802_15_4_fcf->type == 0x04
        if(hdr_802_15_4_fcf->type == 0x05)
        {
            printf("type %02X currently not supported\n",hdr_802_15_4_fcf->type);
            return 0;
        }
        uint8_t seq;
        if(!hdr_802_15_4_fcf->sns)
        {
            seq = packdata->data[pkt_ctr];pkt_ctr++;
        }

        if(hdr_802_15_4_fcf->dest_addr_mode == 0x01)
        {
            if(hdr_802_15_4_fcf->frame_ver == 0)//this address mode is not valid under this spec
            {
                printf("this address mode is not valid under this spec\n");
                return 0;
            }

            dest[1] = packdata->data[pkt_ctr];
            pkt_ctr++;
        }
        else if(hdr_802_15_4_fcf->dest_addr_mode == 0x02)
        {
            dest[1] = packdata->data[pkt_ctr];pkt_ctr++;
            dest[0] = packdata->data[pkt_ctr];pkt_ctr++;

            dest_pan[1] = packdata->data[pkt_ctr];pkt_ctr++;
            dest_pan[0] = packdata->data[pkt_ctr];pkt_ctr++;
        }
        else if(hdr_802_15_4_fcf->dest_addr_mode == 0x03)
        {
            //length means we actually have an extended dest
            dest[1] = packdata->data[pkt_ctr];pkt_ctr++;
            dest[0] = packdata->data[pkt_ctr];pkt_ctr++;
            //extended dest which is what were are looking for
            ext_dest[7] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[6] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[5] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[4] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[3] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[2] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[1] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_dest[0] = packdata->data[pkt_ctr];pkt_ctr++;
        }

        if(hdr_802_15_4_fcf->src_addr_mode == 0x01)
        {
            if(hdr_802_15_4_fcf->frame_ver == 0)//this address mode is not valid under this spec
            {
                printf("this address mode is not valid under this spec\n");
                return 0;
            }
            src[1] = packdata->data[pkt_ctr];pkt_ctr++;
        }
        else if(hdr_802_15_4_fcf->src_addr_mode == 0x02)
        {
            if(!hdr_802_15_4_fcf->pan_id_comp)
            {
                //src pan
                src_pan[1] = packdata->data[pkt_ctr];pkt_ctr++;
                src_pan[0] = packdata->data[pkt_ctr];pkt_ctr++;
            }
            src[1] = packdata->data[pkt_ctr];pkt_ctr++;
            src[0] = packdata->data[pkt_ctr];pkt_ctr++;
        }
        else if(hdr_802_15_4_fcf->src_addr_mode == 0x03)
        {
            //srcpan
            //extended source
            if(!hdr_802_15_4_fcf->pan_id_comp)
            {
                src_pan[1] = packdata->data[pkt_ctr];pkt_ctr++;
                src_pan[0] = packdata->data[pkt_ctr];pkt_ctr++;
            }
            //extended source which is what were are looking for
            ext_source[7] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[6] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[5] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[4] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[3] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[2] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[1] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[0] = packdata->data[pkt_ctr];pkt_ctr++;
        }

    }

    if(hdr_802_15_4_fcf->src_addr_mode >= 0x02 || hdr_802_15_4_fcf->dest_addr_mode >= 0x02)// || fcf_zzh->ext_src == 1
    {
        if(hdr_802_15_4_fcf->src_addr_mode == 0x03)
        {
            printf("src_addr_mode == 0x03\n");
            for(int xps=0;xps<8;xps++)
                printf("%02X ",ext_source[xps]);
            printf("\n");
        }
        if(hdr_802_15_4_fcf->src_addr_mode == 0x02)
        {
            printf("src_addr_mode == 0x02\n");
            for(int xps=0;xps<2;xps++)
                printf("%02X ",src[xps]);
            printf("\n");
            for(int xps=0;xps<2;xps++)
                printf("%02X ",src_pan[xps]);
            printf("\n");
        }

        if(hdr_802_15_4_fcf->dest_addr_mode == 0x03)
        {
            printf("dest_addr_mode == 0x03\n");
            for(int xps=0;xps<8;xps++)
                printf("%02X ",ext_dest[xps]);
            printf("\n");
        }
        if(hdr_802_15_4_fcf->dest_addr_mode == 0x02)
        {
            printf("dest_addr_mode == 0x02\n");
            for(int xps=0;xps<2;xps++)
                printf("%02X ",dest[xps]);
            printf("\n");
            for(int xps=0;xps<2;xps++)
                printf("%02X ",dest_pan[xps]);
            printf("\n");
        }


        common = new kis_common_info;
        common->phyid = mphy->fetch_phy_id();
        //error
        //datasize
        //channel
        common->channel = fmt::format("{}", (chan));
        //freq_khz
        common->basic_crypt_set = crypt_none;
        common->type = packet_basic_data;
        //direction
        //common->direction = packet_direction_to;
        if(hdr_802_15_4_fcf->src_addr_mode == 0x03)
        {
            printf("set source from ext\n");
            common->source = mac_addr(ext_source, 8);
        }
//        else if(hdr_802_15_4_fcf->src_addr_mode == 0x02 && !hdr_802_15_4_fcf->pan_id_comp)
//        {
//            printf("set source from pan\n");
//            common->source = mac_addr(src_pan, 2);
//        }
        else if(hdr_802_15_4_fcf->src_addr_mode == 0x02 && hdr_802_15_4_fcf->pan_id_comp)
        {
            printf("set source from src\n");
            common->source = mac_addr(src, 2);
        }
        else if(hdr_802_15_4_fcf->src_addr_mode == 0x02)
        {
            printf("set source from src\n");
            common->source = mac_addr(src, 2);
        }

        if(hdr_802_15_4_fcf->dest_addr_mode == 0x03)
        {
            printf("set dest from ext\n");
            common->dest = mac_addr(ext_dest, 8);
        }
        else if(hdr_802_15_4_fcf->dest_addr_mode == 0x02)
        {
            printf("set dest from dest\n");
            common->dest = mac_addr(dest, 2);
        }
//        else if(hdr_802_15_4_fcf->dest_addr_mode == 0x02)
//        {
//            printf("set dest from pan\n");
//            common->dest = mac_addr(dest_pan, 2);
//        }

        //network
        //transmitter
        printf("insert src->dest\n");
        in_pack->insert(mphy->pack_comp_common, common);

    }

    return 1;
}

int kis_802154_phy::commonclassifier802154(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_802154_phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    printf("in commonclassifier802154\n");
    if (packdata == nullptr)
        return 0;

    // Is it a packet we care about?
    printf("commonclassifier802154 packdata->dlt:%d mphy->dlt:%d\n",packdata->dlt,mphy->dlt);
    if (packdata->dlt != mphy->dlt && (packdata->dlt != KDLT_IEEE802_15_4_NOFCS && packdata->dlt != KDLT_IEEE802_15_4_TAP))
        return 0;

    // Did we classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common == NULL)
        return 0;

    printf("as source\n");
    // Update with all the options in case we can add signal and frequency
    // in the future
    auto source_dev = 
        mphy->devicetracker->update_common_device(common,
                common->source, mphy, in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                "802.15.4");

    auto source_kis_802154 =
        source_dev->get_sub_as<kis_802154_tracked_device>(mphy->kis_802154_device_entry_id);

    if (source_kis_802154 == NULL) {
        _MSG_INFO("Detected new 802.15.4 device {}",
                common->source.mac_to_string());
        source_kis_802154 = std::make_shared<kis_802154_tracked_device>(mphy->kis_802154_device_entry_id);
        source_dev->insert(source_kis_802154);
    }

    printf("as dest\n");
    //as destination
    // Update with all the options in case we can add signal and frequency
    // in the future
    auto dest_dev = 
        mphy->devicetracker->update_common_device(common,
                common->dest, mphy, in_pack,
                (UCD_UPDATE_SIGNAL | UCD_UPDATE_FREQUENCIES |
                 UCD_UPDATE_PACKETS | UCD_UPDATE_LOCATION |
                 UCD_UPDATE_SEENBY | UCD_UPDATE_ENCRYPTION),
                "802.15.4");

    auto dest_kis_802154 =
        dest_dev->get_sub_as<kis_802154_tracked_device>(mphy->kis_802154_device_entry_id);

    if (dest_kis_802154 == NULL) {
        _MSG_INFO("Detected new 802.15.4 device {}",
                common->dest.mac_to_string());
        dest_kis_802154 = std::make_shared<kis_802154_tracked_device>(mphy->kis_802154_device_entry_id);
        dest_dev->insert(dest_kis_802154);
    }

    return 1;
}

void kis_802154_phy::load_phy_storage(shared_tracker_element in_storage,
        shared_tracker_element in_device) {
    if (in_storage == nullptr || in_device == nullptr)
        return;

    auto storage = std::static_pointer_cast<tracker_element_map>(in_storage);

    auto kis_802154devi = storage->find(kis_802154_device_entry_id);
    
    if (kis_802154devi != storage->end()) {
        auto kis_802154dev =
            std::make_shared<kis_802154_tracked_device>(kis_802154_device_entry_id,
                    std::static_pointer_cast<tracker_element_map>(kis_802154devi->second));
        std::static_pointer_cast<tracker_element_map>(in_device)->insert(kis_802154dev);
    }
    
}

