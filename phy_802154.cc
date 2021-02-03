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
#include "messagebus.h"

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

//zigbee header
struct _zigbee_fcf{
    unsigned char type : 2;
    unsigned char proto_ver : 4;
    unsigned char dis_route : 2;
    unsigned char multicast : 1;
    unsigned char security : 1;
    unsigned char src_route : 1;
    unsigned char dest : 1;
    unsigned char ext_src : 1;
    unsigned char end_dev_initator : 1;
};
_zigbee_fcf * hdr_zigbee_fcf;


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
        return 0;

    // Do we have enough data for an OUI?
    if (packdata->length < 6)
        return 0;

    // Did something already classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common != NULL)
        return 0;

    //process the packet
    //printf("process a packet from within the phy_802154\n");
    //hurray we make it here

    uint8_t pkt_ctr = 0;
    if(packdata->dlt == KDLT_IEEE802_15_4_TAP)
    {
        uint64_t tap_header_size = sizeof(zigbee_tap);
        uint8_t tmp_header[32];memset(tmp_header,0x00,32);
        memcpy(tmp_header, &packdata->data[pkt_ctr], tap_header_size);
        tap_header = (zigbee_tap *)&tmp_header;

        //realy we are going to want to iterate through them to pull them correctly.
        chan = tap_header->tlv[2].value;
        sigstr = tap_header->tlv[1].value;
        pkt_ctr += tap_header_size;
    }

    //printf("pkt_ctr:%d\n",pkt_ctr);

    int start_of_main_packet = pkt_ctr;

    if(packdata->dlt == KDLT_IEEE802_15_4_NOFCS || packdata->dlt == KDLT_IEEE802_15_4_TAP)
    {
        unsigned short fcf = (((short)packdata->data[pkt_ctr+1]) << 8) | (0x00ff & packdata->data[pkt_ctr]);
        pkt_ctr+=2;

        hdr_802_15_4_fcf = (_802_15_4_fcf* )&fcf;

        if(hdr_802_15_4_fcf->type > 0x03)
        {
            printf("type %02X currently not supported\n",hdr_802_15_4_fcf->type);
            return 0;
        }
        if(hdr_802_15_4_fcf->type == 0x00)//beacon
        {
            //look for an invalid beacon
            //beacon should not have security enabled
            if(hdr_802_15_4_fcf->security == 0x01)
            {
                printf("beacon should not have security enabled\n");
                return 0;
            }
            //beacon should not have a dest
            if(hdr_802_15_4_fcf->dest_addr_mode != 0x00)
            {
                printf("beacon should not have a dest\n");
                return 0;
            }
            if(hdr_802_15_4_fcf->sns)
            {
                printf("sns not valid for this header type\n");
                return 0;
            }
            if(hdr_802_15_4_fcf->frame_ver == 0x03)
            {
                printf("frame version not valid for this header type\n");
                return 0;
            }
        }
        if(hdr_802_15_4_fcf->type == 0x01)//data
        {
            if(hdr_802_15_4_fcf->dest_addr_mode == 0x01)
            {
                printf("data should not have a dest 0x01\n");
                return 0;
            }
            if(hdr_802_15_4_fcf->frame_ver == 0x03)
            {
                printf("frame version not valid for this header type\n");
                return 0;
            }
        }
        if(hdr_802_15_4_fcf->type == 0x02)//ack
        {
            //ack needs a source
            if(hdr_802_15_4_fcf->src_addr_mode <= 0x01)
            {
                //printf("ack needs a source\n");
                return 0;
            }
            if(hdr_802_15_4_fcf->dest_addr_mode == 0x01)
            {
                printf("ack should not have a dest 0x01\n");
                return 0;
            }
            //ack should not have security enabled
            if(hdr_802_15_4_fcf->security == 0x01)
            {
                printf("ack should not have security enabled\n");
                return 0;
            }
        }
        if(hdr_802_15_4_fcf->type == 0x03)//command
        {
            //command needs a source
            if(hdr_802_15_4_fcf->src_addr_mode <= 0x01)
            {
                //printf("command needs a source\n");
                return 0;
            }
            if(hdr_802_15_4_fcf->sns)
            {
                printf("sns not valid for this header type\n");
                return 0;
            }
            if(hdr_802_15_4_fcf->frame_ver == 0x03)
            {
                printf("frame version not valid for this header type\n");
                return 0;
            }
        }
        //uint8_t seq;
        if(!hdr_802_15_4_fcf->sns)
        {
            //seq = packdata->data[pkt_ctr];
            pkt_ctr++;
        }
        else
        {
            printf("sns not valid for this header type\n");
            return 0;
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

    //ok so we should be able to look at the next byte to be able to find some things out.
    //one being that if it contains 6LoWPAN info or not.
    if(hdr_802_15_4_fcf->frame_ver == 1)//Frame Version: IEEE Std 802.15.4-2006 (1)
    {
        uint8_t byte7 = packdata->data[pkt_ctr] & (1 << 7);
        uint8_t byte6 = packdata->data[pkt_ctr] & (1 << 6);
        if(byte7 > 0 && byte6 > 0)
        {
            //LoWPAN fragmentation header
            printf("possible LoWPAN fragmentation header %02X\n",packdata->data[pkt_ctr]);
            for(int xps=start_of_main_packet;xps <= pkt_ctr;xps++)
            {
                printf("%02X ",packdata->data[xps]);
            }
            printf("\n");
        }
        else if(byte7 > 0 && byte6 == 0)
        {
            //LoWPAN mesh header
            printf("possible LoWPAN mesh header %02X\n",packdata->data[pkt_ctr]);
            for(int xps=start_of_main_packet;xps <= pkt_ctr;xps++)
            {
                printf("%02X ",packdata->data[xps]);
            }
            printf("\n");
        }
        else if(byte7 == 0 && byte6 > 0)
        {
            //LoWPAN IPv6 addressing header
            printf("possible LoWPAN IPv6 addressing header %02X\n",packdata->data[pkt_ctr]);
            for(int xps=start_of_main_packet;xps <= pkt_ctr;xps++)
            {
                printf("%02X ",packdata->data[xps]);
            }
            printf("\n");
        }
    }
    else if(hdr_802_15_4_fcf->frame_ver == 0)//Frame Version: IEEE Std 802.15.4-2003 (0)
    {
        //get the zigbee network layer header
        unsigned short zigbee_fcf = (((short)packdata->data[pkt_ctr+1]) << 8) | (0x00ff & packdata->data[pkt_ctr]);
        pkt_ctr+=2;

        hdr_zigbee_fcf = (_zigbee_fcf* )&zigbee_fcf;
/**
        printf("hdr_zigbee_fcf.type:%.02X\n",hdr_zigbee_fcf->type);
        printf("hdr_zigbee_fcf.proto_ver:%.02X\n",hdr_zigbee_fcf->proto_ver);
        printf("hdr_zigbee_fcf.dis_route:%.02X\n",hdr_zigbee_fcf->dis_route);
        printf("hdr_zigbee_fcf.multicast:%.02X\n",hdr_zigbee_fcf->multicast);
        printf("hdr_zigbee_fcf.security:%.02X\n",hdr_zigbee_fcf->security);
        printf("hdr_zigbee_fcf.src_route:%.02X\n",hdr_zigbee_fcf->src_route);
        printf("hdr_zigbee_fcf.dest:%.02X\n",hdr_zigbee_fcf->dest);
        printf("hdr_zigbee_fcf.ext_src:%.02X\n",hdr_zigbee_fcf->ext_src);
        printf("hdr_zigbee_fcf.end_dev_initator:%.02X\n",hdr_zigbee_fcf->end_dev_initator);
        printf("\n");
**/
        //next part of the packet
        //Destination 2 bytes reversed
        unsigned short zigbee_dest = (((short)packdata->data[pkt_ctr+1]) << 8) | (0x00ff & packdata->data[pkt_ctr]);
        pkt_ctr+=2;
        //Source 2 bytes reversed
        unsigned short zigbee_src = (((short)packdata->data[pkt_ctr+1]) << 8) | (0x00ff & packdata->data[pkt_ctr]);
        pkt_ctr+=2;
        //Radius 1 byte
        uint8_t zigbee_radius = packdata->data[pkt_ctr];pkt_ctr++;
        //seq num 1 byte
        uint8_t zigbee_seq = packdata->data[pkt_ctr];pkt_ctr++;
        //Extended source 8 bytes - if set
        if(hdr_zigbee_fcf->ext_src)
        {
            //extended source which is what were are looking for
            ext_source[7] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[6] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[5] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[4] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[3] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[2] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[1] = packdata->data[pkt_ctr];pkt_ctr++;
            ext_source[0] = packdata->data[pkt_ctr];pkt_ctr++;
            hdr_802_15_4_fcf->src_addr_mode = 0x03;
        }
    }
    

    if(hdr_802_15_4_fcf->src_addr_mode >= 0x02 || hdr_802_15_4_fcf->dest_addr_mode >= 0x02)
    {
        common = new kis_common_info;
        common->phyid = mphy->fetch_phy_id();
        //error
        //datasize
        //channel
        //common->channel = fmt::format("{}", (chan));
        //freq_khz
        common->basic_crypt_set = crypt_none;
        common->type = packet_basic_data;
        //direction
        //common->direction = packet_direction_to;
        if(hdr_802_15_4_fcf->src_addr_mode == 0x03)
        {
//            printf("set source from ext\n");
            common->source = mac_addr(ext_source, 8);
        }
        else if(hdr_802_15_4_fcf->src_addr_mode == 0x02 && hdr_802_15_4_fcf->pan_id_comp)
        {
//            printf("set source from src\n");
            common->source = mac_addr(src, 2);
        }
        else if(hdr_802_15_4_fcf->src_addr_mode == 0x02)
        {
//            printf("set source from src\n");
            common->source = mac_addr(src, 2);
        }

        if(hdr_802_15_4_fcf->dest_addr_mode == 0x03)
        {
//            printf("set dest from ext\n");
            common->dest = mac_addr(ext_dest, 8);
        }
        else if(hdr_802_15_4_fcf->dest_addr_mode == 0x02)
        {
//            printf("set dest from dest\n");
            common->dest = mac_addr(dest, 2);
        }

        //network
        //transmitter
        in_pack->insert(mphy->pack_comp_common, common);
    }

    return 1;
}

int kis_802154_phy::commonclassifier802154(CHAINCALL_PARMS) {
    auto mphy = static_cast<kis_802154_phy *>(auxdata);

    auto packdata = in_pack->fetch<kis_datachunk>(mphy->pack_comp_linkframe);

    //printf("in commonclassifier802154\n");
    if (packdata == nullptr)
        return 0;

    // Is it a packet we care about?
    if (packdata->dlt != mphy->dlt && (packdata->dlt != KDLT_IEEE802_15_4_NOFCS && packdata->dlt != KDLT_IEEE802_15_4_TAP))
        return 0;

    // Did we classify this?
    auto common = in_pack->fetch<kis_common_info>(mphy->pack_comp_common);

    if (common == NULL)
        return 0;

    // as source
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

    // as destination
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

