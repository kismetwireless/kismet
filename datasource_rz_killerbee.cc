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

#include "datasource_rz_killerbee.h"

void kis_datasource_rzkillerbee::handle_rx_packet(kis_packet *packet) {

    auto cc_chunk = 
        packet->fetch<kis_datachunk>(pack_comp_linkframe);

    printf("datasource killerbee got a packet\n");
    for(unsigned int i=0;i<cc_chunk->length;i++)
    {
            printf("%02X",cc_chunk->data[i]);
    }
    printf("\n");

    bool valid_pkt = false;

    int rssi = cc_chunk->data[6];
    if(cc_chunk->data[7])
	    valid_pkt = true;

    printf("rssi:%d valid_pkt:%d\n",rssi,valid_pkt);

    if(valid_pkt)
    {
        //add in a valid crc
	int zb_pkt_len = cc_chunk->data[8];
        auto decapchunk = new kis_datachunk;
        decapchunk->set_data(&cc_chunk->data[9], zb_pkt_len, false);
        decapchunk->dlt = 230;//LINKTYPE_IEEE802_15_4_NOFCS
        packet->insert(pack_comp_decap, decapchunk);

        // Pass the packet on
	printf("Pass the packet on\n");
        packetchain->process_packet(packet);
    }
    else
    {
        delete(packet);
        return;
    }
}

