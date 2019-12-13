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

#include "datasource_nrf_52840.h"

void kis_datasource_nrf52840::handle_rx_packet(kis_packet *packet) {

    auto cc_chunk = 
        packet->fetch<kis_datachunk>(pack_comp_linkframe);

    printf("datasource 52840 got a packet\n");
/*
    for(unsigned int i=0;i<cc_chunk->length;i++)
    {
            printf("%02X",cc_chunk->data[i]);
    }
    printf("\n");
*/
/*
    for(unsigned int i=0;i<cc_chunk->length;i++)
    {
            printf("%c",cc_chunk->data[i]);
    }
    printf("\n");
*/
    uint8_t c_payload[255];memset(c_payload,0x00,255);
    uint8_t payload[255];memset(payload,0x00,255);
    char tmp[16];memset(tmp,0x00,16);
    int16_t lqi = 0;
    int16_t rssi = 0;

    int16_t loc[4] = {0,0,0,0};
    uint8_t li=0;

    for(unsigned int i=0;i<cc_chunk->length;i++)
    {
        if(cc_chunk->data[i] == ':')
	{
		loc[li] = i;
		li++;
		if(li > 4)
			break;
	}
    }
    //printf("loc[0]:%d loc[1]:%d loc[2]:%d loc[3]:%d\n",loc[0],loc[1],loc[2],loc[3]);
    //copy over the packet
    memcpy(c_payload,&cc_chunk->data[loc[0]+2],(loc[1] - loc[0] - 1 - (strlen("payload")))); 

    //copy over the power/rssi
    memcpy(tmp,&cc_chunk->data[loc[1]+2],(loc[2] - loc[1] - 2 - (strlen("lqi"))));
    //printf("rssi:%s\n",tmp);
    rssi = atoi(tmp);
    memset(tmp,0x00,16);

    //copy over the lqi
    memcpy(tmp,&cc_chunk->data[loc[2]+2],(loc[3] - loc[2] - 3 - (strlen("time"))));
    //printf("lqi:%s\n",tmp);
    lqi = atoi(tmp);
    memset(tmp,0x00,16);

    /*received: %s power: %d lqi: %d time: %d */
    
    printf("c_payload:%s\n",c_payload);
    printf("power:%d\n",rssi);
    printf("lqi:%d\n",lqi);
    
		// Pass the packet on
		//printf("Pass the packet on\n");
	//	packetchain->process_packet(packet);

}

