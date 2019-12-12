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
    for(unsigned int i=0;i<cc_chunk->length;i++)
    {
            printf("%02X",cc_chunk->data[i]);
    }
    printf("\n");


		// Pass the packet on
		//printf("Pass the packet on\n");
	//	packetchain->process_packet(packet);

}

