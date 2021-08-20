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

#ifndef __PACKINFO_SIGNAL_H__
#define __PACKINFO_SIGNAL_H__

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "globalregistry.h"
#include "gpstracker.h"
#include "packet.h"

class packinfo_sig_combo {
    public:
        packinfo_sig_combo(std::shared_ptr<kis_layer1_packinfo> l1, 
                std::shared_ptr<kis_gps_packinfo> gp) :
        lay1{l1},
        gps{gp} {  }

        std::shared_ptr<kis_layer1_packinfo> lay1;
        std::shared_ptr<kis_gps_packinfo> gps;
};

#endif

