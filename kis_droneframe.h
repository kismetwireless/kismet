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

#ifndef __KISDRONEFRAME_H__
#define __KISDRONEFRAME_H__

#include "config.h"

#include "util.h"
#include "messagebus.h"
#include "netframework.h"
#include "tracktypes.h"

// Forward prototype
class KisDroneFramework;

// Drone network server framework
class KisDroneFramework : public ServerFramework {
public:
    KisDroneFramework();
    KisDroneFramework(GlobalRegistry *in_globalreg);
    virtual ~KisDroneFramework();
 
    virtual int Accept(int in_fd);
    virtual int ParseData(int in_fd);
    virtual int KillConnection(int in_fd);

    // How many clients total?
    int FetchNumClients();

protected:
    // Client options
    struct client_opt {
        int validated;
    };

    // Client options
    map<int, KisDroneFramework::client_opt *> client_optmap;

    // Password from config file
    string passwd;
};

#endif

