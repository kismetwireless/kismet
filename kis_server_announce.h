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

#ifndef __KIS_SERVER_ANNOUNCE__
#define __KIS_SERVER_ANNOUNCE__ 

#include "config.h"

#include <memory>

#include "datasourcetracker.h"
#include "globalregistry.h"

// System to announce a Kismet server via broadcast packets to the local network at
// periodic intervals.
//
// This allows a server to announce it is available for remote capture sources, for
// a zero-config setup on trusted local networks


class kis_server_announce : public lifetime_global, public deferred_startup {
public:
    static std::string global_name() { return "KISMET_SERVER_ANNOUNCE"; }

    static std::shared_ptr<kis_server_announce> create_server_announce() {
        std::shared_ptr<kis_server_announce> shared(new kis_server_announce());
        Globalreg::globalreg->register_lifetime_global(shared);
        Globalreg::globalreg->insert_global(global_name(), shared);
        Globalreg::globalreg->register_deferred_global(shared);
        return shared;
    }

private:
    kis_server_announce();

public:
    virtual ~kis_server_announce();

protected:
    virtual void trigger_deferred_startup() override;

    std::shared_ptr<datasource_tracker> datasourcetracker;
    std::shared_ptr<kis_net_beast_httpd> httpdserver;

    int timerid;

    int announce_sock;
};


#endif /* ifndef KIS_SERVER_ANNOUNCE */
