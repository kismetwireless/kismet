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

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <string.h>

#include <chrono>

#include "kis_server_announce.h"

#include "configfile.h"
#include "datasourcetracker.h"
#include "kis_endian.h"
#include "timetracker.h"
#include "remote_announcement.h"
#include "kis_net_beast_httpd.h"

kis_server_announce::kis_server_announce() :
    lifetime_global(),
    timerid{-1},
    announce_sock{-1} { }

void kis_server_announce::trigger_deferred_startup() {
    datasourcetracker = Globalreg::fetch_mandatory_global_as<datasource_tracker>();
    httpdserver = Globalreg::fetch_mandatory_global_as<kis_net_beast_httpd>();

    auto timetracker = Globalreg::fetch_mandatory_global_as<time_tracker>();

    if (!Globalreg::globalreg->kismet_config->fetch_opt_bool("server_announce", false))
        return;

    auto announce_port = 
        Globalreg::globalreg->kismet_config->fetch_opt_as<unsigned int>("server_announce_port", 2501);
    auto announce_address = 
        Globalreg::globalreg->kismet_config->fetch_opt_as<std::string>("server_announce_address", "0.0.0.0");

    struct sockaddr_in sin, lin;

    memset(&sin, 0, sizeof(sin));
    memset(&lin, 0, sizeof(lin));

    sin.sin_family = AF_INET;
    sin.sin_port = htons(announce_port);
    sin.sin_addr.s_addr = INADDR_BROADCAST;

    lin.sin_family = AF_INET;
    lin.sin_port = htons(0);
    if (inet_pton(AF_INET, announce_address.c_str(), 
                &(lin.sin_addr.s_addr)) == 0) {
        lin.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if ((announce_sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        _MSG_FATAL("Could not create remote capture announcement socket: {}", kis_strerror_r(errno));
        Globalreg::globalreg->fatal_condition = 1;
    }

    int x = 1;
    if (setsockopt(announce_sock, SOL_SOCKET, SO_BROADCAST, &x, sizeof(x)) < 0) {
        _MSG_FATAL("Could not set remote capture announcement socket to broadcast: {}",
                kis_strerror_r(errno));
        Globalreg::globalreg->fatal_condition = 1;
        close(announce_sock);
        return;
    }

    if (bind(announce_sock, (struct sockaddr *) &lin, sizeof(lin)) < 0) {
        _MSG_FATAL("Could not bind remote capture announcement socket: {}", kis_strerror_r(errno));
        Globalreg::globalreg->fatal_condition = 1;
        close(announce_sock);
        return;
    }

    if (connect(announce_sock, (struct sockaddr *) &sin, sizeof(sin)) < 0) {
        _MSG_FATAL("Could not connect remote capture announcement socket: {}", kis_strerror_r(errno));
        Globalreg::globalreg->fatal_condition = 1;
        close(announce_sock);
        return;
    }

    _MSG_INFO("Announcing remote capture service on {}:{}", 
            datasourcetracker->remote_listen(), datasourcetracker->remote_port());


    timetracker->register_timer(std::chrono::seconds(5), true,
            [this](int) -> int {
                if (announce_sock <= 0)
                    return 0;

                kismet_remote_announce announcement;

                memset(&announcement, 0, sizeof(kismet_remote_announce));

                announcement.tag = htobe64(REMOTE_ANNOUNCE_TAG);
                announcement.announce_version = htobe16(REMOTE_ANNOUNCE_VERSION);
                announcement.server_port = htobe32(httpdserver->fetch_port());
                announcement.remote_port = htobe32(datasourcetracker->remote_port());

                struct timeval tv;
                gettimeofday(&tv, 0);

                announcement.server_ts_sec = htobe64(tv.tv_sec);
                announcement.server_ts_usec = htobe64(tv.tv_usec);
               
                auto uuid_str = Globalreg::globalreg->server_uuid->get().as_string();

                if (uuid_str.length() != 36)
                    snprintf(announcement.uuid, 36, "INVALID");
                else
                    memcpy(announcement.uuid, uuid_str.c_str(), 36);

                snprintf(announcement.name, 32, "%s", Globalreg::globalreg->servername.c_str());

                if (send(announce_sock, &announcement, sizeof(kismet_remote_announce), 0) < 0) {
                    _MSG_ERROR("Error sending Kismet announcement frame: {}", kis_strerror_r(errno));
                }

                return 1;
            });


}

kis_server_announce::~kis_server_announce() {
    auto timetracker = Globalreg::fetch_global_as<time_tracker>();
    if (timetracker != nullptr)
        timetracker->remove_timer(timerid);

    if (announce_sock > 0)
        close(announce_sock);

}



