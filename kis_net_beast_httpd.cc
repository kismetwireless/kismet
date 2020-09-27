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

#include "kis_net_beast_httpd.h"

#include "configfile.h"
#include "messagebus.h"


std::shared_ptr<kis_net_beast_httpd> kis_net_beast_httpd::create_httpd() {
    auto httpd_interface = 
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("httpd_bind_address", "127.0.0.1");
    auto httpd_port = 
        Globalreg::globalreg->kismet_config->fetch_opt_as<unsigned short>("httpd_port", 2501);

    // Increment beast by 1 for now
    httpd_port = httpd_port + 1;

    boost::asio::ip::address bind_address;

    try {
       bind_address = boost::asio::ip::make_address(httpd_interface);
    } catch (const std::exception& e) {
        _MSG_FATAL("Invalid bind address {} for httpd server; expected interface address: {}", e.what());
        Globalreg::globalreg->fatal_condition = 1;
        return nullptr;
    }

    std::shared_ptr<kis_net_beast_httpd> mon;

    // TODO probably need to build SSL here?

    try {
        auto acceptor = boost::asio::ip::tcp::acceptor(Globalreg::globalreg->io, {bind_address, httpd_port});
        auto socket = boost::asio::ip::tcp::socket(Globalreg::globalreg->io);

        mon = std::shared_ptr<kis_net_beast_httpd>(new kis_net_beast_httpd(acceptor, socket));
    } catch (const std::exception& e) {

    }

    Globalreg::globalreg->register_lifetime_global(mon);
    Globalreg::globalreg->insert_global(global_name(), mon);

    return mon;
}

kis_net_beast_httpd::kis_net_beast_httpd(boost::asio::ip::tcp::acceptor& acceptor,
        boost::asio::ip::tcp::socket& socket) :
    lifetime_global{},
    running{false},
    acceptor{std::move(acceptor)},
    socket{std::move(socket)} {

}

