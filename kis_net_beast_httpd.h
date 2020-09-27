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

#ifndef __KIS_NET_BEAST_HTTPD_H__
#define __KIS_NET_BEAST_HTTPD_H__ 

#include "config.h"

#include <atomic>
#include <string>

#include "globalregistry.h"

#include "boost/asio.hpp"
#include "boost/beast.hpp"

class kis_net_beast_httpd : public lifetime_global, public std::enable_shared_from_this<kis_net_beast_httpd> {
public:
    static std::string global_name() { return "BEAST_HTTPD_SERVER"; }

    static std::shared_ptr<kis_net_beast_httpd> create_httpd();

private:
    kis_net_beast_httpd(boost::asio::ip::tcp::acceptor& acceptor, boost::asio::ip::tcp::socket& socket);

public:
    virtual ~kis_net_beast_httpd();

    int start_httpd();
    int stop_httpd();

    bool httpd_running() { return running; }
    unsigned int fetch_port() { return port; }
    bool fetch_using_ssl() { return use_ssl; }

protected:
    std::atomic<bool> running;
    unsigned int port;

    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    void start_accept();
    void handle_connection(const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket);

    bool use_ssl;
};

#endif /* ifndef KIS_NET_BEAST_HTTPD_H */
