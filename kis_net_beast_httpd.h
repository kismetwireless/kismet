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
#include <list>
#include <regex>
#include <string>
#include <thread>
#include <unordered_map>

#include "globalregistry.h"

#include "boost/asio.hpp"
#include "boost/beast.hpp"

#include "string_view.hpp"

using namespace nonstd::literals;

class kis_net_beast_httpd_connection;
class kis_net_beast_route;

class kis_net_beast_httpd : public lifetime_global, public std::enable_shared_from_this<kis_net_beast_httpd> {
public:
    static std::string global_name() { return "BEAST_HTTPD_SERVER"; }
    static std::shared_ptr<kis_net_beast_httpd> create_httpd();

    using http_var_map_t = std::unordered_map<std::string, std::string>;

private:
    kis_net_beast_httpd(boost::asio::ip::tcp::acceptor& acceptor, boost::asio::ip::tcp::socket& socket);

public:
    virtual ~kis_net_beast_httpd();

    int start_httpd();
    int stop_httpd();

    bool httpd_running() { return running; }
    unsigned int fetch_port() { return port; }
    bool fetch_using_ssl() { return use_ssl; }

    static std::string decode_uri(nonstd::string_view in) {
        std::string ret;
        ret.reserve(in.length());

        std::string::size_type p = 0;

        while (p < in.length()) {
            if (in[p] == '%' && (p + 2) < in.length() && std::isxdigit(in[p+1]) && std::isxdigit(in[p+2])) {
                char c1 = in[p+1] - (in[p+1] <= '9' ? '0' : (in[p+1] <= 'F' ? 'A' : 'a') - 10);
                char c2 = in[p+2] - (in[p+2] <= '9' ? '0' : (in[p+2] <= 'F' ? 'A' : 'a') - 10);
                ret += char(16 * c1 + c2);
                p += 3;
                continue;
            }

            ret += in[p++];
        }

        return ret;
    }

    static void decode_variables(const nonstd::string_view decoded, http_var_map_t& var_map) {
        nonstd::string_view::size_type pos = 0;
        while (pos != nonstd::string_view::npos) {
            auto next = decoded.find("&", pos);

            nonstd::string_view varline;

            if (next == nonstd::string_view::npos) {
                varline = decoded.substr(pos, decoded.length());
                pos = next;
            } else {
                varline = decoded.substr(pos, next - pos);
                pos = next + 1;
            }

            auto eqpos = varline.find("=");

            if (eqpos == nonstd::string_view::npos)
                var_map[static_cast<std::string>(varline)] = "";
            else
                var_map[static_cast<std::string>(varline.substr(0, eqpos))] = 
                    static_cast<std::string>(varline.substr(eqpos + 1, varline.length()));
        }
    }

protected:
    std::atomic<bool> running;
    unsigned int port;

    boost::asio::ip::tcp::acceptor acceptor;
    boost::asio::ip::tcp::socket socket;
    void start_accept();
    void handle_connection(const boost::system::error_code& ec, boost::asio::ip::tcp::socket socket);

    bool use_ssl;
};

// Central entity which tracks everything about a connection, parsed variables, generator thread, etc.
class kis_net_beast_httpd_connection : public std::enable_shared_from_this<kis_net_beast_httpd_connection> {
public:
    kis_net_beast_httpd_connection(boost::asio::ip::tcp::socket socket,
            std::shared_ptr<kis_net_beast_httpd> httpd);

    using uri_param_t = std::unordered_map<std::string, std::string>;

    void start();

protected:
    std::shared_ptr<kis_net_beast_httpd> httpd;

    boost::asio::ip::tcp::socket socket;

    boost::beast::flat_buffer buffer{8192};
    boost::beast::http::dynamic_body request;
    boost::beast::http::response<boost::beast::http::dynamic_body> response;

    boost::asio::steady_timer deadline;

    std::thread request_thread;

    kis_net_beast_httpd::http_var_map_t http_variables;

    nonstd::string_view uri;
    uri_param_t uri_params;

    nonstd::string_view http_post;
};

// Routes map a templated URL path to a callback generator which creates the content.
//
// Routes are formatted of the type /path/:key/etc
//
// Routes constructed with *no* extensions list match *only* that route
// Routes constructed with an *empty* extensions list {} match *all file types* and resolve at serialization
// Routes constructed with an explicit extensions list {"json", "prettyjson"} resolve ONLY those types
//
// Keys are extracted from the URL and placed in the uri_params dictionary.
// The FILETYPE key is automatically populated with the extracted request file extension (HTML, JSON, etc)
// The GETVARS key is automatically populated with the raw HTTP GET variables string
class kis_net_beast_route {
public:
    // Under this design, all the connection data, uri, variables, streams, etc are stored in the
    // connection record; we don't need to pass anything else
    using http_handler_t = std::function<void (std::shared_ptr<kis_net_beast_httpd_connection>)>;

    kis_net_beast_route(const std::string& route, http_handler_t handler);
    kis_net_beast_route(const std::string& route, const std::list<std::string>& extensions, http_handler_t handler);

    // Does a URL match this route?  If so, populate uri params and uri variables
    bool match_url(const std::string& url, kis_net_beast_httpd_connection::uri_param_t& uri_params,
            kis_net_beast_httpd::http_var_map_t& uri_variables);
    
    // Invoke our registered callback
    void invoke(std::shared_ptr<kis_net_beast_httpd_connection> connection);

protected:
    http_handler_t handler;

    const std::string path_id_pattern = ":([^\\/]+)?";
    const std::string path_capture_pattern = "(?:([^\\/]+?))";
    const std::regex path_re = std::regex(path_id_pattern);

    bool match_types;
    std::vector<std::string> match_keys;

    std::regex match_re;
};

#endif /* ifndef KIS_NET_BEAST_HTTPD_H */
