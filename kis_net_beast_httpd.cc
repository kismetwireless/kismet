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

    mime_mutex.set_name("kis_net_beast_httpd MIME map");
    route_mutex.set_name("kis_net_beast_httpd route vector");

}

kis_net_beast_httpd::~kis_net_beast_httpd() {
    _MSG_INFO("Shutting down HTTPD server...");
    stop_httpd();
}

int kis_net_beast_httpd::start_httpd() {
    if (running)
        return 0;

    running = true;

    start_accept();

    return 1;
}

int kis_net_beast_httpd::stop_httpd() {
    if (!running)
        return 0;

    running = false;

    if (acceptor.is_open()) {
        try {
            acceptor.cancel();
            acceptor.close();
        } catch (const std::exception& e) {
            ;
        }
    }

    return 1;
}

void kis_net_beast_httpd::start_accept() {
    if (!running)
        return;

    auto this_ref = shared_from_this();

    acceptor.async_accept(socket,
            [this, this_ref](boost::system::error_code ec) {
                if (!running)
                    return;

                if (!ec) {
                    std::make_shared<kis_net_beast_httpd_connection>(std::move(socket), 
                            shared_from_this())->start();
                }

                start_accept();
            });
}

std::string kis_net_beast_httpd::decode_uri(nonstd::string_view in) {
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

void kis_net_beast_httpd::decode_variables(const nonstd::string_view decoded, http_var_map_t& var_map) {
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

void kis_net_beast_httpd::register_mime_type(const std::string& extension, const std::string& type) {
    local_locker l(&mime_mutex, "beast_httpd::register_mime_type");
    mime_map.emplace(std::make_pair(extension, type));
}

void kis_net_beast_httpd::remove_mime_type(const std::string& extension) {
    local_locker l(&mime_mutex, "beast_httpd::remove_mime_type");
    auto k = mime_map.find(extension);
    if (k != mime_map.end())
        mime_map.erase(k);
}

std::string kis_net_beast_httpd::resolve_mime_type(const std::string& extension) {
    local_shared_locker l(&mime_mutex, "beast_httpd::resolve_mime_type");
    auto k = mime_map.find(extension);
    if (k != mime_map.end())
        return k->second;
    return "text/plain";
}

void kis_net_beast_httpd::register_route(const std::string& route, http_handler_t handler) {
    local_locker l(&route_mutex, "beast_httpd::register_route");
    route_vec.push_back(std::make_shared<kis_net_beast_route>(route, handler));
}

void kis_net_beast_httpd::register_route(const std::string& route, 
        const std::list<std::string>& extensions, http_handler_t handler) {
    local_locker l(&route_mutex, "beast_httpd::register_route (with extensions)");
    route_vec.push_back(std::make_shared<kis_net_beast_route>(route, extensions, handler));
}

void kis_net_beast_httpd::remove_route(const std::string& route) {
    local_locker l(&route_mutex, "beast_httpd::remove_route");

    for (auto i = route_vec.begin(); i != route_vec.end(); ++i) {
        if ((*i)->route() == route) {
            route_vec.erase(i);
            return;
        }
    }
}

void kis_net_beast_httpd::register_unauth_route(const std::string& route, http_handler_t handler) {
    local_locker l(&route_mutex, "beast_httpd::register_unauth_route");
    unauth_route_vec.push_back(std::make_shared<kis_net_beast_route>(route, handler));
}

void kis_net_beast_httpd::register_unauth_route(const std::string& route, 
        const std::list<std::string>& extensions, http_handler_t handler) {
    local_locker l(&route_mutex, "beast_httpd::register_unauth_route (with extensions)");
    unauth_route_vec.push_back(std::make_shared<kis_net_beast_route>(route, extensions, handler));
}

void kis_net_beast_httpd::remove_unauth_route(const std::string& route) {
    local_locker l(&route_mutex, "beast_httpd::remove_unauth_route");

    for (auto i = unauth_route_vec.begin(); i != unauth_route_vec.end(); ++i) {
        if ((*i)->route() == route) {
            unauth_route_vec.erase(i);
            return;
        }
    }
}




kis_net_beast_httpd_connection::kis_net_beast_httpd_connection(boost::asio::ip::tcp::socket socket,
        std::shared_ptr<kis_net_beast_httpd> httpd) :
    httpd{httpd},
    socket{std::move(socket)},
    deadline{socket.get_executor(), std::chrono::seconds(60)} {

}

void kis_net_beast_httpd_connection::start() {

}


kis_net_beast_route::kis_net_beast_route(const std::string& route, 
        const std::list<boost::beast::http::verb>& verbs, 
        kis_net_beast_httpd::http_handler_t handler) :
    handler{handler},
    route_{route},
    verbs_{verbs},
    match_types{false} {

    // Generate the keys list
    for (auto i = std::sregex_token_iterator(route.begin(), route.end(), path_re); 
            i != std::sregex_token_iterator(); i++) {
        match_keys.push_back(static_cast<std::string>(*i));
    }
    match_keys.push_back("GETVARS");

    // Generate the extractor expressions
    auto ext_str = std::regex_replace(route, path_re, path_capture_pattern);
    // Match the RE + http variables
    match_re = std::regex(fmt::format("^{}(\\?.*?)?$", ext_str));
}

kis_net_beast_route::kis_net_beast_route(const std::string& route, 
        const std::list<boost::beast::http::verb>& verbs,
        const std::list<std::string>& extensions, kis_net_beast_httpd::http_handler_t handler) :
    handler{handler},
    route_{route},
    verbs_{verbs},
    match_types{true} {

    // Generate the keys list
    for (auto i = std::sregex_token_iterator(route.begin(), route.end(), path_re); 
            i != std::sregex_token_iterator(); i++) {
        match_keys.push_back(static_cast<std::string>(*i));
    }
    match_keys.push_back("FILETYPE");
    match_keys.push_back("GETVARS");

    // Generate the file type regex
    auto ft_regex = std::string("\\.(");
    if (extensions.size() == 0) {
        // If passed an empty list we accept all types and resolve during serialziation
        ft_regex += "[A-Za-z0-9]+";
    } else {
        bool prepend_pipe = false;
        for (const auto& i : extensions) {
            if (prepend_pipe)
                ft_regex += fmt::format("|{}", i);
            else
                ft_regex += fmt::format("{}", i);
            prepend_pipe = true;
        }
    }
    ft_regex += ")";

    // Generate the extractor expressions
    auto ext_str = std::regex_replace(route, path_re, path_capture_pattern);
    // Match the RE + filetypes + http variables
    match_re = std::regex(fmt::format("^{}{}(\\?.*?)?$", ft_regex, ext_str));
}

bool kis_net_beast_route::match_url(const std::string& url, 
        boost::beast::http::verb verb,
        kis_net_beast_httpd_connection::uri_param_t& uri_params,
        kis_net_beast_httpd::http_var_map_t& uri_variables) {

    bool match_verb = false;
    for (const auto& v : verbs_) {
        if (verb == v) {
            match_verb = true;
            break;
        }
    }

    if (!match_verb)
        return false;

    auto match_values = std::smatch();

    if (!std::regex_match(url, match_values, match_re))
        return false;

    size_t key_pos = 0;
    for (const auto& i : match_values) {
        if (key_pos >= match_keys.size()) {
            _MSG_ERROR("(DEBUG) HTTP req {} matched more values than known keys in route, something is wrong");
            break;
        }

        uri_params.emplace(std::make_pair(match_keys[key_pos], static_cast<std::string>(i)));
        key_pos++;
    }

    // Decode GET params into the variables map
    const auto& g_k = uri_params.find("GETVARS");
    if (g_k != uri_params.end()) {
        if (g_k->second.length() > 1) {
            // Trim the ? and decode the rest for URL encoding
            auto uri_decode = kis_net_beast_httpd::decode_uri(g_k->second.substr(1, g_k->second.length()));
            // Parse into variables
            kis_net_beast_httpd::decode_variables(uri_decode, uri_variables);
        }
    }

    return true;
}

void kis_net_beast_route::invoke(std::shared_ptr<kis_net_beast_httpd_connection> connection) {
    handler(connection);
}

