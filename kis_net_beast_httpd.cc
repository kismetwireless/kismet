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

#include <iostream>
#include <fstream>
#include <random>

#include <stdio.h>

#include "alertracker.h"
#include "base64.h"
#include "configfile.h"
#include "messagebus.h"
#include "util.h"


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
        auto endpoint = boost::asio::ip::tcp::endpoint(bind_address, httpd_port);

        _MSG_INFO("Starting Beast webserver on {}:{}", endpoint.address(), endpoint.port());

        mon = std::shared_ptr<kis_net_beast_httpd>(new kis_net_beast_httpd(endpoint));
    } catch (const std::exception& e) {

    }

    Globalreg::globalreg->register_lifetime_global(mon);
    Globalreg::globalreg->register_deferred_global(mon);
    Globalreg::globalreg->insert_global(global_name(), mon);

    return mon;
}

kis_net_beast_httpd::kis_net_beast_httpd(boost::asio::ip::tcp::endpoint& endpoint) :
    lifetime_global{},
    deferred_startup{},
    running{false},
    endpoint{endpoint},
    acceptor{Globalreg::globalreg->io} {

    mime_mutex.set_name("kis_net_beast_httpd MIME map");
    route_mutex.set_name("kis_net_beast_httpd route vector");
    auth_mutex.set_name("kis_net_beast_httpd auth");
}

void kis_net_beast_httpd::trigger_deferred_startup() {
    auto alertracker = Globalreg::fetch_mandatory_global_as<alert_tracker>();

    register_mime_type("html", "text/html");
    register_mime_type("htm", "text/html");
    register_mime_type("css", "text/css");
    register_mime_type("js", "application/javascript");
    register_mime_type("json", "application/json");
    register_mime_type("prettyjson", "application/json");
    register_mime_type("cmd", "application/json");
    register_mime_type("jcmd", "application/json");
    register_mime_type("xml", "application/xml");
    register_mime_type("png", "image/png");
    register_mime_type("jpg", "image/jpeg");
    register_mime_type("jpeg", "image/jpeg");
    register_mime_type("gif", "image/gif");
    register_mime_type("bmp", "image/bmp");
    register_mime_type("ico", "image/vnd.microsoft.icon");
    register_mime_type("svg", "image/svg+xml");
    register_mime_type("svgz", "image/svg+xml");
    register_mime_type("txt", "text/plain");
    register_mime_type("pcap", "application/vnd.tcpdump.pcap");
    register_mime_type("pcapng", "application/vnd.tcpdump.pcap");

    admin_username = Globalreg::globalreg->kismet_config->fetch_opt("httpd_username");
    admin_password = Globalreg::globalreg->kismet_config->fetch_opt("httpd_password");

    auto user_config_path = 
        Globalreg::globalreg->kismet_config->fetch_opt_path("httpd_auth_file",
                "%h/.kismetkismet_httpd.conf");

    if (admin_username != "" || admin_password != "") {
        if (admin_username == "") {
            _MSG_FATAL("Found a httpd_password in a global configuration file, such as kismet.conf, "
                    "kismet_httpd.conf, or kismet_site.conf, but did not find a httpd_username "
                    "configuration option.");
            Globalreg::globalreg->fatal_condition = 1;
            return;
        } else if (admin_password == "") {
            _MSG_FATAL("Found a httpd_username in a global configuration file, such as kismet.conf, "
                    "kismet_httpd.conf, or kismet_site.conf, but did not find a httpd_password "
                    "configuration option.");
            Globalreg::globalreg->fatal_condition = 1;
            return;
        } else {
            alertracker->raise_one_shot("GLOBALHTTPDUSER",
                    fmt::format("Found a httpd_username and httpd_password configuration in a global Kismet "
                        "config file, such as kismet.conf, kismet_httpd.conf, or kismet_site.conf.  "
                        "Any login in the user configuration file {} will be ignored.", user_config_path), -1);
        }

        global_login_config = true;
    } else {
        global_login_config = false;

        config_file user_httpd_config;
        user_httpd_config.parse_config(user_config_path);

        admin_username = user_httpd_config.fetch_opt("httpd_username");
        admin_password = user_httpd_config.fetch_opt("httpd_password");

        if ((admin_username == "" || admin_password == "") && (admin_username != "" || admin_password != "")) {
            _MSG_ERROR("Found a partial configuration in {}, resetting login information.", user_config_path);
            admin_username = "";
            admin_password = "";
        }
    }

    if (admin_password == "") {
        _MSG("This is the first time Kismet has been run as this user.  You will need to set an "
                "administrator username and password before you can use any features of Kismet.  Visit "
                "http://localhost:2501/ to configure the initial login, or consult the Kismet "
                "documentation at https://www.kismetwireless.net/docs/readme/webserver/ about how to "
                "set a password manually.", MSGFLAG_INFO | MSGFLAG_LOCAL);
    }

    load_auth();

    allow_cors_ =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("httpd_allow_cors", false);
    allowed_cors_referrer_ =
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("httpd_allowed_origin", "");

    // Basic session management endpoints
    register_unauth_route("/session/check_setup_ok", {"GET"}, 
            [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                std::ostream os(&con->response_stream());

                if (global_login_config) {
                    con->set_status(406);
                    os << "Login configured in global config\n";
                } else if (admin_password != "") {
                    con->set_status(200);
                    os << "Login configured in user config\n";
                } else {
                    con->set_status(500);
                    os << "Login not configured\n";
                }
            });
}

kis_net_beast_httpd::~kis_net_beast_httpd() {
    _MSG_INFO("Shutting down HTTPD server...");
    stop_httpd();
}

int kis_net_beast_httpd::start_httpd() {
    if (running)
        return 0;

    boost::system::error_code ec;

    acceptor.open(endpoint.protocol(), ec);
    if (ec) {
        _MSG_FATAL("Could not initialize HTTP server on {}:{} - {}", endpoint.address(), endpoint.port(), 
                ec.message());
        Globalreg::globalreg->fatal_condition = 1;
        return -1;
    }

    acceptor.set_option(boost::asio::socket_base::reuse_address(true), ec);
    if (ec) {
        _MSG_FATAL("Could not initialize HTTP server on {}:{}, could not set socket options - {}",
                endpoint.address(), endpoint.port(), ec.message());
        Globalreg::globalreg->fatal_condition = 1;
        return -1;
    }

    acceptor.bind(endpoint, ec);
    if (ec) {
        _MSG_FATAL("Could not initialize HTTP server on {}:{}, could not bind socket - {}",
                endpoint.address(), endpoint.port(), ec.message());
        Globalreg::globalreg->fatal_condition = 1;
        return -1;
    }

    acceptor.listen(boost::asio::socket_base::max_listen_connections, ec);
    if (ec) {
        _MSG_FATAL("Could not initialize HTTP server on {}:{}, could not initiate listen - {}",
                endpoint.address(), endpoint.port(), ec.message());
        Globalreg::globalreg->fatal_condition = 1;
        return -1;
    }

    _MSG_INFO("(DEBUG) Beast server listening on {}:{}", endpoint.address(), endpoint.port());

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

    acceptor.async_accept(boost::asio::make_strand(Globalreg::globalreg->io),
            boost::beast::bind_front_handler(&kis_net_beast_httpd::handle_connection, shared_from_this()));
}

void kis_net_beast_httpd::handle_connection(const boost::system::error_code& ec,
        boost::asio::ip::tcp::socket socket) {

    if (!running)
        return;

    if (!ec) {
        std::make_shared<kis_net_beast_httpd_connection>(std::move(socket), shared_from_this())->start();
    }

    start_accept();
}

std::string kis_net_beast_httpd::decode_uri(boost::beast::string_view in) {
    std::string ret;
    ret.reserve(in.length());

    std::string::size_type p = 0;

    while (p < in.length()) {
        if (in[p] == '%' && (p + 2) < in.length() && std::isxdigit(in[p+1]) && 
                std::isxdigit(in[p+2])) {
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

void kis_net_beast_httpd::set_admin_login(const std::string& username, const std::string& password) {
    auto user_config_path = 
        Globalreg::globalreg->kismet_config->fetch_opt_path("httpd_auth_file",
                "%h/.kismetkismet_httpd.conf");

    config_file user_httpd_config;
    user_httpd_config.parse_config(user_config_path);

    admin_username = user_httpd_config.fetch_opt("httpd_username");
    admin_password = user_httpd_config.fetch_opt("httpd_password");

    user_httpd_config.set_opt("httpd_username", admin_username, true);
    user_httpd_config.set_opt("httpd_password", admin_password, true);

    user_httpd_config.save_config(user_config_path);
}

bool kis_net_beast_httpd::check_admin_login(const std::string& username, const std::string& password) {
    boost_stringview_constant_time_string_compare_ne compare;
    return !compare(username, admin_username) && !compare(password, admin_password);
}

void kis_net_beast_httpd::decode_variables(const boost::beast::string_view decoded, 
        http_var_map_t& var_map) {
    boost::beast::string_view::size_type pos = 0;
    while (pos != boost::beast::string_view::npos) {
        auto next = decoded.find("&", pos);

        boost::beast::string_view varline;

        if (next == boost::beast::string_view::npos) {
            varline = decoded.substr(pos, decoded.length());
            pos = next;
        } else {
            varline = decoded.substr(pos, next - pos);
            pos = next + 1;
        }

        auto eqpos = varline.find("=");

        if (eqpos == boost::beast::string_view::npos)
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

void kis_net_beast_httpd::register_route(const std::string& route, const std::list<std::string>& verbs,
        const std::string& role, http_handler_t handler) {
    local_locker l(&route_mutex, "beast_httpd::register_route");

    std::list<boost::beast::http::verb> b_verbs;
    for (const auto& v : verbs) 
        b_verbs.emplace_back(boost::beast::http::string_to_verb(v));

    route_vec.emplace_back(std::make_shared<kis_net_beast_route>(route, b_verbs, true, role, handler));
}

void kis_net_beast_httpd::register_route(const std::string& route, 
        const std::list<std::string>& verbs, const std::string& role,
        const std::list<std::string>& extensions, http_handler_t handler) {
    local_locker l(&route_mutex, "beast_httpd::register_route (with extensions)");

    std::list<boost::beast::http::verb> b_verbs;
    for (const auto& v : verbs) 
        b_verbs.emplace_back(boost::beast::http::string_to_verb(v));

    route_vec.emplace_back(std::make_shared<kis_net_beast_route>(route, b_verbs, true, role, extensions, handler));
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

void kis_net_beast_httpd::register_unauth_route(const std::string& route, 
        const std::list<std::string>& verbs,
        http_handler_t handler) {
    local_locker l(&route_mutex, "beast_httpd::register_unauth_route");
    std::list<boost::beast::http::verb> b_verbs;
    for (const auto& v : verbs) 
        b_verbs.emplace_back(boost::beast::http::string_to_verb(v));
    route_vec.emplace_back(std::make_shared<kis_net_beast_route>(route, b_verbs, false, "", handler));
}

void kis_net_beast_httpd::register_unauth_route(const std::string& route, 
        const std::list<std::string>& verbs,
        const std::list<std::string>& extensions, http_handler_t handler) {
    local_locker l(&route_mutex, "beast_httpd::register_unauth_route (with extensions)");
    std::list<boost::beast::http::verb> b_verbs;
    for (const auto& v : verbs) 
        b_verbs.emplace_back(boost::beast::http::string_to_verb(v));
    route_vec.emplace_back(std::make_shared<kis_net_beast_route>(route, b_verbs, false, "",
                extensions, handler));
}

std::string kis_net_beast_httpd::create_auth(const std::string& name, const std::string& role, time_t expiry) {
    std::random_device rnd;
    auto dist = std::uniform_int_distribution<uint8_t>(0, 0xFF);
    uint8_t rdata[16];

    for (auto i = 0; i < 16; i++)
        rdata[i] = dist(rnd);

    auto token = uint8_to_hex_str(rdata, 16);

    auto auth = std::make_shared<kis_net_beast_auth>(token, name, role, expiry);

    local_locker l(&auth_mutex, "add auth");
    auth_vec.emplace_back(auth);
    store_auth();

    return token;
}

void kis_net_beast_httpd::remove_auth(const std::string& token) {
    local_locker l(&auth_mutex, "remove auth");

    for (auto a = auth_vec.cbegin(); a != auth_vec.cend(); ++a) {
        if ((*a)->token() == token) {
            auth_vec.erase(a);
            store_auth();
            return;
        }
    }
}

std::shared_ptr<kis_net_beast_auth> kis_net_beast_httpd::check_auth_token(const boost::beast::string_view& token) {
    local_shared_locker l(&auth_mutex, "check auth");

    for (const auto& a : auth_vec) {
        if (a->check_auth(token)) 
            return a;
    }

    return nullptr;
}

void kis_net_beast_httpd::store_auth() {
    local_locker l(&auth_mutex, "store auth");

    Json::Value vec(Json::arrayValue);

    for (const auto& a : auth_vec) {
        if (a->is_valid())
            vec.append(a->as_json());
    }

    for (auto a = auth_vec.begin(); a != auth_vec.end(); ++a) {
        if (!(*a)->is_valid()) {
            auth_vec.erase(a);
            a = auth_vec.begin();
        }
    }

    auto sessiondb_file = 
        Globalreg::globalreg->kismet_config->fetch_opt_path("httpd_session_db2", 
                "%h/.kismet/session.db2");
    FILE *sf = fopen(sessiondb_file.c_str(), "w");

    if (sf == NULL) {
        _MSG_ERROR("(HTTPD) Could not write session data file: {}", 
                kis_strerror_r(errno));
        return;
    }

    fmt::print(sf, "{}", vec);
    fclose(sf);
}

void kis_net_beast_httpd::load_auth() {
    local_locker l(&auth_mutex, "load auth");

    auth_vec.clear();

    auto sessiondb_file = 
        Globalreg::globalreg->kismet_config->fetch_opt_path("httpd_session_db2", 
                "%h/.kismet/session.db2");
    auto sf = std::ifstream(sessiondb_file, std::ifstream::binary);

    Json::Value json;
    std::string errs;

    if (!Json::parseFromStream(Json::CharReaderBuilder(), sf, &json, &errs)) {
        _MSG_ERROR("(HTTPD) Could not read session data file, skipping loading saved sessions.");
        return;
    }

    try {
        for (const auto& j : json) {
            try {
                auth_vec.emplace_back(std::make_shared<kis_net_beast_auth>(j));
            } catch (const auth_construction_error& e) {
                ;
            }
        }
    } catch (const std::exception& e) {
        _MSG_ERROR("(HTTPD) Could not process session data file, skipping loading saved sessions.");
        return;
    }
}

std::shared_ptr<kis_net_beast_route> kis_net_beast_httpd::find_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    local_shared_locker l(&route_mutex, "find_endpoint");

    _MSG_INFO("(DEBUG) Matching request '{}'", con->uri());

    for (const auto& r : route_vec) {
        if (r->match_url(static_cast<const std::string>(con->uri()), con->verb(), 
                    con->uri_params_, con->http_variables_)) 
            return r;
    }

    return nullptr;
}



kis_net_beast_httpd_connection::kis_net_beast_httpd_connection(boost::asio::ip::tcp::socket socket,
        std::shared_ptr<kis_net_beast_httpd> httpd) :
    httpd{httpd},
    stream{std::move(socket)} { }

void kis_net_beast_httpd_connection::start() {
    boost::asio::dispatch(stream.get_executor(),
            boost::beast::bind_front_handler(&kis_net_beast_httpd_connection::do_read,
                shared_from_this()));

}

void kis_net_beast_httpd_connection::set_status(unsigned int status) {
    if (first_response_write)
        throw std::runtime_error("tried to set status connection already in progress");

    response.result(status);
}

void kis_net_beast_httpd_connection::set_status(boost::beast::http::status status) {
    if (first_response_write)
        throw std::runtime_error("tried to set status connection already in progress");

    response.result(status);
}

void kis_net_beast_httpd_connection::set_mime_type(const std::string& type) {
    if (first_response_write)
        throw std::runtime_error("tried to set mime type of connection already in progress");

    response.set(boost::beast::http::field::content_type, type);
}

void kis_net_beast_httpd_connection::set_target_file(const std::string& fname) {
    if (first_response_write)
        throw std::runtime_error("tried to set file target on connection already in progress");

    response.set(boost::beast::http::field::content_disposition,
            fmt::format("attachment; filename=\"{}\"", fname));
}

void kis_net_beast_httpd_connection::do_read() {
    verb_ = {};
    buffer = {};
    http_variables_ = {};
    uri_ = {};
    uri_params_ = {};
    http_post = {};
    response = {};
    response_stream_.consume(response_stream_.size());
    login_valid_ = false;
    login_role_ = {};
    first_response_write = false;

    parser_.emplace();
    parser_->body_limit(100000);


    // TODO how do we handle infinite responders like pcap?  Do we just keep pushing it out 
    // every read/write?
    // stream.expires_after(std::chrono::seconds(60));

    boost::beast::http::async_read(stream, buffer, *parser_, 
            boost::beast::bind_front_handler(&kis_net_beast_httpd_connection::handle_read, 
                shared_from_this()));
}

void kis_net_beast_httpd_connection::handle_read(const boost::system::error_code& ec, size_t sz) {
    if (ec == boost::beast::http::error::end_of_stream)
        return do_close();

    if (ec) {
        _MSG_ERROR("(DEBUG) beast read error: {}", ec.message());
        return do_close();
    }

    if (boost::beast::websocket::is_upgrade(parser_->get())) {
        _MSG_ERROR("(DEBUG) Incoming websocket but we don't deal with it yet");
        /*
        std::make_shared<websocket_session>(
                stream_.release_socket())->do_accept(parser_->release());
                */
        return;
    }

    request_ = boost::beast::http::request<boost::beast::http::string_body>(parser_->release());

    uri_ = request_.target();
    verb_ = request_.method();

    // Extract the auth cookie
    auto cookie_h = request_.find(AUTH_COOKIE);
    if (cookie_h != request_.end()) 
        auth_token_ = cookie_h->value();

    // Extract the basic auth
    auto auth_h = request_.find(boost::beast::http::field::authorization);
    if (auth_h != request_.end()) {
        auto sp = auth_h->value().find_first_of(" ");

        if (sp != boost::beast::string_view::npos) {
            auto auth_type = auth_h->value().substr(0, sp);
            if (auth_type == "Basic") {
                auto auth_data = 
                    base64::decode(static_cast<std::string>(auth_h->value().substr(sp + 1, 
                                    auth_h->value().length())));

                auto cp = auth_data.find_first_of(":");

                if (cp != std::string::npos) {
                    auto user = auth_data.substr(0, cp);
                    auto pass = auth_data.substr(cp + 1, auth_data.length());

                    // Basic auth *always* grants us the login role and overrides a session check
                    login_valid_ = httpd->check_admin_login(user, pass);
                    login_role_ = "login";
                }
            }
        }
    }

    // Look up the token if we didn't log in directly
    if (!login_valid_ && auth_token_ != "") {
        auto auth = httpd->check_auth_token(auth_token_);

        if (auth != nullptr) {
            login_valid_ = true;
            login_role_ = auth->role();
        } else {
            auth_token_ = "";
        }
    }

    // Look for a route
    auto route = httpd->find_endpoint(shared_from_this());

    if (route != nullptr) {
        if (!route->match_role(login_valid_, login_role_)) {
            boost::beast::http::response<boost::beast::http::string_body> 
                res{boost::beast::http::status::unauthorized, request_.version()};

            res.set(boost::beast::http::field::server, "Kismet");
            res.set(boost::beast::http::field::content_type, "text/html");
            res.keep_alive(request_.keep_alive());
            res.body() = std::string("Permission denied");
            res.prepare_payload();

            boost::system::error_code error;

            boost::beast::http::write(stream, res, error);
            if (error) 
                return do_close();

            return do_read();
        }

        _MSG_INFO("(DBEUG) Matched acceptable endpoint");
    }

    // Append the common headers
    response.set(boost::beast::http::field::server, "Kismet");
    response.set(boost::beast::http::field::transfer_encoding, "chunked");

    // Last modified is always "now"
    char lastmod[31];
    struct tm tmstruct;
    time_t now;
    time(&now);
    gmtime_r(&now, &tmstruct);
    strftime(lastmod, 31, "%a, %d %b %Y %H:%M:%S %Z", &tmstruct);
    response.set(boost::beast::http::field::last_modified, lastmod);

    // Defer adding mime type until the first block
    // Defer adding disposition until the first block

    // Append the session headers
    if (auth_token_.length()) {
        response.set(boost::beast::http::field::set_cookie,
                fmt::format("{}={}; Path=/", AUTH_COOKIE, auth_token_));
    }

    // Turn off caching
    response.set(boost::beast::http::field::cache_control, "no-cache");
    response.set(boost::beast::http::field::pragma, "no-cache");
    response.set(boost::beast::http::field::expires, "Sat, 01 Jan 2000 00:00:00 GMT");

    // Append the CORS headers
    if (httpd->allow_cors()) {
        if (httpd->allowed_cors_referrer().length()) {
            response.set(boost::beast::http::field::access_control_allow_origin, httpd->allowed_cors_referrer());
        } else {
            auto origin = request_.find(boost::beast::http::field::origin);

            if (origin != request_.end())
                response.set(boost::beast::http::field::access_control_allow_origin, origin->value());
            else
                response.set(boost::beast::http::field::access_control_allow_origin, "*");
        }

        response.set(boost::beast::http::field::access_control_allow_credentials, "true");
        response.set(boost::beast::http::field::vary, "Origin");
        response.set(boost::beast::http::field::access_control_max_age, "86400");
        response.set(boost::beast::http::field::access_control_allow_methods, "POST, GET, OPTIONS, UPGRADE");
        response.set(boost::beast::http::field::access_control_allow_headers, "Content-Type, Authorization");
    }

    if (request_.method() == boost::beast::http::verb::options && httpd->allow_cors()) {
        // Handle a CORS OPTION request
        response.result(boost::beast::http::status::ok);

        boost::beast::http::response_serializer<boost::beast::http::buffer_body,
            boost::beast::http::fields> sr{response};

        boost::system::error_code error;
        boost::beast::http::write_header(stream, sr, error);

        if (error) 
            return do_close();

        // Send the completion record for the chunked response
        response.body().data = nullptr;
        response.body().size = 0;
        response.body().more = false;

        boost::beast::http::write(stream, sr, error);
        if (error) 
            return do_close();

        return do_read();

    } else if (request_.method() == boost::beast::http::verb::post) {
        // Handle POST data fields
        http_post = request_.body();

        auto content_type = request_[boost::beast::http::field::content_type];

        if (content_type == "application/x-www-form-urlencoded") {
            auto decoded_body = httpd->decode_uri(http_post);
            httpd->decode_variables(decoded_body, http_variables_);

            auto j_k = http_variables_.find("json");
            if (j_k != http_variables_.end()) {
                try {
                    std::stringstream ss(j_k->second);
                    ss >> json;
                } catch (std::exception& e) {
                    ;
                }
            }
        } else if (content_type == "application/json") {
            Json::CharReaderBuilder cbuilder;
            cbuilder["collectComments"] = false;
            auto reader = cbuilder.newCharReader();
            std::string errs;

            reader->parse(http_post.data(), http_post.data() + http_post.length(), &json, &errs);
        }
    }

    response.result(boost::beast::http::status::ok);

    // Prep the streaming body
    boost::beast::http::response_serializer<boost::beast::http::buffer_body,
        boost::beast::http::fields> sr{response};

    boost::system::error_code error;
    boost::beast::http::write_header(stream, sr, error);

    if (error) {
        return do_close();

    }

    // Spawn the generator thread
    std::thread tr([this, route]() {
        auto ref = shared_from_this();

        if (route != nullptr) {
            route->invoke(ref);
        } else {
        // Example populator thread, this will be called as the routed handler in the future
        char *foo = new char[512];
        std::ostream os(&response_stream_);

        for (int x = 0; x < 5; x++) {
            if (response_stream_.is_complete())
                break;

            snprintf(foo, 512, "thread generated data %d\n", x);

            os.write(foo, strlen(foo));

            sleep(1);
        }

        free(foo);

        os.flush();

        }

        response_stream_.complete();
    });

    while (1) {
        boost::system::error_code error;

        auto sz = response_stream_.size();

        if (sz) {
            first_response_write = true;

            // This void * cast is awful but I don't how how to resolve it for a buffer body
            response.body().data = (void *) boost::asio::buffer_cast<const void *>(response_stream_.data());
            response.body().size = sz;
            response.body().more = true;

            boost::beast::http::write(stream, sr, error);

            response_stream_.consume(sz);

            if (error == boost::beast::http::error::need_buffer) {
                // Beast returns 'need_buffer' when it's completed writing a buffer, configure
                // as a non-error
                error = {};
            } else if (error) {
                do_close();
                response_stream_.cancel();
                break;
            }
        }

        // Only exit if the buffer is complete AND empty
        if (response_stream_.size() == 0 && response_stream_.is_complete())
            break;

        // If the buffer has any pending data, regardless of error or completeness,
        // this will instantly return, otherwise it will stall waiting for it to be 
        // populated
        response_stream_.wait();
    }        

    // This should instantly rejoin because we've completed the populator loop
    tr.join();

    // Send the completion record for the chunked response
    response.body().data = nullptr;
    response.body().size = 0;
    response.body().more = false;

    boost::beast::http::write(stream, sr, error);
    if (error) {
        return do_close();
    }

    // Read any more requests in the same connection
    do_read();
}

void kis_net_beast_httpd_connection::handle_write(bool close, const boost::system::error_code& ec,
        size_t sz) {

    if (ec) {
        _MSG_ERROR("(DEBUG) error on connection, closing - {}", ec.message());
        return do_close();
    }

    if (close) {
        return do_close();
    }

    // Perform another read request
    do_read();
}

void kis_net_beast_httpd_connection::do_close() {
    boost::system::error_code ec;
    stream.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send, ec);
}



kis_net_beast_route::kis_net_beast_route(const std::string& route, 
        const std::list<boost::beast::http::verb>& verbs, 
        bool login, const std::string& role, kis_net_beast_httpd::http_handler_t handler) :
    handler{handler},
    route_{route},
    verbs_{verbs},
    login_{login},
    role_{role},
    match_types{false} {

    // Generate the keys list
    for (auto i = std::sregex_token_iterator(route.begin(), route.end(), path_re); 
            i != std::sregex_token_iterator(); i++) {
        match_keys.push_back(static_cast<std::string>(*i));
    }

    if (match_keys.size() == 0)
        match_keys.push_back("URL");

    match_keys.push_back("GETVARS");

    // Generate the extractor expressions
    auto ext_str = std::regex_replace(route, path_re, path_capture_pattern);
    // Match the RE + http variables
    match_re = std::regex(fmt::format("^{}(\\?.*?)?$", ext_str));
}

kis_net_beast_route::kis_net_beast_route(const std::string& route, 
        const std::list<boost::beast::http::verb>& verbs,
        bool login, const std::string& role,
        const std::list<std::string>& extensions, kis_net_beast_httpd::http_handler_t handler) :
    handler{handler},
    route_{route},
    verbs_{verbs},
    login_{login},
    role_{role},
    match_types{true} {

    // Generate the keys list
    for (auto i = std::sregex_token_iterator(route.begin(), route.end(), path_re); 
            i != std::sregex_token_iterator(); i++) {
        match_keys.push_back(static_cast<std::string>(*i));
    }

    if (match_keys.size() == 0)
        match_keys.push_back("URL");

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

    size_t key_num = 0;
    for (const auto& i : match_values) {
        if (key_num >= match_keys.size()) {
            _MSG_ERROR("(DEBUG) HTTP req {} matched more values than known keys in route, something is wrong key pos {}", url, key_num);
            break;
        }

        uri_params.emplace(std::make_pair(match_keys[key_num], static_cast<std::string>(i)));
        key_num++;
    }

    // Decode GET params into the variables map
    const auto& g_k = uri_params.find("GETVARS");
    if (g_k != uri_params.end()) {
        if (g_k->second.length() > 1) {
            // Trim the ? and decode the rest for URL encoding
            auto uri_decode = 
                kis_net_beast_httpd::decode_uri(g_k->second.substr(1, g_k->second.length()));
            // Parse into variables
            kis_net_beast_httpd::decode_variables(uri_decode, uri_variables);
        }
    }

    return true;
}

bool kis_net_beast_route::match_role(bool login, const std::string& role) {
    if (login_ && !login)
        return false;

    boost_stringview_constant_time_string_compare_ne compare;

    auto valid = !compare(role_, role);

    if (role_.length() == 0)
        return true;

    if (role == "login")
        return true;

    return valid;
}

void kis_net_beast_route::invoke(std::shared_ptr<kis_net_beast_httpd_connection> connection) {
    handler(connection);
}



kis_net_beast_auth::kis_net_beast_auth(const Json::Value& json)  {
    try {
        token_ = json["token"].asString();
        name_ = json["name"].asString();
        role_ = json["role"].asString();
        time_created_ = static_cast<time_t>(json["created"].asUInt());
        time_accessed_ = static_cast<time_t>(json["accessed"].asUInt());
        time_expires_ = static_cast<time_t>(json["expires"].asUInt());

    } catch (const std::exception& e) {
        throw auth_construction_error();
    }
}

kis_net_beast_auth::kis_net_beast_auth(const std::string& token, const std::string& name,
        const std::string& role, time_t expires) :
    token_{token},
    name_{name},
    role_{role},
    time_created_{time(0)},
    time_accessed_{0},
    time_expires_{0} { }

bool kis_net_beast_auth::check_auth(const boost::beast::string_view& token) const {
    boost_stringview_constant_time_string_compare_ne compare;
    return !compare(token_, token);
}

Json::Value kis_net_beast_auth::as_json() {
    Json::Value ret;

    ret["token"] = token_;
    ret["name"] = name_;
    ret["role"] = role_;
    ret["created"] = time_created_;
    ret["accessed"] = time_accessed_;
    ret["expires"] = time_expires_;

    return ret;
}

