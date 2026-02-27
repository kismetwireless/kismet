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

#include "globalregistry.h"

#include "alertracker.h"
#include "base64.h"
#include "configfile.h"
#include "messagebus.h"
#include "util.h"

const std::string kis_net_beast_httpd::LOGON_ROLE{"admin"};
const std::string kis_net_beast_httpd::ANY_ROLE{"any"};
const std::string kis_net_beast_httpd::RO_ROLE{"readonly"};

const std::string kis_net_beast_httpd::AUTH_COOKIE{"KISMET"};

std::shared_ptr<kis_net_beast_httpd> kis_net_beast_httpd::create_httpd() {
    auto httpd_interface =
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("httpd_bind_address", "0.0.0.0");
    auto httpd_port =
        Globalreg::globalreg->kismet_config->fetch_opt_as<unsigned short>("httpd_port", 2501);

    boost::asio::ip::address bind_address;

    try {
       bind_address = boost::asio::ip::make_address(httpd_interface);
    } catch (const std::exception& e) {
        _MSG_FATAL("Invalid bind address {} for httpd server; expected interface address: {}",
                httpd_interface,  e.what());
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
        _MSG_FATAL("Unable to start httpd server on {}:{}: {}",
                httpd_interface, httpd_port, e.what());
        Globalreg::globalreg->fatal_condition = 1;
        return nullptr;
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
    register_mime_type("ekjson", "application/json");
    register_mime_type("itjson", "application/json");
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
    register_mime_type("ttf", "font/ttf");
    register_mime_type("otf", "font/otf");
    register_mime_type("eot", "application/vnd.ms-fontobject");
    register_mime_type("woff", "font/woff");
    register_mime_type("woff2", "font/woff2");


    for (const auto& m : Globalreg::globalreg->kismet_config->fetch_opt_vec("httpd_mime")) {
        auto comps = str_tokenize(m, ":");

        if (comps.size() != 2) {
            _MSG_ERROR("Expected config option httpd_mime=extension:type, got {}", m);
            continue;
        }

        register_mime_type(comps[0], comps[1]);
    }

    allow_auth_creation = Globalreg::globalreg->kismet_config->fetch_opt_bool("httpd_allow_auth_creation", true);
    allow_auth_view = Globalreg::globalreg->kismet_config->fetch_opt_bool("httpd_allow_auth_view", true);

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
                    "SYSTEM", kis_alert_severity::info,
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

    jwt_auth_key = Globalreg::globalreg->kismet_config->fetch_opt_dfl("httpd_jwt_key", "");
    if (jwt_auth_key.length() == 0) {
        std::random_device rnd;
        auto dist = std::uniform_int_distribution<uint8_t>(0, 0xFF);
        char rdata[16];

        for (auto i = 0; i < 16; i++)
            rdata[i] = dist(rnd);

        jwt_auth_key = std::string(rdata, 16);
    } else if (jwt_auth_key.length() < 8) {
        _MSG_FATAL("Invalid httpd_jwt_key value, expected at least 8 characters");
        Globalreg::globalreg->fatal_condition = 1;
        return;
    }

    jwt_auth_issuer = Globalreg::globalreg->kismet_config->fetch_opt_dfl("httpd_jwt_issuer", "kismet");

    allow_cors_ =
        Globalreg::globalreg->kismet_config->fetch_opt_bool("httpd_allow_cors", false);
    allowed_cors_referrer_ =
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("httpd_allowed_origin", "");

    redirect_unknown_target_ =
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("httpd_redirect_unknown", "");
    redirect_unknown_ = redirect_unknown_target_.length();

    auto http_data_dir =
        Globalreg::globalreg->kismet_config->fetch_opt_path("httpd_home", "");
    if (http_data_dir == "") {
        _MSG_ERROR("No httpd_home found in the Kismet configs, disabling static file serving. "
                "This will disable the webui entirely, however the REST endpoints will still "
                "function.");
    } else {
        serve_files = true;
        _MSG_INFO("Serving static file content from {}", http_data_dir);

        register_static_dir("/", http_data_dir);
    }

    allowed_prefix =
        Globalreg::globalreg->kismet_config->fetch_opt("httpd_uri_prefix");

    // Basic session management endpoints
    register_unauth_route("/session/check_setup_ok", {"GET"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                con->set_mime_type("text/plain");
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
            }));

    register_route("/session/check_login", {"GET"}, LOGON_ROLE,
            std::make_shared<kis_net_web_function_endpoint>(
                [](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                con->set_mime_type("text/plain");
                std::ostream os(&con->response_stream());
                os << "Login valid\n";
            }));

    register_route("/session/check_session", {"GET"}, ANY_ROLE,
            std::make_shared<kis_net_web_function_endpoint>(
                [](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                con->set_mime_type("text/plain");
                std::ostream os(&con->response_stream());
                os << "Session valid\n";
            }));

    register_unauth_route("/session/set_password", {"POST"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                con->set_mime_type("text/plain");

                std::ostream os(&con->response_stream());

                if (global_login_config) {
                    con->set_status(boost::beast::http::status::forbidden);
                    os << "Login is configured in global Kismet configuration and may not "
                        "be configured via this API.\n";
                    return;
                }

                if (admin_password != "") {
                    if (!con->login_valid() || con->login_role() != LOGON_ROLE) {
                        con->set_status(boost::beast::http::status::forbidden);
                        os << "Login is already configured; The existing login is required "
                            "before it can be changed via this API.\n";
                        return;
                    }
                }

                auto u_k = con->http_variables().find("username");
                auto p_k = con->http_variables().find("password");

                if (u_k == con->http_variables().end() || p_k == con->http_variables().end()) {
                    con->set_status(boost::beast::http::status::bad_request);
                    os << "Missing username or password in request\n";
                    return;
                }

                set_admin_login(u_k->second, p_k->second);

                _MSG_INFO("A new administrator login and password have been set.");

                os << "Login configured\n";
            }));

    register_route("/auth/apikey/generate", {"POST"}, LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    con->set_mime_type("text/plain");

                    if (!allow_auth_creation)
                        throw std::runtime_error("auth creation is disabled in the kismet configuration");

                    auto n_auth_name = con->json()["name"].get<std::string>();
                    auto n_auth_role = con->json()["role"].get<std::string>();
                    auto n_duration = con->json()["duration"].get<uint64_t>();

                    time_t expiration = 0;

                    if (n_duration != 0)
                        expiration = time(0) + n_duration;

                    auto token = create_auth(n_auth_name, n_auth_role, expiration);

                    std::ostream os(&con->response_stream());
                    os << token;
                }));

    register_route("/auth/apikey/revoke", {"POST"}, LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    con->set_mime_type("text/plain");

                    if (!allow_auth_creation)
                        throw std::runtime_error("auth creation/deletion is disabled in the kismet configuration");

                    auto n_auth_name = con->json()["name"].get<std::string>();

                    if (n_auth_name == "web logon")
                        throw std::runtime_error("cannot remove autoprovisioned web logon");

                    auto r = remove_auth(n_auth_name);

                    if (!r)
                        throw std::runtime_error("cannot delete unknown auth record");

                    std::ostream os(&con->response_stream());
                    os << "revoked\n";
                }));

    register_route("/auth/apikey/list", {"GET"}, LOGON_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {

                auto ret = std::make_shared<tracker_element_vector>();

                for (const auto& a : auth_vec) {
                    if (a->name() == "web logon")
                        continue;

                    // Be lazy and don't generate a full tracked element, this is a super rare endpoint anyhow
                    auto amap = std::make_shared<tracker_element_string_map>();
                    amap->insert(std::make_pair("kismet.httpd.auth.name",
                                std::make_shared<tracker_element_string>(a->name())));
                    amap->insert(std::make_pair("kismet.httpd.auth.role",
                                std::make_shared<tracker_element_string>(a->role())));
                    amap->insert(std::make_pair("kismet.httpd.auth.expiration",
                                std::make_shared<tracker_element_uint64>(a->expires())));

                    if (allow_auth_view)
                        amap->insert(std::make_pair("kismet.httpd.auth.token",
                                    std::make_shared<tracker_element_string>(a->token())));

                    ret->push_back(amap);
                }

                return ret;

                }, auth_mutex));


    // Test echo websocket
    register_websocket_route("/debug/echo", LOGON_ROLE, {"ws"},
            std::make_shared<kis_net_web_function_endpoint>(
                [](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                con->stream().expires_never();
                auto ws =
                    std::make_shared<kis_net_web_websocket_endpoint>(con,
                        [](std::shared_ptr<kis_net_web_websocket_endpoint> ws,
                            std::shared_ptr<boost::asio::streambuf> buf, bool text) {
                            // Simple echo protocol
                            ws->write(static_cast<const char *>(buf->data().data()), buf->size());
                        });

                ws->text();
                ws->handle_request(con);
                }));
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

    _MSG_INFO("HTTP server listening on {}:{}", endpoint.address(), endpoint.port());

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

	// Spin each connection into its own thread
    if (!ec) {
        std::thread conthread([this, tcp_socket = boost::beast::tcp_stream(std::move(socket))]() mutable {
                thread_set_process_name("BEAST");

                while (tcp_socket.socket().is_open()) {
					// Reset the timeout every loop through; each request in this
					// socket pipeline has up to 30 seconds to complete
					boost::beast::get_lowest_layer(tcp_socket).expires_after(std::chrono::seconds(30));

                    // Associate the socket
                    auto conn =
                        std::make_shared<kis_net_beast_httpd_connection>(tcp_socket, shared_from_this());

                    // Run the connection
                    auto retain = conn->start();

                    if (retain == false)
                        break;
                }

                try {
                    tcp_socket.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send);
                } catch (...) {
                    ;
                }
            });

        conthread.detach();
    }

    // Accept another connection
    return start_accept();
}

std::string kis_net_beast_httpd::decode_uri(boost::beast::string_view in, bool query) {
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

        // Plusses are spaces in queries but not URIs
        if (query && in[p] == '+') {
            ret += ' ';
            p++;
            continue;
        }

        ret += in[p++];
    }

    return ret;
}

void kis_net_beast_httpd::set_admin_login(const std::string& username, const std::string& password) {
    auto user_config_path =
        Globalreg::globalreg->kismet_config->fetch_opt_path("httpd_auth_file",
                "%h/.kismet/kismet_httpd.conf");

    config_file user_httpd_config;
    user_httpd_config.parse_config(user_config_path);

    admin_username = username;
    admin_password = password;

    user_httpd_config.set_opt("httpd_username", admin_username, true);
    user_httpd_config.set_opt("httpd_password", admin_password, true);

    user_httpd_config.save_config(user_config_path);
}

bool kis_net_beast_httpd::check_admin_login(const std::string& username, const std::string& password) {
    constant_time_string_compare_ne compare;
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

std::string kis_net_beast_httpd::decode_get_variables(const boost::beast::string_view uri,
        http_var_map_t& var_map) {

    auto q_pos = uri.find_first_of("?");

    if (q_pos == boost::beast::string_view::npos)
        return std::string(uri);

    auto uri_decode = kis_net_beast_httpd::decode_uri(uri.substr(q_pos + 1, uri.length()), false);
    kis_net_beast_httpd::decode_variables(uri_decode, var_map);

    return std::string(uri.substr(0, q_pos));
}

void kis_net_beast_httpd::decode_cookies(const boost::beast::string_view decoded, http_cookie_map_t& var_map) {
    boost::beast::string_view::size_type pos = 0;
    while (pos != boost::beast::string_view::npos && pos < decoded.length()) {
        if (decoded[pos] == ' ') {
            pos++;
            continue;
        }

        auto eq = decoded.find("=", pos);

        if (eq == boost::beast::string_view::npos)
            break;

        auto end = decoded.find(";", eq);

        if (end == boost::beast::string_view::npos)
            end = decoded.length();

        var_map[static_cast<std::string>(decoded.substr(pos, eq - pos))] =
            static_cast<std::string>(decoded.substr(eq + 1, end - (eq + 1)));

        pos = end + 1;
    }
}

void kis_net_beast_httpd::register_mime_type(const std::string& extension, const std::string& type) {
    mime_map.emplace(std::make_pair(extension, type));
}

void kis_net_beast_httpd::remove_mime_type(const std::string& extension) {
    auto k = mime_map.find(extension);
    if (k != mime_map.end())
        mime_map.erase(k);
}

std::string kis_net_beast_httpd::resolve_mime_type(const std::string& extension) {
    auto dpos = extension.find_last_of(".");

    if (dpos == std::string::npos) {
        auto k = mime_map.find(extension);
        if (k != mime_map.end())
            return k->second;
    } else {
        auto k = mime_map.find(extension.substr(dpos + 1, extension.length()));
        if (k != mime_map.end())
            return k->second;
    }

    return "text/plain";
}

std::string kis_net_beast_httpd::resolve_mime_type(const boost::beast::string_view& extension) {
    auto dpos = extension.find_last_of(".");

    if (dpos == boost::beast::string_view::npos) {
        auto k = mime_map.find(static_cast<std::string>(extension));
        if (k != mime_map.end())
            return k->second;
    } else {
        auto k = mime_map.find(static_cast<std::string>(extension.substr(dpos + 1, extension.length())));
        if (k != mime_map.end())
            return k->second;
    }

    return "text/plain";

}

void kis_net_beast_httpd::register_route(const std::string& route, const std::list<std::string>& verbs,
        const std::string& role, std::shared_ptr<kis_net_web_endpoint> handler) {

    if (role.length() == 0)
        throw std::runtime_error("can not register auth http route with no role");

    return register_route(route, verbs, std::list<std::string>{role}, handler);
}

void kis_net_beast_httpd::register_route(const std::string& route, const std::list<std::string>& verbs,
        const std::list<std::string>& roles, std::shared_ptr<kis_net_web_endpoint> handler) {

    if (roles.size() == 0)
        throw std::runtime_error("can not register auth http route with no role");

    kis_lock_guard<kis_mutex> lk(route_mutex, "beast_httpd register_route");

    std::list<boost::beast::http::verb> b_verbs;
    for (const auto& v : verbs)
        b_verbs.emplace_back(boost::beast::http::string_to_verb(v));

    route_vec.emplace_back(std::make_shared<kis_net_beast_route>(route, b_verbs, true, roles, handler));
}

void kis_net_beast_httpd::register_route(const std::string& route,
        const std::list<std::string>& verbs, const std::string& role,
        const std::list<std::string>& extensions, std::shared_ptr<kis_net_web_endpoint> handler) {

    if (role.length() == 0)
        throw std::runtime_error("can not register auth http route with no role");

    return register_route(route, verbs, std::list<std::string>{role}, extensions, handler);
}

void kis_net_beast_httpd::register_route(const std::string& route,
        const std::list<std::string>& verbs, const std::list<std::string>& roles,
        const std::list<std::string>& extensions, std::shared_ptr<kis_net_web_endpoint> handler) {

    if (roles.size() == 0)
        throw std::runtime_error("can not register auth http route with no role");

    kis_lock_guard<kis_mutex> lk(route_mutex, "beast_httpd register_route (extensions)");

    std::list<boost::beast::http::verb> b_verbs;
    for (const auto& v : verbs)
        b_verbs.emplace_back(boost::beast::http::string_to_verb(v));

    route_vec.emplace_back(std::make_shared<kis_net_beast_route>(route, b_verbs, true, roles, extensions, handler));
}

void kis_net_beast_httpd::remove_route(const std::string& route) {
    kis_lock_guard<kis_mutex> lk(route_mutex, "beast_httpd remove_route");

    for (auto i = route_vec.begin(); i != route_vec.end(); ++i) {
        if ((*i)->route() == route) {
            route_vec.erase(i);
            return;
        }
    }
}

void kis_net_beast_httpd::register_unauth_route(const std::string& route,
        const std::list<std::string>& verbs,
        std::shared_ptr<kis_net_web_endpoint> handler) {
    kis_lock_guard<kis_mutex> lk(route_mutex, "beast_httpd register_unauth_route");
    std::list<boost::beast::http::verb> b_verbs;
    for (const auto& v : verbs)
        b_verbs.emplace_back(boost::beast::http::string_to_verb(v));
    route_vec.emplace_back(std::make_shared<kis_net_beast_route>(route, b_verbs, false,
                std::list<std::string>{""}, handler));
}

void kis_net_beast_httpd::register_unauth_route(const std::string& route,
        const std::list<std::string>& verbs,
        const std::list<std::string>& extensions, std::shared_ptr<kis_net_web_endpoint> handler) {
    kis_lock_guard<kis_mutex> lk(route_mutex, "beast_httpd register_unauth_route (extensions)");
    std::list<boost::beast::http::verb> b_verbs;
    for (const auto& v : verbs)
        b_verbs.emplace_back(boost::beast::http::string_to_verb(v));
    route_vec.emplace_back(std::make_shared<kis_net_beast_route>(route, b_verbs, false,
                std::list<std::string>{""},
                extensions, handler));
}

void kis_net_beast_httpd::register_websocket_route(const std::string& route,
        const std::string& role, const std::list<std::string>& extensions,
        std::shared_ptr<kis_net_web_endpoint> handler) {
    return register_websocket_route(route, std::list<std::string>{role}, extensions, handler);
}

void kis_net_beast_httpd::register_websocket_route(const std::string& route,
        const std::list<std::string>& roles, const std::list<std::string>& extensions,
        std::shared_ptr<kis_net_web_endpoint> handler) {
    kis_lock_guard<kis_mutex> lk(route_mutex, "beast_httpd register_websocket_route");

    websocket_route_vec.emplace_back(std::make_shared<kis_net_beast_route>(route,
                std::list<boost::beast::http::verb>{}, true, roles, extensions, handler));

}

std::string kis_net_beast_httpd::create_auth(const std::string& name, const std::string& role, time_t expiry) {
    kis_lock_guard<kis_mutex> lk(auth_mutex, "beast_httpd create_auth");

	return create_auth_impl(name, role, expiry);
}

std::string kis_net_beast_httpd::create_auth_impl(const std::string& name, const std::string& role, time_t expiry) {

    // Pull an existing token if one exists for this name
    for (const auto& a : auth_vec) {
        if (a->name() == name) {
            throw std::runtime_error("cannot create duplicate auth");
        }
    }


    std::random_device rnd;
    auto dist = std::uniform_int_distribution<uint8_t>(0, 0xFF);
    uint8_t rdata[16];

    for (auto i = 0; i < 16; i++)
        rdata[i] = dist(rnd);

    auto token = uint8_to_hex_str(rdata, 16);
    auto auth = std::make_shared<kis_net_beast_auth>(token, name, role, expiry);

    auth_vec.emplace_back(auth);
    store_auth();

    return token;
}

std::string kis_net_beast_httpd::create_or_find_auth(const std::string& name,
        const std::string& role, time_t expiry) {
    kis_lock_guard<kis_mutex> lk(auth_mutex, "beast_httpd create_or_find_auth");

    // Pull an existing token if one exists for this name
    for (const auto& a : auth_vec) {
        if (a->name() == name) {
            /*
            if (a->role() != role)
                throw std::runtime_error(fmt::format("conflicting role for creating or finding "
                            "auth (found existing login for {} tried to create for {})",
                            a->role, role));
                            */

            // Reset the role to the new one
            if (a->role() != role)
                a->set_role(role);

            if (a->expires() < expiry) {
                a->set_expiration(expiry);
                store_auth();
            }

            return a->token();
        }
    }

    return create_auth_impl(name, role, expiry);
}

std::string kis_net_beast_httpd::create_jwt_auth(const std::string& name,
        const std::string& role, time_t expiry) {

    auto token = jwt::create()
        .set_issuer(jwt_auth_issuer)
        .set_type("JWS")
        .set_payload_claim("name", jwt::claim(name))
        .set_payload_claim("role", jwt::claim(role))
        .set_payload_claim("created", picojson::value(static_cast<double>(Globalreg::globalreg->last_tv_sec)))
        .set_payload_claim("expires", picojson::value(static_cast<double>(expiry)))
        .sign(jwt::algorithm::hs256{jwt_auth_key});

    return token;
}


bool kis_net_beast_httpd::remove_auth(const std::string& auth_name) {
    kis_lock_guard<kis_mutex> lk(auth_mutex, "beast_httpd remove_auth");

    for (auto a = auth_vec.begin(); a != auth_vec.end(); ++a) {
        if ((*a)->name() == auth_name) {
            auth_vec.erase(a);
            store_auth();
            return true;
        }
    }

    return false;
}

std::shared_ptr<kis_net_beast_auth> kis_net_beast_httpd::check_auth_token(const boost::beast::string_view& token) {
    kis_lock_guard<kis_mutex> lk(auth_mutex, "beast_httpd check_auth_token");

    // Step one: is it a JWT token?
    auto authtoken = check_jwt_token(token);

    if (authtoken != nullptr)
        return authtoken;

    for (const auto& a : auth_vec) {
        if (a->check_auth(token))
            return a;

    }

    return nullptr;
}

std::shared_ptr<kis_net_beast_auth> kis_net_beast_httpd::check_jwt_token(const boost::beast::string_view& token) {
    try {
        auto decoded = jwt::decode(std::string(token));

        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::hs256{jwt_auth_key})
            .with_issuer(jwt_auth_issuer);

        verifier.verify(decoded);

        auto auth = std::make_shared<kis_net_beast_auth>(decoded);

        return auth;

    } catch (...) {
        return nullptr;
    }

    return nullptr;
}

void kis_net_beast_httpd::store_auth() {
    kis_lock_guard<kis_mutex> lk(auth_mutex, "beast_httpd store_auth");

    nlohmann::json::array_t vec;

    for (const auto& a : auth_vec) {
        if (a->is_valid())
            vec.push_back(a->as_json());
    }

    /*
    for (auto a = auth_vec.begin(); a != auth_vec.end(); ++a) {
        if (!(*a)->is_valid()) {
            auth_vec.erase(a);
            a = auth_vec.begin();
        }
    }
    */

    auto sessiondb_file =
        Globalreg::globalreg->kismet_config->fetch_opt_path("httpd_session_db", "%h/.kismet/session.db");
    FILE *sf = fopen(sessiondb_file.c_str(), "w");

    if (sf == NULL) {
        _MSG_ERROR("(HTTPD) Could not write session data file: {}",
                kis_strerror_r(errno));
        return;
    }

    fmt::print(sf, "{}", ((nlohmann::json) vec).dump());
    fclose(sf);
}

void kis_net_beast_httpd::load_auth() {
    kis_lock_guard<kis_mutex> lk(auth_mutex, "beast_httpd load_auth");

    auth_vec.clear();

    auto sessiondb_file =
        Globalreg::globalreg->kismet_config->fetch_opt_path("httpd_session_db",
                "%h/.kismet/session.db");
    auto sf = std::ifstream(sessiondb_file, std::ifstream::binary);

    nlohmann::json json;

    try {
        json = nlohmann::json::parse(sf);
    } catch (const std::exception& e) {
        _MSG_INFO("(HTTPD) Could not read session data file, skipping loading saved sessions.");
        return;
    }

    try {
        for (const auto& j : json) {
            try {
                auto auth = std::make_shared<kis_net_beast_auth>(j);
                if (auth->is_valid())
                    auth_vec.emplace_back(auth);
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
    kis_lock_guard<kis_mutex> lk(route_mutex, "beast_httpd find_endpoint");

    for (const auto& r : route_vec) {
        if (r->match_url(static_cast<const std::string>(con->uri()), con->uri_params_, con->http_variables_))
            return r;
    }

    return nullptr;
}

std::shared_ptr<kis_net_beast_route> kis_net_beast_httpd::find_websocket_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    kis_lock_guard<kis_mutex> lk(route_mutex, "beast_httpd find_websocket_endpoint");

    for (const auto& r : websocket_route_vec) {
        if (r->match_url(static_cast<const std::string>(con->uri()), con->uri_params_, con->http_variables_))
            return r;
    }

    return nullptr;
}

void kis_net_beast_httpd::register_static_dir(const std::string& prefix, const std::string& path) {
    static_dir_vec.emplace_back(static_content_dir(prefix, path));
}

std::string kis_net_beast_httpd::escape_html(const boost::beast::string_view& html) {
    std::stringstream ss;

    for (const auto& c : html) {
        switch (c) {
            case '&':
                ss << "&amp;";
                break;
            case '<':
                ss << "&lt;";
                break;
            case '>':
                ss << "&gt;";
                break;
            case '"':
                ss << "&quot;";
                break;
            case '/':
                ss << "&#x2F;";
                break;
            default:
                ss << c;
        }
    }

    return ss.str();
}

bool kis_net_beast_httpd::serve_file(std::shared_ptr<kis_net_beast_httpd_connection> con,
                                     std::string uri) {
    boost::beast::error_code ec;

    if (uri.length() == 0)
        uri = "/index.html";
    else if (uri.back() == '/')
        uri += "index.html";

    for (auto sd : static_dir_vec) {
        ec = {};

        if (uri.size() < sd.prefix.size())
            continue;

        if (uri.find(sd.prefix) != 0)
            continue;

        auto modified_fpath = sd.path + "/" + uri.substr(sd.prefix.length(), uri.length());

        char *modified_realpath = nullptr;
        char *base_realpath = realpath(sd.path.c_str(), nullptr);

        modified_realpath = realpath(modified_fpath.c_str(), nullptr);

        if (modified_realpath == nullptr || base_realpath == nullptr) {
            if (modified_realpath)
                free(modified_realpath);

            if (base_realpath)
                free(base_realpath);

            continue;
        }

        if (strstr(modified_realpath, base_realpath) != modified_realpath) {
            if (modified_realpath)
                free(modified_realpath);
            if (base_realpath)
                free(base_realpath);
            continue;
        }

        boost::beast::http::file_body::value_type body;
        body.open(modified_realpath, boost::beast::file_mode::scan, ec);

        free(modified_realpath);
        free(base_realpath);

        if (ec == boost::beast::errc::no_such_file_or_directory) {
            continue;
        } else if (ec) {
            // _MSG_ERROR("(DEBUG) {} - {}", uri, ec.message());
            continue;
        }

        auto const size = body.size();

        if (con->request().method() == boost::beast::http::verb::head) {
            boost::beast::http::response<boost::beast::http::empty_body> res{boost::beast::http::status::ok,
                con->request().version()};

            con->append_common_headers(res, uri);

            res.content_length(size);

            ec = {};

            boost::beast::http::write(con->stream(), res, ec);

            return true;
        }

        boost::beast::http::response<boost::beast::http::file_body> res{std::piecewise_construct,
                std::make_tuple(std::move(body)), std::make_tuple(boost::beast::http::status::ok,
                        con->request().version())};

        con->append_common_headers(res, uri);
        res.content_length(size);

        ec = {};

        boost::beast::http::write(con->stream(), res, ec);

        return true;
    }

    return false;
}

bool kis_net_beast_httpd::serve_file(std::shared_ptr<kis_net_beast_httpd_connection> con) {

    std::string uri;
    auto encoding_pos = con->uri().find_first_of("?");
    if (encoding_pos != con->uri().npos)
        uri = static_cast<std::string>(con->uri().substr(0, encoding_pos));
    else
        uri = static_cast<std::string>(con->uri());

    return serve_file(con, uri);
}

void kis_net_beast_httpd::strip_uri_prefix(boost::beast::string_view& uri_view) {
    if (allowed_prefix.length() == 0)
        return;

    if (uri_view.starts_with(allowed_prefix)) {
        uri_view.remove_prefix(std::min(allowed_prefix.length(), uri_view.size()));
    }
}



kis_net_beast_httpd_connection::kis_net_beast_httpd_connection(boost::beast::tcp_stream& socket,
        std::shared_ptr<kis_net_beast_httpd> httpd) :
    httpd{httpd},
    stream_{socket},
    login_valid_{false},
    first_response_write{false} {
        Globalreg::n_tracked_http_connections++;
    }

kis_net_beast_httpd_connection::~kis_net_beast_httpd_connection() {
    Globalreg::n_tracked_http_connections--;
    if (closure_cb)
        closure_cb();
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

void kis_net_beast_httpd_connection::clear_timeout() {
    boost::beast::get_lowest_layer(stream_).expires_never();
}

void kis_net_beast_httpd_connection::append_header(const std::string& header, const std::string& value) {
    if (first_response_write)
        throw std::runtime_error("tried to set a header on a connection already in progress");

    response.set(header, value);
}

bool kis_net_beast_httpd_connection::start() {
    parser_.emplace();
    parser_->body_limit(100000);

    try {
        boost::beast::http::read(stream_, buffer, *parser_);
    } catch (const boost::system::system_error& e) {
        // Silently catch and fail on any error from the transport layer, because we don't
        // care; we can't deal with a broken client spamming us
        return do_close();
    }

    request_ = boost::beast::http::request<boost::beast::http::string_body>(parser_->release());

    uri_ = request_.target();
    verb_ = request_.method();

    httpd->strip_uri_prefix(uri_);
    auto trimmed_uri = httpd->decode_get_variables(uri_, http_variables_);

    // Fix any double-slashes which will break the parser/splitter
    std::regex re("/+/");
    trimmed_uri = std::regex_replace(trimmed_uri, re, "/");

    uri_ = boost::beast::string_view(trimmed_uri);

    // Process close headers - http 1.0 always closes unless keepalive, 1.1 never closes unless specified
    bool client_req_close = false;

    if (request_.version() == 10)
        client_req_close = true;

    auto client_connection_h = request_.find(boost::beast::http::field::connection);
    if (client_connection_h != request_.end()) {
        auto connection_decode = httpd->decode_uri(client_connection_h->value(), true);

        if (request_.version() == 10 && connection_decode == "keep-alive") {
            client_req_close = false;
            response.set(boost::beast::http::field::connection, "keep-alive");
        }

        if (connection_decode == "close") {
            client_req_close = true;
        }
    }

    // Handle CORS before auth and route finding; always returns
    if (request_.method() == boost::beast::http::verb::options && httpd->allow_cors()) {
        response.result(boost::beast::http::status::ok);

        std::string uri_rewrite = "";
        append_common_headers(response, uri_rewrite);

        response.set(boost::beast::http::field::content_length, "0");

        boost::beast::http::response_serializer<boost::beast::http::buffer_body,
            boost::beast::http::fields> sr{response};

        boost::system::error_code error;
        boost::beast::http::write_header(stream_, sr, error);

        if (error)
            return do_close();

        // Send the completion record for the chunked response
        response.body().data = nullptr;
        response.body().size = 0;
        response.body().more = false;

        boost::beast::http::write(stream_, sr, error);

        if (error || client_req_close)
            return do_close();

        return true;
    }

    // Extract the auth cookie
    auto cookie_h = request_.find(boost::beast::http::field::cookie);
    if (cookie_h != request_.end()) {
        auto cookie_decode = httpd->decode_uri(cookie_h->value(), true);
        httpd->decode_cookies(cookie_decode, cookies_);

        auto auth_cookie_k = cookies_.find(httpd->AUTH_COOKIE);
        if (auth_cookie_k != cookies_.end())
            auth_token_ = auth_cookie_k->second;
    } else {
        auto uri_cookie_k = http_variables_.find(httpd->AUTH_COOKIE);
        if (uri_cookie_k != http_variables_.end())
            auth_token_ = uri_cookie_k->second;
    }

    auto auth_t = httpd->check_auth_token(auth_token_);
    if (auth_t != nullptr) {
        login_valid_ = true;
        login_role_ = auth_t->role();
    } else {
        // _MSG_INFO("(DEBUG) {} {} had auth {} but isn't valid", verb_, uri_, auth_token_);

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

                        if (login_valid_) {
                            login_role_ = kis_net_beast_httpd::LOGON_ROLE;

                            // If we have a valid pw login and no, or an invalid, auth token, create one
                            // auth_token_ = httpd->create_or_find_auth("web logon", httpd->LOGON_ROLE, time(0) + (60*60*24));
                            auth_token_ = httpd->create_jwt_auth("web logon", httpd->LOGON_ROLE, time(0) + (60*60*24));
                        }
                    }
                }
            }
        } else {
            auto uri_user_k = http_variables_.find("user");
            auto uri_pass_k = http_variables_.find("password");

            if (uri_user_k != http_variables_.end() && uri_pass_k != http_variables_.end()) {
                login_valid_ = httpd->check_admin_login(uri_user_k->second, uri_pass_k->second);

                if (login_valid_) {
                    login_role_ = kis_net_beast_httpd::LOGON_ROLE;

                    // auth_token_ = httpd->create_or_find_auth("web logon", httpd->LOGON_ROLE, time(0) + (60*60*24));
                    auth_token_ = httpd->create_jwt_auth("web logon", httpd->LOGON_ROLE, time(0) + (60*60*24));
                }
            }
        }
    }

    if (boost::beast::websocket::is_upgrade(request_)) {
        // All websockets must be authenticated, and are resolved in their own routing table
        auto route = httpd->find_websocket_endpoint(shared_from_this());

        if (route == nullptr) {
            boost::beast::http::response<boost::beast::http::string_body>
                res{boost::beast::http::status::not_found, request_.version()};

            res.set(boost::beast::http::field::server, "Kismet");
            res.set(boost::beast::http::field::content_type, "text/html");
            res.body() =
                std::string(fmt::format("<html><head><title>404 not found</title></head>"
                            "<body><h1>404 Not Found</h1><br>"
                            "<p>Could not find <code>{}</code></p></body></html>\n",
                            httpd->escape_html(static_cast<std::string>(uri_))));
            res.prepare_payload();

            boost::system::error_code error;

            boost::beast::http::write(stream_, res, error);

            return do_close();
        }

        if (!route->match_role(login_valid_, login_role_)) {
            boost::beast::http::response<boost::beast::http::string_body>
                res{boost::beast::http::status::unauthorized, request_.version()};

            res.set(boost::beast::http::field::server, "Kismet");
            res.set(boost::beast::http::field::content_type, "text/html");
            res.body() = std::string("<html><head><title>401 Permission denied</title></head><body>"
                    "<h1>401 Permission denied</h1><br><p>This resource requires a login or session "
                    "token.</p></body></html>\n");
            res.prepare_payload();

            boost::system::error_code error;

            boost::beast::http::write(stream_, res, error);

            return do_close();
        }

        boost::beast::get_lowest_layer(stream_).expires_never();

        route->invoke(shared_from_this());

        return do_close();
    }

    // Look for a route
    auto route = httpd->find_endpoint(shared_from_this());

    if (route != nullptr) {
        if (!route->match_verb(verb_)) {
            boost::beast::http::response<boost::beast::http::string_body>
                res{boost::beast::http::status::method_not_allowed, request_.version()};

            res.set(boost::beast::http::field::server, "Kismet");
            res.set(boost::beast::http::field::content_type, "text/html");
            res.body() = std::string("<html><head><title>405 Incorrect method</title></head><body><h1>405 Incorrect method</h1><br><p>This method is not valid for this resource.</p></body></html>\n");
            res.prepare_payload();

            boost::system::error_code error;

            boost::beast::http::write(stream_, res, error);

            if (error || client_req_close)
                return do_close();

            return true;
        }

        if (!route->match_role(login_valid_, login_role_)) {
            boost::beast::http::response<boost::beast::http::string_body>
                res{boost::beast::http::status::unauthorized, request_.version()};

            // We don't generally want to send a WWW-Authorize header because it makes browsers prompt for logins
            // which interrupts the UI, and curl handles it fine - but wget will not send the auth until it gets
            // a 401 with a WWW-Authorize then it repeats the request
            auto ua_h = request_.find(boost::beast::http::field::user_agent);
            if (ua_h != request_.end()) {
                auto ua = httpd->decode_uri(ua_h->value(), true);

                if (ua.find_first_of("Wget") == 0) {
                    res.set(boost::beast::http::field::www_authenticate, "Basic realm=Kismet");
                }
            }

            res.set(boost::beast::http::field::server, "Kismet");
            res.set(boost::beast::http::field::content_type, "text/html");
            res.body() = std::string("<html><head><title>401 Permission denied</title></head><body><h1>401 Permission denied</h1><br><p>This resource requires a login or session token.</p></body></html>\n");
            res.prepare_payload();

            boost::system::error_code error;

            boost::beast::http::write(stream_, res, error);

            if (error || client_req_close)
                return do_close();

            return true;
        }
    } else if (route == nullptr) {
        bool file_served = false;
        if (verb_ == boost::beast::http::verb::get || verb_ == boost::beast::http::verb::head)
            file_served = httpd->serve_file(shared_from_this());

        // Fallback to trying to serve the fallback content
        if (!file_served && httpd->redirect_unknown())
            file_served = httpd->serve_file(shared_from_this(), httpd->redirect_unknown_target());

        // If we still didn't serve content, 404
        if (!file_served) {
            boost::beast::http::response<boost::beast::http::string_body>
                res{boost::beast::http::status::not_found, request_.version()};

            res.set(boost::beast::http::field::server, "Kismet");
            res.set(boost::beast::http::field::content_type, "text/html");
            res.body() =
                std::string(fmt::format("<html><head><title>404 not found</title></head>"
                            "<body><h1>404 Not Found</h1><br>"
                            "<p>Could not find <code>{}</code></p></body></html>\n",
                            httpd->escape_html(static_cast<std::string>(uri_))));
            res.prepare_payload();

            boost::system::error_code error;

            boost::beast::http::write(stream_, res, error);

            if (error || client_req_close)
                return do_close();

            return true;
        }

        if (client_req_close)
            return do_close();

        return true;
    }

    append_common_headers(response, uri_);

    if (request_.method() == boost::beast::http::verb::post) {
        // Handle POST data fields
        http_post = request_.body();

        auto content_type = request_[boost::beast::http::field::content_type];

        if (boost::beast::iequals(content_type, "application/x-www-form-urlencoded") ||
                boost::beast::iequals(content_type, "application/x-www-form-urlencoded; charset=UTF-8")) {
            auto decoded_body = httpd->decode_uri(http_post, true);
            httpd->decode_variables(decoded_body, http_variables_);

            auto j_k = http_variables_.find("json");
            if (j_k != http_variables_.end()) {
                try {
                    std::stringstream ss(j_k->second);
                    ss >> json_;
                } catch (std::exception& e) {
                    ;
                }
            }
        } else if (boost::beast::iequals(content_type, "application/json") ||
                boost::beast::iequals(content_type, "application/json; charset=UTF-8")) {

            try {
                json_ = nlohmann::json::parse(http_post.data());
            } catch (std::exception& e) {
                ;
            }
        }
    }

    response.result(boost::beast::http::status::ok);
    response.set(boost::beast::http::field::transfer_encoding, "chunked");

    // Create the chunked response serializer
    boost::beast::http::response_serializer<boost::beast::http::buffer_body,
        boost::beast::http::fields> sr{response};


    // Spawn the generator thread
    auto generator_launched = std::promise<void>();
    auto generator_ft = generator_launched.get_future();

    std::thread tr([this, route, generator_launched = std::move(generator_launched),
            self = shared_from_this()]() mutable {
        thread_set_process_name("BEAST-WAIT");

        generator_launched.set_value();

        try {
            route->invoke(self);
        } catch (const std::exception& e) {
            try {
                set_status(500);
            } catch (...) {
                ;
            }

            std::ostream os(&response_stream_);
            os << "ERROR: " << e.what();
        }

        response_stream_.complete();
    });
    tr.detach();

    generator_ft.wait();

    boost::system::error_code error;
    while (response_stream_.size() || response_stream_.running()) {
        auto sz = response_stream_.size();

        if (sz) {
            // Write the headers once we have body content
            if (!first_response_write) {
                boost::beast::http::write_header(stream_, sr, error);

                if (error) {
                    // _MSG_ERROR("(DEBUG) {} {} - Error writing headers - {}", verb_, uri_, error.message());
                    return do_close();
                }
            }

            // we no longer accept header modifiers
            first_response_write = true;

            char *body_data;
            auto chunk_sz = response_stream_.get(&body_data);

            response.body().data = (void *) body_data;
            response.body().size = chunk_sz;
            response.body().more = true;

            boost::beast::http::write(stream_, sr, error);

            response_stream_.consume(chunk_sz);

            // _MSG_INFO("(DEBUG) {} {} - Consumed {}/{} running {}", verb_, uri_, sz, response_stream_.size(), response_stream_.running());

            if (error == boost::beast::http::error::need_buffer) {
                // Beast returns 'need_buffer' when it's completed writing a buffer, configure
                // as a non-error
                error = {};
            } else if (error) {
                // _MSG_INFO("(DEBUG) {} {} - chunk write error {}", verb_, uri_, error.message());
                response_stream_.cancel();
                return do_close();
            }
        }

        // If the buffer has any pending data, regardless of error or completeness,
        // this will instantly return, otherwise it will stall waiting for it to be
        // populated
        response_stream_.wait();
    }

    // _MSG_INFO("(DEBUG) {} {} - Out of buffer poll loop, remaining {}, running {}", verb_, uri_, response_stream_.size(), response_stream_.running());

    // Send the completion record for the chunked response
    response.body().data = nullptr;
    response.body().size = 0;
    response.body().more = false;

    boost::beast::http::write(stream_, sr, error);

    if (error) {
        // _MSG_INFO("(DEBUG) {} {} - Error writing conclusion of stream: {}", verb_, uri_, error.message());
        return do_close();
    }

    if (client_req_close)
        return do_close();

    return true;
}

bool kis_net_beast_httpd_connection::do_close() {
    if (closure_cb) {
        closure_cb();
        closure_cb = nullptr;
    }

    try {
        stream_.socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send);
    } catch (const std::exception& e) {
        ;
    }

    return false;
}


kis_net_beast_route::kis_net_beast_route(const std::string& route,
        const std::list<boost::beast::http::verb>& verbs,
        bool login, const std::list<std::string>& roles, std::shared_ptr<kis_net_web_endpoint> handler) :
    handler{handler},
    route_{route},
    verbs_{verbs},
    login_{login},
    roles_{roles},
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
        bool login, const std::list<std::string>& roles,
        const std::list<std::string>& extensions, std::shared_ptr<kis_net_web_endpoint> handler) :
    handler{handler},
    route_{route},
    verbs_{verbs},
    login_{login},
    roles_{roles},
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
        // If passed an empty list we accept all types and resolve during serialization
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
    match_re = std::regex(fmt::format("^{}{}(\\?.*?)?$", ext_str, ft_regex));
}

bool kis_net_beast_route::match_url(const std::string& url,
        kis_net_beast_httpd_connection::uri_param_t& uri_params,
        kis_net_beast_httpd::http_var_map_t& uri_variables) {

    auto match_values = std::smatch();

    if (!std::regex_match(url, match_values, match_re))
        return false;

    if (match_values.size() != match_keys.size() + 1) {
        // _MSG_ERROR("(DEBUG) HTTP req {} didn't match enough elements, {} wanted {}", url, match_values.size(), match_keys.size());
        return false;
    }

    size_t key_num = 0;
    bool first = true;
    for (const auto& i : match_values) {
        if (first) {
            first = false;
            continue;
        }

        if (key_num >= match_keys.size()) {
            // _MSG_ERROR("(DEBUG) HTTP req {} matched more values than known keys in route, something is wrong key pos {}", url, key_num);
            continue;
        }

        uri_params.emplace(std::make_pair(match_keys[key_num], static_cast<std::string>(i)));
        key_num++;
    }

    return true;
}

bool kis_net_beast_route::match_verb(boost::beast::http::verb verb) {
    for (const auto& v : verbs_)
        if (v == verb)
            return true;
    return false;
}

bool kis_net_beast_route::match_role(bool login, const std::string& role) {
    if (login_ && !login)
        return false;

    bool valid = false;
    bool any = false;

    for (const auto& r : roles_) {
        if (r == kis_net_beast_httpd::ANY_ROLE)
            any = true;

        constant_time_string_compare_ne compare;

        if (!compare(r, role))
            valid = true;
    }

    // If the endpoint allows any role, always accept
    if (any)
        return true;

    // If the supplied role is logon, it can do everything
    if (role == kis_net_beast_httpd::LOGON_ROLE)
        return true;

    return valid;
}

void kis_net_beast_route::invoke(std::shared_ptr<kis_net_beast_httpd_connection> connection) {
    handler->handle_request(connection);
}


kis_net_beast_auth::kis_net_beast_auth(const nlohmann::json& json)  {
    try {
        token_ = json["token"].get<std::string>();
        name_ = json["name"].get<std::string>();
        role_ = json["role"].get<std::string>();
        time_created_ = static_cast<time_t>(json["created"].get<unsigned int>());
        time_accessed_ = static_cast<time_t>(json["accessed"].get<unsigned int>());
        time_expires_ = static_cast<time_t>(json["expires"].get<unsigned int>());

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

kis_net_beast_auth::kis_net_beast_auth(const jwt::decoded_jwt<jwt::traits::kazuho_picojson>& jwt) {
    try {
        token_ = "jwt";
        name_ = jwt.get_payload_claim("name").as_string();
        role_ = jwt.get_payload_claim("role").as_string();
        time_created_ = static_cast<time_t>(jwt.get_payload_claim("created").as_number());
        time_expires_ = static_cast<time_t>(jwt.get_payload_claim("expires").as_number());
    } catch (...) {
        throw auth_construction_error();
    }

}

bool kis_net_beast_auth::check_auth(const boost::beast::string_view& token) const {
    constant_time_string_compare_ne compare;
    return !compare(token_, static_cast<std::string>(token));
}

nlohmann::json kis_net_beast_auth::as_json() {
    nlohmann::json ret;

    ret["token"] = token_;
    ret["name"] = name_;
    ret["role"] = role_;
    ret["created"] = (unsigned int) time_created_;
    ret["accessed"] = (unsigned int) time_accessed_;
    ret["expires"] = (unsigned int) time_expires_;

    return ret;
}


void kis_net_web_tracked_endpoint::handle_request(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    kis_unique_lock<kis_mutex> lk(mutex, std::defer_lock, "tracked endpoint");

    if (use_mutex)
        lk.lock();

    std::ostream os(&con->response_stream());

    try {
        auto output_content = std::shared_ptr<tracker_element>();
        auto rename_map = Globalreg::new_from_pool<tracker_element_serializer::rename_map>();

        if (content == nullptr && generator == nullptr) {
            con->set_status(500);
            os << "Invalid request:  No backing content or generator\n";
            return;
        }

        if (generator != nullptr)
            output_content = generator(con);
        else
            output_content = content;

        if (pre_func)
            pre_func(output_content);

        auto summary = con->summarize_with_json(output_content, rename_map);

        Globalreg::globalreg->entrytracker->serialize(static_cast<std::string>(con->uri()), os,
                summary, rename_map);

        os.flush();

        if (post_func)
            post_func(output_content);

    } catch (const std::exception& e) {
        try {
            con->set_status(500);
        } catch (const std::exception& e) {
            ;
        }

        os << "ERROR: " << e.what() << "\n";
    }
}

void kis_net_web_function_endpoint::handle_request(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    kis_unique_lock<kis_mutex> lk(mutex, std::defer_lock, "function endpoint");

    if (use_mutex)
        lk.lock();

    try {
        if (pre_func != nullptr)
            pre_func();

        function(con);

        if (post_func != nullptr)
            post_func();
    } catch (const std::exception& e) {
        try {
            con->set_status(500);
        } catch (const std::exception& e) {
            ;
        }

        std::ostream os(&con->response_stream());
        os << "ERROR: " << e.what() << "\n";
    }

}


void kis_net_web_websocket_endpoint::close() {
    close_impl();
}

void kis_net_web_websocket_endpoint::close_impl() {
    running = false;

    try {
        ws_.next_layer().socket().shutdown(boost::asio::ip::tcp::socket::shutdown_send);
    } catch (...) { }

    try {
        running_promise.set_value();
    } catch (const std::future_error& e) {
        // If somehow we already pulled the future, fail silently
    }
}

void kis_net_web_websocket_endpoint::start_read(std::shared_ptr<kis_net_web_websocket_endpoint> ref) {

    buffer_ = Globalreg::globalreg->streambuf_pool.acquire();

    ws_.async_read(*buffer_.get(),
            boost::asio::bind_executor(
                strand_,
                std::bind(
                    &kis_net_web_websocket_endpoint::handle_read,
                    shared_from_this(),
                    std::placeholders::_1,
                    std::placeholders::_2)));
}

void kis_net_web_websocket_endpoint::handle_read(boost::beast::error_code ec, std::size_t) {
    if (ec) {
        buffer_ = nullptr;
        return close_impl();
    }

    if (!running) {
        buffer_ = nullptr;
        return close_impl();
    }

    try {
        handler_cb(shared_from_this(), buffer_, ws_.got_text());


        buffer_ = Globalreg::globalreg->streambuf_pool.acquire();

        ws_.async_read(*buffer_.get(),
                boost::asio::bind_executor(
                    strand_,
                    std::bind(
                        &kis_net_web_websocket_endpoint::handle_read,
                        shared_from_this(),
                        std::placeholders::_1,
                        std::placeholders::_2)));
    } catch (const std::exception& e) {
        return close_impl();
    }
}

void kis_net_web_websocket_endpoint::on_write(const std::string& msg) {
    if (!running || !ws_.is_open())
        return;

    ws_write_queue_.push(msg);

    // _MSG_DEBUG("ws {} write len {} queue {}", fmt::ptr(this), msg.size(), ws_write_queue_.size());

    if (ws_write_queue_.size() > 1)
        return;

    boost::asio::post(strand_,
            [self = shared_from_this()]() {
                self->handle_write();
            });
}

void kis_net_web_websocket_endpoint::handle_write() {
    if (!running || !ws_.is_open() || ws_write_queue_.empty()) {
        return;
    }

    ws_.async_write(boost::asio::buffer(ws_write_queue_.front()),
            boost::asio::bind_executor(
                strand_,
                std::bind(
                    [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
                        if (ec) {
                            if (ec != boost::beast::websocket::error::closed) {
                                _MSG_ERROR("Websocket error: {}", ec.message());
                            }

                            return self->close_impl();
                        }

                        self->ws_write_queue_.pop();

                        if (!self->ws_write_queue_.empty()) {
                            return self->handle_write();
                        }
                    },
                    std::placeholders::_1,
                    std::placeholders::_2)));
}


void kis_net_web_websocket_endpoint::handle_request(std::shared_ptr<kis_net_beast_httpd_connection> con) {
    // _MSG_DEBUG("websocket {} - {}", fmt::ptr(this), con->uri());
    thread_set_process_name("BEAST-WS");

    // Set the default timeouts
    ws_.set_option(boost::beast::websocket::stream_base::timeout::suggested(
                boost::beast::role_type::server));

    ws_.accept(con->request());

    running = true;

    auto running_future = running_promise.get_future();

    // Launch an async read loop
    start_read(shared_from_this());

    // That will eventually complete this future
    running_future.wait();
}

