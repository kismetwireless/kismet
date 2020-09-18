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

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <vector>
#include <string>
#include <sstream>
#include <iomanip>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <microhttpd.h>

#include <memory>
#include <chrono>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "globalregistry.h"
#include "messagebus.h"
#include "configfile.h"
#include "kis_net_microhttpd.h"
#include "base64.h"
#include "entrytracker.h"
#include "kis_httpd_websession.h"

std::string kishttpd::get_suffix(const std::string& url) {
    size_t lastdot = url.find_last_of(".");

    if (lastdot != std::string::npos)
        return url.substr(lastdot + 1, url.length() - lastdot);

    return "";
}

std::string kishttpd::strip_suffix(const std::string& url) {
    size_t lastdot = url.find_last_of(".");

    if (lastdot == std::string::npos)
        lastdot = url.length();

    return url.substr(0, lastdot);
}

std::string kishttpd::escape_html(const std::string& in) {
    std::stringstream ss;

    for (unsigned int c = 0; c < in.length(); c++) {
        switch (in[c]) {
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
                ss << in[c];
        }
    }

    return ss.str();
}

kis_net_httpd::kis_net_httpd() {
    controller_mutex.set_name("kis_net_httpd_controller");
    session_mutex.set_name("kis_net_httpd_session");

    microhttpd = nullptr;

    running = false;

    use_ssl = false;
    cert_pem = NULL;
    cert_key = NULL;

    if (Globalreg::globalreg->kismet_config == NULL) {
        fprintf(stderr, "FATAL OOPS: kis_net_httpd called without kismet_config\n");
        exit(1);
    }

    http_port = Globalreg::globalreg->kismet_config->fetch_opt_uint("httpd_port", 2501);
    http_host = Globalreg::globalreg->kismet_config->fetch_opt_dfl("httpd_bind_address", "");

    if (http_host == "") {
        _MSG_INFO("Kismet will only listen to HTTP requests on {}:{}", http_port, http_host);
    }

    uri_prefix = Globalreg::globalreg->kismet_config->fetch_opt_dfl("httpd_uri_prefix", "");

    std::string http_data_dir, http_aux_data_dir;

    http_data_dir = Globalreg::globalreg->kismet_config->fetch_opt("httpd_home");
    http_aux_data_dir = Globalreg::globalreg->kismet_config->fetch_opt("httpd_user_home");

    if (http_data_dir == "") {
        _MSG("No httpd_home defined in kismet.conf, disabling static file serving. "
                "This will disable the web UI, but the REST interface will still "
                "function.", MSGFLAG_ERROR);
        http_serve_files = false;
    } else {
        http_data_dir = 
            Globalreg::globalreg->kismet_config->expand_log_path(http_data_dir, "", "", 0, 1);
        _MSG("Serving static content from '" + http_data_dir + "'",
                MSGFLAG_INFO);
        http_serve_files = true;

        // Add it as a possible file dir
        register_static_dir("/", http_data_dir);
    }

    if (http_aux_data_dir == "") {
        _MSG("No httpd_user_home defined in kismet.conf, disabling static file serving "
                "from user directory", MSGFLAG_ERROR);
        http_serve_user_files = false;
    } else {
        http_aux_data_dir = 
            Globalreg::globalreg->kismet_config->expand_log_path(http_aux_data_dir, "", "", 0, 1);
        _MSG("Serving static userdir content from '" + http_aux_data_dir + "'",
                MSGFLAG_INFO);
        http_serve_user_files = true;
        
        // Add it as a second possible source of '/' files
        register_static_dir("/", http_aux_data_dir);
    }

    if (http_serve_files == false && http_serve_user_files == false) {
        register_unauth_handler(new kis_net_httpd_no_files_handler());
    }

    session_timeout = 
        Globalreg::globalreg->kismet_config->fetch_opt_uint("httpd_session_timeout", 7200);

    use_ssl = Globalreg::globalreg->kismet_config->fetch_opt_bool("httpd_ssl", false);
    pem_path = Globalreg::globalreg->kismet_config->fetch_opt("httpd_ssl_cert");
    key_path = Globalreg::globalreg->kismet_config->fetch_opt("httpd_ssl_key");

    allow_cors = 
        Globalreg::globalreg->kismet_config->fetch_opt_bool("httpd_allow_cors", false);
    allowed_cors_referrer =
        Globalreg::globalreg->kismet_config->fetch_opt_dfl("httpd_allowed_origin", "");

    register_mime_type("html", "text/html");
    register_mime_type("js", "text/javascript");
    register_mime_type("svg", "image/svg+xml");
    register_mime_type("css", "text/css");
    register_mime_type("jpeg", "image/jpeg");
    register_mime_type("gif", "image/gif");
    register_mime_type("ico", "image/x-icon");
    register_mime_type("json", "application/json");
    register_mime_type("ekjson", "application/json");
    register_mime_type("itjson", "application/json");
    register_mime_type("pcap", "application/vnd.tcpdump.pcap");

    std::vector<std::string> mimeopts = Globalreg::globalreg->kismet_config->fetch_opt_vec("httpd_mime");
    for (unsigned int i = 0; i < mimeopts.size(); i++) {
        std::vector<std::string> mime_comps = str_tokenize(mimeopts[i], ":");

        if (mime_comps.size() != 2) {
            _MSG("Expected httpd_mime=extension:type", MSGFLAG_ERROR);
            continue;
        }

        _MSG("Adding user-defined MIME type " + mime_comps[1] + " for " + mime_comps[0],
                MSGFLAG_INFO);
        register_mime_type(mime_comps[0], mime_comps[1]);
        
    }

    // Do we store sessions?
    store_sessions = false;
    session_db = NULL;

    sessiondb_file = Globalreg::globalreg->kismet_config->fetch_opt("httpd_session_db");

    if (sessiondb_file != "") {
        sessiondb_file = 
            Globalreg::globalreg->kismet_config->expand_log_path(sessiondb_file, "", "", 0, 1);

        session_db = new config_file(Globalreg::globalreg);

        store_sessions = true;

        struct stat buf;
        if (stat(sessiondb_file.c_str(), &buf) == 0) {
            session_db->parse_config(sessiondb_file.c_str());

            std::vector<std::string> oldsessions = session_db->fetch_opt_vec("session");

            if (oldsessions.size() > 0) 
                _MSG("Loading saved HTTP sessions", MSGFLAG_INFO);

            for (unsigned int s = 0; s < oldsessions.size(); s++) {
                std::vector<std::string> sestok = str_tokenize(oldsessions[s], ",");

                if (sestok.size() != 4)
                    continue;

                std::shared_ptr<kis_net_httpd_session> sess(new kis_net_httpd_session());

                sess->sessionid = sestok[0];

                if (sscanf(sestok[1].c_str(), "%lu", &(sess->session_created)) != 1) {
                    continue;
                }

                if (sscanf(sestok[2].c_str(), "%lu", &(sess->session_seen)) != 1) {
                    continue;
                }

                if (sscanf(sestok[3].c_str(), "%lu", &(sess->session_lifetime)) != 1) {
                    continue;
                }

                // Ignore old sessions
                if (sess->session_created + sess->session_lifetime < time(0)) 
                    continue;

                // Don't use add_session because we don't want to trigger a write, yet
                session_map[sess->sessionid] = sess;
            }
        }
    }
}

kis_net_httpd::~kis_net_httpd() {
    stop_httpd();

    // Wipe out all handlers
    handler_vec.erase(handler_vec.begin(), handler_vec.end());

    if (session_db) {
        delete(session_db);
    }

    session_map.clear();

    Globalreg::globalreg->remove_global(global_name());
}

void kis_net_httpd::register_session_handler(std::shared_ptr<kis_httpd_websession> in_session) {
    local_locker l(&controller_mutex);
    websession = in_session;
}

char *kis_net_httpd::read_ssl_file(std::string in_fname) {
    FILE *f;
    char *buf = NULL;
    long sz;

    // Read errors are considered fatal
    if ((f = fopen(in_fname.c_str(), "rb")) == NULL) {
        _MSG_FATAL("Unable to open SSL certificate file {}: {}", in_fname, kis_strerror_r(errno));
        Globalreg::globalreg->fatal_condition = 1;
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    rewind(f);

    if (sz <= 0) {
        _MSG_FATAL("Unable to load SSL certificate file {}: File is empty", in_fname);
        Globalreg::globalreg->fatal_condition = 1;
        return NULL;
    }

    buf = new char[sz + 1];
    if (fread(buf, sz, 1, f) <= 0) {
        _MSG_FATAL("Unable to read SSL file {}: {}", in_fname, kis_strerror_r(errno));
        Globalreg::globalreg->fatal_condition = 1;
        return NULL;
    }
    fclose(f);

    // Null terminate the buffer
    buf[sz] = 0;

    return buf;
}

std::string kis_net_httpd::get_suffix(std::string url) {
    size_t lastdot = url.find_last_of(".");

    if (lastdot != std::string::npos)
        return url.substr(lastdot + 1, url.length() - lastdot);

    return "";
}

std::string kis_net_httpd::strip_suffix(std::string url) {
    size_t lastdot = url.find_last_of(".");

    if (lastdot == std::string::npos)
        lastdot = url.length();

    return url.substr(0, lastdot);
}

void kis_net_httpd::register_mime_type(std::string suffix, std::string mimetype) {
    local_locker lock(&controller_mutex);
    mime_type_map[str_lower(suffix)] = mimetype;
}

void kis_net_httpd::register_alias(const std::string& in_alias, const std::string& in_dest) {
    local_locker lock(&controller_mutex);
    alias_rewrite_map[in_alias] = in_dest;
}

void kis_net_httpd::remove_alias(const std::string& in_alias) {
    local_locker lock(&controller_mutex);

    auto k = alias_rewrite_map.find(in_alias);
    if (k != alias_rewrite_map.end())
        alias_rewrite_map.erase(k);
}

void kis_net_httpd::register_static_dir(std::string in_prefix, std::string in_path) {
    local_locker lock(&controller_mutex);

    static_dir_vec.push_back(static_dir(in_prefix, in_path));
}

void kis_net_httpd::register_handler(kis_net_httpd_handler *in_handler) {
    local_locker lock(&controller_mutex);

    handler_vec.push_back(in_handler);
}

void kis_net_httpd::remove_handler(kis_net_httpd_handler *in_handler) {
    local_locker lock(&controller_mutex);

    for (unsigned int x = 0; x < handler_vec.size(); x++) {
        if (handler_vec[x] == in_handler) {
            handler_vec.erase(handler_vec.begin() + x);
            break;
        }
    }
}

void kis_net_httpd::register_unauth_handler(kis_net_httpd_handler *in_handler) {
    local_locker lock(&controller_mutex);

    unauth_handler_vec.push_back(in_handler);
}

void kis_net_httpd::remove_unauth_handler(kis_net_httpd_handler *in_handler) {
    local_locker lock(&controller_mutex);

    for (unsigned int x = 0; x < unauth_handler_vec.size(); x++) {
        if (unauth_handler_vec[x] == in_handler) {
            unauth_handler_vec.erase(unauth_handler_vec.begin() + x);
            break;
        }
    }
}

int kis_net_httpd::start_httpd() {
    local_locker lock(&controller_mutex);

    if (use_ssl) {
        // If we can't load the SSL key files, crash and burn.  We can't safely
        // degrade to non-ssl when the user is expecting encryption.
        if (pem_path == "") {
            _MSG("SSL requested but missing httpd_ssl_cert= configuration option.",
                    MSGFLAG_FATAL);
            Globalreg::globalreg->fatal_condition = 1;
            return -1;
        }

        if (key_path == "") {
            _MSG("SSL requested but missing httpd_ssl_key= configuration option.",
                    MSGFLAG_FATAL);
            Globalreg::globalreg->fatal_condition = 1;
            return -1;
        }

        pem_path =
            Globalreg::globalreg->kismet_config->expand_log_path(pem_path, "", "", 0, 1);
        key_path =
            Globalreg::globalreg->kismet_config->expand_log_path(key_path, "", "", 0, 1);

        cert_pem = read_ssl_file(pem_path);
        cert_key = read_ssl_file(key_path);

        if (cert_pem == NULL || cert_key == NULL) {
            _MSG("SSL requested but unable to load cert and key files, check your "
                    "configuration!", MSGFLAG_FATAL);
            Globalreg::globalreg->fatal_condition = 1;
            return -1;
        }
    }

    struct sockaddr_in listen_addr;

    memset(&listen_addr, 0, sizeof(struct sockaddr_in));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(http_port);

    if (http_host == "") {
        listen_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        if (inet_pton(AF_INET, http_host.c_str(), &(listen_addr.sin_addr.s_addr)) == 0) {
            _MSG_FATAL("httpd_bind_address provided, but couldn't parse {} as an address, expected an "
                    "IP address of a local interface in a.b.c.d format.", http_host);
            Globalreg::globalreg->fatal_condition = 1;
            return -1;
        }
    }

    if (!use_ssl) {
        microhttpd = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,
                http_port, NULL, NULL, 
                &http_request_handler, this, 
                MHD_OPTION_NOTIFY_COMPLETED, &http_request_completed, NULL,
                MHD_OPTION_SOCK_ADDR, (struct sockaddr *) &listen_addr, 
                MHD_OPTION_END); 
    } else {
        microhttpd = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL,
                http_port, NULL, NULL, &http_request_handler, this, 
                MHD_OPTION_NOTIFY_COMPLETED, &http_request_completed, NULL,
                MHD_OPTION_SOCK_ADDR, (struct sockaddr *) &listen_addr, 
                MHD_OPTION_HTTPS_MEM_KEY, cert_key,
                MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                MHD_OPTION_END); 
    }


    if (microhttpd == nullptr) {
        if (http_port < 1024 && geteuid() == 0) {
            _MSG_FATAL("(HTTPD) Unable to start HTTP server on port {}.  To start servers on "
                    "ports below 1024, you must be running as root.  This is not recommended; "
                    "for greater security use a higher port and a proxy or port redirect.",
                    http_port);
        } else { 
            _MSG_FATAL("(HTTPD) Unable to start HTTP server on port {}; make sure no other "
                    "services are using this port and no other copy of Kismet is running.",
                    http_port);
        }

        Globalreg::globalreg->fatal_condition = 1;
        return -1;
    }

    MHD_set_panic_func(kis_net_httpd::MHD_Panic, this);

    running = true;

    if (http_host == "")
        _MSG_INFO("(HTTPD) Started http server on port {}", http_port);
    else
        _MSG_INFO("(HTTPD) Started http server on {}:{}", http_host, http_port);

    return 1;
}

int kis_net_httpd::stop_httpd() {
    local_locker lock(&controller_mutex);

    if (microhttpd != NULL) {
        running = false;

        // If possible we want to quiesce the daemon and stop it fully in our 
        // deconstructor; however on some implementations of microhttpd that's 
        // not available.
        //
        // Unfortunately, on OTHER builds of microhttpd, 'stop' has a race
        // condition (notably the version shipped in ubuntu up to, at least,
        // 17.10) so we want to prefer the 'right' one
#ifdef MHD_QUIESCE
        MHD_quiesce_daemon(microhttpd);
#else
        MHD_stop_daemon(microhttpd);
#endif
    }

    handler_vec.clear();
    static_dir_vec.clear();

    return 1;
}

void kis_net_httpd::MHD_Panic(void *cls, const char *file __attribute__((unused)), 
            unsigned int line __attribute__((unused)), const char *reason) {
    kis_net_httpd *httpd = (kis_net_httpd *) cls;

    // Do nothing if we're already closing down
    if (!httpd->running)
        return;

    httpd->running = false;

    Globalreg::globalreg->fatal_condition = 1;
    _MSG_FATAL("Unable to continue after MicroHTTPD fatal issue: {}", reason);

    // Null out the microhttpd since it can't keep operating and can't be
    // trusted to close down properly
    httpd->microhttpd = NULL;
}

bool kis_net_httpd::has_valid_session(kis_net_httpd_connection *connection, bool send_invalid) {
    if (connection->session != NULL)
        return true;

    std::shared_ptr<kis_net_httpd_session> s;
    const char *cookieval;

    cookieval = MHD_lookup_connection_value(connection->connection,
            MHD_COOKIE_KIND, KIS_SESSION_COOKIE);

    if (cookieval != nullptr) {
        if (FindSession(cookieval) != nullptr)
            return true;
    }

    // If we got here, we either don't have a session, or the session isn't valid.
    if (websession != NULL && websession->validate_login(connection->connection)) {
        create_session(connection, NULL, session_timeout);
        return true;
    }

    // If we got here it's invalid.  Do we automatically send an invalidation 
    // response?
    if (send_invalid) {
        auto fourohone = fmt::format("<h1>401 - Access denied</h1>Login required to access this resource.\n");

        connection->response = 
            MHD_create_response_from_buffer(fourohone.length(),
                    (void *) fourohone.c_str(), MHD_RESPMEM_MUST_COPY);

        // Still append the standard headers
        append_standard_headers(this, connection, connection->url.c_str());

        // Queue a 401 fail instead of a basic auth fail so we don't cause a bunch of prompting in the browser
        // Make sure this doesn't actually break anything...
        MHD_queue_response(connection->connection, 401, connection->response);

        // MHD_queue_basic_auth_fail_response(connection->connection, "Kismet", connection->response);
    }

    return false;
}

std::shared_ptr<kis_net_httpd_session> 
kis_net_httpd::create_session(kis_net_httpd_connection *connection, 
        struct MHD_Response *response, time_t in_lifetime) {
    
    std::shared_ptr<kis_net_httpd_session> s;

    // Use 128 bits of entropy to make a session key

    char rdata[16];
    FILE *urandom;

    if ((urandom = fopen("/dev/urandom", "rb")) == NULL) {
        _MSG("Failed to open /dev/urandom to create a HTTPD session, unable to "
                "assign a sessionid, not creating session", MSGFLAG_ERROR);
        return NULL;
    }

    if (fread(rdata, 16, 1, urandom) != 1) {
        _MSG("Failed to read entropy from /dev/urandom to create a HTTPD session, "
                "unable to assign a sessionid, not creating session", MSGFLAG_ERROR);
        fclose(urandom);
        return NULL;
    }
    fclose(urandom);

    std::stringstream cookiestr;
    std::stringstream cookie;
    
    cookiestr << KIS_SESSION_COOKIE << "=";

    for (unsigned int x = 0; x < 16; x++) {
        cookie << std::uppercase << std::setfill('0') << std::setw(2) 
            << std::hex << (int) (rdata[x] & 0xFF);
    }

    cookiestr << cookie.str();

    cookiestr << "; Path=/";

    if (response != NULL) {
        auto str = cookiestr.str();
        if (MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, 
                    str.c_str()) == MHD_NO) {
            _MSG("Failed to add session cookie to response header, unable to create "
                    "a session", MSGFLAG_ERROR);
            return NULL;
        }
    }

    s = std::make_shared<kis_net_httpd_session>();
    s->sessionid = cookie.str();
    s->session_created = time(0);
    s->session_seen = s->session_created;
    s->session_lifetime = in_lifetime;

    if (connection != NULL)
        connection->session = s;

    add_session(s);

    return s;
}


void kis_net_httpd::add_session(std::shared_ptr<kis_net_httpd_session> in_session) {
    local_locker lock(&session_mutex);

    session_map[in_session->sessionid] = in_session;
    write_sessions();
}

void kis_net_httpd::del_session(std::string in_key) {
    local_locker lock(&session_mutex);

    auto i = session_map.find(in_key);

    if (i != session_map.end()) {
        session_map.erase(i);
        write_sessions();
    }
}

void kis_net_httpd::del_session(std::map<std::string, std::shared_ptr<kis_net_httpd_session> >::iterator in_itr) {
    local_locker lock(&session_mutex);

    if (in_itr != session_map.end()) {
        session_map.erase(in_itr);
        write_sessions();
    }
}

std::shared_ptr<kis_net_httpd_session> kis_net_httpd::FindSession(const std::string& in_session_tok) {
    local_locker lock(&session_mutex);

    auto si = session_map.find(in_session_tok);

    if (si != session_map.end()) {
        // Delete if the session has expired and don't assign as a session
        if (si->second->session_lifetime != 0 &&
                si->second->session_seen + si->second->session_lifetime < time(0)) {
            del_session(si);
            return nullptr;
        } else {
            return si->second;
        }
    }

    return nullptr;
}


void kis_net_httpd::write_sessions() {
    if (!store_sessions)
        return;

    std::vector<std::string> sessions;
    std::stringstream str;

    {
        local_locker lock(&session_mutex);

        for (auto i : session_map) {
            str.str("");

            str << i.second->sessionid << "," << i.second->session_created << "," <<
                i.second->session_seen << "," << i.second->session_lifetime;

            sessions.push_back(str.str());
        }
    }

    session_db->set_opt_vec("session", sessions, true);

    // Ignore failures here I guess?
    session_db->save_config(sessiondb_file.c_str());
}

KIS_MHD_RETURN kis_net_httpd::http_request_handler(void *cls, struct MHD_Connection *connection,
    const char *in_url, const char *method, const char *version __attribute__ ((unused)),
    const char *upload_data, size_t *upload_data_size, void **ptr) {

    //fprintf(stderr, "debug - HTTP request: '%s' method '%s'\n", url, method); 
    //
    kis_net_httpd *kishttpd = (kis_net_httpd *) cls;

    if (Globalreg::globalreg->spindown || Globalreg::globalreg->fatal_condition)
        return MHD_NO;
    
    // Update the session records if one exists
    std::shared_ptr<kis_net_httpd_session> s = NULL;
    const char *cookieval;
    KIS_MHD_RETURN ret = MHD_NO;

    kis_net_httpd_connection *concls = NULL;
    bool new_concls = false;

    // Handle a CORS preflight OPTIONS request by sending back an allow-all header
    if (strcmp(method, "OPTIONS") == 0 && kishttpd->allow_cors) {
        auto response = 
            MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);

        append_cors_headers(kishttpd, connection, response);

        ret = MHD_queue_response(connection, MHD_HTTP_OK, response);
        MHD_destroy_response(response);

        return MHD_YES;
    }

    cookieval = 
        MHD_lookup_connection_value(connection, MHD_COOKIE_KIND, KIS_SESSION_COOKIE);

    if (cookieval != NULL) {
        s = kishttpd->FindSession(cookieval);

        if (s != nullptr) {
            s->session_seen = time(0);
        }
    } 
    
    kis_net_httpd_handler *handler = NULL;

    // Collapse multiple slashes
    std::string url(in_url);

    size_t spos;
    while ((spos = url.find("//")) != std::string::npos)
        url = url.replace(spos, 2, "/");

    // Look for the URI prefix
    auto uri_prefix_len = kishttpd->uri_prefix.length();

    if (uri_prefix_len > 0 && url.substr(0, uri_prefix_len) == kishttpd->uri_prefix) {
        url = url.substr(uri_prefix_len, url.length());

        // Don't kill a leading '/' if the user specified a match that eats it
        if (url[0] != '/')
            url = "/" + url;
    }

    {
        // Lock controller and process rewrites
        local_shared_locker conclock(&(kishttpd->controller_mutex));
        auto rw = kishttpd->alias_rewrite_map.find(url);
        if (rw != kishttpd->alias_rewrite_map.end())
            url = rw->second;
    }
    
    // If we don't have a connection state, make one
    if (*ptr == NULL) {
        concls = new kis_net_httpd_connection();
        // fprintf(stderr, "debug - allocated new connection state %p\n", concls);

        *ptr = (void *) concls;

        concls->httpd = kishttpd;
        concls->httpdhandler = nullptr;
        concls->session = s;
        concls->httpcode = MHD_HTTP_OK;
        concls->url = url;
        concls->connection = connection;

        new_concls = true;
    } else {
        concls = (kis_net_httpd_connection *) *ptr;
    }

    {
        local_shared_locker conclock(&(kishttpd->controller_mutex));

        /* Look for a handler that can process this; first we look for handlers which
         * don't require auth */
        for (auto h : kishttpd->unauth_handler_vec) {
            if (h->httpd_verify_path(url.c_str(), method)) {
                handler = h;
                break;
            }
        }

        /* If we didn't find a no-auth handler, move on to the auth handlers, and 
         * force them to have a valid login */
        if (handler == nullptr) {
            for (auto h : kishttpd->handler_vec) {
                if (h->httpd_verify_path(url.c_str(), method)) {
                    if (!kishttpd->has_valid_session(concls, true)) {
                        return MHD_YES;
                    }

                    handler = h;

                    break;
                }
            }
        }
    }

    // Now that we know the handler, we need to assign it to the concls.  
    // If we're doing a POST to a new connection we need to assign a post processor
    // and process the incoming data.
    if (new_concls && handler != nullptr) {
        concls->httpdhandler = handler;

        /* Set up a POST handler */
        if (strcmp(method, "POST") == 0) {
            concls->connection_type = kis_net_httpd_connection::CONNECTION_POST;

            concls->postprocessor =
                MHD_create_post_processor(connection, KIS_HTTPD_POSTBUFFERSZ,
                        kishttpd->http_post_handler, (void *) concls);

            if (concls->postprocessor == NULL) {
                // fprintf(stderr, "debug - failed to make postprocessor\n");
                // This might get cleaned up elsewhere? The examples don't 
                // free it.
                // delete(concls);
                return MHD_NO;
            }
        } else {
            // Otherwise default to the get handler
            concls->connection_type = kis_net_httpd_connection::CONNECTION_GET;
        }

        // We're done
        return MHD_YES;
    }
    

    /* If we didn't get a handler for the URI look at the filesystem.  Filesystem lookups 
     * don't require a login, so that we can serve our static html/js correctly. */
    if (handler == nullptr) {
        // Try to check a static url
        if (handle_static_file(cls, concls, url.c_str(), method) < 0) {
            // fprintf(stderr, "   404 no handler for request %s\n", url);

            auto fourohfour = fmt::format("<h1>404</h1>Unable to find resource {}\n", 
                    kishttpd::escape_html(url));

            struct MHD_Response *response = 
                MHD_create_response_from_buffer(fourohfour.length(), 
                        (void *) fourohfour.c_str(), MHD_RESPMEM_MUST_COPY);

            return MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
        }

        return MHD_YES;
    }

    if (strcmp(method, "POST") == 0) {
        // Handle post
        
        // If we still have data to process
        if (*upload_data_size != 0) {
            // Process regardless of size to get our completion
            MHD_post_process(concls->postprocessor, upload_data, *upload_data_size);

            // Continue processing post data
            *upload_data_size = 0;
            return MHD_YES;
        } 

        // Otherwise we've completed our post data processing, flag us
        // as completed so our post handler knows we're done
        
        // fprintf(stderr, "con %p post complete\n", concls);
        concls->post_complete = true;

        // Handle a post req inside the processor and return the results
        return (concls->httpdhandler)->httpd_handle_post_request(kishttpd, concls, url.c_str(),
                method, upload_data, upload_data_size);
    } else {
        // Handle GET + any others
        
        MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, 
                [](void *cls, enum MHD_ValueKind, const char *key, const char *value) -> KIS_MHD_RETURN {
                    auto concls = static_cast<kis_net_httpd_connection *>(cls);

                    concls->variable_cache[key] = std::make_shared<std::stringstream>();

                    if (value != nullptr)
                        concls->variable_cache[key]->write(value, strlen(value));

                    return MHD_YES;
                }, concls);
       
        ret = (concls->httpdhandler)->httpd_handle_get_request(kishttpd, concls, url.c_str(), method, 
                upload_data, upload_data_size);
    }

    return ret;
}

KIS_MHD_RETURN kis_net_httpd::http_post_handler(void *coninfo_cls, enum MHD_ValueKind kind, 
        const char *key, const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data, 
        uint64_t off, size_t size) {

    kis_net_httpd_connection *concls = (kis_net_httpd_connection *) coninfo_cls;

    if (concls->httpdhandler->httpd_use_custom_post_iterator()) {
        return (concls->httpdhandler)->httpd_post_iterator(coninfo_cls, kind,
                key, filename, content_type, transfer_encoding, data, off, size);
    } else {
        // Cache all the variables by name until we're complete
        if (concls->variable_cache.find(key) == concls->variable_cache.end())
            concls->variable_cache[key] = std::make_shared<std::stringstream>();

        concls->variable_cache[key]->write(data, size);

        return MHD_YES;
    }
}

void kis_net_httpd::http_request_completed(void *cls __attribute__((unused)), 
        struct MHD_Connection *connection __attribute__((unused)),
        void **con_cls, 
        enum MHD_RequestTerminationCode toe __attribute__((unused))) {

    if (con_cls == nullptr)
        return;

    auto con_info = static_cast<kis_net_httpd_connection *>(*con_cls);

    if (con_info == nullptr)
        return;

    // Lock and shut it down
    {
        std::lock_guard<std::mutex> lk(con_info->connection_mutex);

        if (con_info->connection_type == kis_net_httpd_connection::CONNECTION_POST) {
            MHD_destroy_post_processor(con_info->postprocessor);
            con_info->postprocessor = NULL;
        }
    }

    // Destroy connection
    delete(con_info);

    *con_cls = nullptr;
}

static ssize_t file_reader(void *cls, uint64_t pos, char *buf, size_t max) {
    FILE *file = (FILE *) cls;

    fseek(file, pos, SEEK_SET);
    return fread(buf, 1, max, file);
}


static void free_callback(void *cls) {
    FILE *file = (FILE *) cls;
    fclose(file);
}

std::string kis_net_httpd::get_mime_type(std::string ext) {
    std::map<std::string, std::string>::iterator mi = mime_type_map.find(ext);
    if (mi != mime_type_map.end()) {
        return mi->second;
    }

    return "";
}

int kis_net_httpd::handle_static_file(void *cls, kis_net_httpd_connection *connection,
        const char *url, const char *method) {
    kis_net_httpd *kishttpd = (kis_net_httpd *) cls;

    if (strcmp(method, "GET") != 0)
        return -1;

    std::string surl(url);

    // Kluge URL
    if (surl.length() == 0)
        surl = "/index.html";
    else if (surl[surl.length() - 1] == '/')
        surl += "index.html";

    local_shared_locker lock(&(kishttpd->controller_mutex));

    for (auto sd : kishttpd->static_dir_vec) {
        if (strlen(url) < sd.prefix.size())
            continue;

        if (surl.find(sd.prefix) != 0) 
            continue;

        std::string modified_fpath = sd.path + "/" + 
            surl.substr(sd.prefix.length(), surl.length());

        char *modified_realpath;
        char *base_realpath = realpath(sd.path.c_str(), NULL);

        modified_realpath = realpath(modified_fpath.c_str(), NULL);

        // Couldn't resolve real path
        if (modified_realpath == NULL || base_realpath == NULL) {
            if (modified_realpath != NULL)
                free(modified_realpath);

            if (base_realpath != NULL)
                free(base_realpath);

            continue;
        }

        // Make sure real path resolves inside the served path
        if (strstr(modified_realpath, base_realpath) != modified_realpath) {
            if (modified_realpath != NULL)
                free(modified_realpath);

            if (base_realpath != NULL)
                free(base_realpath);

            continue;
        }

        // The path is resolved, try to open the file
        FILE *f = fopen(modified_realpath, "rb");

        free(modified_realpath);
        free(base_realpath);

        if (f != NULL) {
            struct MHD_Response *response;
            struct stat buf;

            int fd;

            fd = fileno(f);
            if (fstat(fd, &buf) != 0 || (!S_ISREG(buf.st_mode))) {
                fclose(f);
                return -1;
            }

            response = MHD_create_response_from_callback(buf.st_size, 32 * 1024,
                    &file_reader, f, &free_callback);

            if (response == NULL) {
                fclose(f);
                return -1;
            }

            char lastmod[31];
            struct tm tmstruct;
            localtime_r(&(buf.st_ctime), &tmstruct);
            strftime(lastmod, 31, "%a, %d %b %Y %H:%M:%S %Z", &tmstruct);
            MHD_add_response_header(response, "Last-Modified", lastmod);

            std::string suffix = get_suffix(surl);
            std::string mime = kishttpd->get_mime_type(suffix);

            if (mime != "") {
                MHD_add_response_header(response, "Content-Type", mime.c_str());
            } else {
                MHD_add_response_header(response, "Content-Type", "text/plain");
            }

            // Allow any?
            MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");

            // Never let the browser cache our responses.  Maybe moderate this
            // in the future to cache for 60 seconds or something?
            MHD_add_response_header(response, "Cache-Control", "no-cache");
            MHD_add_response_header(response, "Pragma", "no-cache");
            MHD_add_response_header(response, 
                    "Expires", "Sat, 01 Jan 2000 00:00:00 GMT");

            MHD_queue_response(connection->connection, MHD_HTTP_OK, response);
            MHD_destroy_response(response);

            return 1;
        }
    }

    return -1;
}

void kis_net_httpd::append_http_session(kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection) {

    if (connection->session != NULL) {
        std::stringstream cookiestr;
        std::stringstream cookie;

        cookiestr << KIS_SESSION_COOKIE << "=";
        cookiestr << connection->session->sessionid;
        cookiestr << "; Path=/";

        auto str = cookiestr.str();

        MHD_add_response_header(connection->response, MHD_HTTP_HEADER_SET_COOKIE, 
                str.c_str());
    }
}

void kis_net_httpd::append_cors_headers(kis_net_httpd* httpd,
        struct MHD_Connection *connection,
        struct MHD_Response *response) {

    if (!httpd->allow_cors)
        return;

    if (httpd->allowed_cors_referrer.length() != 0) {
        // Send only the origin we allow if we have it restricted
        MHD_add_response_header(response, "Access-Control-Allow-Origin", 
                httpd->allowed_cors_referrer.c_str());
    } else {
        // Echo back the origin if we allow any
        const char *origin =
            MHD_lookup_connection_value (connection, MHD_HEADER_KIND, "Origin");

        if (origin != NULL)
            MHD_add_response_header(response, "Access-Control-Allow-Origin", origin);
        else
            MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");
    }

    MHD_add_response_header(response, "Access-Control-Allow-Credentials", "true");
    MHD_add_response_header(response, "Vary", "Origin");
    MHD_add_response_header(response, "Access-Control-Max-Age", "86400");
    MHD_add_response_header(response, "Access-Control-Allow-Methods", "POST, GET, OPTIONS");
    MHD_add_response_header(response, "Access-Control-Allow-Headers", "Content-Type, Authorization");

}

void kis_net_httpd::append_standard_headers(kis_net_httpd *httpd,
        kis_net_httpd_connection *connection, const char *url) {

    // Last-modified is always now
    char lastmod[31];
    struct tm tmstruct;
    time_t now;
    time(&now);
    gmtime_r(&now, &tmstruct);
    strftime(lastmod, 31, "%a, %d %b %Y %H:%M:%S %Z", &tmstruct);
    MHD_add_response_header(connection->response, "Last-Modified", lastmod);

    std::string suffix;

    if (connection->mime_url != "")
        suffix = get_suffix(connection->mime_url);
    else
        suffix = get_suffix(connection->url);

    std::string mime = httpd->get_mime_type(suffix);

    if (mime != "") {
        MHD_add_response_header(connection->response, "Content-Type", mime.c_str());
    } else {
        MHD_add_response_header(connection->response, "Content-Type", "text/plain");
    }

    // If we have an optional filename set, set our disposition type and then
    // add the filename attribute
    if (connection->optional_filename != "") {
        std::string disp = "attachment; filename=\"" + connection->optional_filename + "\"";
        MHD_add_response_header(connection->response, "Content-Disposition", disp.c_str());
    }

    // Never let the browser cache our responses.  Maybe moderate this
    // in the future to cache for 60 seconds or something?
    MHD_add_response_header(connection->response, "Cache-Control", "no-cache");
    MHD_add_response_header(connection->response, "Pragma", "no-cache");
    MHD_add_response_header(connection->response, 
            "Expires", "Sat, 01 Jan 2000 00:00:00 GMT");

    append_cors_headers(httpd, connection->connection, connection->response);

}

KIS_MHD_RETURN kis_net_httpd::send_http_response(kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection) {
    MHD_queue_response(connection->connection, connection->httpcode, connection->response);
    MHD_destroy_response(connection->response);
    return MHD_YES;
}

KIS_MHD_RETURN kis_net_httpd::send_standard_http_response(kis_net_httpd *httpd,
        kis_net_httpd_connection *connection, const char *url) {
    append_http_session(httpd, connection);
    append_standard_headers(httpd, connection, url);
    return send_http_response(httpd, connection);
}

kis_net_httpd_simple_tracked_endpoint::kis_net_httpd_simple_tracked_endpoint(const std::string& in_uri,
        std::shared_ptr<tracker_element> in_element, kis_recursive_timed_mutex *in_mutex) :
    kis_net_httpd_chain_stream_handler {},
    uri {in_uri},
    content {in_element},
    generator {nullptr},
    mutex {in_mutex} { 
        bind_httpd_server();
    }

kis_net_httpd_simple_tracked_endpoint::kis_net_httpd_simple_tracked_endpoint(const std::string& in_uri,
        kis_net_httpd_simple_tracked_endpoint::gen_func in_func) :
    kis_net_httpd_chain_stream_handler {},
    uri {in_uri}, 
    content { nullptr },
    generator {in_func},
    mutex {nullptr} {

    bind_httpd_server();
}

kis_net_httpd_simple_tracked_endpoint::kis_net_httpd_simple_tracked_endpoint(const std::string& in_uri,
        kis_net_httpd_simple_tracked_endpoint::gen_func in_func,
        kis_recursive_timed_mutex *in_mutex) :
    kis_net_httpd_chain_stream_handler {},
    uri {in_uri}, 
    content { nullptr },
    generator {in_func},
    mutex {in_mutex} {

    bind_httpd_server();
}

bool kis_net_httpd_simple_tracked_endpoint::httpd_verify_path(const char *path, const char *method) {
    auto stripped = httpd_strip_suffix(path);

    if (stripped == uri && httpd_can_serialize(path))
        return true;

    return false;
}

KIS_MHD_RETURN kis_net_httpd_simple_tracked_endpoint::httpd_create_stream_response(
        kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    local_demand_locker l(mutex, fmt::format("simple_tracked_endpoint::stream_response {}", uri));

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    // Allocate our buffer aux
    kis_net_httpd_buffer_stream_aux *saux = 
        (kis_net_httpd_buffer_stream_aux *) connection->custom_extension;

    buffer_handler_ostringstream_buf *streambuf = 
        new buffer_handler_ostringstream_buf(saux->get_rbhandler());
    std::ostream stream(streambuf);

    // Set our cleanup function
    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    if (mutex != nullptr)
        l.lock();

    try {
        std::shared_ptr<tracker_element> output_content;

        if (content == nullptr && generator == nullptr) {
            stream << "Invalid request: No backing content present";
            connection->httpcode = 400;
            return MHD_YES;
        }

        if (generator != nullptr)
            output_content = generator();
        else
            output_content = content;

        Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(connection->url), stream, 
                output_content, nullptr);
    } catch (const std::exception& e) {
        stream << "Error: " << e.what() << "\n";
        connection->httpcode = 500;
        return MHD_YES;
    }

    return MHD_YES;
}

KIS_MHD_RETURN kis_net_httpd_simple_tracked_endpoint::httpd_post_complete(kis_net_httpd_connection *concls) {
    auto saux = (kis_net_httpd_buffer_stream_aux *) concls->custom_extension;
    auto streambuf = new buffer_handler_ostringstream_buf(saux->get_rbhandler());

    local_demand_locker l(mutex, fmt::format("simple_tracked_endpoint::post_complete {}", uri));

    std::lock_guard<std::mutex> lk(concls->connection_mutex);

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    if (content == nullptr && generator == nullptr) {
        stream << "Invalid request: No backing content present";
        concls->httpcode = 400;
        return MHD_YES;
    }

    std::shared_ptr<tracker_element> output_content;

    if (mutex != nullptr)
        l.lock();

    try {
        if (generator != nullptr)
            output_content = generator();
        else
            output_content = content;
    } catch (const std::exception& e) {
        stream << "Invalid request / error processing request: " << e.what() << "\n";
        concls->httpcode = 500;
        return MHD_YES;
    }

    Json::Value json;
    std::vector<SharedElementSummary> summary_vec;
    auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();

    try {
        json = concls->variable_cache_as<Json::Value>("json", "{}");
    } catch(const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        concls->httpcode = 400;
        return MHD_YES;
    }

    auto summary = 
        kishttpd::summarize_with_json(output_content, json, rename_map);

    Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(concls->url), stream, 
            summary, rename_map);

    return MHD_YES;
}

kis_net_httpd_simple_unauth_tracked_endpoint::kis_net_httpd_simple_unauth_tracked_endpoint(const std::string& in_uri,
        std::shared_ptr<tracker_element> in_element, kis_recursive_timed_mutex *in_mutex) :
    kis_net_httpd_chain_stream_handler {},
    uri {in_uri},
    content {in_element},
    generator {nullptr},
    mutex {in_mutex} { 
    httpd->register_unauth_handler(this);
}

kis_net_httpd_simple_unauth_tracked_endpoint::kis_net_httpd_simple_unauth_tracked_endpoint(const std::string& in_uri,
        kis_net_httpd_simple_tracked_endpoint::gen_func in_func) :
    kis_net_httpd_chain_stream_handler {},
    uri {in_uri}, 
    content { nullptr },
    generator {in_func},
    mutex {nullptr} {
    httpd->register_unauth_handler(this);
}

kis_net_httpd_simple_unauth_tracked_endpoint::kis_net_httpd_simple_unauth_tracked_endpoint(const std::string& in_uri,
        kis_net_httpd_simple_tracked_endpoint::gen_func in_func,
        kis_recursive_timed_mutex *in_mutex) :
    kis_net_httpd_chain_stream_handler {},
    uri {in_uri}, 
    content { nullptr },
    generator {in_func},
    mutex {in_mutex} {
    httpd->register_unauth_handler(this);
}

bool kis_net_httpd_simple_unauth_tracked_endpoint::httpd_verify_path(const char *path, const char *method) {
    auto stripped = httpd_strip_suffix(path);

    if (stripped == uri && httpd_can_serialize(path))
        return true;

    return false;
}

KIS_MHD_RETURN kis_net_httpd_simple_unauth_tracked_endpoint::httpd_create_stream_response(
        kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    local_demand_locker l(mutex, fmt::format("unauthed_tracked_endpoint::stream_response {}", uri));
    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    if (mutex != nullptr)
        l.lock();

    // Allocate our buffer aux
    kis_net_httpd_buffer_stream_aux *saux = 
        (kis_net_httpd_buffer_stream_aux *) connection->custom_extension;

    buffer_handler_ostringstream_buf *streambuf = 
        new buffer_handler_ostringstream_buf(saux->get_rbhandler());
    std::ostream stream(streambuf);

    // Set our cleanup function
    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    try {
        std::shared_ptr<tracker_element> output_content;

        if (content == nullptr && generator == nullptr) {
            stream << "Invalid request: No backing content present";
            connection->httpcode = 400;
            return MHD_YES;
        }

        if (generator != nullptr)
            output_content = generator();
        else
            output_content = content;

        Globalreg::fetch_mandatory_global_as<entry_tracker>("ENTRYTRACKER")->serialize(httpd->get_suffix(connection->url), stream, output_content, nullptr);
    } catch (const std::exception& e) {
        stream << "Error: " << e.what() << "\n";
        connection->httpcode = 500;
        return MHD_YES;
    }

    return MHD_YES;
}

KIS_MHD_RETURN kis_net_httpd_simple_unauth_tracked_endpoint::httpd_post_complete(kis_net_httpd_connection *concls) {
    auto saux = (kis_net_httpd_buffer_stream_aux *) concls->custom_extension;
    auto streambuf = new buffer_handler_ostringstream_buf(saux->get_rbhandler());

    local_demand_locker l(mutex, fmt::format("unauth_tracked_endpoint::post_complete {}", uri));
    std::lock_guard<std::mutex> lk(concls->connection_mutex);

    if (mutex != nullptr)
        l.lock();

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    if (content == nullptr && generator == nullptr) {
        stream << "Invalid request: No backing content present";
        concls->httpcode = 400;
        return MHD_YES;
    }

    std::shared_ptr<tracker_element> output_content;

    try {
        if (generator != nullptr)
            output_content = generator();
        else
            output_content = content;
    } catch (const std::exception& e) {
        stream << "Invalid request / error processing request: " << e.what() << "\n";
        concls->httpcode = 500;
        return MHD_YES;
    }

    // Common structured API data
    Json::Value json;
    auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();

    try {
        json = concls->variable_cache_as<Json::Value>("json");
    } catch(const std::runtime_error& e) {
        stream << "Invalid request: ";
        stream << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    auto summary = 
        kishttpd::summarize_with_json(output_content, json, rename_map);

    Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(concls->url), stream, summary, rename_map);
    return MHD_YES;
}

kis_net_httpd_path_tracked_endpoint::kis_net_httpd_path_tracked_endpoint(
        kis_net_httpd_path_tracked_endpoint::path_func in_path,
        kis_net_httpd_path_tracked_endpoint::gen_func in_gen) :
    kis_net_httpd_chain_stream_handler {},
    path { in_path },
    generator {in_gen},
    mutex {nullptr} { 
        bind_httpd_server();
}

kis_net_httpd_path_tracked_endpoint::kis_net_httpd_path_tracked_endpoint(
        kis_net_httpd_path_tracked_endpoint::path_func in_path,
        kis_net_httpd_path_tracked_endpoint::gen_func in_gen,
        kis_recursive_timed_mutex *in_mutex) :
    kis_net_httpd_chain_stream_handler {},
    path { in_path },
    generator {in_gen},
    mutex {in_mutex} { 
        bind_httpd_server();
}


bool kis_net_httpd_path_tracked_endpoint::httpd_verify_path(const char *in_path, const char *in_method) {
    if (!httpd_can_serialize(in_path))
        return false;

    auto stripped = httpd_strip_suffix(in_path);
    auto tokenurl = str_tokenize(stripped, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (tokenurl.size())
        tokenurl = std::vector<std::string>(tokenurl.begin() + 1, tokenurl.end());

    local_demand_locker l(mutex);
    if (mutex != nullptr)
        l.lock();

    return path(tokenurl);
}

KIS_MHD_RETURN kis_net_httpd_path_tracked_endpoint::httpd_create_stream_response(
        kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection,
        const char *in_path, const char *in_method, const char *upload_data,
        size_t *upload_data_size) {

    local_demand_locker l(mutex, fmt::format("path_tracked_endpoint::stream_response {}", in_path));
    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    if (mutex != nullptr)
        l.lock();

    // Allocate our buffer aux
    kis_net_httpd_buffer_stream_aux *saux = 
        (kis_net_httpd_buffer_stream_aux *) connection->custom_extension;

    buffer_handler_ostringstream_buf *streambuf = 
        new buffer_handler_ostringstream_buf(saux->get_rbhandler());
    std::ostream stream(streambuf);

    // Set our cleanup function
    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    std::shared_ptr<tracker_element> output_content;

    auto stripped = httpd_strip_suffix(in_path);
    auto tokenurl = str_tokenize(stripped, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (tokenurl.size())
        tokenurl = std::vector<std::string>(tokenurl.begin() + 1, tokenurl.end());

    try {
        output_content = generator(tokenurl);
    } catch (const std::exception& e) {
        stream << "Invalid request / error processing request: " << e.what() << "\n";
        connection->httpcode = 500;
        return MHD_YES;
    }

    Globalreg::fetch_mandatory_global_as<entry_tracker>("ENTRYTRACKER")->serialize(httpd->get_suffix(connection->url), stream, output_content, nullptr);

    return MHD_YES;
}

KIS_MHD_RETURN kis_net_httpd_path_tracked_endpoint::httpd_post_complete(kis_net_httpd_connection *concls) {
    auto saux = (kis_net_httpd_buffer_stream_aux *) concls->custom_extension;
    auto streambuf = new buffer_handler_ostringstream_buf(saux->get_rbhandler());

    local_demand_locker l(mutex, fmt::format("path_tracked_endpoint::post_complete {}", concls->url));
    std::lock_guard<std::mutex> lk(concls->connection_mutex);

    if (mutex != nullptr)
        l.lock();

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    auto stripped = httpd_strip_suffix(concls->url);
    auto tokenurl = str_tokenize(stripped, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (tokenurl.size())
        tokenurl = std::vector<std::string>(tokenurl.begin() + 1, tokenurl.end());

    std::shared_ptr<tracker_element> output_content;

    try {
        output_content = generator(tokenurl);
    } catch (const std::exception& e) {
        stream << "Invalid request / error processing request: " << e.what() << "\n";
        concls->httpcode = 500;
        return MHD_YES;
    }

    Json::Value json;
    auto rename_map = std::make_shared<tracker_element_serializer::rename_map>();

    try {
        json = concls->variable_cache_as<Json::Value>("json", "{}");
    } catch(const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        concls->httpcode = 400;
        return MHD_YES;
    }

    auto summary =
        kishttpd::summarize_with_json(output_content, json, rename_map);

    Globalreg::globalreg->entrytracker->serialize(httpd->get_suffix(concls->url), stream, summary, rename_map);
    return MHD_YES;
}

kis_net_httpd_simple_stream_endpoint::kis_net_httpd_simple_stream_endpoint(const std::string& in_uri,
        kis_net_httpd_simple_stream_endpoint::gen_func in_func) :
    kis_net_httpd_chain_stream_handler {},
    uri {in_uri}, 
    generator {in_func},
    mutex {nullptr} {

    bind_httpd_server();
}

kis_net_httpd_simple_stream_endpoint::kis_net_httpd_simple_stream_endpoint(const std::string& in_uri,
        kis_net_httpd_simple_stream_endpoint::gen_func in_func,
        kis_recursive_timed_mutex *in_mutex) :
    kis_net_httpd_chain_stream_handler {},
    uri {in_uri}, 
    generator {in_func},
    mutex {in_mutex} {

    bind_httpd_server();
}

bool kis_net_httpd_simple_stream_endpoint::httpd_verify_path(const char *path, const char *method) {
    if (uri == path)
        return true;

    return false;
}

KIS_MHD_RETURN kis_net_httpd_simple_stream_endpoint::httpd_create_stream_response(
        kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    local_demand_locker l(mutex, fmt::format("simple_stream_endpoint::stream_response {}", uri));
    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    if (mutex != nullptr)
        l.lock();

    // Allocate our buffer aux
    kis_net_httpd_buffer_stream_aux *saux = 
        (kis_net_httpd_buffer_stream_aux *) connection->custom_extension;

    buffer_handler_ostringstream_buf *streambuf = 
        new buffer_handler_ostringstream_buf(saux->get_rbhandler());
    std::ostream stream(streambuf);

    // Set our cleanup function
    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    try {
        std::shared_ptr<tracker_element> output_content;

        if (generator == nullptr) {
            stream << "Invalid request: No backing content present";
            connection->httpcode = 400;
            return MHD_YES;
        }

        connection->httpcode = generator(stream);

    } catch (const std::exception& e) {
        stream << "Error: " << e.what() << "\n";
        connection->httpcode = 500;
        return MHD_YES;
    }

    return MHD_YES;
}

KIS_MHD_RETURN kis_net_httpd_simple_stream_endpoint::httpd_post_complete(kis_net_httpd_connection *concls) {
    auto saux = (kis_net_httpd_buffer_stream_aux *) concls->custom_extension;
    auto streambuf = new buffer_handler_ostringstream_buf(saux->get_rbhandler());

    local_demand_locker l(mutex, fmt::format("simple_stream_endpoint::post_complete {}", uri));
    std::lock_guard<std::mutex> lk(concls->connection_mutex);

    if (mutex != nullptr)
        l.lock();

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    if (generator == nullptr) {
        stream << "Invalid request: No backing content present";
        concls->httpcode = 400;
        return MHD_YES;
    }

    std::shared_ptr<tracker_element> output_content;

    try {
        concls->httpcode = generator(stream);
    } catch (const std::exception& e) {
        stream << "Invalid request / error processing request: " << e.what() << "\n";
        concls->httpcode = 500;
        return MHD_YES;
    }

    return MHD_YES;
}

kis_net_httpd_simple_post_endpoint::kis_net_httpd_simple_post_endpoint(const std::string& in_uri,
        kis_net_httpd_simple_post_endpoint::handler_func in_func) :
    kis_net_httpd_chain_stream_handler {},
    uri {in_uri},
    generator {in_func}, 
    mutex {nullptr} {

    bind_httpd_server();
}

kis_net_httpd_simple_post_endpoint::kis_net_httpd_simple_post_endpoint(const std::string& in_uri,
        kis_net_httpd_simple_post_endpoint::handler_func in_func, 
        kis_recursive_timed_mutex *in_mutex) :
    kis_net_httpd_chain_stream_handler {},
    uri {in_uri},
    generator {in_func},
    mutex {in_mutex} {

    bind_httpd_server();
}

bool kis_net_httpd_simple_post_endpoint::httpd_verify_path(const char *path, const char *method) {
    /*
    if (strcmp(method, "POST") != 0)
        return false;
        */

    auto stripped = httpd_strip_suffix(path);

    if (stripped == uri && httpd_can_serialize(path)) {
        return true;
    }

    return false;
}

KIS_MHD_RETURN kis_net_httpd_simple_post_endpoint::httpd_create_stream_response(
        kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    // Do nothing, we only handle POST
    connection->response_stream << "Invalid request: POST expected\n";
    connection->httpcode = 400;
   
    return MHD_YES;
}

KIS_MHD_RETURN kis_net_httpd_simple_post_endpoint::httpd_post_complete(kis_net_httpd_connection *concls) {
    auto saux = (kis_net_httpd_buffer_stream_aux *) concls->custom_extension;
    auto streambuf = new buffer_handler_ostringstream_buf(saux->get_rbhandler());

    local_demand_locker l(mutex, fmt::format("simple_post_endpoint::post_complete {}", uri));
    std::lock_guard<std::mutex> lk(concls->connection_mutex);

    if (mutex != nullptr)
        l.lock();

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    try {
        auto json = concls->variable_cache_as<Json::Value>("json", "{}");

        auto r = generator(stream, concls->url, json, concls->variable_cache);
        concls->httpcode = r;

        return MHD_YES;
    } catch(const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        concls->httpcode = 400;
        return MHD_YES;
    }

    stream << "Unhandled request\n";
    concls->httpcode = 500;
    return MHD_YES;
}

kis_net_httpd_path_post_endpoint::kis_net_httpd_path_post_endpoint(
        kis_net_httpd_path_post_endpoint::path_func in_path,
        kis_net_httpd_path_post_endpoint::handler_func in_func) :
    kis_net_httpd_chain_stream_handler {},
    path {in_path},
    generator {in_func}, 
    mutex {nullptr} {
    bind_httpd_server();
}

kis_net_httpd_path_post_endpoint::kis_net_httpd_path_post_endpoint(
        kis_net_httpd_path_post_endpoint::path_func in_path,
        kis_net_httpd_path_post_endpoint::handler_func in_func, 
        kis_recursive_timed_mutex *in_mutex) :
    kis_net_httpd_chain_stream_handler {},
    path {in_path},
    generator {in_func},
    mutex {in_mutex} {

    bind_httpd_server();
}

bool kis_net_httpd_path_post_endpoint::httpd_verify_path(const char *in_path, const char *in_method) {
    /*
    if (strcmp(in_method, "POST") != 0)
        return false;
        */

    if (!httpd_can_serialize(in_path))
        return false;

    auto stripped = httpd_strip_suffix(in_path);
    auto tokenurl = str_tokenize(stripped, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (tokenurl.size())
        tokenurl = std::vector<std::string>(tokenurl.begin() + 1, tokenurl.end());

    local_demand_locker l(mutex);
    if (mutex != nullptr)
        l.lock();

    return path(tokenurl, in_path);
}

KIS_MHD_RETURN kis_net_httpd_path_post_endpoint::httpd_create_stream_response(
        kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection,
        const char *in_path, const char *in_method, const char *upload_data,
        size_t *upload_data_size) {

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    // Do nothing, we only handle POST
    connection->response_stream << "Invalid request: POST expected\n";
    connection->httpcode = 400;

    return MHD_YES;
}

KIS_MHD_RETURN kis_net_httpd_path_post_endpoint::httpd_post_complete(kis_net_httpd_connection *concls) {
    auto saux = (kis_net_httpd_buffer_stream_aux *) concls->custom_extension;
    auto streambuf = new buffer_handler_ostringstream_buf(saux->get_rbhandler());

    local_demand_locker l(mutex, fmt::format("path_post_endpoint::post_complete {}", concls->url));
    std::lock_guard<std::mutex> lk(concls->connection_mutex);

    if (mutex != nullptr)
        l.lock();

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    auto stripped = httpd_strip_suffix(concls->url);
    auto tokenurl = str_tokenize(stripped, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (tokenurl.size())
        tokenurl = std::vector<std::string>(tokenurl.begin() + 1, tokenurl.end());

    try {
        auto json = concls->variable_cache_as<Json::Value>("json", "{}");

        auto r = generator(stream, tokenurl, concls->url, json, concls->variable_cache);

        concls->httpcode = r;
        return MHD_YES;
    } catch(const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        concls->httpcode = 400;
        return MHD_YES;
    }

    return MHD_YES;
}

kis_net_httpd_path_combo_endpoint::kis_net_httpd_path_combo_endpoint(
        kis_net_httpd_path_combo_endpoint::path_func in_path,
        kis_net_httpd_path_combo_endpoint::handler_func in_func) :
    kis_net_httpd_chain_stream_handler {},
    path {in_path},
    generator {in_func}, 
    mutex {nullptr} {
    bind_httpd_server();
}

kis_net_httpd_path_combo_endpoint::kis_net_httpd_path_combo_endpoint(
        kis_net_httpd_path_combo_endpoint::path_func in_path,
        kis_net_httpd_path_combo_endpoint::handler_func in_func, 
        kis_recursive_timed_mutex *in_mutex) :
    kis_net_httpd_chain_stream_handler {},
    path {in_path},
    generator {in_func},
    mutex {in_mutex} {

    bind_httpd_server();
}

bool kis_net_httpd_path_combo_endpoint::httpd_verify_path(const char *in_path, const char *in_method) {
    if (strcmp(in_method, "POST") != 0 && strcmp(in_method, "GET") != 0)
        return false;

    if (!httpd_can_serialize(in_path))
        return false;

    auto stripped = httpd_strip_suffix(in_path);
    auto tokenurl = str_tokenize(stripped, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (tokenurl.size())
        tokenurl = std::vector<std::string>(tokenurl.begin() + 1, tokenurl.end());

    local_demand_locker l(mutex);
    if (mutex != nullptr)
        l.lock();

    return path(tokenurl, in_path);
}

KIS_MHD_RETURN kis_net_httpd_path_combo_endpoint::httpd_create_stream_response(
        kis_net_httpd *httpd __attribute__((unused)),
        kis_net_httpd_connection *connection,
        const char *in_path, const char *in_method, const char *upload_data,
        size_t *upload_data_size) {

    std::lock_guard<std::mutex> lk(connection->connection_mutex);

    // Do nothing, we only handle POST
    connection->response_stream << "Invalid request: POST expected\n";
    connection->httpcode = 400;

    return MHD_YES;
}

KIS_MHD_RETURN kis_net_httpd_path_combo_endpoint::httpd_post_complete(kis_net_httpd_connection *concls) {
    auto saux = (kis_net_httpd_buffer_stream_aux *) concls->custom_extension;
    auto streambuf = new buffer_handler_ostringstream_buf(saux->get_rbhandler());

    local_demand_locker l(mutex, fmt::format("path_combo_endpoint::post_complete {}", concls->url));
    std::lock_guard<std::mutex> lk(concls->connection_mutex);

    if (mutex != nullptr)
        l.lock();

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](kis_net_httpd_buffer_stream_aux *aux) {
                if (aux->aux != NULL)
                    delete((buffer_handler_ostringstream_buf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](kis_net_httpd_buffer_stream_aux *aux) {
            if (aux->aux != NULL) {
                ((buffer_handler_ostringstream_buf *) aux->aux)->pubsync();
                }
            });

    auto stripped = httpd_strip_suffix(concls->url);
    auto tokenurl = str_tokenize(stripped, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (tokenurl.size())
        tokenurl = std::vector<std::string>(tokenurl.begin() + 1, tokenurl.end());

    try {
        auto json = concls->variable_cache_as<Json::Value>("json", "{}");

        auto r = generator(stream, "POST", tokenurl, concls->url, json, concls->variable_cache);

        concls->httpcode = r;
        return MHD_YES;
    } catch(const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        concls->httpcode = 400;
        return MHD_YES;
    }

    return MHD_YES;
}

