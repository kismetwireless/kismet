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

#include "structured.h"
#include "kismet_json.h"

std::string kishttpd::GetSuffix(const std::string& url) {
    size_t lastdot = url.find_last_of(".");

    if (lastdot != std::string::npos)
        return url.substr(lastdot + 1, url.length() - lastdot);

    return "";
}

std::string kishttpd::StripSuffix(const std::string& url) {
    size_t lastdot = url.find_last_of(".");

    if (lastdot == std::string::npos)
        lastdot = url.length();

    return url.substr(0, lastdot);
}

std::string kishttpd::EscapeHtml(const std::string& in) {
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

std::shared_ptr<TrackerElement> kishttpd::SummarizeWithStructured(std::shared_ptr<TrackerElement> in_data,
        SharedStructured structured, std::shared_ptr<TrackerElementSerializer::rename_map> rename_map) {

    auto summary_vec = std::vector<SharedElementSummary>{};

    if (structured->hasKey("fields")) {
        auto fields = structured->getStructuredByKey("fields");
        auto fvec = fields->getStructuredArray();

        for (const auto& i : fvec) {
            if (i->isString()) {
                auto s = std::make_shared<TrackerElementSummary>(i->getString());
                summary_vec.push_back(s);
            } else if (i->isArray()) {
                auto mapvec = i->getStringVec();

                if (mapvec.size() != 2)
                    throw StructuredDataException("Invalid field mapping, expected "
                            "[field, rename]");

                auto s = std::make_shared<TrackerElementSummary>(mapvec[0], mapvec[1]);
                summary_vec.push_back(s);
            } else {
                throw StructuredDataException("Invalid field mapping, expected "
                        "field or [field,rename]");
            }
        }
    }

    return SummarizeTrackerElement(in_data, summary_vec, rename_map);
}

Kis_Net_Httpd::Kis_Net_Httpd() {
    running = false;

    use_ssl = false;
    cert_pem = NULL;
    cert_key = NULL;

    if (Globalreg::globalreg->kismet_config == NULL) {
        fprintf(stderr, "FATAL OOPS: Kis_Net_Httpd called without kismet_config\n");
        exit(1);
    }

    http_port = Globalreg::globalreg->kismet_config->FetchOptUInt("httpd_port", 2501);
    http_host = Globalreg::globalreg->kismet_config->FetchOptDfl("httpd_bind_address", "");

    if (http_host == "") {
        _MSG_INFO("Kismet will only listen to HTTP requests on {}:{}", http_port, http_host);
    }

    uri_prefix = Globalreg::globalreg->kismet_config->FetchOptDfl("httpd_uri_prefix", "");

    std::string http_data_dir, http_aux_data_dir;

    http_data_dir = Globalreg::globalreg->kismet_config->FetchOpt("httpd_home");
    http_aux_data_dir = Globalreg::globalreg->kismet_config->FetchOpt("httpd_user_home");

    if (http_data_dir == "") {
        _MSG("No httpd_home defined in kismet.conf, disabling static file serving. "
                "This will disable the web UI, but the REST interface will still "
                "function.", MSGFLAG_ERROR);
        http_serve_files = false;
    } else {
        http_data_dir = 
            Globalreg::globalreg->kismet_config->ExpandLogPath(http_data_dir, "", "", 0, 1);
        _MSG("Serving static content from '" + http_data_dir + "'",
                MSGFLAG_INFO);
        http_serve_files = true;

        // Add it as a possible file dir
        RegisterStaticDir("/", http_data_dir);
    }

    if (http_aux_data_dir == "") {
        _MSG("No httpd_user_home defined in kismet.conf, disabling static file serving "
                "from user directory", MSGFLAG_ERROR);
        http_serve_user_files = false;
    } else {
        http_aux_data_dir = 
            Globalreg::globalreg->kismet_config->ExpandLogPath(http_aux_data_dir, "", "", 0, 1);
        _MSG("Serving static userdir content from '" + http_aux_data_dir + "'",
                MSGFLAG_INFO);
        http_serve_user_files = true;
        
        // Add it as a second possible source of '/' files
        RegisterStaticDir("/", http_aux_data_dir);
    }

    if (http_serve_files == false && http_serve_user_files == false) {
        RegisterUnauthHandler(new Kis_Net_Httpd_No_Files_Handler());
    }

    session_timeout = 
        Globalreg::globalreg->kismet_config->FetchOptUInt("httpd_session_timeout", 7200);

    use_ssl = Globalreg::globalreg->kismet_config->FetchOptBoolean("httpd_ssl", false);
    pem_path = Globalreg::globalreg->kismet_config->FetchOpt("httpd_ssl_cert");
    key_path = Globalreg::globalreg->kismet_config->FetchOpt("httpd_ssl_key");

    RegisterMimeType("html", "text/html");
    RegisterMimeType("svg", "image/svg+xml");
    RegisterMimeType("css", "text/css");
    RegisterMimeType("jpeg", "image/jpeg");
    RegisterMimeType("gif", "image/gif");
    RegisterMimeType("ico", "image/x-icon");
    RegisterMimeType("json", "application/json");
    RegisterMimeType("ekjson", "application/json");
    RegisterMimeType("pcap", "application/vnd.tcpdump.pcap");

    std::vector<std::string> mimeopts = Globalreg::globalreg->kismet_config->FetchOptVec("httpd_mime");
    for (unsigned int i = 0; i < mimeopts.size(); i++) {
        std::vector<std::string> mime_comps = StrTokenize(mimeopts[i], ":");

        if (mime_comps.size() != 2) {
            _MSG("Expected httpd_mime=extension:type", MSGFLAG_ERROR);
            continue;
        }

        _MSG("Adding user-defined MIME type " + mime_comps[1] + " for " + mime_comps[0],
                MSGFLAG_INFO);
        RegisterMimeType(mime_comps[0], mime_comps[1]);
        
    }

    // Do we store sessions?
    store_sessions = false;
    session_db = NULL;

    sessiondb_file = Globalreg::globalreg->kismet_config->FetchOpt("httpd_session_db");

    if (sessiondb_file != "") {
        sessiondb_file = 
            Globalreg::globalreg->kismet_config->ExpandLogPath(sessiondb_file, "", "", 0, 1);

        session_db = new ConfigFile(Globalreg::globalreg);

        store_sessions = true;

        struct stat buf;
        if (stat(sessiondb_file.c_str(), &buf) == 0) {
            session_db->ParseConfig(sessiondb_file.c_str());

            std::vector<std::string> oldsessions = session_db->FetchOptVec("session");

            if (oldsessions.size() > 0) 
                _MSG("Loading saved HTTP sessions", MSGFLAG_INFO);

            for (unsigned int s = 0; s < oldsessions.size(); s++) {
                std::vector<std::string> sestok = StrTokenize(oldsessions[s], ",");

                if (sestok.size() != 4)
                    continue;

                std::shared_ptr<Kis_Net_Httpd_Session> sess(new Kis_Net_Httpd_Session());

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

                // Don't use AddSession because we don't want to trigger a write, yet
                session_map[sess->sessionid] = sess;
            }
        }
    }
}

Kis_Net_Httpd::~Kis_Net_Httpd() {
    // Wipe out all handlers
    handler_vec.erase(handler_vec.begin(), handler_vec.end());

    if (running)
        StopHttpd();

    if (session_db) {
        delete(session_db);
    }

#ifdef MHD_QUIESCE
    if (microhttpd != NULL)
        MHD_stop_daemon(microhttpd);
#endif

    session_map.clear();

    Globalreg::globalreg->RemoveGlobal("HTTPD_SERVER");
}

void Kis_Net_Httpd::RegisterSessionHandler(std::shared_ptr<Kis_Httpd_Websession> in_session) {
    local_locker l(&controller_mutex);
    websession = in_session;
}

char *Kis_Net_Httpd::read_ssl_file(std::string in_fname) {
    FILE *f;
    std::stringstream str;
    char *buf = NULL;
    long sz;

    // Read errors are considered fatal
    if ((f = fopen(in_fname.c_str(), "rb")) == NULL) {
        str << "Unable to open SSL file " << in_fname <<
            ": " << kis_strerror_r(errno);
        _MSG(str.str(), MSGFLAG_FATAL);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    rewind(f);

    if (sz <= 0) {
       str << "Unable to load SSL file " << in_fname << ": File is empty";
       _MSG(str.str(), MSGFLAG_FATAL);
       return NULL;
    }

    buf = new char[sz + 1];
    if (fread(buf, sz, 1, f) <= 0) {
        str << "Unable to read SSL file " << in_fname <<
            ": " << kis_strerror_r(errno);
        _MSG(str.str(), MSGFLAG_FATAL);
        return NULL;
    }
    fclose(f);

    // Null terminate the buffer
    buf[sz] = 0;

    return buf;
}

std::string Kis_Net_Httpd::GetSuffix(std::string url) {
    size_t lastdot = url.find_last_of(".");

    if (lastdot != std::string::npos)
        return url.substr(lastdot + 1, url.length() - lastdot);

    return "";
}

std::string Kis_Net_Httpd::StripSuffix(std::string url) {
    size_t lastdot = url.find_last_of(".");

    if (lastdot == std::string::npos)
        lastdot = url.length();

    return url.substr(0, lastdot);
}

void Kis_Net_Httpd::RegisterMimeType(std::string suffix, std::string mimetype) {
    local_locker lock(&controller_mutex);
    mime_type_map[StrLower(suffix)] = mimetype;
}

void Kis_Net_Httpd::RegisterAlias(const std::string& in_alias, const std::string& in_dest) {
    local_locker lock(&controller_mutex);
    alias_rewrite_map[in_alias] = in_dest;
}

void Kis_Net_Httpd::RemoveAlias(const std::string& in_alias) {
    local_locker lock(&controller_mutex);

    auto k = alias_rewrite_map.find(in_alias);
    if (k != alias_rewrite_map.end())
        alias_rewrite_map.erase(k);
}

void Kis_Net_Httpd::RegisterStaticDir(std::string in_prefix, std::string in_path) {
    local_locker lock(&controller_mutex);

    static_dir_vec.push_back(static_dir(in_prefix, in_path));
}

void Kis_Net_Httpd::RegisterHandler(Kis_Net_Httpd_Handler *in_handler) {
    local_locker lock(&controller_mutex);

    handler_vec.push_back(in_handler);
}

void Kis_Net_Httpd::RemoveHandler(Kis_Net_Httpd_Handler *in_handler) {
    local_locker lock(&controller_mutex);

    for (unsigned int x = 0; x < handler_vec.size(); x++) {
        if (handler_vec[x] == in_handler) {
            handler_vec.erase(handler_vec.begin() + x);
            break;
        }
    }
}

void Kis_Net_Httpd::RegisterUnauthHandler(Kis_Net_Httpd_Handler *in_handler) {
    local_locker lock(&controller_mutex);

    unauth_handler_vec.push_back(in_handler);
}

void Kis_Net_Httpd::RemoveUnauthHandler(Kis_Net_Httpd_Handler *in_handler) {
    local_locker lock(&controller_mutex);

    for (unsigned int x = 0; x < unauth_handler_vec.size(); x++) {
        if (unauth_handler_vec[x] == in_handler) {
            unauth_handler_vec.erase(unauth_handler_vec.begin() + x);
            break;
        }
    }
}

int Kis_Net_Httpd::StartHttpd() {
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
            Globalreg::globalreg->kismet_config->ExpandLogPath(pem_path, "", "", 0, 1);
        key_path =
            Globalreg::globalreg->kismet_config->ExpandLogPath(key_path, "", "", 0, 1);

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


    if (microhttpd == NULL) {
        _MSG("Failed to start http server on port " + UIntToString(http_port),
                MSGFLAG_FATAL);
        Globalreg::globalreg->fatal_condition = 1;
        return -1;
    }

    MHD_set_panic_func(Kis_Net_Httpd::MHD_Panic, this);

    running = true;

    if (http_host == "")
        _MSG_INFO("Started http server on port {}", http_port);
    else
        _MSG_INFO("Started http server on {}:{}", http_host, http_port);

    return 1;
}

int Kis_Net_Httpd::StopHttpd() {
    local_locker lock(&controller_mutex);

    handler_vec.clear();
    static_dir_vec.clear();

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
        return 1;
    }

    return 0;
}

void Kis_Net_Httpd::MHD_Panic(void *cls, const char *file __attribute__((unused)), 
            unsigned int line __attribute__((unused)), const char *reason) {
    Kis_Net_Httpd *httpd = (Kis_Net_Httpd *) cls;

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

bool Kis_Net_Httpd::HasValidSession(Kis_Net_Httpd_Connection *connection, bool send_invalid) {
    if (connection->session != NULL)
        return true;

    std::shared_ptr<Kis_Net_Httpd_Session> s;
    const char *cookieval;

    cookieval = MHD_lookup_connection_value(connection->connection,
            MHD_COOKIE_KIND, KIS_SESSION_COOKIE);

    if (cookieval != NULL) {
        local_shared_demand_locker csl(&session_mutex);

        auto si = session_map.find(cookieval);
        if (si != session_map.end()) {
            s = si->second;

            // Does the session never expire?
            if (s->session_lifetime == 0) {
                connection->session = s;
                return true;
            }

            // Is the session still valid?
            if (time(0) < s->session_created + s->session_lifetime) {
                connection->session = s;
                return true;
            } else {
                connection->session = NULL;
                csl.unlock();
                DelSession(si);
            }
        }
    }

    // If we got here, we either don't have a session, or the session isn't valid.
    if (websession != NULL && websession->validate_login(connection->connection)) {
        CreateSession(connection, NULL, session_timeout);
        return true;
    }

    // If we got here it's invalid.  Do we automatically send an invalidation 
    // response?
    if (send_invalid) {
        auto fourohone = fmt::format("<h1>401 - Access denied</h1>Login required to access this resource.\n");

        connection->response = 
            MHD_create_response_from_buffer(fourohone.length(),
                    (void *) fourohone.c_str(), MHD_RESPMEM_MUST_COPY);

        // Queue a 401 fail instead of a basic auth fail so we don't cause a bunch of prompting in the browser
        // Make sure this doesn't actually break anything...
        MHD_queue_response(connection->connection, 401, connection->response);

        // MHD_queue_basic_auth_fail_response(connection->connection, "Kismet", connection->response);
    }

    return false;
}

std::shared_ptr<Kis_Net_Httpd_Session> 
Kis_Net_Httpd::CreateSession(Kis_Net_Httpd_Connection *connection, 
        struct MHD_Response *response, time_t in_lifetime) {
    
    std::shared_ptr<Kis_Net_Httpd_Session> s;

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
        if (MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, 
                    cookiestr.str().c_str()) == MHD_NO) {
            _MSG("Failed to add session cookie to response header, unable to create "
                    "a session", MSGFLAG_ERROR);
            return NULL;
        }
    }

    s = std::make_shared<Kis_Net_Httpd_Session>();
    s->sessionid = cookie.str();
    s->session_created = time(0);
    s->session_seen = s->session_created;
    s->session_lifetime = in_lifetime;

    if (connection != NULL)
        connection->session = s;

    AddSession(s);

    return s;
}


void Kis_Net_Httpd::AddSession(std::shared_ptr<Kis_Net_Httpd_Session> in_session) {
    local_locker lock(&session_mutex);

    session_map[in_session->sessionid] = in_session;
    WriteSessions();
}

void Kis_Net_Httpd::DelSession(std::string in_key) {
    local_locker lock(&session_mutex);

    auto i = session_map.find(in_key);

    if (i != session_map.end()) {
        session_map.erase(i);
        WriteSessions();
    }

}

void Kis_Net_Httpd::DelSession(std::map<std::string, std::shared_ptr<Kis_Net_Httpd_Session> >::iterator in_itr) {
    local_locker lock(&session_mutex);

    if (in_itr != session_map.end()) {
        session_map.erase(in_itr);
        WriteSessions();
    }
}

void Kis_Net_Httpd::WriteSessions() {
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

    session_db->SetOptVec("session", sessions, true);

    // Ignore failures here I guess?
    session_db->SaveConfig(sessiondb_file.c_str());
}

int Kis_Net_Httpd::http_request_handler(void *cls, struct MHD_Connection *connection,
    const char *in_url, const char *method, const char *version __attribute__ ((unused)),
    const char *upload_data, size_t *upload_data_size, void **ptr) {

    //fprintf(stderr, "debug - HTTP request: '%s' method '%s'\n", url, method); 
    //
    Kis_Net_Httpd *kishttpd = (Kis_Net_Httpd *) cls;

    if (Globalreg::globalreg->spindown || Globalreg::globalreg->fatal_condition)
        return MHD_NO;
    
    // Update the session records if one exists
    std::shared_ptr<Kis_Net_Httpd_Session> s = NULL;
    const char *cookieval;
    int ret = MHD_NO;

    Kis_Net_Httpd_Connection *concls = NULL;
    bool new_concls = false;

    cookieval = MHD_lookup_connection_value(connection, MHD_COOKIE_KIND, KIS_SESSION_COOKIE);

    if (cookieval != NULL) {
        local_shared_demand_locker csl(&kishttpd->session_mutex);

        auto si = kishttpd->session_map.find(cookieval);

        if (si != kishttpd->session_map.end()) {
            // Delete if the session has expired and don't assign as a session
            if (si->second->session_lifetime != 0 &&
                    si->second->session_seen + si->second->session_lifetime < time(0)) {
                csl.unlock();
                kishttpd->DelSession(si);
            } else {
                // Update the last seen, assign as the current session
                s = si->second;
                s->session_seen = time(0);
                csl.unlock();
            }
        }
    } 
    
    Kis_Net_Httpd_Handler *handler = NULL;

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
        concls = new Kis_Net_Httpd_Connection();
        // fprintf(stderr, "debug - allocated new connection state %p\n", concls);

        *ptr = (void *) concls;

        concls->httpd = kishttpd;
        concls->httpdhandler = nullptr;
        concls->session = s;
        concls->httpcode = MHD_HTTP_OK;
        concls->url = std::string(url);
        concls->connection = connection;

        new_concls = true;
    } else {
        concls = (Kis_Net_Httpd_Connection *) *ptr;
    }

    {
        local_shared_locker conclock(&(kishttpd->controller_mutex));

        /* Look for a handler that can process this; first we look for handlers which
         * don't require auth */
        for (auto h : kishttpd->unauth_handler_vec) {
            if (h->Httpd_VerifyPath(url.c_str(), method)) {
                handler = h;
                break;
            }
        }

        /* If we didn't find a no-auth handler, move on to the auth handlers, and 
         * force them to have a valid login */
        if (handler == nullptr) {
            for (auto h : kishttpd->handler_vec) {
                if (h->Httpd_VerifyPath(url.c_str(), method)) {
                    if (!kishttpd->HasValidSession(concls, true)) {
                        /*
                        auto fourohone = fmt::format("<h1>401 - Access denied</h1>Login required to access this resource.\n");
                        fmt::print("no valid login for {}, {}\n", url, fourohone);

                        struct MHD_Response *response = 
                            MHD_create_response_from_buffer(fourohone.length(), 
                                    (void *) fourohone.c_str(), MHD_RESPMEM_MUST_COPY);

                        MHD_queue_response(connection, 401, response);
                        MHD_destroy_response(response);
                        */

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
            concls->connection_type = Kis_Net_Httpd_Connection::CONNECTION_POST;

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
            concls->connection_type = Kis_Net_Httpd_Connection::CONNECTION_GET;
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
                    kishttpd::EscapeHtml(url));

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
        return (concls->httpdhandler)->Httpd_HandlePostRequest(kishttpd, concls, url.c_str(),
                method, upload_data, upload_data_size);
    } else {
        // Handle GET + any others
        
        MHD_get_connection_values(connection, MHD_GET_ARGUMENT_KIND, 
                [](void *cls, enum MHD_ValueKind, const char *key, const char *value) -> int {
                    auto concls = static_cast<Kis_Net_Httpd_Connection *>(cls);

                    concls->variable_cache[key] = std::make_shared<std::stringstream>();

                    if (value != nullptr)
                        concls->variable_cache[key]->write(value, strlen(value));

                    return MHD_YES;
                }, concls);
       
        ret = (concls->httpdhandler)->Httpd_HandleGetRequest(kishttpd, concls, url.c_str(), method, 
                upload_data, upload_data_size);
    }

    return ret;
}

int Kis_Net_Httpd::http_post_handler(void *coninfo_cls, enum MHD_ValueKind kind, 
        const char *key, const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data, 
        uint64_t off, size_t size) {

    Kis_Net_Httpd_Connection *concls = (Kis_Net_Httpd_Connection *) coninfo_cls;

    if (concls->httpdhandler->Httpd_UseCustomPostIterator()) {
        return (concls->httpdhandler)->Httpd_PostIterator(coninfo_cls, kind,
                key, filename, content_type, transfer_encoding, data, off, size);
    } else {
        // Cache all the variables by name until we're complete
        if (concls->variable_cache.find(key) == concls->variable_cache.end())
            concls->variable_cache[key] = std::make_shared<std::stringstream>();

        concls->variable_cache[key]->write(data, size);

        return MHD_YES;
    }
}

void Kis_Net_Httpd::http_request_completed(void *cls __attribute__((unused)), 
        struct MHD_Connection *connection __attribute__((unused)),
        void **con_cls, 
        enum MHD_RequestTerminationCode toe __attribute__((unused))) {
    Kis_Net_Httpd_Connection *con_info = (Kis_Net_Httpd_Connection *) *con_cls;

    if (con_info == NULL)
        return;

    // Lock and shut it down
    {
        std::lock_guard<std::mutex> lk(con_info->connection_mutex);

        if (con_info->connection_type == Kis_Net_Httpd_Connection::CONNECTION_POST) {
            MHD_destroy_post_processor(con_info->postprocessor);
            con_info->postprocessor = NULL;
        }
    }

    // Destroy connection
    
    delete(con_info);
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

std::string Kis_Net_Httpd::GetMimeType(std::string ext) {
    std::map<std::string, std::string>::iterator mi = mime_type_map.find(ext);
    if (mi != mime_type_map.end()) {
        return mi->second;
    }

    return "";
}

int Kis_Net_Httpd::handle_static_file(void *cls, Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method) {
    Kis_Net_Httpd *kishttpd = (Kis_Net_Httpd *) cls;

    if (strcmp(method, "GET") != 0)
        return -1;

    std::string surl(url);

    // Append index.html to directory requests
    if (surl[surl.length() - 1] == '/')
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

            /*
            if (connection->session != NULL) {
                std::stringstream cookiestr;
                std::stringstream cookie;

                cookiestr << KIS_SESSION_COOKIE << "=";
                cookiestr << connection->session->sessionid;
                cookiestr << "; Path=/";

                MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, 
                        cookiestr.str().c_str());
            }
            */

            char lastmod[31];
            struct tm tmstruct;
            localtime_r(&(buf.st_ctime), &tmstruct);
            strftime(lastmod, 31, "%a, %d %b %Y %H:%M:%S %Z", &tmstruct);
            MHD_add_response_header(response, "Last-Modified", lastmod);

            std::string suffix = GetSuffix(surl);
            std::string mime = kishttpd->GetMimeType(suffix);

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

void Kis_Net_Httpd::AppendHttpSession(Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection) {

    if (connection->session != NULL) {
        std::stringstream cookiestr;
        std::stringstream cookie;

        cookiestr << KIS_SESSION_COOKIE << "=";
        cookiestr << connection->session->sessionid;
        cookiestr << "; Path=/";

        MHD_add_response_header(connection->response, MHD_HTTP_HEADER_SET_COOKIE, 
                cookiestr.str().c_str());
    }
}

void Kis_Net_Httpd::AppendStandardHeaders(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection, const char *url) {

    // Last-modified is always now
    char lastmod[31];
    struct tm tmstruct;
    time_t now;
    time(&now);
    gmtime_r(&now, &tmstruct);
    strftime(lastmod, 31, "%a, %d %b %Y %H:%M:%S %Z", &tmstruct);
    MHD_add_response_header(connection->response, "Last-Modified", lastmod);

    std::string suffix = GetSuffix(url);
    std::string mime = httpd->GetMimeType(suffix);

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

    // Allow any?  This lets us handle webuis hosted elsewhere
    MHD_add_response_header(connection->response, 
            "Access-Control-Allow-Origin", "*");

    // Never let the browser cache our responses.  Maybe moderate this
    // in the future to cache for 60 seconds or something?
    MHD_add_response_header(connection->response, "Cache-Control", "no-cache");
    MHD_add_response_header(connection->response, "Pragma", "no-cache");
    MHD_add_response_header(connection->response, 
            "Expires", "Sat, 01 Jan 2000 00:00:00 GMT");

}

int Kis_Net_Httpd::SendHttpResponse(Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection) {

    MHD_queue_response(connection->connection, connection->httpcode, 
            connection->response);

    MHD_destroy_response(connection->response);

    return MHD_YES;
}

int Kis_Net_Httpd::SendStandardHttpResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection, const char *url) {
    AppendHttpSession(httpd, connection);
    AppendStandardHeaders(httpd, connection, url);
    return SendHttpResponse(httpd, connection);
}

Kis_Net_Httpd_Simple_Tracked_Endpoint::Kis_Net_Httpd_Simple_Tracked_Endpoint(const std::string& in_uri,
        std::shared_ptr<TrackerElement> in_element, kis_recursive_timed_mutex *in_mutex) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    uri {in_uri},
    content {in_element},
    generator {nullptr},
    mutex {in_mutex} { 
        Bind_Httpd_Server();
    }

Kis_Net_Httpd_Simple_Tracked_Endpoint::Kis_Net_Httpd_Simple_Tracked_Endpoint(const std::string& in_uri,
        Kis_Net_Httpd_Simple_Tracked_Endpoint::gen_func in_func) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    uri {in_uri}, 
    content { nullptr },
    generator {in_func},
    mutex {nullptr} {

    Bind_Httpd_Server();
}

Kis_Net_Httpd_Simple_Tracked_Endpoint::Kis_Net_Httpd_Simple_Tracked_Endpoint(const std::string& in_uri,
        Kis_Net_Httpd_Simple_Tracked_Endpoint::gen_func in_func,
        kis_recursive_timed_mutex *in_mutex) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    uri {in_uri}, 
    content { nullptr },
    generator {in_func},
    mutex {in_mutex} {

    Bind_Httpd_Server();
}

bool Kis_Net_Httpd_Simple_Tracked_Endpoint::Httpd_VerifyPath(const char *path, const char *method) {
    auto stripped = Httpd_StripSuffix(path);

    if (stripped == uri && Httpd_CanSerialize(path))
        return true;

    return false;
}

int Kis_Net_Httpd_Simple_Tracked_Endpoint::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    local_demand_locker l(mutex);

    if (mutex != nullptr)
        l.lock();

    // Allocate our buffer aux
    Kis_Net_Httpd_Buffer_Stream_Aux *saux = 
        (Kis_Net_Httpd_Buffer_Stream_Aux *) connection->custom_extension;

    BufferHandlerOStringStreambuf *streambuf = 
        new BufferHandlerOStringStreambuf(saux->get_rbhandler());
    std::ostream stream(streambuf);

    // Set our cleanup function
    saux->set_aux(streambuf, 
            [](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                if (aux->aux != NULL)
                    delete((BufferHandlerOStringStreambuf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            if (aux->aux != NULL) {
                ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
                }
            });

    try {
        std::shared_ptr<TrackerElement> output_content;

        if (content == nullptr && generator == nullptr) {
            stream << "Invalid request: No backing content present";
            connection->httpcode = 400;
            return MHD_YES;
        }

        if (generator != nullptr)
            output_content = generator();
        else
            output_content = content;

        Globalreg::FetchMandatoryGlobalAs<EntryTracker>("ENTRYTRACKER")->Serialize(httpd->GetSuffix(connection->url), stream, output_content, nullptr);
    } catch (const std::exception& e) {
        stream << "Error: " << e.what() << "\n";
        connection->httpcode = 500;
        return MHD_YES;
    }

    return MHD_YES;
}

int Kis_Net_Httpd_Simple_Tracked_Endpoint::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    auto saux = (Kis_Net_Httpd_Buffer_Stream_Aux *) concls->custom_extension;
    auto streambuf = new BufferHandlerOStringStreambuf(saux->get_rbhandler());

    local_demand_locker l(mutex);

    if (mutex != nullptr)
        l.lock();

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                if (aux->aux != NULL)
                    delete((BufferHandlerOStringStreambuf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            if (aux->aux != NULL) {
                ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
                }
            });

    if (content == nullptr && generator == nullptr) {
        stream << "Invalid request: No backing content present";
        concls->httpcode = 400;
        return MHD_YES;
    }

    std::shared_ptr<TrackerElement> output_content;

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
    SharedStructured structdata;
    std::vector<SharedElementSummary> summary_vec;
    auto rename_map = std::make_shared<TrackerElementSerializer::rename_map>();

    try {
        if (concls->variable_cache.find("json") != 
                concls->variable_cache.end()) {
            structdata =
                std::make_shared<StructuredJson>(concls->variable_cache["json"]->str());
        } else {
            // fprintf(stderr, "debug - missing data\n");
            throw StructuredDataException("Missing data");
        }
    } catch(const StructuredDataException& e) {
        stream << "Invalid request: ";
        stream << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    try {
        if (structdata->hasKey("fields")) {
            SharedStructured fields = structdata->getStructuredByKey("fields");
            StructuredData::structured_vec fvec = fields->getStructuredArray();

            for (const auto& i : fvec) {
                if (i->isString()) {
                    auto s = std::make_shared<TrackerElementSummary>(i->getString());
                    summary_vec.push_back(s);
                } else if (i->isArray()) {
                    StructuredData::string_vec mapvec = i->getStringVec();

                    if (mapvec.size() != 2) {
                        // fprintf(stderr, "debug - malformed rename pair\n");
                        stream << "Invalid request: Expected field, rename";
                        concls->httpcode = 400;
                        return MHD_YES;
                    }

                    auto s = 
                        std::make_shared<TrackerElementSummary>(mapvec[0], mapvec[1]);
                    summary_vec.push_back(s);
                }
            }
        }
    } catch(const StructuredDataException& e) {
        stream << "Invalid request: ";
        stream << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    if (summary_vec.size()) {
        auto simple = 
            SummarizeTrackerElement(output_content, summary_vec, rename_map);

        Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(concls->url), stream, 
                simple, rename_map);
        return MHD_YES;
    }

    Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(concls->url), stream, 
            output_content, nullptr);
    return MHD_YES;
}

Kis_Net_Httpd_Simple_Unauth_Tracked_Endpoint::Kis_Net_Httpd_Simple_Unauth_Tracked_Endpoint(const std::string& in_uri,
        std::shared_ptr<TrackerElement> in_element, kis_recursive_timed_mutex *in_mutex) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    uri {in_uri},
    content {in_element},
    generator {nullptr},
    mutex {in_mutex} { 
    httpd->RegisterUnauthHandler(this);
}

Kis_Net_Httpd_Simple_Unauth_Tracked_Endpoint::Kis_Net_Httpd_Simple_Unauth_Tracked_Endpoint(const std::string& in_uri,
        Kis_Net_Httpd_Simple_Tracked_Endpoint::gen_func in_func) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    uri {in_uri}, 
    content { nullptr },
    generator {in_func},
    mutex {nullptr} {
    httpd->RegisterUnauthHandler(this);
}

Kis_Net_Httpd_Simple_Unauth_Tracked_Endpoint::Kis_Net_Httpd_Simple_Unauth_Tracked_Endpoint(const std::string& in_uri,
        Kis_Net_Httpd_Simple_Tracked_Endpoint::gen_func in_func,
        kis_recursive_timed_mutex *in_mutex) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    uri {in_uri}, 
    content { nullptr },
    generator {in_func},
    mutex {in_mutex} {
    httpd->RegisterUnauthHandler(this);
}

bool Kis_Net_Httpd_Simple_Unauth_Tracked_Endpoint::Httpd_VerifyPath(const char *path, const char *method) {
    auto stripped = Httpd_StripSuffix(path);

    if (stripped == uri && Httpd_CanSerialize(path))
        return true;

    return false;
}

int Kis_Net_Httpd_Simple_Unauth_Tracked_Endpoint::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    local_demand_locker l(mutex);

    if (mutex != nullptr)
        l.lock();

    // Allocate our buffer aux
    Kis_Net_Httpd_Buffer_Stream_Aux *saux = 
        (Kis_Net_Httpd_Buffer_Stream_Aux *) connection->custom_extension;

    BufferHandlerOStringStreambuf *streambuf = 
        new BufferHandlerOStringStreambuf(saux->get_rbhandler());
    std::ostream stream(streambuf);

    // Set our cleanup function
    saux->set_aux(streambuf, 
            [](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                if (aux->aux != NULL)
                    delete((BufferHandlerOStringStreambuf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            if (aux->aux != NULL) {
                ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
                }
            });

    try {
        std::shared_ptr<TrackerElement> output_content;

        if (content == nullptr && generator == nullptr) {
            stream << "Invalid request: No backing content present";
            connection->httpcode = 400;
            return MHD_YES;
        }

        if (generator != nullptr)
            output_content = generator();
        else
            output_content = content;

        Globalreg::FetchMandatoryGlobalAs<EntryTracker>("ENTRYTRACKER")->Serialize(httpd->GetSuffix(connection->url), stream, output_content, nullptr);
    } catch (const std::exception& e) {
        stream << "Error: " << e.what() << "\n";
        connection->httpcode = 500;
        return MHD_YES;
    }

    return MHD_YES;
}

int Kis_Net_Httpd_Simple_Unauth_Tracked_Endpoint::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    auto saux = (Kis_Net_Httpd_Buffer_Stream_Aux *) concls->custom_extension;
    auto streambuf = new BufferHandlerOStringStreambuf(saux->get_rbhandler());

    local_demand_locker l(mutex);

    if (mutex != nullptr)
        l.lock();

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                if (aux->aux != NULL)
                    delete((BufferHandlerOStringStreambuf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            if (aux->aux != NULL) {
                ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
                }
            });

    if (content == nullptr && generator == nullptr) {
        stream << "Invalid request: No backing content present";
        concls->httpcode = 400;
        return MHD_YES;
    }

    std::shared_ptr<TrackerElement> output_content;

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
    SharedStructured structdata;
    std::vector<SharedElementSummary> summary_vec;
    auto rename_map = std::make_shared<TrackerElementSerializer::rename_map>();

    try {
        if (concls->variable_cache.find("json") != 
                concls->variable_cache.end()) {
            structdata =
                std::make_shared<StructuredJson>(concls->variable_cache["json"]->str());
        } else {
            // fprintf(stderr, "debug - missing data\n");
            throw StructuredDataException("Missing data");
        }
    } catch(const StructuredDataException& e) {
        stream << "Invalid request: ";
        stream << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    try {
        if (structdata->hasKey("fields")) {
            SharedStructured fields = structdata->getStructuredByKey("fields");
            StructuredData::structured_vec fvec = fields->getStructuredArray();

            for (const auto& i : fvec) {
                if (i->isString()) {
                    auto s = std::make_shared<TrackerElementSummary>(i->getString());
                    summary_vec.push_back(s);
                } else if (i->isArray()) {
                    StructuredData::string_vec mapvec = i->getStringVec();

                    if (mapvec.size() != 2) {
                        // fprintf(stderr, "debug - malformed rename pair\n");
                        stream << "Invalid request: Expected field, rename";
                        concls->httpcode = 400;
                        return MHD_YES;
                    }

                    auto s = 
                        std::make_shared<TrackerElementSummary>(mapvec[0], mapvec[1]);
                    summary_vec.push_back(s);
                }
            }
        }
    } catch(const StructuredDataException& e) {
        stream << "Invalid request: ";
        stream << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    if (summary_vec.size()) {
        auto simple = 
            SummarizeTrackerElement(output_content, summary_vec, rename_map);

        Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(concls->url), stream, 
                simple, rename_map);
        return MHD_YES;
    }

    Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(concls->url), stream, 
            output_content, nullptr);
    return MHD_YES;
}

Kis_Net_Httpd_Path_Tracked_Endpoint::Kis_Net_Httpd_Path_Tracked_Endpoint(
        Kis_Net_Httpd_Path_Tracked_Endpoint::path_func in_path,
        Kis_Net_Httpd_Path_Tracked_Endpoint::gen_func in_gen) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    path { in_path },
    generator {in_gen},
    mutex {nullptr} { 
        Bind_Httpd_Server();
}

Kis_Net_Httpd_Path_Tracked_Endpoint::Kis_Net_Httpd_Path_Tracked_Endpoint(
        Kis_Net_Httpd_Path_Tracked_Endpoint::path_func in_path,
        Kis_Net_Httpd_Path_Tracked_Endpoint::gen_func in_gen,
        kis_recursive_timed_mutex *in_mutex) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    path { in_path },
    generator {in_gen},
    mutex {in_mutex} { 
        Bind_Httpd_Server();
}


bool Kis_Net_Httpd_Path_Tracked_Endpoint::Httpd_VerifyPath(const char *in_path, const char *in_method) {
    if (!Httpd_CanSerialize(in_path))
        return false;

    auto stripped = Httpd_StripSuffix(in_path);
    auto tokenurl = StrTokenize(stripped, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (tokenurl.size())
        tokenurl = std::vector<std::string>(tokenurl.begin() + 1, tokenurl.end());

    local_demand_locker l(mutex);
    if (mutex != nullptr)
        l.lock();

    return path(tokenurl);
}

int Kis_Net_Httpd_Path_Tracked_Endpoint::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection,
        const char *in_path, const char *in_method, const char *upload_data,
        size_t *upload_data_size) {

    local_demand_locker l(mutex);

    if (mutex != nullptr)
        l.lock();

    // Allocate our buffer aux
    Kis_Net_Httpd_Buffer_Stream_Aux *saux = 
        (Kis_Net_Httpd_Buffer_Stream_Aux *) connection->custom_extension;

    BufferHandlerOStringStreambuf *streambuf = 
        new BufferHandlerOStringStreambuf(saux->get_rbhandler());
    std::ostream stream(streambuf);

    // Set our cleanup function
    saux->set_aux(streambuf, 
            [](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                if (aux->aux != NULL)
                    delete((BufferHandlerOStringStreambuf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            if (aux->aux != NULL) {
                ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
                }
            });

    std::shared_ptr<TrackerElement> output_content;

    auto stripped = Httpd_StripSuffix(in_path);
    auto tokenurl = StrTokenize(stripped, "/");

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

    Globalreg::FetchMandatoryGlobalAs<EntryTracker>("ENTRYTRACKER")->Serialize(httpd->GetSuffix(connection->url), stream, output_content, nullptr);

    return MHD_YES;
}

int Kis_Net_Httpd_Path_Tracked_Endpoint::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    auto saux = (Kis_Net_Httpd_Buffer_Stream_Aux *) concls->custom_extension;
    auto streambuf = new BufferHandlerOStringStreambuf(saux->get_rbhandler());

    local_demand_locker l(mutex);

    if (mutex != nullptr)
        l.lock();

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                if (aux->aux != NULL)
                    delete((BufferHandlerOStringStreambuf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            if (aux->aux != NULL) {
                ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
                }
            });

    auto stripped = Httpd_StripSuffix(concls->url);
    auto tokenurl = StrTokenize(stripped, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (tokenurl.size())
        tokenurl = std::vector<std::string>(tokenurl.begin() + 1, tokenurl.end());

    std::shared_ptr<TrackerElement> output_content;

    try {
        output_content = generator(tokenurl);
    } catch (const std::exception& e) {
        stream << "Invalid request / error processing request: " << e.what() << "\n";
        concls->httpcode = 500;
        return MHD_YES;
    }

    // Common structured API data
    SharedStructured structdata;
    std::vector<SharedElementSummary> summary_vec;
    auto rename_map = std::make_shared<TrackerElementSerializer::rename_map>();

    try {
        if (concls->variable_cache.find("json") != concls->variable_cache.end()) {
            structdata =
                std::make_shared<StructuredJson>(concls->variable_cache["json"]->str());
        } else {
            structdata =
                std::make_shared<StructuredJson>(std::string{"{}"});
        }
    } catch(const StructuredDataException& e) {
        stream << "Invalid request: " << e.what() << "\n";
        concls->httpcode = 400;
        return MHD_YES;
    }

    try {
        if (structdata->hasKey("fields")) {
            SharedStructured fields = structdata->getStructuredByKey("fields");
            StructuredData::structured_vec fvec = fields->getStructuredArray();

            for (const auto& i : fvec) {
                if (i->isString()) {
                    auto s = std::make_shared<TrackerElementSummary>(i->getString());
                    summary_vec.push_back(s);
                } else if (i->isArray()) {
                    StructuredData::string_vec mapvec = i->getStringVec();

                    if (mapvec.size() != 2) {
                        // fprintf(stderr, "debug - malformed rename pair\n");
                        stream << "Invalid request: Expected field, rename";
                        concls->httpcode = 400;
                        return MHD_YES;
                    }

                    auto s = 
                        std::make_shared<TrackerElementSummary>(mapvec[0], mapvec[1]);
                    summary_vec.push_back(s);
                }
            }
        }
    } catch(const StructuredDataException& e) {
        stream << "Invalid request: ";
        stream << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    if (summary_vec.size()) {
        auto simple = 
            SummarizeTrackerElement(output_content, summary_vec, rename_map);

        Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(concls->url), stream, 
                simple, rename_map);
        return MHD_YES;
    }

    Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(concls->url), stream, 
            output_content, nullptr);
    return MHD_YES;
}

Kis_Net_Httpd_Simple_Post_Endpoint::Kis_Net_Httpd_Simple_Post_Endpoint(const std::string& in_uri,
        Kis_Net_Httpd_Simple_Post_Endpoint::handler_func in_func) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    uri {in_uri},
    generator {in_func}, 
    mutex {nullptr} {

    Bind_Httpd_Server();
}

Kis_Net_Httpd_Simple_Post_Endpoint::Kis_Net_Httpd_Simple_Post_Endpoint(const std::string& in_uri,
        Kis_Net_Httpd_Simple_Post_Endpoint::handler_func in_func, 
        kis_recursive_timed_mutex *in_mutex) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    uri {in_uri},
    generator {in_func},
    mutex {in_mutex} {

    Bind_Httpd_Server();
}

bool Kis_Net_Httpd_Simple_Post_Endpoint::Httpd_VerifyPath(const char *path, const char *method) {
    if (strcmp(method, "POST") != 0)
        return false;

    auto stripped = Httpd_StripSuffix(path);

    if (stripped == uri && Httpd_CanSerialize(path)) {
        return true;
    }

    return false;
}

int Kis_Net_Httpd_Simple_Post_Endpoint::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection,
        const char *path, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    // Do nothing, we only handle POST
    connection->response_stream << "Invalid request: POST expected\n";
    connection->httpcode = 400;
   
    return MHD_YES;
}

int Kis_Net_Httpd_Simple_Post_Endpoint::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    auto saux = (Kis_Net_Httpd_Buffer_Stream_Aux *) concls->custom_extension;
    auto streambuf = new BufferHandlerOStringStreambuf(saux->get_rbhandler());

    local_demand_locker l(mutex);

    if (mutex != nullptr)
        l.lock();

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                if (aux->aux != NULL)
                    delete((BufferHandlerOStringStreambuf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            if (aux->aux != NULL) {
                ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
                }
            });

    try {
        SharedStructured structdata;

        if (concls->variable_cache.find("json") != concls->variable_cache.end()) {
            structdata =
                std::make_shared<StructuredJson>(concls->variable_cache["json"]->str());
        } else {
            structdata =
                std::make_shared<StructuredJson>(std::string{"{}"});
        }

        auto r = generator(stream, concls->url, structdata, concls->variable_cache);
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

Kis_Net_Httpd_Path_Post_Endpoint::Kis_Net_Httpd_Path_Post_Endpoint(
        Kis_Net_Httpd_Path_Post_Endpoint::path_func in_path,
        Kis_Net_Httpd_Path_Post_Endpoint::handler_func in_func) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    path {in_path},
    generator {in_func}, 
    mutex {nullptr} {
    Bind_Httpd_Server();
}

Kis_Net_Httpd_Path_Post_Endpoint::Kis_Net_Httpd_Path_Post_Endpoint(
        Kis_Net_Httpd_Path_Post_Endpoint::path_func in_path,
        Kis_Net_Httpd_Path_Post_Endpoint::handler_func in_func, 
        kis_recursive_timed_mutex *in_mutex) :
    Kis_Net_Httpd_Chain_Stream_Handler {},
    path {in_path},
    generator {in_func},
    mutex {in_mutex} {

    Bind_Httpd_Server();
}

bool Kis_Net_Httpd_Path_Post_Endpoint::Httpd_VerifyPath(const char *in_path, const char *in_method) {
    if (strcmp(in_method, "POST") != 0)
        return false;

    if (!Httpd_CanSerialize(in_path))
        return false;

    auto stripped = Httpd_StripSuffix(in_path);
    auto tokenurl = StrTokenize(stripped, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (tokenurl.size())
        tokenurl = std::vector<std::string>(tokenurl.begin() + 1, tokenurl.end());

    local_demand_locker l(mutex);
    if (mutex != nullptr)
        l.lock();

    return path(tokenurl, in_path);
}

int Kis_Net_Httpd_Path_Post_Endpoint::Httpd_CreateStreamResponse(
        Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection,
        const char *in_path, const char *in_method, const char *upload_data,
        size_t *upload_data_size) {

    // Do nothing, we only handle POST
    return MHD_YES;
}

int Kis_Net_Httpd_Path_Post_Endpoint::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    auto saux = (Kis_Net_Httpd_Buffer_Stream_Aux *) concls->custom_extension;
    auto streambuf = new BufferHandlerOStringStreambuf(saux->get_rbhandler());

    local_demand_locker l(mutex);

    if (mutex != nullptr)
        l.lock();

    std::ostream stream(streambuf);

    saux->set_aux(streambuf, 
            [](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
                if (aux->aux != NULL)
                    delete((BufferHandlerOStringStreambuf *) (aux->aux));
            });

    // Set our sync function which is called by the webserver side before we
    // clean up...
    saux->set_sync([](Kis_Net_Httpd_Buffer_Stream_Aux *aux) {
            if (aux->aux != NULL) {
                ((BufferHandlerOStringStreambuf *) aux->aux)->pubsync();
                }
            });

    auto stripped = Httpd_StripSuffix(concls->url);
    auto tokenurl = StrTokenize(stripped, "/");

    // Tokenized paths begin with / which yields a blank [0] element, so trim that
    if (tokenurl.size())
        tokenurl = std::vector<std::string>(tokenurl.begin() + 1, tokenurl.end());

    try {
        SharedStructured structdata;

        if (concls->variable_cache.find("json") != concls->variable_cache.end()) {
            structdata =
                std::make_shared<StructuredJson>(concls->variable_cache["json"]->str());
        } else {
            structdata = 
                std::make_shared<StructuredJson>(std::string{"{}"});
        }

        auto r = generator(stream, tokenurl, concls->url, structdata, concls->variable_cache);

        concls->httpcode = r;
        return MHD_YES;
    } catch(const std::exception& e) {
        stream << "Invalid request: " << e.what() << "\n";
        concls->httpcode = 400;
        return MHD_YES;
    }

    return MHD_YES;
}

