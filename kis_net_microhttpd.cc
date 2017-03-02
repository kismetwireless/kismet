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
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <microhttpd.h>
#include <msgpack.hpp>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "globalregistry.h"
#include "messagebus.h"
#include "configfile.h"
#include "kis_net_microhttpd.h"
#include "base64.h"
#include "entrytracker.h"

Kis_Net_Httpd::Kis_Net_Httpd(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    running = false;

    use_ssl = false;
    cert_pem = NULL;
    cert_key = NULL;

    pthread_mutex_init(&controller_mutex, NULL);

    if (globalreg->kismet_config == NULL) {
        fprintf(stderr, "FATAL OOPS: Kis_Net_Httpd called without kismet_config\n");
        exit(1);
    }

    http_port = globalreg->kismet_config->FetchOptUInt("httpd_port", 2501);

    http_data_dir = globalreg->kismet_config->FetchOpt("httpd_home");
    http_aux_data_dir = globalreg->kismet_config->FetchOpt("httpd_user_home");

    if (http_data_dir == "") {
        _MSG("No httpd_home defined in kismet.conf, disabling static file serving. "
                "This will disable the web UI, but the REST interface will still "
                "function.", MSGFLAG_ERROR);
        http_serve_files = false;
    } else {
        http_data_dir = 
            globalreg->kismet_config->ExpandLogPath(http_data_dir, "", "", 0, 1);
        _MSG("Serving static content from '" + http_data_dir + "'",
                MSGFLAG_INFO);
        http_serve_files = true;
    }

    if (http_aux_data_dir == "") {
        _MSG("No httpd_user_home defined in kismet.conf, disabling static file serving "
                "from user directory", MSGFLAG_ERROR);
        http_serve_user_files = false;
    } else {
        http_aux_data_dir = 
            globalreg->kismet_config->ExpandLogPath(http_aux_data_dir, "", "", 0, 1);
        _MSG("Serving static userdir content from '" + http_aux_data_dir + "'",
                MSGFLAG_INFO);
        http_serve_user_files = true;
    }

    if (http_serve_files == false && http_serve_user_files == false) {
        RegisterHandler(new Kis_Net_Httpd_No_Files_Handler());
    }

    use_ssl = globalreg->kismet_config->FetchOptBoolean("httpd_ssl", false);
    pem_path = globalreg->kismet_config->FetchOpt("httpd_ssl_cert");
    key_path = globalreg->kismet_config->FetchOpt("httpd_ssl_key");

    RegisterMimeType("html", "text/html");
    RegisterMimeType("svg", "image/svg+xml");
    RegisterMimeType("css", "text/css");
    RegisterMimeType("jpeg", "image/jpeg");
    RegisterMimeType("gif", "image/gif");
    RegisterMimeType("ico", "image/x-icon");
    RegisterMimeType("json", "application/json");
    RegisterMimeType("pcap", "application/vnd.tcpdump.pcap");

    vector<string> mimeopts = globalreg->kismet_config->FetchOptVec("httpd_mime");
    for (unsigned int i = 0; i < mimeopts.size(); i++) {
        vector<string> mime_comps = StrTokenize(mimeopts[i], ":");

        if (mime_comps.size() != 2) {
            _MSG("Expected httpd_mime=extension:type", MSGFLAG_ERROR);
            continue;
        }

        _MSG("Adding user-defined MIME type " + mime_comps[1] + " for " + mime_comps[0],
                MSGFLAG_INFO);
        RegisterMimeType(mime_comps[0], mime_comps[1]);
        
    }

    // Fetch configured usernames
    string userpair = globalreg->kismet_config->FetchOpt("httpd_user");
    vector<string> up = StrTokenize(userpair, ":");

    if (up.size() != 2) {
        _MSG("Expected user:password in httpd_user config variable.  Without a "
                "valid user, it is not possible to configure Kismet via the web.",
                MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
    }

    conf_username = up[0];
    conf_password = up[1];

    // Do we store sessions?
    store_sessions = false;
    session_db = NULL;

    sessiondb_file = globalreg->kismet_config->FetchOpt("httpd_session_db");

    if (sessiondb_file != "") {
        sessiondb_file = 
            globalreg->kismet_config->ExpandLogPath(sessiondb_file, "", "", 0, 1);

        session_db = new ConfigFile(globalreg);

        store_sessions = true;

        struct stat buf;
        if (stat(sessiondb_file.c_str(), &buf) == 0) {
            session_db->ParseConfig(sessiondb_file.c_str());

            vector<string> oldsessions = session_db->FetchOptVec("session");

            if (oldsessions.size() > 0) 
                _MSG("Loading saved HTTP sessions", MSGFLAG_INFO);

            for (unsigned int s = 0; s < oldsessions.size(); s++) {
                vector<string> sestok = StrTokenize(oldsessions[s], ",");

                if (sestok.size() != 4)
                    continue;

                Kis_Net_Httpd_Session *sess = new Kis_Net_Httpd_Session();

                sess->sessionid = sestok[0];

                if (sscanf(sestok[1].c_str(), "%lu", &(sess->session_created)) != 1) {
                    delete sess;
                    continue;
                }

                if (sscanf(sestok[2].c_str(), "%lu", &(sess->session_seen)) != 1) {
                    delete sess;
                    continue;
                }

                if (sscanf(sestok[3].c_str(), "%lu", &(sess->session_lifetime)) != 1) {
                    delete sess;
                    continue;
                }

                session_map[sess->sessionid] = sess;

            }
        }
    }
}

Kis_Net_Httpd::~Kis_Net_Httpd() {
    pthread_mutex_lock(&controller_mutex);

    globalreg->RemoveGlobal("HTTPD_SERVER");
    globalreg->httpd_server = NULL;

    // Wipe out all handlers
    handler_vec.erase(handler_vec.begin(), handler_vec.end());

    if (running)
        StopHttpd();

    if (session_db) {
        delete(session_db);
    }

    for (map<string, Kis_Net_Httpd_Session *>::iterator i = session_map.begin();
            i != session_map.end(); ++i) {
        delete(i->second);
    }

    pthread_mutex_destroy(&controller_mutex);
}

char *Kis_Net_Httpd::read_ssl_file(string in_fname) {
    FILE *f;
    stringstream str;
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

string Kis_Net_Httpd::GetSuffix(string url) {
    size_t lastdot = url.find_last_of(".");

    if (lastdot != string::npos)
        return url.substr(lastdot + 1, url.length() - lastdot);

    return "";
}

string Kis_Net_Httpd::StripSuffix(string url) {
    size_t lastdot = url.find_last_of(".");

    if (lastdot == std::string::npos)
        lastdot = url.length();

    return url.substr(0, lastdot);
}

void Kis_Net_Httpd::RegisterMimeType(string suffix, string mimetype) {
    mime_type_map[StrLower(suffix)] = mimetype;
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

int Kis_Net_Httpd::StartHttpd() {
    if (use_ssl) {
        // If we can't load the SSL key files, crash and burn.  We can't safely
        // degrade to non-ssl when the user is expecting encryption.
        if (pem_path == "") {
            _MSG("SSL requested but missing httpd_ssl_cert= configuration option.",
                    MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

        if (key_path == "") {
            _MSG("SSL requested but missing httpd_ssl_key= configuration option.",
                    MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }

        pem_path =
            globalreg->kismet_config->ExpandLogPath(pem_path, "", "", 0, 1);
        key_path =
            globalreg->kismet_config->ExpandLogPath(key_path, "", "", 0, 1);

        cert_pem = read_ssl_file(pem_path);
        cert_key = read_ssl_file(key_path);

        if (cert_pem == NULL || cert_key == NULL) {
            _MSG("SSL requested but unable to load cert and key files, check your "
                    "configuration!", MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return -1;
        }
    }


    if (!use_ssl) {
        microhttpd = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,
                http_port, NULL, NULL, 
                &http_request_handler, this, 
                MHD_OPTION_NOTIFY_COMPLETED, &http_request_completed, NULL,
                MHD_OPTION_END); 
    } else {
        microhttpd = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION | MHD_USE_SSL,
                http_port, NULL, NULL, &http_request_handler, this, 
                MHD_OPTION_HTTPS_MEM_KEY, cert_key,
                MHD_OPTION_HTTPS_MEM_CERT, cert_pem,
                MHD_OPTION_END); 
    }


    if (microhttpd == NULL) {
        _MSG("Failed to start http server on port " + UIntToString(http_port),
                MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }

    MHD_set_panic_func(Kis_Net_Httpd::MHD_Panic, this);

    _MSG("Started http server on port " + UIntToString(http_port), MSGFLAG_INFO);

    return 1;
}

int Kis_Net_Httpd::StopHttpd() {
    if (microhttpd != NULL) {
        // We would want to stop but that seems to have some problems with
        // thread joining; for now, quiesce it, and we'll kill it when the
        // process exits, because we never shut down httpd and keep running
        MHD_quiesce_daemon(microhttpd);

        // MHD_stop_daemon(microhttpd);
        return 1;
    }

    return 0;
}

void Kis_Net_Httpd::MHD_Panic(void *cls, const char *file, unsigned int line,
        const char *reason) {
    Kis_Net_Httpd *httpd = (Kis_Net_Httpd *) cls;

    httpd->globalreg->fatal_condition = 1;
    httpd->globalreg->messagebus->InjectMessage("Unable to continue after "
            "MicroHTTPD fatal error: " + string(reason), MSGFLAG_FATAL);

    // Null out the microhttpd since it can't keep operating and can't be
    // trusted to close down properly
    httpd->microhttpd = NULL;
}

void Kis_Net_Httpd::AddSession(Kis_Net_Httpd_Session *in_session) {
    session_map[in_session->sessionid] = in_session;
    WriteSessions();
}

void Kis_Net_Httpd::DelSession(string in_key) {
    map<string, Kis_Net_Httpd_Session *>::iterator i = session_map.find(in_key);

    DelSession(i);
}

void Kis_Net_Httpd::DelSession(map<string, Kis_Net_Httpd_Session *>::iterator in_itr) {
    if (in_itr != session_map.end()) {
        delete in_itr->second;
        session_map.erase(in_itr);
        WriteSessions();
    }
}

void Kis_Net_Httpd::WriteSessions() {
    if (!store_sessions)
        return;

    vector<string> sessions;
    stringstream str;

    for (map<string, Kis_Net_Httpd_Session *>::iterator i = session_map.begin();
            i != session_map.end(); ++i) {
        str.str("");

        str << i->second->sessionid << "," << i->second->session_created << "," <<
            i->second->session_seen << "," << i->second->session_lifetime;

        sessions.push_back(str.str());
    }

    session_db->SetOptVec("session", sessions, true);

    // Ignore failures here I guess?
    session_db->SaveConfig(sessiondb_file.c_str());

}

int Kis_Net_Httpd::http_request_handler(void *cls, struct MHD_Connection *connection,
    const char *url, const char *method, const char *version __attribute__ ((unused)),
    const char *upload_data, size_t *upload_data_size, void **ptr) {

    //fprintf(stderr, "debug - HTTP request: '%s' method '%s'\n", url, method); 
    //
    Kis_Net_Httpd *kishttpd = (Kis_Net_Httpd *) cls;
    
    // Update the session records if one exists
    Kis_Net_Httpd_Session *s = NULL;
    const char *cookieval;
    int ret = MHD_NO;

    Kis_Net_Httpd_Connection *concls = NULL;

    cookieval = MHD_lookup_connection_value(connection, 
            MHD_COOKIE_KIND, KIS_SESSION_COOKIE);

    if (cookieval != NULL) {
        map<string, Kis_Net_Httpd_Session *>::iterator si = 
            kishttpd->session_map.find(cookieval);

        if (si != kishttpd->session_map.end()) {
            s = si->second;

            if (s->session_lifetime != 0) {
                // Delete if the session has expired
                if (s->session_seen + s->session_lifetime < 
                        kishttpd->globalreg->timestamp.tv_sec) {
                    kishttpd->DelSession(si);
                }
            }

            // Update the last seen
            s->session_seen = kishttpd->globalreg->timestamp.tv_sec;
        }
    } 
    
    Kis_Net_Httpd_Handler *handler = NULL;

    {
        local_locker(&(kishttpd->controller_mutex));
        /* Find a handler that can handle this path & method */
        for (unsigned int i = 0; i < kishttpd->handler_vec.size(); i++) {
            Kis_Net_Httpd_Handler *h = kishttpd->handler_vec[i];

            if (h->Httpd_VerifyPath(url, method)) {
                handler = h;
                break;
            }
        }
    }

    // If we don't have a connection state, make one
    if (*ptr == NULL) {
        concls = new Kis_Net_Httpd_Connection();
        // fprintf(stderr, "debug - allocated new connection state %p\n", concls);

        *ptr = (void *) concls;

        concls->httpd = kishttpd;
        concls->httpdhandler = handler;
        concls->session = s;
        concls->httpcode = MHD_HTTP_OK;
        concls->url = string(url);
        concls->connection = connection;

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
    } else {
        concls = (Kis_Net_Httpd_Connection *) *ptr;
    }

    if (handler == NULL) {
        // Try to check a static url
        if (handle_static_file(cls, concls, url, method) < 0) {
            // fprintf(stderr, "   404 no handler for request\n");

            string fourohfour = "404";

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

        // Notify the processor it's complete
        (concls->httpdhandler)->Httpd_PostComplete(concls);

        // Send the content
        // fprintf(stderr, "debug - sending postprocessor content %p\n", concls);
        ret = kishttpd->SendHttpResponse(kishttpd, concls, 
                url, concls->httpcode, concls->response_stream.str());
      
        return MHD_YES;
    } else {
        // Handle GET + any others
        ret = handler->Httpd_HandleRequest(kishttpd, concls, url, method, 
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
            concls->variable_cache[key] = 
                unique_ptr<std::stringstream>(new std::stringstream);

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

    if (con_info->connection_type == Kis_Net_Httpd_Connection::CONNECTION_POST) {
        MHD_destroy_post_processor(con_info->postprocessor);
        con_info->postprocessor = NULL;
    }

    delete(con_info);
    *con_cls = NULL;
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

string Kis_Net_Httpd::GetMimeType(string ext) {
    std::map<string, string>::iterator mi = mime_type_map.find(ext);
    if (mi != mime_type_map.end()) {
        return mi->second;
    }

    return "";
}

int Kis_Net_Httpd::handle_static_file(void *cls, Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method) {
    Kis_Net_Httpd *kishttpd = (Kis_Net_Httpd *) cls;

    if (!kishttpd->http_serve_files)
        return -1;

    if (strcmp(method, "GET") != 0)
        return -1;

    string fullfile = kishttpd->http_data_dir + "/" + url;

    if (fullfile[fullfile.size() - 1] == '/')
        fullfile += "index.html";

    char *realpath_path;
    const char *datadir_path;

    datadir_path = kishttpd->http_data_dir.c_str();
    realpath_path = realpath(fullfile.c_str(), NULL);

    if (realpath_path == NULL) {
        return -1;
    } else {
        // Make sure we're hosted inside the data dir
        if (strstr(realpath_path, datadir_path) == realpath_path) {

            struct MHD_Response *response;
            struct stat buf;

            FILE *f = fopen(realpath_path, "rb");
            int fd;
            free(realpath_path);
            
            if (f != NULL) {
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

                if (connection->session != NULL) {
                    std::stringstream cookiestr;
                    std::stringstream cookie;

                    cookiestr << KIS_SESSION_COOKIE << "=";
                    cookiestr << connection->session->sessionid;
                    cookiestr << "; Path=/";

                    MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, 
                                cookiestr.str().c_str());
                }

                char lastmod[31];
                struct tm tmstruct;
                localtime_r(&(buf.st_ctime), &tmstruct);
                strftime(lastmod, 31, "%a, %d %b %Y %H:%M:%S %Z", &tmstruct);
                MHD_add_response_header(response, "Last-Modified", lastmod);

                string suffix = GetSuffix(url);
                string mime = kishttpd->GetMimeType(suffix);

                if (mime != "") {
                    MHD_add_response_header(response, "Content-Type", mime.c_str());
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

            return -1;
        } else {
            return -1;
        }
    }

    return -1;
}

int Kis_Net_Httpd::SendHttpResponse(Kis_Net_Httpd *httpd,
        Kis_Net_Httpd_Connection *connection,
        const char *url, int httpcode, string responsestr) {

    struct MHD_Response *response = 
        MHD_create_response_from_buffer(responsestr.length(),
                (void *) responsestr.data(), MHD_RESPMEM_MUST_COPY);

    if (connection->session != NULL) {
        std::stringstream cookiestr;
        std::stringstream cookie;

        cookiestr << KIS_SESSION_COOKIE << "=";
        cookiestr << connection->session->sessionid;
        cookiestr << "; Path=/";

        MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, 
                cookiestr.str().c_str());
    }

    char lastmod[31];
    struct tm tmstruct;
    time_t now;
    time(&now);
    localtime_r(&now, &tmstruct);
    strftime(lastmod, 31, "%a, %d %b %Y %H:%M:%S %Z", &tmstruct);
    MHD_add_response_header(response, "Last-Modified", lastmod);

    string suffix = GetSuffix(url);
    string mime = httpd->GetMimeType(suffix);

    if (mime != "") {
        MHD_add_response_header(response, "Content-Type", mime.c_str());
    }

    // Allow any?  This lets us handle webuis hosted elsewhere
    MHD_add_response_header(response, "Access-Control-Allow-Origin", "*");

    int ret = MHD_queue_response(connection->connection, httpcode, response);

    MHD_destroy_response(response);

    return ret;
}

Kis_Net_Httpd_Handler::Kis_Net_Httpd_Handler(GlobalRegistry *in_globalreg) {
    httpd = NULL;
    http_globalreg = in_globalreg;

    Bind_Httpd_Server(in_globalreg);

}

Kis_Net_Httpd_Handler::~Kis_Net_Httpd_Handler() {
    httpd = 
        static_pointer_cast<Kis_Net_Httpd>(http_globalreg->FetchGlobal("HTTPD_SERVER"));

    if (httpd != NULL)
        httpd->RemoveHandler(this);
}

void Kis_Net_Httpd_Handler::Bind_Httpd_Server(GlobalRegistry *in_globalreg) {
    if (in_globalreg != NULL) {
        http_globalreg = in_globalreg;

        httpd = 
            static_pointer_cast<Kis_Net_Httpd>(in_globalreg->FetchGlobal("HTTPD_SERVER"));
        if (httpd != NULL)
            httpd->RegisterHandler(this);

        entrytracker = 
            static_pointer_cast<EntryTracker>(http_globalreg->FetchGlobal("ENTRY_TRACKER"));
    }
}

bool Kis_Net_Httpd_Handler::Httpd_CanSerialize(string path) {
    return entrytracker->CanSerialize(httpd->GetSuffix(path));
}

string Kis_Net_Httpd_Handler::Httpd_GetSuffix(string path) {
    return httpd->GetSuffix(path);
}

string Kis_Net_Httpd_Handler::Httpd_StripSuffix(string path) {
    return httpd->StripSuffix(path);
}

bool Kis_Net_Httpd_Stream_Handler::Httpd_Serialize(string path, 
        std::stringstream &stream, SharedTrackerElement e, 
        TrackerElementSerializer::rename_map *name_map) {
    return entrytracker->Serialize(httpd->GetSuffix(path), stream, e, name_map);
}

int Kis_Net_Httpd_Stream_Handler::Httpd_HandleRequest(Kis_Net_Httpd *httpd, 
        Kis_Net_Httpd_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    std::stringstream stream;
    int ret;

    Httpd_CreateStreamResponse(httpd, connection, url, method, upload_data,
            upload_data_size, stream);

    ret = httpd->SendHttpResponse(httpd, connection, url, MHD_HTTP_OK, stream.str());
    
    return ret;
}

bool Kis_Net_Httpd::HasValidSession(Kis_Net_Httpd_Connection *connection,
        bool send_invalid) {
    if (connection->session != NULL)
        return true;

    Kis_Net_Httpd_Session *s;
    const char *cookieval;

    cookieval = MHD_lookup_connection_value(connection->connection,
            MHD_COOKIE_KIND, KIS_SESSION_COOKIE);

    if (cookieval != NULL) {
        fprintf(stderr, "debug - comparing session cookie '%s'\n", cookieval);
        map<string, Kis_Net_Httpd_Session *>::iterator si = session_map.find(cookieval);

        if (si != session_map.end()) {

            s = si->second;

            // Does the session never expire?
            if (s->session_lifetime == 0) {
                connection->session = s;
                return true;
            }

            // Is the session still valid?
            if (globalreg->timestamp.tv_sec < s->session_seen + s->session_lifetime) {
                connection->session = s;
                return true;
            } else {
                DelSession(si);
            }
        }
    }

    // If we got here, we either don't have a session, or the session isn't valid.
    // Check the login.
    char *user;
    char *pass = NULL;

    user = MHD_basic_auth_get_username_password(connection->connection, &pass);
    if (user == NULL || conf_username != user || conf_password != pass) {
        ;
    } else {
        CreateSession(connection, NULL, 0);
        return true;
    }

    // If we got here it's invalid.  Do we automatically send an invalidation 
    // response?
    if (send_invalid) {
        string respstr = "Login Required";

        struct MHD_Response *response = 
            MHD_create_response_from_buffer(respstr.length(),
                    (void *) respstr.c_str(), MHD_RESPMEM_MUST_COPY);

        MHD_queue_basic_auth_fail_response(connection->connection,
                "Kismet Admin", response);

        MHD_destroy_response(response);
    }

    return false;
}

void Kis_Net_Httpd::CreateSession(Kis_Net_Httpd_Connection *connection, 
        struct MHD_Response *response, time_t in_lifetime) {
    Kis_Net_Httpd_Session *s;

    // Use 128 bits of entropy to make a session key

    char rdata[16];
    FILE *urandom;

    if ((urandom = fopen("/dev/urandom", "rb")) == NULL) {
        _MSG("Failed to open /dev/urandom to create a HTTPD session, unable to "
                "assign a sessionid, not creating session", MSGFLAG_ERROR);
        return;
    }

    if (fread(rdata, 16, 1, urandom) != 1) {
        _MSG("Failed to read entropy from /dev/urandom to create a HTTPD session, "
                "unable to assign a sessionid, not creating session", MSGFLAG_ERROR);
        fclose(urandom);
        return;
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

    fprintf(stderr, "debug - created new session %s\n", cookiestr.str().c_str());

    if (response != NULL) {
        if (MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, 
                    cookiestr.str().c_str()) == MHD_NO) {
            _MSG("Failed to add session cookie to response header, unable to create "
                    "a session", MSGFLAG_ERROR);
            return;
        }
    }

    s = new Kis_Net_Httpd_Session();
    s->sessionid = cookie.str();
    s->session_created = globalreg->timestamp.tv_sec;
    s->session_seen = s->session_created;
    s->session_lifetime = in_lifetime;

    if (connection != NULL)
        connection->session = s;

    AddSession(s);
}

bool Kis_Net_Httpd_No_Files_Handler::Httpd_VerifyPath(const char *path, 
        const char *method) {

    if (strcmp(method, "GET") != 0)
        return false;

    if (strcmp(path, "/index.html") == 0 ||
            strcmp(path, "/") == 0)
        return true;

    return false;
}


void Kis_Net_Httpd_No_Files_Handler::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd __attribute__((unused)),
        Kis_Net_Httpd_Connection *connection __attribute__((unused)),
        const char *url __attribute__((unused)), 
        const char *method __attribute__((unused)), 
        const char *upload_data __attribute__((unused)),
        size_t *upload_data_size __attribute__((unused)), 
        std::stringstream &stream) {

    stream << "<html>";
    stream << "<head><title>Web UI Disabled</title></head>";
    stream << "<body>";
    stream << "<h2>Sorry</h2>";
    stream << "<p>The Web UI in Kismet is disabled because Kismet cannot serve ";
    stream << "static web pages.";
    stream << "<p>Check the output of kismet_server and make sure your ";
    stream << "<blockquote><pre>httpd_home=...</pre>";
    stream << "and/or<br>";
    stream << "<pre>httpd_user_home=...</pre></blockquote>";
    stream << "configuration values are set in kismet.conf or kismet_httpd.conf ";
    stream << "and restart Kismet";
    stream << "</body>";
    stream << "</html>";
}

