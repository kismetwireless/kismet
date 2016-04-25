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

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#include "globalregistry.h"
#include "messagebus.h"
#include "configfile.h"
#include "kis_net_microhttpd.h"

Kis_Net_Httpd::Kis_Net_Httpd(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    globalreg->InsertGlobal("HTTPD_SERVER", this);

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
    if (running)
        StopHttpd();

    globalreg->RemoveGlobal("HTTPD_SERVER");

    pthread_mutex_destroy(&controller_mutex);
}

char *Kis_Net_Httpd::read_ssl_file(string in_fname) {
    FILE *f;
    char strerrbuf[1024];
    char *errstr;
    stringstream str;
    char *buf = NULL;
    long sz;

    // Read errors are considered fatal
    if ((f = fopen(in_fname.c_str(), "rb")) == NULL) {
        errstr = strerror_r(errno, strerrbuf, 1024);
        str << "Unable to open SSL file " << in_fname << ": " << errstr;
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
        errstr = strerror_r(errno, strerrbuf, 1024);
        str << "Unable to read SSL file " << in_fname << ": " << errstr;
        _MSG(str.str(), MSGFLAG_FATAL);
        return NULL;
    }
    fclose(f);

    // Null terminate the buffer
    buf[sz] = 0;

    return buf;
}

void Kis_Net_Httpd::RegisterMimeType(string suffix, string mimetype) {
    mime_type_map[StrLower(suffix)] = mimetype;
}

void Kis_Net_Httpd::RegisterHandler(Kis_Net_Httpd_Handler *in_handler) {
    pthread_mutex_lock(&controller_mutex);

    handler_vec.push_back(in_handler);

    pthread_mutex_unlock(&controller_mutex);
}

void Kis_Net_Httpd::RemoveHandler(Kis_Net_Httpd_Handler *in_handler) {
    pthread_mutex_lock(&controller_mutex);

    for (unsigned int x = 0; x < handler_vec.size(); x++) {
        if (handler_vec[x] == in_handler) {
            handler_vec.erase(handler_vec.begin() + x);
            break;
        }
    }

    pthread_mutex_unlock(&controller_mutex);
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

    _MSG("Started http server on port " + UIntToString(http_port), MSGFLAG_INFO);

    return 1;
}

int Kis_Net_Httpd::StopHttpd() {
    if (microhttpd != NULL) {
        MHD_stop_daemon(microhttpd);
        return 1;
    }

    return 0;
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

    // fprintf(stderr, "HTTP request: '%s' method '%s'\n", url, method); 
    //
    Kis_Net_Httpd *kishttpd = (Kis_Net_Httpd *) cls;
    
    // Update the session records if one exists
    Kis_Net_Httpd_Session *s = NULL;
    const char *cookieval;
    int ret = MHD_NO;

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

    if (handler == NULL) {
        // Try to check a static url
        if (handle_static_file(cls, connection, url, method) < 0) {
            // fprintf(stderr, "   404 no handler for request\n");

            string fourohfour = "404";

            struct MHD_Response *response = 
                MHD_create_response_from_buffer(fourohfour.length(), 
                        (void *) fourohfour.c_str(), MHD_RESPMEM_MUST_COPY);

            return MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
        }

        return MHD_YES;
    }

    // If we don't have a connection state, make one
    if (*ptr == NULL) {
        Kis_Net_Httpd_Connection *concls = new Kis_Net_Httpd_Connection();

        concls->httpd = kishttpd;
        concls->httpdhandler = handler;
        // printf("%s %s session = %p\n", method, url, s);
        concls->session = s;
        concls->httpcode = MHD_HTTP_OK;
        concls->url = string(url);

        /* If we're doing a post, set up a post handler */
        if (strcmp(method, "POST") == 0) {
            concls->connection_type = Kis_Net_Httpd_Connection::CONNECTION_POST;

            concls->postprocessor =
                MHD_create_post_processor(connection, KIS_HTTPD_POSTBUFFERSZ,
                        kishttpd->http_post_handler, (void *) concls);

            if (concls->postprocessor == NULL) {
                delete(concls);
                return MHD_NO;
            }

        } else {
            concls->connection_type = Kis_Net_Httpd_Connection::CONNECTION_POST;
        }

        *ptr = (void *) concls;

        return MHD_YES;
    }

    // Handle post
    if (strcmp(method, "POST") == 0) {
        Kis_Net_Httpd_Connection *concls = (Kis_Net_Httpd_Connection *) *ptr;

        if (*upload_data_size != 0) {
            MHD_post_process(concls->postprocessor, upload_data, *upload_data_size);
            *upload_data_size = 0;
            return MHD_YES;
        } else if (concls->response_stream.str().length() != 0) {
            // Send the content
            ret = kishttpd->SendHttpResponse(kishttpd, connection, 
                    url, concls->httpcode, concls->response_stream.str());
    
            return ret;
        }
    } else {
        ret = 
            handler->Httpd_HandleRequest(kishttpd, connection, url, method, 
                    upload_data, upload_data_size);
    }

    return ret;
}

int Kis_Net_Httpd::http_post_handler(void *coninfo_cls, enum MHD_ValueKind kind, 
        const char *key, const char *filename, const char *content_type,
        const char *transfer_encoding, const char *data, 
        uint64_t off, size_t size) {

    Kis_Net_Httpd_Connection *concls = (Kis_Net_Httpd_Connection *) coninfo_cls;

    return (concls->httpdhandler)->Httpd_PostIterator(coninfo_cls, kind,
            key, filename, content_type, transfer_encoding, data, off, size);
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

int Kis_Net_Httpd::handle_static_file(void *cls, struct MHD_Connection *connection,
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

                char lastmod[31];
                struct tm tmstruct;
                localtime_r(&(buf.st_ctime), &tmstruct);
                strftime(lastmod, 31, "%a, %d %b %Y %H:%M:%S %Z", &tmstruct);
                MHD_add_response_header(response, "Last-Modified", lastmod);

                // Smarter way to do this in the future?  Probably.
                vector<string> ext_comps = StrTokenize(url, ".");
                if (ext_comps.size() >= 1) {
                    string ext = StrLower(ext_comps[ext_comps.size() - 1]);
                    string mime = kishttpd->GetMimeType(ext);

                    if (mime != "") {
                        MHD_add_response_header(response, "Content-Type", mime.c_str());
                    }
                }


                MHD_queue_response(connection, MHD_HTTP_OK, response);
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
        struct MHD_Connection *connection, 
        const char *url, int httpcode, string responsestr) {

    struct MHD_Response *response = 
        MHD_create_response_from_buffer(responsestr.length(),
                (void *) responsestr.c_str(), MHD_RESPMEM_MUST_COPY);

    char lastmod[31];
    struct tm tmstruct;
    time_t now;
    time(&now);
    localtime_r(&now, &tmstruct);
    strftime(lastmod, 31, "%a, %d %b %Y %H:%M:%S %Z", &tmstruct);
    MHD_add_response_header(response, "Last-Modified", lastmod);

    // Smarter way to do this in the future?  Probably.
    vector<string> ext_comps = StrTokenize(url, ".");
    if (ext_comps.size() >= 1) {
        string ext = StrLower(ext_comps[ext_comps.size() - 1]);

        string mime = httpd->GetMimeType(ext);
        if (mime != "") {
            MHD_add_response_header(response, "Content-Type", mime.c_str());
        }
    }

    int ret = MHD_queue_response(connection, httpcode, response);

    MHD_destroy_response(response);

    return ret;
}

int Kis_Net_Httpd_Stream_Handler::Httpd_HandleRequest(Kis_Net_Httpd *httpd, 
        struct MHD_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    std::stringstream stream;
    int ret;

    Httpd_CreateStreamResponse(httpd, connection, url, method, upload_data,
            upload_data_size, stream);

    ret = httpd->SendHttpResponse(httpd, connection, url, MHD_HTTP_OK, stream.str());
    
    return ret;
}

bool Kis_Net_Httpd::HasValidSession(struct MHD_Connection *connection) {
    Kis_Net_Httpd_Session *s;
    const char *cookieval;

    cookieval = MHD_lookup_connection_value (connection,
            MHD_COOKIE_KIND, KIS_SESSION_COOKIE);

    if (cookieval == NULL)
        return false;

    map<string, Kis_Net_Httpd_Session *>::iterator si = session_map.find(cookieval);

    if (si == session_map.end())
        return false;

    s = si->second;

    // Does the session never expire?
    if (s->session_lifetime == 0)
        return true;

    // Has the session expired?
    if (s->session_seen + s->session_lifetime < globalreg->timestamp.tv_sec) {
        DelSession(si);
        return false;
    }

    // We're good
    return true;
}

bool Kis_Net_Httpd::HasValidSession(Kis_Net_Httpd_Connection *connection) {
    return (connection->session != NULL);
}

void Kis_Net_Httpd::CreateSession(struct MHD_Response *response, time_t in_lifetime) {
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

    if (MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, 
                cookiestr.str().c_str()) == MHD_NO) {
        _MSG("Failed to add session cookie to response header, unable to create "
                "a session", MSGFLAG_ERROR);
        return;
    }

    s = new Kis_Net_Httpd_Session();
    s->sessionid = cookie.str();
    s->session_created = globalreg->timestamp.tv_sec;
    s->session_seen = s->session_created;
    s->session_lifetime = in_lifetime;

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
        struct MHD_Connection *connection __attribute__((unused)),
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

