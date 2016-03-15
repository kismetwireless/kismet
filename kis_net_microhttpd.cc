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
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sstream>
#include <iomanip>
#include <pthread.h>
#include <limits.h>
#include <stdlib.h>
#include <microhttpd.h>

#include "globalregistry.h"
#include "messagebus.h"
#include "configfile.h"
#include "kis_net_microhttpd.h"

Kis_Net_Httpd::Kis_Net_Httpd(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;

    globalreg->InsertGlobal("HTTPD_SERVER", this);

    running = false;

    pthread_mutex_init(&controller_mutex, NULL);

    if (globalreg->kismet_config == NULL) {
        fprintf(stderr, "FATAL OOPS: Kis_Net_Httpd called without kismet_config\n");
        exit(1);
    }

    http_port = globalreg->kismet_config->FetchOptUInt("httpd_port", 2501);

    http_data_dir = globalreg->kismet_config->FetchOpt("httpd_home");
    http_aux_data_dir = globalreg->kismet_config->FetchOpt("httpd_user_home");

    if (http_data_dir == "") {
        _MSG("No httpd_home defined in kismet.conf, disabling static file serving",
                MSGFLAG_ERROR);
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

}

Kis_Net_Httpd::~Kis_Net_Httpd() {
    if (running)
        StopHttpd();

    globalreg->RemoveGlobal("HTTPD_SERVER");

    pthread_mutex_destroy(&controller_mutex);
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
    microhttpd = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,
            http_port, NULL, NULL, &http_request_handler, this, MHD_OPTION_END); 

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

int Kis_Net_Httpd::http_request_handler(void *cls, struct MHD_Connection *connection,
    const char *url, const char *method, const char *version __attribute__ ((unused)),
    const char *upload_data, size_t *upload_data_size, 
    void **ptr __attribute__ ((unused))) {

    // fprintf(stderr, "HTTP request: '%s' method '%s'\n", url, method); 
    //
    Kis_Net_Httpd *kishttpd = (Kis_Net_Httpd *) cls;
    
    // Update the session records if one exists
    session *s;
    const char *cookieval;

    cookieval = MHD_lookup_connection_value (connection,
            MHD_COOKIE_KIND, KIS_SESSION_COOKIE);

    if (cookieval != NULL) {
        map<string, session *>::iterator si = kishttpd->session_map.find(cookieval);

        if (si != kishttpd->session_map.end()) {
            s = si->second;

            if (s->session_lifetime != 0) {
                // Delete if the session has expired
                if (s->session_seen + s->session_lifetime < 
                        kishttpd->globalreg->timestamp.tv_sec) {
                    kishttpd->session_map.erase(si);
                    delete(s);
                }
            }

            // Update the last seen
            s->session_seen = kishttpd->globalreg->timestamp.tv_sec;
        }
    }
    
    Kis_Net_Httpd_Handler *handler = NULL;
    pthread_mutex_lock(&(kishttpd->controller_mutex));

    for (unsigned int i = 0; i < kishttpd->handler_vec.size(); i++) {
        Kis_Net_Httpd_Handler *h = kishttpd->handler_vec[i];

        if (h->Httpd_VerifyPath(url, method)) {
            handler = h;
            break;
        }
    }

    if (handler == NULL) {
        pthread_mutex_unlock(&(kishttpd->controller_mutex));

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

    int ret = 
        handler->Httpd_HandleRequest(kishttpd, connection, url, method, upload_data, 
                upload_data_size);

    pthread_mutex_unlock(&(kishttpd->controller_mutex));

    return ret;
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

int Kis_Net_Httpd_Stream_Handler::Httpd_HandleRequest(Kis_Net_Httpd *httpd, 
        struct MHD_Connection *connection,
        const char *url, const char *method, const char *upload_data,
        size_t *upload_data_size) {

    std::stringstream stream;

    Httpd_CreateStreamResponse(httpd, connection, url, method, upload_data,
            upload_data_size, stream);

    struct MHD_Response *response = 
        MHD_create_response_from_buffer(stream.str().length(),
                (void *) stream.str().c_str(), MHD_RESPMEM_MUST_COPY);

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

    int ret = MHD_queue_response(connection, MHD_HTTP_OK, response);

    MHD_destroy_response(response);

    return ret;
}

bool Kis_Net_Httpd::HasValidSession(struct MHD_Connection *connection) {
    session *s;
    const char *cookieval;

    cookieval = MHD_lookup_connection_value (connection,
            MHD_COOKIE_KIND, KIS_SESSION_COOKIE);

    if (cookieval == NULL)
        return false;

    map<string, session *>::iterator si = session_map.find(cookieval);

    if (si == session_map.end())
        return false;

    s = si->second;

    // Does the session never expire?
    if (s->session_lifetime == 0)
        return true;

    // Has the session expired?
    if (s->session_seen + s->session_lifetime < globalreg->timestamp.tv_sec) {
        session_map.erase(si);
        delete(s);
        return false;
    }

    // We're good
    return true;
}

void Kis_Net_Httpd::CreateSession(struct MHD_Response *response, time_t in_lifetime) {
    session *s;

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

    if (MHD_add_response_header(response, MHD_HTTP_HEADER_SET_COOKIE, 
                cookiestr.str().c_str()) == MHD_NO) {
        _MSG("Failed to add session cookie to response header, unable to create "
                "a session", MSGFLAG_ERROR);
        return;
    }

    s = new session();
    s->sessionid = cookie.str();
    s->session_created = globalreg->timestamp.tv_sec;
    s->session_seen = s->session_created;
    s->session_lifetime = in_lifetime;

    session_map[cookie.str()] = s;
}

