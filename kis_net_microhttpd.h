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
#include <pthread.h>
#include <microhttpd.h>

#include "globalregistry.h"

#ifndef __KIS_NET_MICROHTTPD__
#define __KIS_NET_MICROHTTPD__

class Kis_Net_Httpd;

// Basic request handler from MHD
class Kis_Net_Httpd_Handler {
public:
    // Handle a request
    virtual int Httpd_HandleRequest(Kis_Net_Httpd *httpd,
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) = 0;


    // Can this handler process this request?
    virtual bool Httpd_VerifyPath(const char *path, const char *method) = 0;
};

// Take a C++ stringstream and use it as a response
class Kis_Net_Httpd_Stream_Handler : public Kis_Net_Httpd_Handler {
public:
    virtual bool Httpd_VerifyPath(const char *path, const char *method) = 0;

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream) = 0;

    virtual int Httpd_HandleRequest(Kis_Net_Httpd *httpd, 
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size);
};

// Fallback handler to report that we can't serve static files
class Kis_Net_Httpd_No_Files_Handler : public Kis_Net_Httpd_Stream_Handler {
public:
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            struct MHD_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);
};

#define KIS_SESSION_COOKIE      "KISMET"

class Kis_Net_Httpd {
public:
    Kis_Net_Httpd(GlobalRegistry *in_globalreg);
    ~Kis_Net_Httpd();

    int StartHttpd();
    int StopHttpd();

    bool HttpdRunning() { return running; }

    void RegisterHandler(Kis_Net_Httpd_Handler *in_handler);
    void RemoveHandler(Kis_Net_Httpd_Handler *in_handler);

    void RegisterMimeType(string suffix, string mimetype);
    string GetMimeType(string suffix);

    bool HasValidSession(struct MHD_Connection *connection);
    void CreateSession(struct MHD_Response *response, time_t in_lifetime);

protected:
    GlobalRegistry *globalreg;

    unsigned int http_port;
    string http_data_dir, http_aux_data_dir;

    bool http_serve_files, http_serve_user_files;

    struct MHD_Daemon *microhttpd;
    std::vector<Kis_Net_Httpd_Handler *> handler_vec;

    bool use_ssl;
    char *cert_pem, *cert_key;
    string pem_path, key_path;

    bool running;

    std::map<string, string> mime_type_map;

    pthread_mutex_t controller_mutex;

    // Handle the requests and dispatch to controllers
    static int http_request_handler(void *cls, struct MHD_Connection *connection,
            const char *url, const char *method, const char *version,
            const char *upload_data, size_t *upload_data_size, void **ptr);

    static int handle_static_file(void *cls, struct MHD_Connection *connection,
            const char *url, const char *method);

    char *read_ssl_file(string in_fname);

    class session {
    public:
        // Session ID
        string sessionid;

        // Time session was created
        time_t session_created;

        // Last time the session was seen active
        time_t session_seen;

        // Amount of time session is valid for after last active
        time_t session_lifetime;
    };

    map<string, session *> session_map;
};

#endif

