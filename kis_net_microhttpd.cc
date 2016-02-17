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
#include <limits.h>
#include <stdlib.h>
#include <microhttpd.h>

#include "globalregistry.h"
#include "messagebus.h"
#include "configfile.h"
#include "kis_net_microhttpd.h"

Kis_Net_Httpd::Kis_Net_Httpd(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;
    running = false;

    pthread_mutex_init(&controller_mutex, NULL);

    if (globalreg->kismet_config == NULL) {
        fprintf(stderr, "FATAL OOPS: Kis_Net_Httpd called without kismet_config\n");
        exit(1);
    }

    http_port = globalreg->kismet_config->FetchOptUInt("httpdport", 8080);

    http_data_dir = globalreg->kismet_config->FetchOpt("httpdhome");
    http_aux_data_dir = globalreg->kismet_config->FetchOpt("httpduserhome");

    if (http_data_dir == "") {
        _MSG("No httpdhome defined in kismet.conf, disabling static file serving",
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
        _MSG("No httpduserhome defined in kismet.conf, disabling static file serving "
                "from user directory", MSGFLAG_ERROR);
        http_serve_user_files = false;
    } else {
        http_aux_data_dir = 
            globalreg->kismet_config->ExpandLogPath(http_aux_data_dir, "", "", 0, 1);
        _MSG("Serving static userdir content from '" + http_aux_data_dir + "'",
                MSGFLAG_INFO);
        http_serve_user_files = true;
    }

}

Kis_Net_Httpd::~Kis_Net_Httpd() {
    if (running)
        StopHttpd();

    pthread_mutex_destroy(&controller_mutex);
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
    
    Kis_Net_Httpd *kishttpd = (Kis_Net_Httpd *) cls;

    Kis_Net_Httpd_Handler *handler = NULL;
    pthread_mutex_lock(&(kishttpd->controller_mutex));

    for (unsigned int i = 0; i < kishttpd->handler_vec.size(); i++) {
        Kis_Net_Httpd_Handler *h = kishttpd->handler_vec[i];

        if (h->VerifyPath(url, method)) {
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
        handler->HandleRequest(connection, url, method, upload_data, upload_data_size);

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

