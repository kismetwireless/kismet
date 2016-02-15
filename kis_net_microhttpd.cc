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
#include "kis_net_microhttpd.h"

Kis_Net_Httpd::Kis_Net_Httpd(GlobalRegistry *in_globalreg, int in_port) {
    globalreg = in_globalreg;
    http_port = in_port;
    running = false;

    pthread_mutex_init(&controller_mutex, NULL);
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
    fprintf(stderr, "debug - starting kismet httpd server on port %u\n", http_port);

    microhttpd = MHD_start_daemon(MHD_USE_THREAD_PER_CONNECTION,
            http_port, NULL, NULL, &http_request_handler, this, MHD_OPTION_END); 

    if (microhttpd == NULL)
        return -1;

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

    fprintf(stderr, "HTTP request: '%s' method '%s'\n", url, method); 
    
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

        fprintf(stderr, "   404 no handler for request\n");

        struct MHD_Response *response = 
            MHD_create_response_from_buffer(0, 0, MHD_RESPMEM_PERSISTENT);

        return MHD_queue_response(connection, MHD_HTTP_NOT_FOUND, response);
    }

    int ret = 
        handler->HandleRequest(connection, url, method, upload_data, upload_data_size);

    pthread_mutex_unlock(&(kishttpd->controller_mutex));

    return ret;
}


