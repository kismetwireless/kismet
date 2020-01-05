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

#ifndef __KIS_NET_MICROHTTPD_WEBSOCKET_H__
#define __KIS_NET_MICROHTTPD_WEBSOCKET_H__ 

#include "config.h"
#include "kis_net_microhttpd.h"
#include "kis_net_microhttpd_handlers.h"
#include "pollable.h"

class kis_net_httpd_websocket_pollable : public kis_pollable {
public:
    kis_net_httpd_websocket_pollable();
    virtual ~kis_net_httpd_websocket_pollable();

    virtual void set_mutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent);

    virtual void set_handler(std::shared_ptr<buffer_handler_generic> in_handler);
    virtual void set_connection(MHD_socket in_socket, struct MHD_UpgradeResponseHandle *in_urh);

    void disconnect();

    // Pollable interface
    virtual int pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) override;
    virtual int pollable_poll(fd_set& in_rset, fd_set& in_wset) override;

protected:
    std::shared_ptr<buffer_handler_generic> handler;

    std::shared_ptr<kis_recursive_timed_mutex> websocket_mutex;

    MHD_socket socket;
    MHD_UpgradeResponseHandle *urh;
};

// Control state for a websocket, contains the pollable socket, original connection,
// matched protocol, and so on
class kis_net_httpd_websocket_state {
public:
    kis_net_httpd_websocket_state() :
        ws_pollable {nullptr},
        ws_mhd_urh {nullptr},
        ws_socket {-1} { }

    std::function<void (kis_net_httpd_websocket_state *)> connect_cb;

    std::shared_ptr<kis_net_httpd_websocket_pollable> ws_pollable;
    MHD_UpgradeResponseHandle *ws_mhd_urh;
    MHD_socket ws_socket;
};

// Websocket handler to handle an upgrade and handshake on a ws:// URI and then
// create a pollable object
class kis_net_httpd_websocket_handler : public kis_net_httpd_handler {
public:
    kis_net_httpd_websocket_handler() : kis_net_httpd_handler() { }
    virtual ~kis_net_httpd_websocket_handler();

    virtual int httpd_handle_get_request(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) override;

    // Can this handler process this request?
    virtual bool httpd_verify_path(const char *path, const char *method) override = 0;

protected:
    // Perform a websocket upgrade (returning true) to the connection; 
    // If the upgrade fails, the connection is errored out and , or fail to upgrade,
    // push the error to the connection, and return false
    bool httpd_websocket_upgrade(kis_net_httpd_connection *connection);

    std::vector<std::string> ws_protocols;
    std::function<void (kis_net_httpd_websocket_state *)> ws_establish_cb;
};

#endif /* ifndef KIS_NET_MICROHTTPD_WEBSOCKET_H */
