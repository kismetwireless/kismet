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

#include "asio.hpp"

#define WS_OPCODE_CONTINUE      0x0
#define WS_OPCODE_TEXT          0x1
#define WS_OPCODE_BINARY        0x2
#define WS_OPCODE_CLOSE         0x8

#define WS_FIN                  128

class kis_net_httpd_websocket : public std::enable_shared_from_this<kis_net_httpd_websocket> {
public:
    using data_cb_t = std::function<int (const asio::error_code& ec, asio::streambuf& buf, std::size_t sz)>;

    kis_net_httpd_websocket();
    virtual ~kis_net_httpd_websocket();

    virtual void set_data_handler(data_cb_t cb);
    virtual void set_connection(MHD_socket in_socket, struct MHD_UpgradeResponseHandle *in_urh);

    void disconnect();


protected:
    kis_recursive_timed_mutex websocket_mutex;

    MHD_socket mhd_socket;
    MHD_UpgradeResponseHandle *urh;

    std::atomic<bool> stopped;

    asio::posix::stream_descriptor websocket;
    asio::streambuf in_buf;
    asio::streambuf decoded_buf;

    // Lowlevel ASIO data
    void start_read(std::shared_ptr<kis_net_httpd_websocket> ref, const asio::error_code& ec);
    void handle_read(std::shared_ptr<kis_net_httpd_websocket> ref, const asio::error_code& ec, std::size_t sz);

    // Interpreted data functions
    data_cb_t data_cb;

    void write(const std::string& data);
    void write(const char *data, size_t len);

};

class kis_net_httpd_websocket_state;

class kis_net_httpd_websocket_endpoint : public kis_net_httpd_handler {
public:
    using path_func_t = std::function<bool (const std::vector<std::string>&)>;
    using connect_func_t = std::function<bool (kis_net_httpd_websocket_state *)>;

    kis_net_httpd_websocket_endpoint(const std::string& uri, 
            connect_func_t connect_cb,
            kis_net_httpd_websocket::data_cb_t rx_cb);

    kis_net_httpd_websocket_endpoint(path_func_t path_func, 
            connect_func_t connect_cb,
            kis_net_httpd_websocket::data_cb_t rx_cb);

    virtual ~kis_net_httpd_websocket_endpoint();

    virtual bool httpd_verify_path(const char *path, const char *method) override;

    virtual KIS_MHD_RETURN httpd_handle_get_request(kis_net_httpd *httpd,
            kis_net_httpd_connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size) override;

    virtual KIS_MHD_RETURN httpd_post_complete(kis_net_httpd_connection *concls) override;

protected:
    bool httpd_websocket_upgrade(kis_net_httpd_connection *connection);

    std::vector<std::string> ws_protocols;

    std::string uri;
    path_func_t path_cb;

    connect_func_t ws_establish_cb;
    kis_net_httpd_websocket::data_cb_t data_cb;
};

// Control state for a websocket, contains the pollable socket, original connection,
// matched protocol, and so on
class kis_net_httpd_websocket_state {
public:
    kis_net_httpd_websocket_state() :
        ws_pollable {nullptr},
        ws_mhd_urh {nullptr},
        ws_socket {-1} { }

    std::shared_ptr<kis_net_httpd_websocket> ws_pollable;
    MHD_UpgradeResponseHandle *ws_mhd_urh;
    MHD_socket ws_socket;
};


#endif /* ifndef KIS_NET_MICROHTTPD_WEBSOCKET_H */
