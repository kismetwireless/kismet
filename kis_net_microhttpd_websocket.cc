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

#include "base64.h"
#include "kis_net_microhttpd_websocket.h"
#include "sha1.h"
#include "util.h"

kis_net_httpd_websocket_pollable::kis_net_httpd_websocket_pollable() :
    handler {nullptr},
    websocket_mutex {std::make_shared<kis_recursive_timed_mutex>()},
    socket {-1},
    urh {nullptr} { }

kis_net_httpd_websocket_pollable::~kis_net_httpd_websocket_pollable() {
    disconnect();
}

void kis_net_httpd_websocket_pollable::set_mutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent) {
    local_locker l(websocket_mutex);

    if (in_parent != nullptr)
        websocket_mutex = in_parent;
    else
        websocket_mutex = std::make_shared<kis_recursive_timed_mutex>();
}

void kis_net_httpd_websocket_pollable::set_handler(std::shared_ptr<buffer_handler_generic> in_handler) {
    local_locker l(websocket_mutex);
    handler = in_handler;
}

void kis_net_httpd_websocket_pollable::set_connection(MHD_socket in_sock, struct MHD_UpgradeResponseHandle *in_urh) {
    local_locker l(websocket_mutex);
    socket = in_sock;
    urh = in_urh;
}

void kis_net_httpd_websocket_pollable::disconnect() {
    local_locker l(websocket_mutex);

    if (urh != nullptr) {
        MHD_upgrade_action(urh, MHD_UPGRADE_ACTION_CLOSE);

        socket = -1;
        urh = nullptr;
    }
}

int kis_net_httpd_websocket_pollable::pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    local_locker l(websocket_mutex);

    if (socket < 0)
        return in_max_fd;

    if (handler == nullptr)
        return in_max_fd;

    if (handler->get_write_buffer_used()) {
        FD_SET(socket, out_wset);
    }

    if (handler->get_read_buffer_available()) {
        FD_SET(socket, out_rset);
    }

    // If we have data waiting to be written, fill it in
    if (handler->get_write_buffer_used()) {
        FD_SET(socket, out_wset);
    }

    if (in_max_fd < socket)
        return socket;

    return in_max_fd;
}

int kis_net_httpd_websocket_pollable::pollable_poll(fd_set& in_rset, fd_set& in_wset) {
    /*
       0                   1                   2                   3
       0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
       +-+-+-+-+-------+-+-------------+-------------------------------+
       |F|R|R|R| opcode|M| Payload len |    Extended payload length    |
       |I|S|S|S|  (4)  |A|     (7)     |             (16/64)           |
       |N|V|V|V|       |S|             |   (if payload len==126/127)   |
       | |1|2|3|       |K|             |                               |
       +-+-+-+-+-------+-+-------------+ - - - - - - - - - - - - - - - +
       |     Extended payload length continued, if payload len == 127  |
       + - - - - - - - - - - - - - - - +-------------------------------+
       |                               |Masking-key, if MASK set to 1  |
       +-------------------------------+-------------------------------+
       | Masking-key (continued)       |          Payload Data         |
       +-------------------------------- - - - - - - - - - - - - - - - +
       :                     Payload Data continued ...                :
       + - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - +
       |                     Payload Data continued ...                |
       +---------------------------------------------------------------+
       */

    return 0;
}


bool kis_net_httpd_websocket_handler::httpd_websocket_upgrade(kis_net_httpd_connection *conn) {
    const char *upgrade_hdr, *connection_hdr, *version_hdr, *protocols_hdr, *key_hdr;

    upgrade_hdr = MHD_lookup_connection_value(conn->connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_UPGRADE);
    if (upgrade_hdr == nullptr || strcasecmp(upgrade_hdr, "websocket")) {
        std::string err = "Expected WebSocket Upgrade header\n";
        auto response = MHD_create_response_from_buffer(err.length(), (void *) err.c_str(), MHD_RESPMEM_MUST_COPY);
        MHD_queue_response(conn->connection, 400, response);
        MHD_destroy_response(response);
        return false;
    }

    connection_hdr = MHD_lookup_connection_value(conn->connection, MHD_HEADER_KIND, MHD_HTTP_HEADER_CONNECTION);
    if (connection_hdr == nullptr) {
        std::string err = "Expected WebSocket Connection header\n";
        auto response = MHD_create_response_from_buffer(err.length(), (void *) err.c_str(), MHD_RESPMEM_MUST_COPY);
        MHD_queue_response(conn->connection, 400, response);
        MHD_destroy_response(response);
        return false;
    }

    if (!find_token(std::string(connection_hdr), std::string(MHD_HTTP_HEADER_UPGRADE), std::list<char>{' ', '\t', ','})) {
        std::string err = "Expected WebSocket upgrade in connection header\n";
        auto response = MHD_create_response_from_buffer(err.length(), (void *) err.c_str(), MHD_RESPMEM_MUST_COPY);
        MHD_queue_response(conn->connection, 400, response);
        MHD_destroy_response(response);
        return false;
    }

    key_hdr = MHD_lookup_connection_value(conn->connection, MHD_HEADER_KIND, "Sec-WebSocket-Key");
    version_hdr = MHD_lookup_connection_value(conn->connection, MHD_HEADER_KIND, "Sec-WebSocket-Version");

    if (key_hdr == nullptr || version_hdr == nullptr) {
        std::string err = "Expected WebSocket Key and Version headers\n";
        auto response = MHD_create_response_from_buffer(err.length(), (void *) err.c_str(), MHD_RESPMEM_MUST_COPY);
        MHD_queue_response(conn->connection, 400, response);
        MHD_destroy_response(response);
        return false;
    }

    if (string_to_n<int>(version_hdr) != 13) {
        auto response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, "Sec-WebSocket-Version", "13");
        MHD_queue_response(conn->connection, MHD_HTTP_UPGRADE_REQUIRED, response);
        MHD_destroy_response(response);
        return false;
    }

    // If there's a protocol, see if we support it; otherwise error
    protocols_hdr = MHD_lookup_connection_value(conn->connection, MHD_HEADER_KIND, "Sec-WebSocket-Protocol");
    auto ws_proto_matched = false;
    auto ws_proto = std::string();

    if (protocols_hdr != nullptr) {
        auto req_protocols = str_tokenize(std::string(protocols_hdr), std::list<char>{' ', ',', '\t'});
        for (auto p : ws_protocols) {
            for (auto rp : req_protocols) {
                if (p == rp) {
                    ws_proto_matched = true;
                    ws_proto = rp;
                    break;
                }

                if (ws_proto_matched)
                    break;
            }
        }

        if (ws_proto_matched == false && ws_protocols.size() != 0) {
            std::string err = "Unsupported websocket protocol\n";
            auto response = MHD_create_response_from_buffer(err.length(), (void *) err.c_str(), MHD_RESPMEM_MUST_COPY);
            MHD_queue_response(conn->connection, 400, response);
            MHD_destroy_response(response);
            return false;
        }
    }

    auto ws_state = new kis_net_httpd_websocket_state();
    ws_state->connect_cb = ws_establish_cb;

    auto response = MHD_create_response_for_upgrade(
            [](void *cls,
                struct MHD_Connection *connection,
                void *con_cls,
                const char *extra_in,
                size_t extra_in_size,
                MHD_socket sock,
                struct MHD_UpgradeResponseHandle *urh) -> void {
                    auto ws_state = static_cast<kis_net_httpd_websocket_state *>(cls);

                    // Grab the state on completion
                    ws_state->ws_mhd_urh = urh;
                    ws_state->ws_socket = sock;
                    ws_state->ws_pollable = std::make_shared<kis_net_httpd_websocket_pollable>();
                    ws_state->ws_pollable->set_connection(sock, urh);

                    // Callback; this should be responsible for registering the pollable,
                    // linking it to a buffer handler, and so on
                    if (ws_state->connect_cb)
                        ws_state->connect_cb(ws_state);

            }, (void *) ws_state);

    // Magic universal guid
    std::string magic_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

    // Response key is b64(sha1(supplied key (b64) + magic guid))
    SHA1 sha1;
    sha1.update(std::string(key_hdr) + magic_guid);

    auto accept_b64 = base64::encode(sha1.final());

    MHD_add_response_header(response, "Sec-WebSocket-Accept", accept_b64.c_str());

    if (ws_proto_matched) {
        MHD_add_response_header(response, "Sec-WebSocket-Protocol", ws_proto.c_str());
    }

    MHD_add_response_header(response, MHD_HTTP_HEADER_UPGRADE, "websocket");
    MHD_queue_response(conn->connection, MHD_HTTP_SWITCHING_PROTOCOLS, response);
    MHD_destroy_response(response);

    return true;
}

