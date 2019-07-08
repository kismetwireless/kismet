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

#include "kis_net_microhttpd_websocket.h"

bool Kis_Net_Httpd_Websocket_Handler::Httpd_Websocket_Upgrade(Kis_Net_Httpd_Connection *conn) {
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

    if (!FindToken(std::string(connection_hdr), std::string(MHD_HTTP_HEADER_UPGRADE), std::list<char>{' ', '\t', ','})) {
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

    if (StringTo<int>(version_hdr) != 13) {
        auto response = MHD_create_response_from_buffer(0, NULL, MHD_RESPMEM_PERSISTENT);
        MHD_add_response_header(response, "Sec-WebSocket-Version", "13");
        MHD_queue_response(conn->connection, MHD_HTTP_UPGRADE_REQUIRED, response);
        MHD_destroy_response(response);
        return false;
    }

    protocols_hdr = MHD_lookup_connection_value(conn->connection, MHD_HEADER_KIND, "Sec-WebSocket-Protocol");
    if (protocols_hdr == nullptr) {
        std::string err = "Expected WebSocket protocol header\n";
        auto response = MHD_create_response_from_buffer(err.length(), (void *) err.c_str(), MHD_RESPMEM_MUST_COPY);
        MHD_queue_response(conn->connection, 400, response);
        MHD_destroy_response(response);
        return false;
    }

    bool ws_proto_matched = false;
    for (auto p : ws_protocols) {
        if (p == protocols_hdr) {
            ws_proto_matched = true;
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

    return false;
}

