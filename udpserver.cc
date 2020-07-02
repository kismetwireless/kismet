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
#include "ringbuf3.h"
#include "udpserver.h"

udp_server::udp_server() :
    server_fd {-1} {
    udp_mutex.set_name("udp_server");
    }

udp_server::~udp_server() {
    shutdown();
}

void udp_server::set_new_connection_cb(std::function<std::shared_ptr<buffer_pair> (struct sockaddr_storage *, size_t)> in_cb) {
    local_locker l(&udp_mutex, "udp_server::set_new_connection_cb");
    connection_cb = in_cb;
}

void udp_server::set_timeout_connection_cb(std::function<void (std::shared_ptr<buffer_pair>)> in_cb) {
    local_locker l(&udp_mutex, "udp_server::set_timeout_connection_cb");
    timeout_cb = in_cb;
}



