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

#ifndef __UDB_SERVER_H__
#define __UDB_SERVER_H__ 

#include "config.h"

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#include <chrono>

#include "buffer_handler.h"
#include "buffer_pair.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "messagebus.h"
#include "pollable.h"
#include "ringbuf3.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

// A non-streaming callback-based UDP server which calls a provided cb function for each
// datagram received; currently focused on protocols like TZSP which have no streaming
// components.
//
// Basic connection filtering is handled by the UDP server code, but mapping of datagrams 
// to specific connections is left up to the callback.
//
// The timeout function is called for any source IP which has not seen traffic within the
// timeout parameter
//
// Currently implemented as a receive-only datagram server, writable support will come in 
// the future if it's ever found necessary
class udp_dgram_server : public kis_pollable {
public:
    struct ipfilter {
        in_addr network;
        in_addr mask;
    };

    using dgram_cb = std::function<void (const struct sockaddr_storage *addr, size_t addrsize, 
            uint32_t hash, const char *data, size_t len)>;
    using cancel_cb = std::function<void (uint32_t hash, bool timeout, const std::string& reason)>;

    udp_dgram_server(dgram_cb datagramcb, cancel_cb cancelcb);
    virtual ~udp_dgram_server();

    virtual int configure_server(short int in_port, const std::string& in_bindaddress, 
            const std::vector<std::string>& in_filtervec, std::chrono::seconds in_timeout,
            size_t in_max_packet, size_t in_wbuf_sz);

    virtual void shutdown();

    virtual int pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) override;
    virtual int pollable_poll(fd_set& in_rset, fd_set& in_wset) override;

protected:
    kis_recursive_timed_mutex udp_mutex;

    short int port;
    std::chrono::seconds timeout;

    size_t max_packet;
    char *packet;

    struct client {
        struct sockaddr_in addr;
        time_t last_time;
    };

    std::map<uint32_t, std::shared_ptr<client>> client_map;

    std::vector<ipfilter> ipfilter_vec;

    int server_fd;

    dgram_cb datagramcb;
    cancel_cb cancelcb;

    std::shared_ptr<time_tracker> timetracker;
    int timeout_id;


};


#endif /* ifndef UDB_SERVER_H */
