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

// A pollable-based UDP server implemented with a callback when a new source address is
// received.  Once the source is accepted, data from that source is written to the 
// returned bufferpair.  Currently focusing on receiving the TZSP protocol which is frame-based
// with no streaming component.
//
// If non-zero, after [timeout] seconds, a connection record is considered closed, the buffer
// is removed, and the timeout callback called.  It will be created as a new connection when
// new data is seen.
//
// Each packet is written to the UDP read buffer with the length of the packet as a ssize_t
// prefix.
//
// A UDP streaming listener may be required for future implementations of other protocols.
//
// Currently implemented as a receive-only datagram server, writable support will come in 
// the future if it's ever found necessary
class udp_dgram_server : public kis_pollable {
public:
    struct ipfilter {
        in_addr network;
        in_addr mask;
    };

    udp_dgram_server();
    virtual ~udp_dgram_server();

    virtual int configure_server(short int in_port, const std::string& in_bindaddress, 
            const std::vector<std::string>& in_filtervec, std::chrono::seconds in_timeout,
            size_t in_max_packet, size_t in_wbuf_sz);

    void set_new_connection_cb(std::function<std::shared_ptr<buffer_pair> (const struct sockaddr_storage *, size_t)>);
    void set_timeout_connection_cb(std::function<void (std::shared_ptr<buffer_pair>)> cb);
    
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
        std::shared_ptr<buffer_pair> bufferpair;
    };

    std::map<uint32_t, std::shared_ptr<client>> client_map;

    std::vector<ipfilter> ipfilter_vec;

    int server_fd;

    std::function<std::shared_ptr<buffer_pair> (const struct sockaddr_storage *, size_t)> connection_cb;
    std::function<void (std::shared_ptr<buffer_pair>)> timeout_cb;

};


#endif /* ifndef UDB_SERVER_H */
