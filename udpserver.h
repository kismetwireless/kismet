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
#include <sys/socket.h>
#include <netinet/in.h>

#include <chrono>

#include "buffer_handler.h"
#include "buffer_pair.h"
#include "globalregistry.h"
#include "kis_mutex.h"
#include "messagebus.h"
#include "pollable.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

// A pollable-based UDP server implemented with a callback when a new source address is
// received.  Once the source is accepted, data from that source is written to the 
// returned bufferpair.
//
// If non-zero, after [timeout] seconds, 
//
// Each packet is written to the UDP buffer with the length of the packet as a uint32_t 
// prefix.
//
// Each packet to be transmitted is read from the UDP buffer with the length as a uint32_t
// prefix.
class udp_server : public kis_pollable {
public:
    struct ipfilter {
        in_addr network;
        in_addr mask;
    };

    udp_server();
    virtual ~udp_server();

    virtual int configure_server(short int in_port, const std::string& in_bindaddress, 
            const std::vector<std::string>& in_filtervec, std::chrono::seconds in_timeout);

    void set_new_connection_cb(std::function<std::shared_ptr<buffer_pair> (struct sockaddr_storage *, size_t)>);
    void set_timeout_connection_cb(std::function<void (std::shared_ptr<buffer_pair>)> cb);
    
    virtual void shutdown();

    virtual int pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) override;
    virtual int pollable_poll(fd_set& in_rset, fd_set& in_wset) override;

protected:
    kis_recursive_timed_mutex udp_mutex;

    short int port;
    std::chrono::seconds timeout_seconds;

    struct client {
        time_t last_time;
        std::shared_ptr<buffer_pair> bufferpair;
    };

    std::map<uint32_t, std::shared_ptr<client>> client_map;

    std::vector<ipfilter> ipfilter_vec;

    int server_fd;

    std::function<std::shared_ptr<buffer_pair> (struct sockaddr_storage *, size_t)> connection_cb;
    std::function<void (std::shared_ptr<buffer_pair>)> timeout_cb;

};


#endif /* ifndef UDB_SERVER_H */
