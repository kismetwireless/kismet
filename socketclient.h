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

#ifndef __SOCKETCLIENT_H__
#define __SOCKETCLIENT_H__

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "messagebus.h"
#include "globalregistry.h"
#include "buffer_handler.h"
#include "pollable.h"
#include "kis_mutex.h"

// Generic socket client code which operates on a bidirectional tcp socket.  It inherits
// the mutex of the provided ringbuf handler automatically.  The socket is expected to
// be created already via a tcp client connect() or a server accept()
class socket_client : public kis_pollable {
public:
    socket_client(int fd, std::shared_ptr<buffer_handler_generic> in_rbhandler);
    virtual ~socket_client();

    virtual void set_mutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent);

    virtual void disconnect();
    bool get_connected();

    // kis_pollable interface
    virtual int pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset);
    virtual int pollable_poll(fd_set& in_rset, fd_set& in_wset);

protected:
    std::shared_ptr<buffer_handler_generic> handler;

    std::shared_ptr<kis_recursive_timed_mutex> tcp_mutex;

    std::atomic<int> cli_fd;
    std::atomic<bool> connected;
};

#endif

