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
#include "buffer_pair.h"
#include "pollable.h"
#include "kis_mutex.h"


// Socket communication client, operates on any socket which supports recv/send semantics,
// connects to a buffer_pair and common_buffer_v2
class socket_client_v2 : public kis_pollable {
public:
    socket_client_v2(int fd, std::shared_ptr<buffer_pair> in_pair);
    virtual ~socket_client_v2();

    virtual void disconnect();
    bool connected();

    // kis_pollable interface
    virtual int pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset);
    virtual int pollable_poll(fd_set& in_rset, fd_set& in_wset);

protected:
    std::shared_ptr<buffer_pair> bufferpair;

    std::atomic<int> cli_fd;
};

#endif

