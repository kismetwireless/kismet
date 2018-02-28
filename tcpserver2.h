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

#ifndef __TCPSERVER_V2_H__
#define __TCPSERVER_V2_H__

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

#include "messagebus.h"
#include "globalregistry.h"
#include "buffer_handler.h"
#include "pollable.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

// New TCP server code
//
// This code replaces tcpserver and netframework with a cleaner TCP implementation
// which interacts with a bufferhandler

class TcpServerV2 : public Pollable {
public:
    struct ipfilter {
        in_addr network;
        in_addr mask;
    };

    TcpServerV2(GlobalRegistry *in_globalreg);
    virtual ~TcpServerV2();

    virtual int ConfigureServer(short int in_port, unsigned int in_maxcli,
            std::string in_bindaddress, std::vector<std::string> in_filtervec);

    virtual void KillConnection(int in_fd);
    virtual void KillConnection(std::shared_ptr<BufferHandlerGeneric> in_handler);

    virtual void Shutdown();

    virtual void SetBufferSize(unsigned int in_sz);

    // Pollable
    virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset);
    virtual int Poll(fd_set& in_rset, fd_set& in_wset);
   
    // Must be filled in
    virtual void NewConnection(std::shared_ptr<BufferHandlerGeneric> conn_handler) = 0;
protected:
    GlobalRegistry *globalreg;

    // Perform the TCP accept
    virtual int AcceptConnection();

    // Filter against the filter list
    virtual bool AllowConnection(int in_fd);

    // Allocate the connection
    virtual std::shared_ptr<BufferHandlerGeneric> AllocateConnection(int in_fd);

    bool valid;

    unsigned int ringbuf_size;

    char hostname[MAXHOSTNAMELEN];
    short int port;
    unsigned int maxcli;

    struct sockaddr_in serv_sock;

    std::vector<TcpServerV2::ipfilter> ipfilter_vec;

    int server_fd;

    // FD to handler
    std::map<int, std::shared_ptr<BufferHandlerGeneric> > handler_map;

    std::map<int, std::shared_ptr<BufferHandlerGeneric> > kill_map;

};

#endif

