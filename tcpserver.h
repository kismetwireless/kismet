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

#ifndef __TCPSERVER_H__
#define __TCPSERVER_H__

#include "config.h"

#include <stdio.h>
#include <string>
#include <time.h>
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
#include <map>
#include <vector>

#include "ringbuf.h"
#include "messagebus.h"
#include "timetracker.h"
#include "netframework.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

// Arbitrary 16k ring.
#define SRV_RING_LEN (16384)

class TcpServer : public NetworkServer {
public:
    // IP filtering
    struct client_ipfilter {
        in_addr network;
        in_addr mask;
    };

    TcpServer();
    TcpServer(GlobalRegistry *in_globalreg);
    virtual ~TcpServer();

    // Set up the TCP socket and listening
    virtual int EnableServer();

    // Core select loop merge - combine FDs with the master FD list, and
    // handle a strobe across pending FDs
    virtual unsigned int MergeSet(fd_set in_rset, fd_set in_wset, 
                                  unsigned int in_max_fd,
                                  fd_set *out_rset, fd_set *out_wset);

    // Kill a connection by client ID
    virtual void KillConnection(int in_fd);

    // Shutdown the entire server
    virtual void Shutdown();

protected:
    // Accept the connection TCP-level
    virtual int TcpAccept();

    // Broker various acceptance stuff
    virtual int Accept();

    // Validate a connection by IP
    virtual int ValidateIPFilter(int in_fd);
    
    // Validate a connection
    virtual int Validate(int in_fd);
    
    // Read pending bytes from the socket into the read ring buffer
    virtual int ReadBytes(int in_fd);

    // Write bytes from the write ring buffer to the socket
    virtual int WriteBytes(int in_fd);
    
    // IP filtering
    vector<TcpServer::client_ipfilter *> ipfilter_vec;

    // Server info
    char hostname[MAXHOSTNAMELEN];

    struct sockaddr_in serv_sock;
};

#endif
