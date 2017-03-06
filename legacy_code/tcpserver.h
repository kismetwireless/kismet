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

// Arbitrary 64k ring by default
#define SRV_RING_LEN (65536)

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
    virtual int SetupServer(short int in_port, unsigned int in_maxcli,
							string in_bindaddr, string in_filterstr);

    // Enable server
    virtual int EnableServer();

    // Kill a connection by client ID
    virtual void KillConnection(int in_fd);

    // Fetch the info for a client id
    virtual int FetchClientConnectInfo(int in_clid, void *ret_info);

    // Shutdown the entire server
    virtual void Shutdown();

	// Fetch the port #
	virtual short int FetchPort() { return port; }

	virtual string GetRemoteAddr(int in_fd);

	// Set the size of ring buffers.  This ONLY affects new connections, not
	// existing!
	virtual void SetRingSize(int in_sz);

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
    short int port;
    unsigned int maxcli;
	string bindaddr;

    // Is it configured?
    int sv_configured;

    struct sockaddr_in serv_sock;

	// Ring length, if we resize it
	int int_ring_len;
};

#endif
