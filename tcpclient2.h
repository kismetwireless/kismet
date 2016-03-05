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

#ifndef __TCPCLIENT_V2_H__
#define __TCPCLIENT_V2_H__

#include "config.h"

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "messagebus.h"
#include "globalregistry.h"
#include "ringbuf_handler.h"
#include "pollable.h"

// New TCP client code.
//
// This code replaces tcpclient and clinetframework with a cleaner TCP implementation
// which interacts with a ringbufferhandler
//
// We don't have to implement a ringbuffer interface directly, because we check the
// write buffer during the poll() sequence.  The consumer will use the ringbuffer
// interface for reading data coming in from the client.
class TcpClientV2 : public Pollable {
public:
    TcpClientV2(GlobalRegistry *in_globalreg, RingbufferHandler *in_rbhandler);
    virtual ~TcpClientV2();

    // Connect to a host, returns 0 if connection initiated and negative if fail
    int Connect(string in_host, unsigned int in_port);
    void Disconnect();

    bool FetchConnected();

    // Pollable interface
    virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset);
    virtual int Poll(fd_set& in_rset, fd_set& in_wset);

protected:
    GlobalRegistry *globalreg;
    RingbufferHandler *handler;

    bool pending_connect;
    bool connected;

    int cli_fd;
    struct sockaddr_in client_sock, local_sock;
    struct hostent *client_host;

    string host;
    unsigned int port;

    // strerror_r buffers
    char strerrbuf[1024];
    char *errstr;

};

#endif

