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

#ifndef __NETFRAMEWORK_H__
#define __NETFRAMEWORK_H__

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

#include "messagebus.h"
#include "timetracker.h"
#include "globalregistry.h"
#include "ringbuf.h"
#include "pollable.h"

// Basic superclass frameworks for network servers

// Forward prototypes
// NetworkServer should be subclassed into the basic TCP, SSL, UDP, etc 
// backend mechanisms that establish a server
class NetworkServer;
// ServerInterface should be subclassed into the protocol handlers that
// actually map writing to and from a client, parsing their data, etc
class ServerFramework;

// Skeleton for a network server
class NetworkServer : public Pollable {
public:
    NetworkServer();
    NetworkServer(GlobalRegistry *in_globalreg);
    virtual ~NetworkServer() { }

    // Register global infra
    virtual void RegisterGlobals(GlobalRegistry *in_reg) {
        globalreg = in_reg;
    }
    
    // Register a server framework (mirrored by the SF's registerserver
    virtual void RegisterServerFramework(ServerFramework *in_frm) {
        srvframework = in_frm;
    }

    // Is the server valid for any other ops?
    virtual int Valid() {
        return sv_valid;
    }

    // Generic stuff that every network-y server will need to do.
    // Most of this needs to be overridden

    // Core select loop merge - combine FDs with the master FD list, and
    // handle a strobe across pending FDs
    virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset);
    virtual int Poll(fd_set& in_rset, fd_set& in_wset);

    // Flush all output buffers if we can
    virtual int FlushRings();

    // Kill a connection by client ID - We define a stub that children
    // can use to do the lowlevel cleanup
    virtual void KillConnection(int in_fd);

    // Number of clients (cheat by grabbing the size of the write map)
    virtual int FetchNumClients() {
        return (int) write_buf_map.size();
    }
    
    // Fetch a set of pending client descriptors, ie, clients with
    // something in their read buffers
    virtual void FetchPendingClients(fd_set *ret_pending) {
        ret_pending = &pending_readset;
    }
   
    // Read, write, and mark are essentially fallthroughs directly to
    // the ringbuffers.  We actually define these since it's 
    // unlikely that they'd be drastically overridden

    // Write data to a client
    virtual int WriteData(int in_clid, void *in_data, int in_len);

    // Amount of data pending in a client ring
    virtual int FetchReadLen(int in_clid);

    // Read data from a client
    virtual int ReadData(int in_clid, void *ret_data, int in_max, int *ret_len);

    // Mark data on a client as read (ie, we've extracted it and parsed it)
    virtual int MarkRead(int in_clid, int in_readlen);

    // Fetch a vector of all the current clients for mass-writes
    virtual int FetchClientVector(vector<int> *ret_vec);

    // Fetch info about a client, cast it into whatever makes sense for the
    // future
    virtual int FetchClientConnectInfo(int in_clid, void *ret_info) = 0;

	// Fetch a clients remote address
	virtual string GetRemoteAddr(int in_fd) = 0;

    // Enable server
    virtual int EnableServer() = 0;

    // Shutdown the server
    virtual void Shutdown() = 0;

protected:
    // Broker various acceptance stuff
    virtual int Accept() = 0;
    
    // Validate a connection
    virtual int Validate(int in_fd) = 0;
   
    // Read pending bytes from whereever into the ringbuffer
    virtual int ReadBytes(int in_fd) = 0;
    // Write pending bytes from the ringbuffer to whatever
    virtual int WriteBytes(int in_fd) = 0;

    char errstr[STATUS_MAX];

    int sv_valid;
    int serv_fd;

    GlobalRegistry *globalreg;
    ServerFramework *srvframework;

    fd_set server_fdset;
    fd_set pending_readset;

    // Read ring buffers
    map<int, RingBuffer *> read_buf_map;
    // Write ring buffers
    map<int, RingBuffer *> write_buf_map;

    int max_fd;

	pthread_mutex_t write_mutex;
};

// Skeleton to a protocol interface
class ServerFramework {
public:
    ServerFramework() {
        globalreg = NULL;
        netserver = NULL;
    };

    ServerFramework(GlobalRegistry *in_reg) {
        globalreg = in_reg;
        netserver = NULL;
    }

    virtual ~ServerFramework() { };

    // Register infra globals
    virtual void RegisterGlobals(GlobalRegistry *in_reg) {
        globalreg = in_reg;
    }

    // Register the network server core that we use to talk out
    void RegisterNetworkServer(NetworkServer *in_nets) {
        netserver = in_nets;
    }

	// Is this setup valid?
	virtual int Valid() { return valid; }
    // Handle new connections
    virtual int Accept(int in_fd) = 0;

    // Parse data on a given file descriptor
    virtual int ParseData(int in_fd) = 0;

    // Kill a connection
    virtual int KillConnection(int in_fd) = 0;

    // Shutdown the protocol
    virtual int Shutdown();

	// The ring buffer was drained...  If we have anything cached in the
	// framework to try to send to the client, this is how we should do it.
	virtual int BufferDrained(int in_fd);
    
protected:
    char errstr[STATUS_MAX];
	int valid;

    GlobalRegistry *globalreg;
    NetworkServer *netserver;
};

#endif

