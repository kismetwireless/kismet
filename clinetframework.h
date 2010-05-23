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

#ifndef __CLINETFRAMEWORK_H__
#define __CLINETFRAMEWORK_H__

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

// Basic superclass frameworks for network clients.  Same basic sctructure
// as the server framework

// Forward prototypes
class NetworkClient;
class ClientFramework;

#define CLIFRAME_FAIL_CB_PARMS	GlobalRegistry *globalreg, int in_errno, void *auxptr
typedef void (*cliframe_fail_cb)(CLIFRAME_FAIL_CB_PARMS);

#define NETCLI_CONNECT_CB_PARMS	GlobalRegistry *globalreg, int status, void *auxptr
typedef void (*netcli_connect_cb)(NETCLI_CONNECT_CB_PARMS);

// Skeleton for a network server
class NetworkClient : public Pollable {
public:
    NetworkClient();
    NetworkClient(GlobalRegistry *in_globalreg);
    virtual ~NetworkClient();

    // Register a client protocol framework
    virtual void RegisterClientFramework(ClientFramework *in_frm) {
        cliframework = in_frm;
    }

    // Is the client valid for any other ops?
    virtual int Valid() {
        return cl_valid;
    }

    // Core select loop merge - combine FDs with the master FD list, and
    // handle a strobe across pending FDs
    virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset);
    virtual int Poll(fd_set& in_rset, fd_set& in_wset);

    // Flush all output buffers if we can
    virtual int FlushRings();

    // Connect
    virtual int Connect(const char *in_remotehost, short int in_port, 
						netcli_connect_cb in_connect_cb, void *in_con_aux) = 0;
    
    // Kill the connection
    virtual void KillConnection();

    // Read, write, and mark are essentially fallthroughs directly to
    // the ringbuffers.  We actually define these since it's 
    // unlikely that they'd be drastically overridden

    // Write data 
    virtual int WriteData(void *in_data, int in_len);

    // Amount of data pending in a client ring
    virtual int FetchReadLen();

    // Read data 
    virtual int ReadData(void *ret_data, int in_max, int *ret_len);

    // Mark data as read (ie, we've extracted it and parsed it)
    virtual int MarkRead(int in_readlen);

protected:
    // Validate a connection
    virtual int Validate() = 0;
   
    // Read pending bytes from whereever into the ringbuffer
    virtual int ReadBytes() = 0;
    // Write pending bytes from the ringbuffer to whatever
    virtual int WriteBytes() = 0;

	netcli_connect_cb connect_cb;
	void *connect_aux;

    char errstr[STATUS_MAX];

    int cl_valid;
    int cli_fd;

	int connect_complete;

    GlobalRegistry *globalreg;
    ClientFramework *cliframework;

    RingBuffer *read_buf;
    RingBuffer *write_buf;

    struct sockaddr_in client_sock, local_sock;
    struct hostent *client_host;
};

// Skeleton to a protocol interface
class ClientFramework : public Pollable {
public:
    ClientFramework() {
		fprintf(stderr, "FATAL OOPS:  ClientFramework called with no globalreg\n");
		exit(1);
    };

    ClientFramework(GlobalRegistry *in_reg) {
        globalreg = in_reg;
        netclient = NULL;
		fail_cb = NULL;
		fail_aux = NULL;
		globalreg->RegisterPollableSubsys(this);
    }

    virtual ~ClientFramework() {
		globalreg->RemovePollableSubsys(this);
	};

    // Register the network server core that we use to talk out
    virtual void RegisterNetworkClient(NetworkClient *in_netc) {
        netclient = in_netc;
    }

    // Parse data 
    virtual int ParseData() = 0;

    // Kill a connection
    virtual int KillConnection() {
		if (netclient != NULL && netclient->Valid()) {
			netclient->KillConnection();
		}

		if (fail_cb != NULL)
			(*fail_cb)(globalreg, 0, fail_aux);

		return 1;
	}

    // Shutdown the protocol
    virtual int Shutdown();

	// Is the connection valid?
	virtual int Valid() {
		if (netclient == NULL) return 0;
		return netclient->Valid();
	}

	virtual int MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
		if (netclient == NULL)
			return in_max_fd;

		return netclient->MergeSet(in_max_fd, out_rset, out_wset);
	}

	virtual int Poll(fd_set& in_rset, fd_set& in_wset) {
		if (netclient == NULL)
			return 0;

		return netclient->Poll(in_rset, in_wset);
	}

	virtual void RegisterFailCB(cliframe_fail_cb in_cb, void *in_aux) {
		fail_cb = in_cb;
		fail_aux = in_aux;
	}
    
protected:
	cliframe_fail_cb fail_cb;
	void *fail_aux;

    char errstr[STATUS_MAX];

    GlobalRegistry *globalreg;
    NetworkClient *netclient;
};

#endif

