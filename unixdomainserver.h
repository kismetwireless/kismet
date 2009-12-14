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

#ifndef __UNIXDOMAINSERVER_H__
#define __UNIXDOMAINSERVER_H__

#include "config.h"

#include <stdio.h>
#include <string>
#include <time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
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

// Arbitrary 64k ring by default
#define UNIX_SRV_RING_LEN (65536)

/* man 7 unix */
#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

// WARNING: EXTREME CARE should be used if using this in an environment where
// it is used on a suid-root kismet_server.  Use with a suid-root kismet_capture
// is perfectly safe, however this calls unlink() on potentially user-supplied
// data which could allow an untrusted user to call it.
//
// Since kismet no longer uses suid-root on kismet_server, and does not load plugins
// as root, this *should not* expose any avenues of attack not already available
// (ie, running as root in the first place), but the warning remains.

class UnixDomainServer : public NetworkServer {
public:
    UnixDomainServer();
    UnixDomainServer(GlobalRegistry *in_globalreg);
    virtual ~UnixDomainServer();

    // Set up the Unix-domain socket and listening
    int SetupServer(const std::string& path, int mode, bool force, 
                    unsigned int in_maxcli);

    // Enable server
    virtual int EnableServer();

    // Kill a connection by client ID
    virtual void KillConnection(int in_fd);

    // Fetch the info for a client id
    virtual int FetchClientConnectInfo(int in_clid, void *ret_info);

    // Shutdown the entire server
    virtual void Shutdown();

    virtual string GetRemoteAddr(int in_fd);

    // Set the size of ring buffers.  This ONLY affects new connections, not
    // existing!
    virtual void SetRingSize(int in_sz);

protected:
    // Broker various acceptance stuff
    virtual int Accept();

    // Validate a connection
    virtual int Validate(int in_fd);

    // Read pending bytes from the socket into the read ring buffer
    virtual int ReadBytes(int in_fd);

    // Write bytes from the write ring buffer to the socket
    virtual int WriteBytes(int in_fd);

    // Server info
    string socket_path;
    int socket_mode; /// File mode of the socket
    short int port;
    unsigned int maxcli;
    // Is it configured?
    int sv_configured;

    struct sockaddr_un serv_sock;

    // Ring length, if we resize it
    int int_ring_len;
};

#endif
