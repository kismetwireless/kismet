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

#define TCP_SELECT_TIMEOUT 100

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

/* A structure that holds a command from the client */
struct client_command {
    int client_fd;
    int stamp;
    string cmd;
};

// Client options
struct client_opt {
    client_opt() {
        send_strings = 0;
        send_packtype = 0;
    }

    bool operator== (const client_opt& op) const {
        if (send_strings != op.send_strings)
            return 0;
        if (send_packtype != op.send_packtype)
            return 0;

        return 1;
    }

    bool operator!= (const client_opt& op) const {
        if (send_strings != op.send_strings)
            return 1;
        if (send_packtype != op.send_packtype)
            return 1;

        return 0;
    }

    bool operator>= (const client_opt& op) const {
        if ((op.send_strings == -1 && send_strings == op.send_strings) &&
            (op.send_packtype == -1 && send_packtype == op.send_packtype))
            return 1;

        return 0;
    }

    int send_strings;
    int send_packtype;

};

// TCP/IP server to push data to the frontend.
// Mostly stolen from my Dominia code... I knew that would come in
// useful someday in a real context.

class TcpServer {
public:
    TcpServer();
    ~TcpServer();

    int Valid() { return sv_valid; };

    int Setup(unsigned int in_max_clients, short int in_port, const char *in_allowed);

    unsigned int MergeSet(fd_set in_set, unsigned int in_max, fd_set *out_set,
	    fd_set *outw_set);

    int FetchDescriptor() { return serv_fd; }

    void Kill(int in_fd);

    void Stale(int in_fd);

    int Poll(fd_set& in_rset, fd_set& in_wset);

    void Send(int in_fd, const char *in_data);

    void SendToAll(const char *in_data);

    // Send masked based on the client options
    void SendToAllOpts(const char *in_data, client_opt in_optmask);

    void Shutdown();

    char *FetchError() { return errstr; }

    inline int isClient(int fd) { return FD_ISSET(fd, &client_fds); }
    int HandleClient(int fd, client_command *c, fd_set *rds, fd_set *wrs);

    int GetClientOpts(int in_client, client_opt *in_opt);
    int SetClientOpts(int in_client, client_opt in_opt);

protected:
    int Accept();

    char errstr[1024];

    // Active server
    int sv_valid;

    unsigned int max_clients;

    // Server info
    short int port;
    char hostname[MAXHOSTNAMELEN];

    const char *allowed;

    // Socket items
    unsigned int serv_fd;
    struct sockaddr_in serv_sock;

    // Master list of Fd's
    fd_set server_fds;

    fd_set client_fds;
    fd_set stale_fds;

    unsigned int max_fd;

    map<int, string> client_cmdbuf;
    map<int, string> client_wrbuf;
    map<int, client_opt> client_optmap;

};

#endif
