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

#include "configfile.h"

// Protocol parameters
#define PROTO_PARMS string& out_string, const vector<int> *field_vec, const void *data

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

typedef struct server_protocol {
    int ref_index;
    string header;
    int required;
    // Double-listed (burns a little extra ram but not much) to make mapping requested
    // fields fast.
    map<string, int> field_map;
    vector<string> field_vec;
    int (*printer)(PROTO_PARMS);
    void (*enable)(int);
};

// Client options
struct client_opt {
    // Map of sentence references to field lists
    map<int, vector<int> > protocols;

    string wrbuf, cmdbuf;
};

// Allowed IP information
struct client_ipblock {
    // Allowed network
    in_addr network;
    // Allowed mask
    in_addr mask;
};

// TCP/IP server to push data to the frontend.
class TcpServer {
public:
    TcpServer();
    ~TcpServer();

    int Valid() { return sv_valid; };

    int Setup(unsigned int in_max_clients, short int in_port, vector<client_ipblock *> *in_ipb);

    unsigned int MergeSet(fd_set in_set, unsigned int in_max, fd_set *out_set,
	    fd_set *outw_set);

    int FetchDescriptor() { return serv_fd; }

    void Kill(int in_fd);

    int Poll(fd_set& in_rset, fd_set& in_wset);

    // Send to a specific client, if they support that refnum
    int SendToClient(int in_fd, int in_refnum, const void *in_data);
    // Send to all clients that support the refnum
    int SendToAll(int in_refnum, const void *in_data);
    // Use a little bit of indirecton to allow kismet_server to trigger sending
    // capabilities after it sends our KISMET headers
    int SendMainProtocols(int in_fd, int proto_ref);

    void Shutdown();

    char *FetchError() { return errstr; }

    inline int isClient(int fd) { return FD_ISSET(fd, &client_fds); }
    int HandleClient(int fd, client_command *c, fd_set *rds, fd_set *wrs);

    // Register an output sentence.  This needs:
    // * A header (ie, NETWORK)
    // * A NULL-terminated array of fields
    // * A pointer to a printer that takes a void * and a vector of field numbers
    //   and outputs a c++ string
    // * An optional pointer to a function that takes the file descriptor of a client
    //   that triggers whatever events should happen the the client enables this kind
    //   of protocol.  (ie, send all networks when the client enables the *NETWORK
    //   protocol)
    // It returns the index number of the sentence added.
    int RegisterProtocol(string in_header, int in_required, char **in_fields,
                         int (*in_printer)(PROTO_PARMS),
                         void (*in_enable)(int));
    int FetchProtocolRef(string in_header);
    // How many clients are using this protocol type?
    int FetchNumClientRefs(int in_refnum);

protected:
    void AddProtocolClient(int in_fd, int in_refnum, vector<int> in_fields);
    void DelProtocolClient(int in_fd, int in_refnum);

    int RawSend(int in_fd, const char *in_data);
    int Accept();
    int HandleInternalCommand(client_command *in_command);

    // Map of reference numbers to sentences
    map<int, server_protocol *> protocol_map;
    // Map of headers to reference numbers
    map<string, int> ref_map;
    // Protocols clients are required to support
    vector<int> required_protocols;
    // Map of protocols to the number of clients using them
    map<int, int> client_mapped_protocols;

    char errstr[1024];

    // Active server
    int sv_valid;

    unsigned int max_clients;

    // Server info
    short int port;
    char hostname[MAXHOSTNAMELEN];

    vector<client_ipblock *> *ipblock_vec;

    // Socket items
    unsigned int serv_fd;
    struct sockaddr_in serv_sock;

    // Master list of Fd's
    fd_set server_fds;

    fd_set client_fds;

    unsigned int max_fd;

    map<int, client_opt *> client_optmap;
};

#endif
