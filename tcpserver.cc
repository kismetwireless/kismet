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

#include "config.h"

#include <stdio.h>
#include "tcpserver.h"

// Near-useless constructor, allthe work is done in Setup(...)
TcpServer::TcpServer()
{
    sv_valid = 0;

    // Set the serv_fd to 0 as well so we don't close() an unopen sock
    serv_fd = 0;

    max_fd = 0;
}

// The deconstructor actually does some good work.
TcpServer::~TcpServer()
{
    // Invalidate us immediately
    sv_valid = 0;
}

void TcpServer::Shutdown() {
    // Invalidate us immediately
    sv_valid = 0;

    if (serv_fd)
        close(serv_fd);
}

// Bind to a port and optional hostname/interface
int TcpServer::Setup(unsigned int in_max_clients, string bind_addr, short int in_port, vector<client_ipblock *> *in_ipb)
{
    max_clients = in_max_clients;
    ipblock_vec = in_ipb;

    // If we don't have a host to bind to, try to find one
    // Die violently -- If we can't bind a socket, we're useless
    if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
        snprintf(errstr, 1024, "TcpServer gethostname() failed: %s", strerror(errno));
        return (-1);
    }
    // Copy the port to our local data
    port = in_port;

    // Set up our socket
    //bzero(&serv_sock, sizeof(serv_sock));
    memset(&serv_sock, 0, sizeof(serv_sock));
    serv_sock.sin_family = AF_INET;
    if (! inet_pton(AF_INET, bind_addr.c_str(), &serv_sock.sin_addr.s_addr)) {
        serv_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    serv_sock.sin_port = htons(port);

    // Debug("Server::Setup calling socket()");
    if ((serv_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        snprintf(errstr, 1024, "TcpServer socket() failed: %s", strerror(errno));
        return (-3);
    }

    // Debug("Server::Setup setting socket option SO_REUSEADDR");
    int i = 2;
    if (setsockopt(serv_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1) {
        snprintf(errstr, 1024, "TcpServer setsockopt() failed: %s", strerror(errno));
        return (-4);
    }

    // Bind the named socket
    // Debug("Server::Setup calling bind()");
    if (bind(serv_fd, (struct sockaddr *) &serv_sock, sizeof(serv_sock)) < 0) {
        snprintf(errstr, 1024, "TcpServer bind() failed: %s", strerror(errno));
        return (-5);
    }

    // Start up listening to the socket
    if (listen(serv_fd, 5) < 0) {
        snprintf(errstr, 1024, "TcpServer listen() failed: %s", strerror(errno));
        return (-6);
    }

    // Zero the FD's
    FD_ZERO(&server_fds);
    FD_ZERO(&client_fds);

    // Set the server socket
    FD_SET(serv_fd, &server_fds);
    sv_valid = 1;

    if (serv_fd > max_fd)
        max_fd = serv_fd;

    return (1);
}

// Make one useable fd_set from the fd's flagged for system-wide monitoring
// and from the fd's flagged locally for clients connecting to us.  This lets
// us do 1 big unified select().
int TcpServer::MergeSet(fd_set in_set, int in_max,
                                 fd_set *out_set, fd_set *outw_set) {
    int max;

    FD_ZERO(out_set);
    FD_ZERO(outw_set);

    if (in_max < max_fd) {
        max = max_fd;
    } else {
        max = in_max;
        max_fd = max;
    }

	for (int x = 0; x <= max; x++) {
		if (FD_ISSET(x, &in_set) || FD_ISSET(x, &server_fds)) {
			FD_SET(x, out_set);
		}
		if (FD_ISSET(x, &client_fds) && client_optmap[x]->wrbuf.length() > 0) {
			FD_SET(x, outw_set);
		}
	}

    return max;
}

int TcpServer::Poll(fd_set& in_rset, fd_set& in_wset)
{
    if (!sv_valid)
        return -1;

    int accept_fd = 0;
    if (FD_ISSET(serv_fd, &in_rset))
        if ((accept_fd = Accept()) < 0)
            return -1;

    return accept_fd;
}

// Accept an incoming connection
int TcpServer::Accept() {
    int new_fd;
    struct sockaddr_in client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    //bzero(&client_addr, sizeof(struct sockaddr_in));
    memset(&client_addr, 0, sizeof(struct sockaddr_in));

    client_len = sizeof(struct sockaddr_in);

    // Accept should never block, thanks to select
    if ((new_fd = accept(serv_fd, (struct sockaddr *) &client_addr,
                         &client_len)) < 0) {
        snprintf(errstr, 1024, "TcpServer accept() failed: %s\n", strerror(errno));
        return -1;
    }

    char inhost[16];

    snprintf(inhost, 16, "%s", inet_ntoa(client_addr.sin_addr));

    /*
    if (!strstr(allowed, inhost)) {
        snprintf(errstr, 1024, "TcpServer accept() connect from untrusted host %s",
                 inhost);
        close(new_fd);
        return -1;
    } else {
        snprintf(errstr, 1024, "%s", inhost);
        }
        */

    int legal_ip = 0;
    for (unsigned int ibvi = 0; ibvi < ipblock_vec->size(); ibvi++) {
        if ((client_addr.sin_addr.s_addr & (*ipblock_vec)[ibvi]->mask.s_addr) == (*ipblock_vec)[ibvi]->network.s_addr) {
            legal_ip = 1;
            break;
        }
    }

    if (legal_ip == 0) {
        snprintf(errstr, 1024, "TcpServer accept() connect from untrusted host %s", inhost);
        close(new_fd);
        return -1;
    } else {
        snprintf(errstr, 1024, "%s", inhost);
    }

    if (FetchNumClients() >= (int) max_clients) {
        snprintf(errstr, 1024, "TcpServer accept() max clients already connected, rejecting %s",
                 inhost);
        close(new_fd);
        return -1;
    }

    if (new_fd > max_fd)
        max_fd = new_fd;

    // Set the file descriptor
    FD_SET(new_fd, &server_fds);
    FD_SET(new_fd, &client_fds);

    // Set it to nonblocking.  The app logic handles all the buffering and
    // blocking.
    int save_mode = fcntl(new_fd, F_GETFL, 0);
    fcntl(new_fd, F_SETFL, save_mode | O_NONBLOCK);

    // Create their options
    client_opt *opt = new client_opt;
    client_optmap[new_fd] = opt;

    // Set the mandatory sentences.  We don't have to do error checking here because
    // it can't exist in the required vector if it isn't registered.
    for (unsigned int reqprot = 0; reqprot < required_protocols.size(); reqprot++) {
        int tref = required_protocols[reqprot];
        vector<int> reqfields;
        map<int, server_protocol *>::iterator spitr = protocol_map.find(tref);
        for (unsigned int fnum = 0; fnum < spitr->second->field_vec.size(); fnum++) {
            reqfields.push_back(fnum);
        }

        AddProtocolClient(new_fd, tref, reqfields);
    }

    return new_fd;
}

// Kill a connection
void TcpServer::Kill(int in_fd) {
    if (in_fd) {
		FD_CLR(in_fd, &server_fds);
		FD_CLR(in_fd, &client_fds);
        close(in_fd);
	}

    // Do a little testing here since we might not have an opt record
    map<int, client_opt *>::iterator citr = client_optmap.find(in_fd);
    if (citr != client_optmap.end()) {
		// Remove reference counts to the protocols
        for (map<int, vector<int> >::iterator clpitr = citr->second->protocols.begin();
             clpitr != citr->second->protocols.end(); ++clpitr) {
			client_mapped_protocols[clpitr->first]--;
		}

        delete citr->second;
        client_optmap.erase(citr);
    }
}

int TcpServer::RawSend(int in_fd, const char *in_data) {
    // Anything that calls this is responsible for making sure it's calling it
    // on valid data.
    client_optmap[in_fd]->wrbuf += in_data;
    return 1;
}

// Create an output string based on the clients
// This looks very complex - and it is - but almost all of the "big" ops like
// find are done with integer references.  They're cheap.
// This takes the struct to be sent and pumps it through the dynamic protocol/field
// system.
int TcpServer::SendToClient(int in_fd, int in_refnum, const void *in_data) {
    // Make sure this is a valid client
    map<int, client_opt *>::iterator opitr = client_optmap.find(in_fd);
    if (opitr == client_optmap.end()) {
        snprintf(errstr, 1024, "Illegal client %d.", in_fd);
        return -1;
    }
    client_opt *opt = opitr->second;

    // See if this client even handles this protocol...
    map<int, vector<int> >::iterator clprotitr = opt->protocols.find(in_refnum);
    if (clprotitr == opt->protocols.end())
        return 0;

    const vector<int> *fieldlist = &clprotitr->second;

    // Find this protocol now - we only do this after we're sure we want to print to
    // it.
    map<int, server_protocol *>::iterator spitr = protocol_map.find(in_refnum);
    if (spitr == protocol_map.end()) {
        snprintf(errstr, 1024, "Protocol %d not registered.", in_refnum);
        return -1;
    }
    server_protocol *prot = spitr->second;

    // Bounce through the printer function
    string fieldtext;
    if ((*prot->printer)(fieldtext, fieldlist, in_data) == -1) {
        snprintf(errstr, 1024, "%s", fieldtext.c_str());
        return -1;
    }

    // Assemble a line for them:
    // *HEADER: DATA\n
    //  16      x   1
    int nlen = 20 + fieldtext.length();
    char *outtext = new char[nlen];
    snprintf(outtext, nlen, "*%s: %s\n", prot->header.c_str(), fieldtext.c_str());
    RawSend(in_fd, outtext);
    delete[] outtext;

    return nlen;
}

int TcpServer::SendToAll(int in_refnum, const void *in_data) {
    int nsent = 0;
    for (int x = serv_fd; x <= max_fd; x++) {
        if (!FD_ISSET(x, &client_fds))
            continue;

        if (SendToClient(x, in_refnum, in_data) > 0)
            nsent++;
    }

    return nsent;
}

int TcpServer::HandleClient(int fd, client_command *c, fd_set *rds, fd_set *wrs) {
    if (!FD_ISSET(fd, &client_fds)) {
	/* It's not a client fd */
	return 0;
    }

    // Assign the iterator and freak out if we don't have an option set for this
    // client
    map<int, client_opt *>::iterator citr = client_optmap.find(fd);
    if (citr == client_optmap.end()) {
        snprintf(errstr, 1024, "No option set for client %d, killing it.", fd);
        Kill(fd);
        return -1;
    }
    client_opt *copt = citr->second;
    
    if (FD_ISSET(fd, rds)) {
	/* Slurp in whatever data we've got into the buffer. */
	char buf[2049];
        int res = read(fd, buf, 2048);
        if (res <= 0 && (errno != EAGAIN && errno != EPIPE)) {
            Kill(fd);
            return 0;
	} else {
            buf[res] = '\0';
            copt->cmdbuf += buf;
        }
    }

    if (copt->wrbuf.length() > 0) {
        /* We can write some data to this client. */
        int res = write(fd, copt->wrbuf.c_str(), copt->wrbuf.length());

        if (res <= 0) {
            if (errno != EAGAIN && errno != EINTR) {
                Kill(fd);
                return 0;
            }
        } else {
            copt->wrbuf.erase(0, res);
		}
    }

    /* See if the buffer contains a command. */
    int killbits = 0;
    size_t nl = copt->cmdbuf.find("\r\n");
    if (nl == string::npos) {
        nl = copt->cmdbuf.find('\n');
        if (nl == string::npos)
            return 0;
        else
            killbits = 1;
    } else {
        killbits = 2;
    }

    /* OK; here's a command.  Extract it from the buffer. */
    string cmdline = string(copt->cmdbuf, 0, nl);
    copt->cmdbuf.erase(0, nl+killbits);

    /* A command looks like:
     * '!' unsigned_int space cmd_string
     */
    int nch;
    if (sscanf(cmdline.c_str(), "!%u %n", &c->stamp, &nch) < 1) {
	/* Not a valid command. */
	return 0;
    }

    c->cmd = string(cmdline, nch);
    c->client_fd = fd;

    // Dispatch it to our internal handler for cap requests and opt handling
    return HandleInternalCommand(c);
}

// Process commands we handle in the server itself.  The return value controls
// if the kismet_server component handles the command
int TcpServer::HandleInternalCommand(client_command *in_command) {
    // Get the reference to the error handler - they'd better have registered
    // the error protocol... it'll just get discarded if they didn't.
    int error_ref = FetchProtocolRef("ERROR");
    int ack_ref = FetchProtocolRef("ACK");
    // Prepare the first part of our error string, should we need to use it
    char id[12];
    snprintf(id, 12, "%d ", in_command->stamp);
    string out_error = string(id);

    // Find the first space - this is the command.  If it doesn't look like something
    // we can handle, pass it on.
    size_t start = 0;
    size_t space = in_command->cmd.find(" ");
    if (space == string::npos)
        return 1;

    string com = in_command->cmd.substr(0, space);

    if (com == "CAPABILITY") {
        // Handle requesting capabilities
        start = space + 1;
        space = in_command->cmd.length();

        // Get the protocol
        com = in_command->cmd.substr(start, space-start);
        int cap_ref = FetchProtocolRef(com);
        if (cap_ref == -1) {
            out_error += "Unknown protocol " + com;
            SendToClient(in_command->client_fd, error_ref, (void *) &out_error);
            return 1;
        }
        server_protocol *sprot = protocol_map[cap_ref];

        // Send an ack
        if (in_command->stamp != 0)
            SendToClient(in_command->client_fd, ack_ref, (void *) &in_command->stamp);

        // Grab the CAPABILITY protocol reference.  Like error, this should always
        // be here and if it isn't, we just throw away this data
        int capability_ref = FetchProtocolRef("CAPABILITY");
        SendToClient(in_command->client_fd, capability_ref, (void *) sprot);

        return 0;

    } else if (com == "ENABLE") {
        // Handle requesting new protocols
        start = space + 1;
        space = in_command->cmd.find(" ", start);

        // We'll assume that we're the only thing that can handle ENABLE commands, so if it's
        // not looking like a valid remove, error out.
        if (space == string::npos) {
            out_error += "Invalid ENABLE";
            SendToClient(in_command->client_fd, error_ref, (void *) &out_error);
            return 1;
        }

        // Get the protocol
        com = in_command->cmd.substr(start, space-start);
        int add_ref = FetchProtocolRef(com);
        if (add_ref == -1) {
            out_error += "Unknown protocol " + com;
            SendToClient(in_command->client_fd, error_ref, (void *) &out_error);
            return 1;
        }
        server_protocol *sprot = protocol_map[add_ref];

        // Split all the fields and add up our vector
        start = space + 1;
        vector<int> field_vec;

        size_t end = in_command->cmd.find(",", start);

        int done = 0;
        int initial = 1;
        while (done == 0) {
            if (end == string::npos) {
                end = in_command->cmd.length();
                done = 1;
            }

            com = in_command->cmd.substr(start, end-start);
            start = end+1;
            end = in_command->cmd.find(",", start);

            // Try once to match it to * - an int compare is cheaper than a string
            if (initial) {
                if (com == "*") {
                    for (size_t fld = 0; fld < sprot->field_map.size(); fld++)
                        field_vec.push_back(fld);
                    break;
                }

                initial = 0;
            }

            map<string, int>::iterator fmitr = sprot->field_map.find(com);
            if (fmitr == sprot->field_map.end()) {
                out_error += "Unknown field '" + com + "' for protocol " + sprot->header;
                SendToClient(in_command->client_fd, error_ref, (void *) &out_error);
                return 1;
            }

            field_vec.push_back(fmitr->second);
        }

        // We're done, add this protocol to the client
        AddProtocolClient(in_command->client_fd, add_ref, field_vec);
        // And trigger the enable function, if they have one
        if (sprot->enable != NULL)
            (*sprot->enable)(in_command->client_fd);

        // Send an ack
        if (in_command->stamp != 0)
            SendToClient(in_command->client_fd, ack_ref, (void *) &in_command->stamp);

        return 0;

    } else if (com == "REMOVE") {
        // Handle removing protocols
        start = space + 1;
        space = in_command->cmd.length();

        // Get the protocol
        com = in_command->cmd.substr(start, space-start);
        int del_ref = FetchProtocolRef(com);
        if (del_ref == -1) {
            out_error += "Unknown protocol " + com;
            SendToClient(in_command->client_fd, error_ref, (void *) &out_error);
            return 1;
        }

        // Remove it
        DelProtocolClient(in_command->client_fd, del_ref);

        // Send an ack
        if (in_command->stamp != 0)
            SendToClient(in_command->client_fd, ack_ref, (void *) &in_command->stamp);

        return 0;

    } else {
        return 1;
    }

    return 0;
}

int TcpServer::SendMainProtocols(int in_fd, int in_ref) {
    return SendToClient(in_fd, in_ref, (void *) &protocol_map);
}

int TcpServer::RegisterProtocol(string in_header, int in_required, char const * const *in_fields,
                                int (*in_printer)(PROTO_PARMS),
                                void (*in_enable)(int)) {
    // First, see if we're already registered and return a -1 if we are.  You can't
    // register a protocol twice.
    if (FetchProtocolRef(in_header) != -1) {
        snprintf(errstr, 1024, "Refusing to register '%s' as it is already a registered protocol.",
                 in_header.c_str());
        return -1;
    }

    if (in_header.length() > 16) {
        snprintf(errstr, 1024, "Refusing to register '%s' as it is greater than 16 characters.",
                 in_header.c_str());
        return -1;
    }

    int refnum = protocol_map.size() + 1;

    server_protocol *sen = new server_protocol;
    sen->ref_index = refnum;
    sen->header = in_header;

    int x = 0;
    while (in_fields[x] != NULL) {
        sen->field_map[in_fields[x]] = x;
        sen->field_vec.push_back(in_fields[x]);
        x++;
    }
    sen->printer = in_printer;
    sen->enable = in_enable;
    sen->required = in_required;

    // Put us in the map
    protocol_map[refnum] = sen;
    ref_map[in_header] = refnum;

    if (in_required)
        required_protocols.push_back(refnum);

    /*
    fprintf(stderr, "TcpServer registered %sprotocol '%s', %d fields.\n",
    in_required ? "required " : "", in_header.c_str(), sen->field_vec.size());
    */

    return refnum;
}

int TcpServer::FetchProtocolRef(string in_header) {
    map<string, int>::iterator rmitr = ref_map.find(in_header);
    if (rmitr == ref_map.end())
        return -1;

    return rmitr->second;
}

int TcpServer::FetchNumClientRefs(int in_refnum) {
    map<int, int>::iterator cmpitr = client_mapped_protocols.find(in_refnum);
    if (cmpitr != client_mapped_protocols.end())
        return cmpitr->second;

    return 0;
}

void TcpServer::AddProtocolClient(int in_fd, int in_refnum, vector<int> in_fields) {
    map<int, client_opt *>::iterator citr = client_optmap.find(in_fd);
    if (citr == client_optmap.end())
        return;

    // Find out if it already exists and increment the use count if it does
    map<int, vector<int> >::iterator clpitr = citr->second->protocols.find(in_refnum);
    if (clpitr == citr->second->protocols.end())
        client_mapped_protocols[in_refnum]++;

    citr->second->protocols[in_refnum] = in_fields;
}

void TcpServer::DelProtocolClient(int in_fd, int in_refnum) {
    map<int, client_opt *>::iterator citr = client_optmap.find(in_fd);
    if (citr == client_optmap.end())
        return;

    map<int, vector<int> >::iterator clpitr = citr->second->protocols.find(in_refnum);
    if (clpitr != citr->second->protocols.end()) {
        citr->second->protocols.erase(clpitr);
        client_mapped_protocols[in_refnum]--;
    }
}

int TcpServer::FetchNumClients() {
    int num = 0;

    for (int x = serv_fd + 1; x <= max_fd; x++) {
        if (FD_ISSET(x, &client_fds))
            num++;
    }

    return num;
}
