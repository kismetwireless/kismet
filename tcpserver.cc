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
int TcpServer::Setup(unsigned int in_max_clients, short int in_port, const char *in_allowed)
{
    max_clients = in_max_clients;
    allowed = in_allowed;

    // If we don't have a host to bind to, try to find one
    // Die violently -- If we can't bind a socket, we're useless
    if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
        snprintf(errstr, 1024, "TcpServer gethostname() failed: %s", strerror(errno));
        return (-1);
    }
    // Copy the port to our local data
    port = in_port;

    // Set up our socket
    bzero(&serv_sock, sizeof(serv_sock));
    serv_sock.sin_family = AF_INET;
    serv_sock.sin_addr.s_addr = htonl(INADDR_ANY);
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
    FD_ZERO(&except_fds);
    FD_ZERO(&client_fds);
    FD_ZERO(&stale_fds);

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
unsigned int TcpServer::MergeSet(fd_set in_set, unsigned int in_max,
                                 fd_set *out_set, fd_set *outw_set) {
    unsigned int max;

    FD_ZERO(out_set);
    FD_ZERO(outw_set);

    if (in_max < max_fd)
        max = max_fd;
    else
        max = in_max;

    for (unsigned int x = 0; x <= max; x++) {
        if (FD_ISSET(x, &in_set) || FD_ISSET(x, &server_fds)) {
            FD_SET(x, out_set);
	}
	if (FD_ISSET(x, &client_fds) && client_wrbuf[x].length() > 0) {
	    FD_SET(x, outw_set);
	}
    }

    return max;
}

int TcpServer::Poll(fd_set in_rset, fd_set in_wset, fd_set in_eset)
{
    if (!sv_valid)
        return -1;

    int accept_fd = 0;
    if (FD_ISSET(serv_fd, &in_rset))
        if ((accept_fd = Accept()) < 0)
            return -1;

    for (unsigned int fd = serv_fd; fd < max_fd; fd++) {
        if (FD_ISSET(fd, &in_eset))
            Kill(fd);
    }

    return accept_fd;
}

// Accept an incoming connection
int TcpServer::Accept()
{
    unsigned int new_fd;
    struct sockaddr_in client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    bzero(&client_addr, sizeof(struct sockaddr_in));

    client_len = sizeof(struct sockaddr_in);

    // Accept should never block, thanks to select
    if ((new_fd = accept(serv_fd, (struct sockaddr *) &client_addr,
                         &client_len)) < 0) {
        snprintf(errstr, 1024, "TcpServer accept() failed: %s\n", strerror(errno));
        return -1;
    }

    char inhost[16];

    snprintf(inhost, 16, "%s", inet_ntoa(client_addr.sin_addr));

    if (!strstr(allowed, inhost)) {
        snprintf(errstr, 1024, "TcpServer accept() connect from untrusted host %s",
                 inhost);
        close(new_fd);
        return -1;
    } else {
        snprintf(errstr, 1024, "%s", inhost);
    }

    if (new_fd > max_fd)
        max_fd = new_fd;

    // Set the file descriptor
    FD_SET(new_fd, &server_fds);
    FD_SET(new_fd, &client_fds);
    client_cmdbuf[new_fd] = "";
    client_wrbuf[new_fd] = "";

    // Set it to nonblocking.  The app logic handles all the buffering and
    // blocking.
    int save_mode = fcntl(new_fd, F_GETFL, 0);
    fcntl(new_fd, F_SETFL, save_mode | O_NONBLOCK);

    return new_fd;
}

// Kill a connection
void TcpServer::Kill(int in_fd)
{
    FD_CLR(in_fd, &server_fds);
    FD_CLR(in_fd, &client_fds);
    FD_CLR(in_fd, &stale_fds);
    client_cmdbuf[in_fd] = "";
    client_wrbuf[in_fd] = "";
    if (in_fd)
        close(in_fd);
}

//Mark an fd as "stale"; i.e. we shouldn't read or write it anymore, but
//there's still data we haven't handled.
void TcpServer::Stale(int in_fd)
{
    FD_CLR(in_fd, &server_fds);
    FD_CLR(in_fd, &client_fds);
    FD_SET(in_fd, &stale_fds);
    /* We don't clear client_cmdbuf here, since the client might have
     * spewed a bunch of commands to us and gone away before we've processed
     * them.  We may as well clear the wrbuf, though. */
    client_wrbuf[in_fd] = "";
}

void TcpServer::Send(int in_fd, const char *in_data) {
    if (in_fd < 0 || FD_ISSET(in_fd, &stale_fds)) {
        return;
    }
    client_wrbuf[in_fd] += in_data;

}

void TcpServer::SendToAll(const char *in_data) {
    for (unsigned int x = serv_fd; x <= max_fd; x++) {
        if (!FD_ISSET(x, &client_fds))
            continue;

        Send(x, in_data);
    }
}

int TcpServer::HandleClient(int fd, client_command *c, fd_set *rds, fd_set *wrs) {
    int isstale = FD_ISSET(fd, &stale_fds);

    if (!FD_ISSET(fd, &client_fds) && !isstale) {
	/* It's not a client fd */
	return 0;
    }
    
    if (FD_ISSET(fd, rds)) {
	/* Slurp in whatever data we've got into the buffer. */
	char buf[1025];
        int res = read(fd, buf, 1024);
	if (res <= 0) {
	    if (res == 0 || (errno != EAGAIN && errno != EINTR)) {
		Stale(fd);
	    }
	} else {
	    buf[res] = '\0';
	    client_cmdbuf[fd] += buf;
	}
    }

    if (client_wrbuf[fd].length() > 0 && FD_ISSET(fd, wrs)) {
	/* We can write some data to this client. */
        int res = write(fd, client_wrbuf[fd].c_str(),
                        client_wrbuf[fd].length());
	if (res <= 0) {
	    if (res == 0 || (errno != EAGAIN && errno != EINTR)) {
		Kill(fd);
            }
	} else {
	    client_wrbuf[fd].erase(0, res);
	}
    }

    /* If we're done reading from a stale fd, close it. */
    if (isstale && client_cmdbuf[fd].length() == 0) {
	Kill(fd);
	return 0;
    }

    /* See if the buffer contains a command. */
    int nl = client_cmdbuf[fd].find('\n');
    if (nl < 0) {
	return 0;
    }

    /* OK; here's a command.  Extract it from the buffer. */
    string cmdline = string(client_cmdbuf[fd], 0, nl);
    client_cmdbuf[fd].erase(0, nl+1);

    /* A command looks like:
     * '!' unsigned_int space cmd_string
     */
    int nch;
    if (sscanf(cmdline.c_str(), "!%u %n", &c->stamp, &nch) < 1) {
	/* Not a valid command. */
	return 0;
    }

    c->cmd = string(cmdline, nch);
    c->client_fd = isstale ? -1 : fd;

    return 1;
}

int TcpServer::GetClientOpts(int in_client, client_opt *in_opt) {
    if (client_optmap.find(in_client) != client_optmap.end() && FD_ISSET(in_client, &client_fds)) {
        *in_opt = client_optmap[in_client];
        return 1;
    } else if (FD_ISSET(in_client, &client_fds)) {
        client_opt ret;
        *in_opt = ret;
        return 1;
    }

    return 0;
}

int TcpServer::SetClientOpts(int in_client, client_opt in_opt) {
    if (FD_ISSET(in_client, &client_fds)) {
        client_optmap[in_client] = in_opt;
        return 1;
    }

    return 0;
}

void TcpServer::SendToAllOpts(const char *in_data, client_opt in_opt) {
    for (unsigned int x = serv_fd; x <= max_fd; x++) {
        if (!FD_ISSET(x, &client_fds))
            continue;

        // If we have settings and we don't match...
        if (client_optmap.find(x) != client_optmap.end()) {
            if (client_optmap[x] >= in_opt)
                continue;
        } else {
            continue;
        }

        Send(x, in_data);
    }

}
