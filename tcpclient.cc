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
#include "tcpclient.h"

TcpClient::TcpClient() {
    fprintf(stderr, "*** TcpClient() called with no global registry reference\n");
}

TcpClient::TcpClient(GlobalRegistry *in_globalreg) : NetworkClient(in_globalreg) {
    // Nothing special here
}

TcpClient::~TcpClient() {

}

int TcpClient::Connect(const char *in_remotehost, short int in_port,
					   netcli_connect_cb in_connect_cb, void *in_con_aux) {
	int ret;

	connect_complete = -1;

	connect_cb = in_connect_cb;
	connect_aux = in_con_aux;

    if ((client_host = gethostbyname(in_remotehost)) == NULL) {
        snprintf(errstr, 1024, "TCP client could not resolve host \"%s\"",
                 in_remotehost);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    // This doesn't handle connecting to all the different IPs a name could
    // resolve to.  Deal with this in the future.

    memset(&client_sock, 0, sizeof(client_sock));
    client_sock.sin_family = client_host->h_addrtype;
    memcpy((char *) &client_sock.sin_addr.s_addr, client_host->h_addr_list[0],
           client_host->h_length);
    client_sock.sin_port = htons(in_port);

    if ((cli_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        snprintf(errstr, 1024, "TCP client socket() call failed: %s",
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

	// fprintf(stderr, "debug - tcpcli socket() %d\n", cli_fd);

	// Make the buffers
    read_buf = new RingBuffer(CLI_RING_LEN);
    write_buf = new RingBuffer(CLI_RING_LEN);

    // Bind local half
    memset(&local_sock, 0, sizeof(local_sock));
    local_sock.sin_family = AF_INET;
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    local_sock.sin_port = htons(0);

    if (bind(cli_fd, (struct sockaddr *) &local_sock, sizeof(local_sock)) < 0) {
        snprintf(errstr, 1024, "TCP client bind() failed: %s", strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		close(cli_fd);
        return -1;
    } 

    // Set it to nonblocking
    int save_mode = fcntl(cli_fd, F_GETFL, 0);
    fcntl(cli_fd, F_SETFL, save_mode | O_NONBLOCK);

    // Connect the sockets
    if ((ret = connect(cli_fd, (struct sockaddr *) &client_sock, 
					   sizeof(client_sock))) < 0) {
		// fprintf(stderr, "debug - connect %d ret %d\n", cli_fd, ret);
		if (errno == EINPROGRESS) {
			// fprintf(stderr, "debug - %d deferred connect started\n", cli_fd);
			// We haven't completed the connection, set our connect_complete to a
			// valid value and flag it in write select
			connect_complete = 0;

			return 0;
		} else {
			close(cli_fd);
			cli_fd = -1;

			// Call the connect callback, we failed right off
			if (connect_cb != NULL)
				(*connect_cb)(globalreg, errno, connect_aux);

			return -1;
		}
    } else {
		// fprintf(stderr, "debug - %d connect complete already\n", cli_fd);
		connect_complete = 1;
		cl_valid = 1;
	}

	// Call the connect callback, we worked right off
	if (connect_cb != NULL)
		(*connect_cb)(globalreg, 0, connect_aux);

    // fprintf(stderr, "debug - TcpClient connected to %s:%hd %d\n", in_remotehost, in_port, cli_fd);

    return 1;
}

// Almost the same code as connect, annoying to have it twice, but sometimes
// we really need a synchronous connect (like for the client initial connect)
int TcpClient::ConnectSync(const char *in_remotehost, short int in_port,
						   netcli_connect_cb in_connect_cb, void *in_con_aux) {
	int ret;

	// fprintf(stderr, "debug - tcpclient connect sync\n");

	connect_complete = -1;

	connect_cb = in_connect_cb;
	connect_aux = in_con_aux;

    if ((client_host = gethostbyname(in_remotehost)) == NULL) {
        snprintf(errstr, 1024, "TCP client could not resolve host \"%s\"",
                 in_remotehost);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    // This doesn't handle connecting to all the different IPs a name could
    // resolve to.  Deal with this in the future.

    memset(&client_sock, 0, sizeof(client_sock));
    client_sock.sin_family = client_host->h_addrtype;
    memcpy((char *) &client_sock.sin_addr.s_addr, client_host->h_addr_list[0],
           client_host->h_length);
    client_sock.sin_port = htons(in_port);

    if ((cli_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        snprintf(errstr, 1024, "TCP client socket() call failed: %s",
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

	// fprintf(stderr, "debug - tcpcli socket() %d\n", cli_fd);

	// Make the buffers
    read_buf = new RingBuffer(CLI_RING_LEN);
    write_buf = new RingBuffer(CLI_RING_LEN);

    // Bind local half
    memset(&local_sock, 0, sizeof(local_sock));
    local_sock.sin_family = AF_INET;
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    local_sock.sin_port = htons(0);

    if (bind(cli_fd, (struct sockaddr *) &local_sock, sizeof(local_sock)) < 0) {
        snprintf(errstr, 1024, "TCP client bind() failed: %s", strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		close(cli_fd);
        return -1;
    } 

    // Connect the sockets
    if ((ret = connect(cli_fd, (struct sockaddr *) &client_sock, 
					   sizeof(client_sock))) < 0) {
		// fprintf(stderr, "debug - sync connect failed\n");
		close(cli_fd);
		cli_fd = -1;

		// Call the connect callback, we failed right off
		if (connect_cb != NULL)
			(*connect_cb)(globalreg, errno, connect_aux);

		return -1;
	}

	cl_valid = 1;

    // Set it to nonblocking
    int save_mode = fcntl(cli_fd, F_GETFL, 0);
    fcntl(cli_fd, F_SETFL, save_mode | O_NONBLOCK);

	// fprintf(stderr, "debug - sync connect succeeded\n");

	// Call the connect callback, we worked right off
	if (connect_cb != NULL)
		(*connect_cb)(globalreg, 0, connect_aux);

    return 1;
}

int TcpClient::ReadBytes() {
    uint8_t recv_bytes[1024];
    int ret;

	// Don't read while we're in connect stage
	if (connect_complete == 0)
		return 0;

    if ((ret = read(cli_fd, recv_bytes, 1024)) < 0) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;

        snprintf(errstr, 1024, "TCP client fd %d read() error: %s", 
                 cli_fd, strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    if (ret <= 0) {
        snprintf(errstr, 1024, "TCP client fd %d socket closed.", cli_fd);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    if (read_buf->InsertData(recv_bytes, ret) == 0) {
        snprintf(errstr, 1024, "TCP client fd %d read error, ring buffer full",
                 cli_fd);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    return ret;
}

int TcpClient::WriteBytes() {
    uint8_t dptr[1024];
    int dlen, ret;

	// Don't write while we're in connect stage
	if (connect_complete == 0)
		return 0;

    write_buf->FetchPtr(dptr, 1024, &dlen);

	if (dlen == 0) {
		_MSG("TCP client: Client fd " + IntToString(cli_fd) + " got called to "
			 "write data but has no data pending.  Check your RegisterPollable calls.",
			 MSGFLAG_ERROR);
		return 0;
	}

	// fprintf(stderr, "debug - %d writing %d bytes\n", cli_fd, dlen);

    if ((ret = write(cli_fd, dptr, dlen)) <= 0) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;

		// if (errno == EINPROGRESS) fprintf(stderr, "debug - %d ... einprog on write?  wtf?  ret %d\n", cli_fd, ret);

        snprintf(errstr, 1024, "TCP client: Killing client fd %d write error %s",
                 cli_fd, strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    write_buf->MarkRead(ret);

    return ret;
}

