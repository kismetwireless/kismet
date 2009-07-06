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

int TcpClient::Connect(const char *in_remotehost, short int in_port) {
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
    if (connect(cli_fd, (struct sockaddr *) &client_sock, sizeof(client_sock)) < 0) {
		/*
        snprintf(errstr, 1024, "TCP client connect() failed: %s", strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		*/
		close(cli_fd);
		cli_fd = -1;
        return -1;
    }

    cl_valid = 1;

    read_buf = new RingBuffer(CLI_RING_LEN);
    write_buf = new RingBuffer(CLI_RING_LEN);

    // fprintf(stderr, "debug - TcpClient connected to %s:%hd %d\n", in_remotehost, in_port, cli_fd);

    return 1;
}

int TcpClient::ReadBytes() {
    uint8_t recv_bytes[1024];
    int ret;

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

    write_buf->FetchPtr(dptr, 1024, &dlen);

    if ((ret = write(cli_fd, dptr, dlen)) <= 0) {
		if (errno == EINTR || errno == EAGAIN)
			return 0;

        snprintf(errstr, 1024, "TCP client: Killing client fd %d write error %s",
                 cli_fd, strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    write_buf->MarkRead(ret);

    return ret;
}

