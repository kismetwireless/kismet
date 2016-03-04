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

#include <sstream>
#include <netdb.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "tcpclient2.h"
#include "messagebus.h"

TcpClientV2::TcpClientV2(GlobalRegistry *in_globalreg, 
        RingbufferHandler *in_rbhandler) {
    globalreg = in_globalreg;
    handler = in_rbhandler;

    cli_fd = -1;
    connected = false;
    pending_connect = false;
}

TcpClientV2::~TcpClientV2() {
    Disconnect();
}

int TcpClientV2::Connect(string in_host, unsigned int in_port) {
    stringstream msg;

    if (connected) {
        msg << "TCP client asked to connect to " << in_host << ":" <<
            in_port << " but already connected to " << host << ":" << port;
        _MSG(msg.str(), MSGFLAG_ERROR);

        return -1;
    }

    if ((client_host = gethostbyname(in_host.c_str())) == NULL) {
        msg << "TCP client could not resolve host \"" << in_host << "\"";
        _MSG(msg.str(), MSGFLAG_ERROR);

        return -1;
    }

    // Don't handle connecting to all possible IPs a name can resolve to.
    // We may need to revisit this in the future if we're going to connect
    // to RR services
   
    // Make the socket to the remote end
    memset(&client_sock, 0, sizeof(client_sock));
    client_sock.sin_family = client_host->h_addrtype;
    memcpy((char *) &(client_sock.sin_addr.s_addr), client_host->h_addr_list[0],
            client_host->h_length);
    client_sock.sin_port = htons(in_port);

    if ((cli_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        errstr = strerror_r(errno, strerrbuf, 1024);
        msg << "TCP client could not connect to " << in_host << ":" << in_port <<
            " - " << errstr;
        _MSG(msg.str(), MSGFLAG_ERROR);
        return -1;
    }

    // Bind the local socket
    memset(&local_sock, 0, sizeof(local_sock));
    local_sock.sin_family = AF_INET;
    local_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    local_sock.sin_port = htons(0);

    if (bind(cli_fd, (struct sockaddr *) &local_sock, sizeof(local_sock)) < 0) {
        errstr = strerror_r(errno, strerrbuf, 1024);
        msg << "TCP client could not connect to " << in_host << ":" << in_port <<
            " - " << errstr;
        _MSG(msg.str(), MSGFLAG_ERROR);
        close(cli_fd);
        return -1;
    }

    // Set the connection to nonblocking
    fcntl(cli_fd, F_SETFL, fcntl(cli_fd, F_GETFL, 0) | O_NONBLOCK);

    int ret;

    if ((ret = connect(cli_fd, (struct sockaddr *) &client_sock, 
                    sizeof(client_sock))) < 0) {
        if (errno == EINPROGRESS) {
            pending_connect = true;
            return 0;
        } else {
            close(cli_fd);
            cli_fd = -1;

            connected = false;
            pending_connect = false;

            errstr = strerror_r(errno, strerrbuf, 1024);
            msg << "TCP client could not connect to " << in_host << ":" << in_port <<
                " - " << errstr;
            _MSG(msg.str(), MSGFLAG_ERROR);

            // Send the error to any listeners
            handler->BufferError(msg.str());

            return -1;
        }
    } else {
        connected = true;
        pending_connect = false;
    }

    host = in_host;
    port = in_port;

    return 0;
}

int TcpClientV2::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    // All we fill in is the descriptor for writing if we're still trying to
    // connect
    if (pending_connect) {
        FD_SET(cli_fd, out_wset);
        if (in_max_fd < cli_fd)
            return cli_fd;
        return in_max_fd;
    }

    if (!connected)
        return in_max_fd;

    // If we have data waiting to be written, fill it in
    if (handler->GetWriteBufferUsed())
        FD_SET(cli_fd, out_wset);

    // We always want to read data
    FD_SET(cli_fd, out_rset);

    if (in_max_fd < cli_fd)
        return cli_fd;

    return in_max_fd;
}

int TcpClientV2::Poll(fd_set& in_rset, fd_set& in_wset) {
    stringstream msg;

    uint8_t *buf;
    size_t len;
    ssize_t ret, iret;

    if (pending_connect) {
        // See if connect has completed
        if (FD_ISSET(cli_fd, &in_wset)) {
            int r, e;
            socklen_t l;

            e = 0;
            l = sizeof(int);

            r = getsockopt(cli_fd, SOL_SOCKET, SO_ERROR, &e, &l);

            if (r < 0 || e != 0) {
                errstr = strerror_r(errno, strerrbuf, 1024);
                msg << "TCP client could not connect to " << host << ":" << port <<
                    " - " << errstr;
                _MSG(msg.str(), MSGFLAG_ERROR);

                handler->BufferError(msg.str());

                close(cli_fd);
                connected = false;
                pending_connect = false;
                return 0;
            } else {
                connected = true;
                pending_connect = false;
            }

            return 0;
        }

        // Nothing else to do if we haven't finished connecting
        return 0;
    }

    if (!connected)
        return 0;

    if (FD_ISSET(cli_fd, &in_rset)) {
        // Allocate the biggest buffer we can fit in the ring, read as much
        // as we can at once.
        
        len = handler->GetReadBufferFree();
        buf = new uint8_t[len];

        if ((ret = read(cli_fd, buf, len)) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                // Push the error upstream if we failed to read here
                errstr = strerror_r(errno, strerrbuf, 1024);
                msg << "TCP client error reading from " << host << ":" << port << 
                    " - " << errstr;
                handler->BufferError(msg.str());
                delete[] buf;
                Disconnect();
                return 0;
            }
        } else {
            // Insert into buffer
            iret = handler->PutReadBufferData(buf, ret);

            if (iret != ret) {
                // Die if we couldn't insert all our data, the error is already going
                // upstream.
                delete[] buf;
                Disconnect();
                return 0;
            }
        }

        delete[] buf;
    }

    if (FD_ISSET(cli_fd, &in_wset)) {
        len = handler->GetWriteBufferUsed();
        buf = new uint8_t[len];

        // Peek the data into our buffer
        ret = handler->PeekWriteBufferData(buf, len);

        if ((iret = write(cli_fd, buf, len)) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                // Push the error upstream
                errstr = strerror_r(errno, strerrbuf, 1024);
                msg << "TCP client error writing to " << host << ":" << port << 
                    " - " << errstr;
                handler->BufferError(msg.str());
                delete[] buf;
                Disconnect();
                return 0;
            }
        } else {
            // Consume whatever we managed to write
            handler->GetWriteBufferData(NULL, iret);
        }

        delete[] buf;
    }

    return 0;
}

void TcpClientV2::Disconnect() {
    if (pending_connect || connected) {
        close(cli_fd);
    }

    cli_fd = -1;
    pending_connect = false;
    connected = false;
}

