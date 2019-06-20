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
#include "pollabletracker.h"

TcpClientV2::TcpClientV2(GlobalRegistry *in_globalreg, 
        std::shared_ptr<BufferHandlerGeneric> in_rbhandler) :
    globalreg {Globalreg::globalreg},
    handler {in_rbhandler},
    tcp_mutex {std::make_shared<kis_recursive_timed_mutex>()} ,
    pending_connect {false}, 
    connected {false}, 
    cli_fd {-1} { }

TcpClientV2::~TcpClientV2() {
    Disconnect();
}

void TcpClientV2::SetMutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent) {
    local_locker l(tcp_mutex);

    if (in_parent != nullptr)
        tcp_mutex = in_parent;
    else
        tcp_mutex = std::make_shared<kis_recursive_timed_mutex>();
}

int TcpClientV2::Connect(std::string in_host, unsigned int in_port) {
    local_locker l(tcp_mutex);

    std::stringstream msg;

    if (connected) {
        _MSG_ERROR("TCP client asked to connect to {}:{} but is already connected "
                "to {}:{}", in_host, in_port, host, port);
        return -1;
    }

    if ((client_host = gethostbyname(in_host.c_str())) == NULL) {
        _MSG_ERROR("Could not resolve hostname {}", in_host);
        return -1;
    }

    host = in_host;
    port = in_port;

    // Don't handle connecting to all possible IPs a name can resolve to.
    // We may need to revisit this in the future if we're going to connect
    // to RR services
   
    // Make the socket to the remote end
    memset(&client_sock, 0, sizeof(client_sock));
    client_sock.sin_family = client_host->h_addrtype;
    memcpy((char *) &(client_sock.sin_addr.s_addr), client_host->h_addr_list[0],
            client_host->h_length);
    client_sock.sin_port = htons(in_port);

    if ((cli_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
        _MSG_ERROR("Could not connect to TCP server {}:{} ({} / errno {})",
                in_host, in_port, kis_strerror_r(errno), errno);
        return -1;
    }

    // Set the connection to nonblocking
    fcntl(cli_fd, F_SETFL, fcntl(cli_fd, F_GETFL, 0) | O_NONBLOCK | FD_CLOEXEC);

    int ret;

    if ((ret = connect(cli_fd, (struct sockaddr *) &client_sock, 
                    sizeof(client_sock))) < 0) {
        if (errno == EINPROGRESS) {
            pending_connect = true;
        } else {
            _MSG_ERROR("Could not connect to TCP server {}:{} ({} / errno {})",
                    in_host, in_port, kis_strerror_r(errno), errno);

            if (cli_fd >= 0)
                close(cli_fd);
            cli_fd = -1;

            connected = false;
            pending_connect = false;

            // Send the error to any listeners
            handler->BufferError(msg.str());

            return -1;
        }
    } else {
        connected = true;
        pending_connect = false;
    }

    return 0;
}

int TcpClientV2::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    local_locker l(tcp_mutex);

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
    if (handler->GetWriteBufferUsed()) {
        FD_SET(cli_fd, out_wset);
    }

    // We always want to read data
    FD_SET(cli_fd, out_rset);

    if (in_max_fd < cli_fd)
        return cli_fd;

    return in_max_fd;
}

int TcpClientV2::Poll(fd_set& in_rset, fd_set& in_wset) {
    local_locker l(tcp_mutex);
    
    std::string msg;

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
                msg = fmt::format("Could not connect to TCP server {}:{} ({} / errno {})",
                        host, port, kis_strerror_r(e), e);

                handler->BufferError(msg);

                if (cli_fd >= 0)
                    close(cli_fd);
                cli_fd = -1;
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
        // If we have pending data and the buffer is full, call the pending function immediately
        if (handler->GetReadBufferAvailable() == 0)
            handler->TriggerReadCallback(0);

        // Allocate the biggest buffer we can fit in the ring, read as much
        // as we can at once.
       
        while (connected && handler->GetReadBufferAvailable() > 0) {
            len = handler->ZeroCopyReserveReadBufferData((void **) &buf, 
                    handler->GetReadBufferAvailable());

            // We ought to never hit this because it ought to always be available
            // from the above while loop, but lets be extra cautious
            if (len <= 0) {
                handler->CommitReadBufferData(buf, 0);
                break;
            }

            ret = recv(cli_fd, buf, len, MSG_DONTWAIT);

            if (ret < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Dump the commit, we didn't get any data
                    handler->CommitReadBufferData(buf, 0);

                    break;
                } else {
                    // Push the error upstream if we failed to read here
                    msg = fmt::format("TCP client error reading from {}:{} - {} (errno {})",
                            host, port, kis_strerror_r(errno), errno);

                    // Dump the commit
                    handler->CommitReadBufferData(buf, 0);
                    handler->BufferError(msg);

                    Disconnect();
                    return 0;
                }
            } else if (ret == 0) {
                msg = fmt::format("TCP client closing connection to {}:{}, connection closed by remote",
                        host, port);
                // Dump the commit
                handler->CommitReadBufferData(buf, 0);
                handler->BufferError(msg);

                Disconnect();
                return 0;
            } else {
                // Process the data we got
                iret = handler->CommitReadBufferData(buf, ret);

                if (!iret) {
                    // Die if we couldn't insert all our data, the error is already going
                    // upstream.
                    Disconnect();
                    return 0;
                }
            }
        }
    }

    if (connected && FD_ISSET(cli_fd, &in_wset)) {
        // Peek the entire data 
        len = handler->ZeroCopyPeekWriteBufferData((void **) &buf, 
                handler->GetWriteBufferUsed());

        ret = send(cli_fd, buf, len, MSG_DONTWAIT);

        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                handler->PeekFreeWriteBufferData(buf);
                return 0;
            } else {
                msg = fmt::format("TCP client error writing to {}:{} - {} (errno {})",
                    host, port, kis_strerror_r(errno), errno);

                handler->PeekFreeWriteBufferData(buf);
                handler->BufferError(msg);

                Disconnect();
                return 0;
            }
        } else if (ret == 0) {
            msg = fmt::format("TCP client connection to {}:{} closed by remote",
                    host, port);
            handler->PeekFreeWriteBufferData(buf);
            handler->BufferError(msg);
            Disconnect();
            return 0;
        } else {
            // Consume whatever we managed to write
            handler->PeekFreeWriteBufferData(buf);
            handler->ConsumeWriteBufferData(ret);
        }
    }

    return 0;
}

void TcpClientV2::Disconnect() {
    local_locker l(tcp_mutex);

    if (pending_connect || connected) {
        if (cli_fd >= 0)
            close(cli_fd);
        cli_fd = -1;
    }

    cli_fd = -1;
    pending_connect = false;
    connected = false;
}

bool TcpClientV2::FetchConnected() {
    local_shared_locker l(tcp_mutex);

    if (connected || pending_connect)
        return true;

    return false;
}

