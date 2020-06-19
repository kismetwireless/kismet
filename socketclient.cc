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
#include "socketclient.h"
#include "messagebus.h"
#include "pollabletracker.h"

socket_client::socket_client(int fd, std::shared_ptr<buffer_pair> in_rbhandler) :
    handler {in_rbhandler},
    cli_fd {fd},
    connected {true} { }

socket_client::~socket_client() {
    disconnect();
}

int socket_client::pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    // If we lose our socket, remove ourselves from the pollable system; we cannot re-acquire
    if (!connected)
        return -1;

    if (handler->used_wbuf() > 0) {
        FD_SET(cli_fd, out_wset);
    }

    // We always want to read data; even if the buffer is full we need to know that to
    // return an error during the read.
    FD_SET(cli_fd, out_rset);

    if (in_max_fd < cli_fd)
        return cli_fd;

    return in_max_fd;
}

int socket_client::pollable_poll(fd_set& in_rset, fd_set& in_wset) {
    std::string msg;

    char *buf;
    size_t len;
    ssize_t ret, iret;
    ssize_t rbuf_avail, wbuf_avail;

    // If we're not connected, remove ourselves from the pollable system, we cannot
    // reconnect in the same context
    if (!connected)
        return -1;

    if (FD_ISSET(cli_fd, &in_rset)) {
        // Receive the largest chunk of data we can from the socket
        while (connected && (rbuf_avail = handler->available_rbuf()) > 0) {
            len = handler->zero_copy_reserve_rbuf(&buf, rbuf_avail);

            if (len <= 0) {
                handler->commit_rbuf(buf, 0);
                break;
            }

            ret = recv(cli_fd, buf, len, MSG_DONTWAIT);

            if (ret < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Dump the commit, we didn't get any data
                    handler->commit_rbuf(buf, 0);
                    break;
                } else {
                    try {
                        throw std::runtime_error(fmt::format("socket error reading from fd {}: {} (errno {})",
                                    cli_fd, kis_strerror_r(errno), errno));
                    } catch (const std::runtime_error& e) {
                        handler->throw_error(std::current_exception());
                    }

                    disconnect();
                    return -1;
                }
            } else if (ret == 0) {
                try {
                    throw std::runtime_error(fmt::format("socket fd {} closed by remote during read: {} (errno {})",
                                cli_fd, kis_strerror_r(errno), errno));
                } catch (const std::runtime_error& e) {
                    handler->throw_error(std::current_exception());
                }

                disconnect();
                return -1;
            } else {
                iret = handler->commit_rbuf(buf, ret);

                if (!iret) {
                    try {
                        throw std::runtime_error(fmt::format("socket fd {} could not commit read data", cli_fd));
                    } catch (const std::runtime_error& e) {
                        handler->throw_error(std::current_exception());
                    }

                    disconnect();
                    return -1;
                }
            }
        }
    }

    if (connected && FD_ISSET(cli_fd, &in_wset) && (wbuf_avail = handler->used_wbuf() > 0)) {
        // Peek the entire available data
        len = handler->zero_copy_peek_wbuf(&buf, wbuf_avail);

        ret = send(cli_fd, buf, len, MSG_DONTWAIT);

        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                handler->peek_free_wbuf(buf);
                return 0;
            } else {
                try {
                    throw std::runtime_error(fmt::format("socket error writing to fd {}: {} (errno {})",
                                cli_fd, kis_strerror_r(errno), errno));
                } catch (const std::runtime_error& e) {
                    handler->throw_error(std::current_exception());
                }

                disconnect();
                return -1;
            }
        } else if (ret == 0) {
            try {
                throw std::runtime_error(fmt::format("socket fd {} closed by peer during write: {} (errno {})",
                            cli_fd, kis_strerror_r(errno), errno));
            } catch (const std::runtime_error& e) {
                handler->throw_error(std::current_exception());
            }

            disconnect();
            return -1;
        } else {
            // Consume whatever we managed to write
            handler->peek_free_wbuf(buf);
            handler->consume_wbuf(ret);
        }
    }

    return 0;
}

void socket_client::disconnect() {
    if (connected && cli_fd >= 0) 
        close(cli_fd);

    cli_fd = -1;
    connected = false;
}

bool socket_client::get_connected() {
    return connected;
}

