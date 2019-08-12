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

socket_client::socket_client(int fd, std::shared_ptr<buffer_handler_generic> in_rbhandler) :
    handler {in_rbhandler},
    tcp_mutex {in_rbhandler->get_mutex()} ,
    cli_fd {fd},
    connected {true} { }

socket_client::~socket_client() {
    disconnect();
}

void socket_client::set_mutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent) {
    local_locker l(tcp_mutex);

    if (in_parent != nullptr)
        tcp_mutex = in_parent;
    else
        tcp_mutex = std::make_shared<kis_recursive_timed_mutex>();
}

int socket_client::pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    local_locker l(tcp_mutex);

    // If we lose our socket, remove ourselves from the pollable system; we cannot re-acquire
    if (!connected)
        return -1;

    // If we have data waiting to be written, fill it in
    if (handler->get_write_buffer_used()) {
        FD_SET(cli_fd, out_wset);
    }

    // We always want to read data
    FD_SET(cli_fd, out_rset);

    if (in_max_fd < cli_fd)
        return cli_fd;

    return in_max_fd;
}

int socket_client::pollable_poll(fd_set& in_rset, fd_set& in_wset) {
    local_locker l(tcp_mutex);
    
    std::string msg;

    uint8_t *buf;
    size_t len;
    ssize_t ret, iret;

    // If we're not connected, remove ourselves from the pollable system, we cannot
    // reconnect in the same context
    if (!connected)
        return -1;

    if (FD_ISSET(cli_fd, &in_rset)) {
        // If we have pending data and the buffer is full, call the pending function immediately
        if (handler->get_read_buffer_available() == 0)
            handler->trigger_read_callback(0);

        // Allocate the biggest buffer we can fit in the ring, read as much
        // as we can at once.
       
        while (connected && handler->get_read_buffer_available() > 0) {
            len = handler->zero_copy_reserve_read_buffer_data((void **) &buf, 
                    handler->get_read_buffer_available());

            // We ought to never hit this because it ought to always be available
            // from the above while loop, but lets be extra cautious
            if (len <= 0) {
                handler->commit_read_buffer_data(buf, 0);
                break;
            }

            ret = recv(cli_fd, buf, len, MSG_DONTWAIT);

            if (ret < 0) {
                if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                    // Dump the commit, we didn't get any data
                    handler->commit_read_buffer_data(buf, 0);

                    break;
                } else {
                    // Push the error upstream if we failed to read here
                    msg = fmt::format("TCP socket error reading from fd {}: {} (errno {})",
                           cli_fd, kis_strerror_r(errno), errno);

                    // Dump the commit
                    handler->commit_read_buffer_data(buf, 0);
                    handler->buffer_error(msg);

                    disconnect();
                    return -1;
                }
            } else if (ret == 0) {
                msg = fmt::format("TCP socket fd {} closed by remote peer during read: {} (errno {})", 
                        cli_fd, kis_strerror_r(errno), errno);
                // Dump the commit
                handler->commit_read_buffer_data(buf, 0);
                handler->buffer_error(msg);

                disconnect();
                return -1;
            } else {
                // Process the data we got
                iret = handler->commit_read_buffer_data(buf, ret);

                if (!iret) {
                    // Die if we couldn't insert all our data, the error is already going upstream.
                    disconnect();
                    return -1;
                }
            }
        }
    }

    if (connected && FD_ISSET(cli_fd, &in_wset) && handler->get_write_buffer_used()) {
        // Peek the entire data 
        len = handler->zero_copy_peek_write_buffer_data((void **) &buf, 
                handler->get_write_buffer_used());

        ret = send(cli_fd, buf, len, MSG_DONTWAIT);

        if (ret < 0) {
            if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                handler->peek_free_write_buffer_data(buf);
                return 0;
            } else {
                msg = fmt::format("TCP socket error writing to fd {}: {} (errno {})",
                        cli_fd, kis_strerror_r(errno), errno);

                handler->peek_free_write_buffer_data(buf);
                handler->buffer_error(msg);

                disconnect();
                return -1;
            }
        } else if (ret == 0) {
            msg = fmt::format("TCP socket fd {} closed by remote peer during write: {} (errno {})", 
                    cli_fd, kis_strerror_r(errno), errno);
            handler->peek_free_write_buffer_data(buf);
            handler->buffer_error(msg);
            disconnect();
            return -1;
        } else {
            // Consume whatever we managed to write
            handler->peek_free_write_buffer_data(buf);
            handler->consume_write_buffer_data(ret);
        }
    }

    return 0;
}

void socket_client::disconnect() {
    local_locker l(tcp_mutex);

    if (connected && cli_fd >= 0) 
        close(cli_fd);

    cli_fd = -1;
    connected = false;
}

bool socket_client::get_connected() {
    local_shared_locker l(tcp_mutex);

    return connected;
}

