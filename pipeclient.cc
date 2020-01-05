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
#include <fcntl.h>
#include <termios.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#include "util.h"
#include "pipeclient.h"
#include "messagebus.h"
#include "pollabletracker.h"

pipe_client::pipe_client(global_registry *in_globalreg, 
        std::shared_ptr<buffer_handler_generic> in_rbhandler) :
    globalreg {Globalreg::globalreg},
    pipe_mutex {in_rbhandler->get_mutex()},
    handler {in_rbhandler},
    read_fd {-1},
    write_fd {-1} { }

pipe_client::~pipe_client() {
    // printf("~pipeclient %p\n", this);
    if (read_fd > -1) {
        close(read_fd);
        read_fd = -1;
    }

    if (write_fd > -1) {
        close(write_fd);
        write_fd = -1;
    }
}

void pipe_client::set_mutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent) {
    local_locker l(pipe_mutex);

    if (in_parent != nullptr)
        pipe_mutex = in_parent;
    else
        pipe_mutex = std::make_shared<kis_recursive_timed_mutex>();
}

int pipe_client::open_pipes(int rpipe, int wpipe) {
    local_locker lock(pipe_mutex);

    if (read_fd > -1 || write_fd > -1) {
        _MSG("Pipe client asked to bind to pipes but already connected to a "
                "pipe interface.", MSGFLAG_ERROR);
        return -1;
    }

    read_fd = rpipe;
    write_fd = wpipe;

    if (read_fd > -1) {
        fcntl(read_fd, F_SETFL, fcntl(read_fd, F_GETFL, 0) | O_NONBLOCK);
    }

    if (write_fd > -1) {
        fcntl(write_fd, F_SETFL, fcntl(write_fd, F_GETFL, 0) | O_NONBLOCK);
    }

    return 0;
}

bool pipe_client::get_connected() {
    local_shared_locker lock(pipe_mutex);

    return handler == nullptr || read_fd > -1 || write_fd > -1;
}

int pipe_client::pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    local_locker lock(pipe_mutex);

    if (handler == nullptr)
        return in_max_fd;

    int max_fd = in_max_fd;

    // If we have data waiting to be written, fill it in
    if (write_fd > -1 && handler->get_write_buffer_used()) {
        FD_SET(write_fd, out_wset);
        if (write_fd > in_max_fd)
            max_fd = write_fd;
    }

    // If we have room to read set the readfd, otherwise skip it for now
    if (read_fd > -1) {
        if (handler->get_read_buffer_available() > 0) {
            if (max_fd < read_fd)
                max_fd = read_fd;
            FD_SET(read_fd, out_rset);
        }
    }

    return max_fd;
}

int pipe_client::pollable_poll(fd_set& in_rset, fd_set& in_wset) {
    local_locker lock(pipe_mutex);

    std::stringstream msg;

    uint8_t *buf;
    size_t len;
    ssize_t ret, iret;
    size_t avail;

    if (read_fd > -1 && FD_ISSET(read_fd, &in_rset) && handler != nullptr) {
        // Allocate the biggest buffer we can fit in the ring, read as much
        // as we can at once.
        while ((avail = handler->get_read_buffer_available())) {
            len = handler->zero_copy_reserve_read_buffer_data((void **) &buf, avail);

            if ((ret = read(read_fd, buf, len)) <= 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {

                    if (ret == 0) {
                        msg << "Pipe client closing - remote side closed pipe";
                    } else {
                        msg << "Pipe client error reading - " << kis_strerror_r(errno);
                    }

                    handler->commit_read_buffer_data(buf, 0);
                    handler->buffer_error(msg.str());

                    close_pipes();

                    return 0;
                } else {
                    // Jump out of read loop
                    handler->commit_read_buffer_data(buf, 0);
                    break;
                }
            } else {
                // Insert into buffer
                iret = handler->commit_read_buffer_data(buf, ret);

                if (!iret) {
                    // Die if we couldn't insert all our data, the error is already going
                    // upstream.
                    close_pipes();
                    return 0;
                }
            }
        }
    }

    if (write_fd > -1 && FD_ISSET(write_fd, &in_wset)) {
        len = handler->get_write_buffer_used();

        // Let the caller consider doing something with a full buffer
        if (len == 0)
            handler->trigger_write_callback(0);

        if (len > 0) {
            // Peek the data into our buffer
            ret = handler->zero_copy_peek_write_buffer_data((void **) &buf, len);

            // fprintf(stderr, "debug - pipe client write - used %u peeked %u\n", len, ret);

            if ((iret = write(write_fd, buf, ret)) < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    msg << "Pipe client error writing - " << kis_strerror_r(errno);

                    handler->peek_free_write_buffer_data(buf);

                    // Push the error upstream
                    handler->buffer_error(msg.str());

                    close_pipes();

                    return 0;
                }
            } else {
                // Consume whatever we managed to write
                handler->peek_free_write_buffer_data(buf);
                handler->consume_write_buffer_data(iret);
            }

            // delete[] buf;
        }
    }

    return 0;
}

int pipe_client::flush_read() {
    local_locker lock(pipe_mutex);

    std::stringstream msg;

    uint8_t *buf;
    size_t len;
    ssize_t ret, iret;

    if (read_fd > -1 && handler != nullptr) {
        while (handler->get_read_buffer_available() && read_fd > -1) {
            len = handler->zero_copy_reserve_read_buffer_data((void **) &buf,
                    handler->get_read_buffer_available());

            if ((ret = read(read_fd, buf, len)) <= 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    if (ret == 0) {
                        msg << "Pipe client closing - remote side closed pipe";
                    } else {
                        msg << "Pipe client error reading - " << kis_strerror_r(errno);
                    }

                    handler->commit_read_buffer_data(buf, 0);
                    handler->buffer_error(msg.str());

                    close_pipes();

                    return 0;
                } else {
                    // Jump out of read loop
                    handler->commit_read_buffer_data(buf, 0);
                    break;
                }
            } else {
                iret = handler->commit_read_buffer_data(buf, ret);

                if (!iret) {
                    close_pipes();
                    return 0;
                }
            }
        }
    }

    return 0;
}

void pipe_client::close_pipes() {
    // printf("%p looking for pipe lock lock %p\n", this, &pipe_lock);
    local_locker lock(pipe_mutex);
    // printf("%p got pipe lock\n", this);

    // printf("%p closing\n", this);
    if (read_fd > -1) {
        close(read_fd);
        read_fd = -1;
    }

    if (write_fd > -1) {
        close(write_fd);
        write_fd = -1;
    }

    // printf("%p closed\n", this);
}

