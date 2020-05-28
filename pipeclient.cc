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

pipe_client::pipe_client(std::shared_ptr<buffer_pair> in_rbhandler) :
    handler {in_rbhandler},
    read_fd {-1},
    write_fd {-1},
    connected {false} { }

pipe_client::~pipe_client() {

    if (read_fd > -1) {
        close(read_fd);
        read_fd = -1;
    }

    if (write_fd > -1) {
        close(write_fd);
        write_fd = -1;
    }
}

int pipe_client::open_pipes(int rpipe, int wpipe) {
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

    connected = true;

    return 0;
}

int pipe_client::pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    if (handler == nullptr)
        return in_max_fd;

    int max_fd = in_max_fd;

    if (write_fd > -1 && handler->used_wbuf()) {
        FD_SET(write_fd, out_wset);
        if (write_fd > in_max_fd)
            max_fd = write_fd;
    }

    if (read_fd > -1) {
        if (handler->used_rbuf() > 0) {
            if (max_fd < read_fd)
                max_fd = read_fd;
            FD_SET(read_fd, out_rset);
        }
    }

    return max_fd;
}

int pipe_client::pollable_poll(fd_set& in_rset, fd_set& in_wset) {
    char *buf;
    size_t len;

    ssize_t ret, iret;
    size_t avail;

    if (read_fd > -1 && FD_ISSET(read_fd, &in_rset) && handler != nullptr) {
        // Allocate the biggest buffer we can fit in the ring, read as much
        // as we can at once.
        while ((avail = handler->available_rbuf())) {
            len = handler->zero_copy_reserve_rbuf(&buf, avail);

            if ((ret = read(read_fd, buf, len)) <= 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {

                    if (ret == 0) {
                        try {
                            throw std::runtime_error(fmt::format("pipe fd {} closing during read, remote closed",
                                        read_fd));
                        } catch (const std::runtime_error& e) {
                            handler->throw_error(std::current_exception());
                        }
                    } else {
                        try {
                            throw std::runtime_error(fmt::format("pipe fd {} error reading: {} (errno {})",
                                        read_fd, kis_strerror_r(errno), errno));
                        } catch (const std::runtime_error& e) {
                            handler->throw_error(std::current_exception());
                        }
                    }

                    close_pipes();

                    return 0;
                } else {
                    handler->commit_rbuf(buf, 0);
                    break;
                }
            } else {
                // Insert into buffer
                iret = handler->commit_rbuf(buf, ret);

                if (!iret) {
                    try {
                        throw std::runtime_error(fmt::format("pipe fd {} could not commit read data", read_fd));
                    } catch (const std::runtime_error& e) {
                        handler->throw_error(std::current_exception());
                    }

                    close_pipes();
                    return 0;
                }
            }
        }
    }

    if (write_fd > -1 && FD_ISSET(write_fd, &in_wset)) {
        len = handler->used_wbuf();

        if (len > 0) {
            ret = handler->zero_copy_peek_wbuf(&buf, len);

            if ((iret = write(write_fd, buf, ret)) < 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    try {
                        throw std::runtime_error(fmt::format("pipe fd {} error writing: {} (errno {})",
                                    write_fd, kis_strerror_r(errno), errno));
                    } catch (const std::runtime_error& e) {
                        handler->throw_error(std::current_exception());
                    }

                    close_pipes();
                    return 0;
                }
            } else {
                handler->peek_free_wbuf(buf);
                handler->consume_wbuf(iret);
            }
        }
    }

    return 0;
}

void pipe_client::close_pipes() {
    if (read_fd > -1) {
        close(read_fd);
        read_fd = -1;
    }

    if (write_fd > -1) {
        close(write_fd);
        write_fd = -1;
    }

    connected = false;
}

