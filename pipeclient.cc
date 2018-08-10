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

PipeClient::PipeClient(GlobalRegistry *in_globalreg, 
        std::shared_ptr<BufferHandlerGeneric> in_rbhandler) {
    globalreg = in_globalreg;
    handler = in_rbhandler;

    read_fd = -1;
    write_fd = -1;
}

PipeClient::~PipeClient() {
    local_locker lock(&pipe_lock);

    // fprintf(stderr, "debug - ~Pipeclient() %p\n", this);

    ClosePipes();

    std::shared_ptr<PollableTracker> pollabletracker =
        std::static_pointer_cast<PollableTracker>(globalreg->FetchGlobal("POLLABLETRACKER"));

    handler.reset();
}

int PipeClient::OpenPipes(int rpipe, int wpipe) {
    local_locker lock(&pipe_lock);

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

bool PipeClient::FetchConnected() {
    local_locker lock(&pipe_lock);

    return read_fd > -1 || write_fd > -1;
}

int PipeClient::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    local_locker lock(&pipe_lock);

    int max_fd = in_max_fd;

    // If we have data waiting to be written, fill it in
    if (write_fd > -1 && handler->GetWriteBufferUsed()) {
        FD_SET(write_fd, out_wset);
        if (write_fd > in_max_fd)
            max_fd = write_fd;
    }

    // If we have room to read set the readfd, otherwise skip it for now
    if (read_fd > -1) {
        if (handler->GetReadBufferAvailable() > 0) {
            if (max_fd < read_fd)
                max_fd = read_fd;
            FD_SET(read_fd, out_rset);
        }
    }

    return max_fd;
}

int PipeClient::Poll(fd_set& in_rset, fd_set& in_wset) {
    local_locker lock(&pipe_lock);

    std::stringstream msg;

    uint8_t *buf;
    size_t len;
    ssize_t ret, iret;

    // fprintf(stderr, "debug - pipeclient - poll rfd %d wfd %d\n", read_fd, write_fd);

    if (read_fd > -1 && FD_ISSET(read_fd, &in_rset)) {
        // Allocate the biggest buffer we can fit in the ring, read as much
        // as we can at once.
       
        while (handler->GetReadBufferAvailable()) {
            len = handler->ZeroCopyReserveReadBufferData((void **) &buf,
                    handler->GetReadBufferAvailable());

            // fprintf(stderr, "debug - read buffer available reserved %lu\n", len);

            if ((ret = read(read_fd, buf, len)) <= 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {

                    if (ret == 0) {
                        msg << "Pipe client closing - remote side closed pipe";
                    } else {
                        msg << "Pipe client error reading - " << kis_strerror_r(errno);
                    }

                    handler->CommitReadBufferData(buf, 0);
                    handler->BufferError(msg.str());

                    ClosePipes();

                    // fprintf(stderr, "debug - pipeclient - returning from poll\n");
                    return 0;
                } else {
                    // Jump out of read loop
                    handler->CommitReadBufferData(buf, 0);
                    break;
                }
            } else {
                // Insert into buffer
                // fprintf(stderr, "debug - pipeclient committing %lu\n", ret);
                iret = handler->CommitReadBufferData(buf, ret);

                if (!iret) {
                    // Die if we couldn't insert all our data, the error is already going
                    // upstream.
                    ClosePipes();
                    return 0;
                }
            }

            // delete[] buf;
        }
    }

    if (write_fd > -1 && FD_ISSET(write_fd, &in_wset) && 
            (len = handler->GetWriteBufferUsed()) > 0) {
        // Peek the data into our buffer
        ret = handler->ZeroCopyPeekWriteBufferData((void **) &buf, len);

        // fprintf(stderr, "debug - pipe client write - used %u peeked %u\n", len, ret);

        if ((iret = write(write_fd, buf, ret)) < 0) {
            if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                msg << "Pipe client error writing - " << kis_strerror_r(errno);

                handler->PeekFreeWriteBufferData(buf);

                ClosePipes();
                // Push the error upstream
                handler->BufferError(msg.str());
                return 0;
            }
        } else {
            // Consume whatever we managed to write
            handler->PeekFreeWriteBufferData(buf);
            handler->ConsumeWriteBufferData(iret);
        }

        // delete[] buf;
    }

    return 0;
}

int PipeClient::FlushRead() {
    local_locker lock(&pipe_lock);

    std::stringstream msg;

    uint8_t *buf;
    size_t len;
    ssize_t ret, iret;

    if (read_fd > -1) {
        // Allocate the biggest buffer we can fit in the ring, read as much
        // as we can at once.
       
        while (handler->GetReadBufferAvailable()) {
            len = handler->ZeroCopyReserveReadBufferData((void **) &buf,
                    handler->GetReadBufferAvailable());

            if ((ret = read(read_fd, buf, len)) <= 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    if (ret == 0) {
                        msg << "Pipe client closing - remote side closed pipe";
                    } else {
                        msg << "Pipe client error reading - " << kis_strerror_r(errno);
                    }

                    handler->CommitReadBufferData(buf, 0);
                    handler->BufferError(msg.str());

                    ClosePipes();

                    return 0;
                } else {
                    // Jump out of read loop
                    handler->CommitReadBufferData(buf, 0);
                    break;
                }
            } else {
                iret = handler->CommitReadBufferData(buf, ret);

                if (!iret) {
                    ClosePipes();
                    return 0;
                }
            }
        }
    }

    return 0;
}

void PipeClient::ClosePipes() {
    local_locker lock(&pipe_lock);

    if (read_fd > -1)
        close(read_fd);

    if (write_fd > -1)
        close(write_fd);

    read_fd = -1;
    write_fd = -1;
}

