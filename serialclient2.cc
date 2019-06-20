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
#include "serialclient2.h"
#include "messagebus.h"
#include "pollabletracker.h"

SerialClientV2::SerialClientV2(GlobalRegistry *in_globalreg, 
        std::shared_ptr<BufferHandlerGeneric> in_rbhandler) :
    globalreg {in_globalreg},
    serial_mutex {std::make_shared<kis_recursive_timed_mutex>()},
    handler {in_rbhandler},
    device_fd {-1} { }

SerialClientV2::~SerialClientV2() {
    Close();
}

void SerialClientV2::SetMutex(std::shared_ptr<kis_recursive_timed_mutex> in_parent) {
    local_locker l(serial_mutex);

    if (in_parent != nullptr)
        serial_mutex = in_parent;
    else
        serial_mutex = std::make_shared<kis_recursive_timed_mutex>(); 
}

int SerialClientV2::OpenDevice(std::string in_device, unsigned int in_baud) {
    local_locker l(serial_mutex);

    std::stringstream msg;

    if (device_fd > -1) {
        msg << "Serial client asked to connect to " << in_device << "@" <<
            in_baud << " but already connected to " << device << "@" << baud;
        _MSG(msg.str(), MSGFLAG_ERROR);

        return -1;
    }


    device_fd = open(in_device.c_str(), O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);

    if (device_fd < 0) {
        msg << "Serial client failed to open device " << in_device << "@";
        msg << in_baud;
        msg << " - " << kis_strerror_r(errno);
        _MSG(msg.str(), MSGFLAG_ERROR);
        return -1;
    }

    struct termios options;
    tcgetattr(device_fd, &options);
    
    options.c_oflag = 0;
    options.c_iflag = 0;

	options.c_iflag &= (IXON | IXOFF | IXANY);
	options.c_cflag |= CLOCAL | CREAD;
	options.c_cflag &= ~HUPCL;

    int setbaud = 0;

    // Set the proper baud values
    switch (in_baud) {
        case 0: setbaud = B0; break;
        case 50: setbaud = B50; break;
        case 75: setbaud = B75; break;
        case 110: setbaud = B110; break;
        case 134: setbaud = B134; break;
        case 150: setbaud = B150; break;
        case 200: setbaud = B200; break;
        case 300: setbaud = B300; break;
        case 600: setbaud = B600; break;
        case 1200: setbaud = B1200; break;
        case 1800: setbaud = B1800; break;
        case 2400: setbaud = B2400; break;
        case 4800: setbaud = B4800; break;
        case 9600: setbaud = B9600; break;
        case 19200: setbaud = B19200; break;
        case 38400: setbaud = B38400; break;
    }

    cfsetispeed(&options, setbaud);
    cfsetospeed(&options, setbaud);

    if (tcsetattr(device_fd, TCSANOW, &options) < 0) {
        msg << "Serial client failed to set baud rate " << in_device << "@" <<
            in_baud << " - " << kis_strerror_r(errno);
        _MSG(msg.str(), MSGFLAG_ERROR);
        return -1;
    }

    device = in_device;
    baud = in_baud;

    return 0;
}

bool SerialClientV2::FetchConnected() {
    local_shared_locker ls(serial_mutex);

    return device_fd > -1;
}

int SerialClientV2::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    local_locker l(serial_mutex);

    if (device_fd < 0)
        return in_max_fd;

    // If we have data waiting to be written, fill it in
    if (handler->GetWriteBufferUsed())
        FD_SET(device_fd, out_wset);

    // We always want to read data if we have any space
    if (handler->GetReadBufferAvailable() > 0)
        FD_SET(device_fd, out_rset);

    if (in_max_fd < device_fd)
        return device_fd;

    return in_max_fd;
}

int SerialClientV2::Poll(fd_set& in_rset, fd_set& in_wset) {
    local_locker l(serial_mutex);

    std::stringstream msg;

    uint8_t *buf;
    size_t len;
    ssize_t ret, iret;

    if (device_fd < 0)
        return 0;

    if (FD_ISSET(device_fd, &in_rset)) {
        // Trigger an event on buffer full
        if (handler->GetReadBufferAvailable() == 0)
            handler->TriggerReadCallback(0);

        // Allocate the biggest buffer we can fit in the ring, read as much
        // as we can at once.
        
        while (handler->GetReadBufferAvailable() > 0) {
            len = handler->ZeroCopyReserveReadBufferData((void **) &buf, 
                    handler->GetReadBufferAvailable());

            if ((ret = read(device_fd, buf, len)) <= 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    // Push the error upstream if we failed to read here
                    if (ret == 0) {
                        msg << "Serial client closing " << device << "@" << baud <<
                            " - connection closed / device removed";
                    } else {
                        msg << "Serial client error reading from " << device << "@" << 
                            baud << " - " << kis_strerror_r(errno);
                    }

                    handler->CommitReadBufferData(buf, 0);
                    handler->BufferError(msg.str());

                    Close();
                    return 0;
                } else {
                    handler->CommitReadBufferData(buf, 0);
                    break;
                }
            } else {
                // Insert into buffer
                iret = handler->CommitReadBufferData(buf, ret);

                if (!iret) {
                    // Die if we couldn't insert all our data, the error is already going
                    // upstream.
                    Close();
                    return 0;
                }
            }

            // delete[] buf;
        }
    }

    if (FD_ISSET(device_fd, &in_wset)) {
        len = handler->GetWriteBufferUsed();

        // Peek the data into our buffer
        ret = handler->ZeroCopyPeekWriteBufferData((void **) &buf, len);

        if ((iret = write(device_fd, buf, ret)) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                // Push the error upstream
                msg << "Serial client error writing to " << device << "@" << baud <<
                    " - " << kis_strerror_r(errno);

                handler->PeekFreeWriteBufferData(buf);
                handler->BufferError(msg.str());

                Close();
                return 0;
            }
        } else {
            // Consume whatever we managed to write
            handler->PeekFreeWriteBufferData(buf);
            handler->ConsumeWriteBufferData(iret);
        }

        delete[] buf;
    }

    return 0;
}

void SerialClientV2::Close() {
    local_locker l(serial_mutex);

    if (device_fd > -1) {
        close(device_fd);
    }

    device_fd = -1;
}

