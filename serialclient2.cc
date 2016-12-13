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

SerialClientV2::SerialClientV2(GlobalRegistry *in_globalreg, 
        RingbufferHandler *in_rbhandler) {
    globalreg = in_globalreg;
    handler = in_rbhandler;

    device_fd = -1;
}

SerialClientV2::~SerialClientV2() {
    Close();
}

int SerialClientV2::OpenDevice(string in_device, unsigned int in_baud) {
    stringstream msg;

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
        if (strerror_r(errno, strerrbuf, 1024) == 0) {
            msg << " - " << strerrbuf;
        }
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
            in_baud;
        if (strerror_r(errno, strerrbuf, 1024) == 0) { 
            msg << " - " << strerrbuf;
        }
        _MSG(msg.str(), MSGFLAG_ERROR);
        return -1;
    }

    device = in_device;
    baud = in_baud;

    globalreg->RegisterPollableSubsys(this);

    return 0;
}

bool SerialClientV2::FetchConnected() {
    return device_fd > -1;
}

int SerialClientV2::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    if (device_fd < 0)
        return in_max_fd;

    // If we have data waiting to be written, fill it in
    if (handler->GetWriteBufferUsed())
        FD_SET(device_fd, out_wset);

    // We always want to read data
    FD_SET(device_fd, out_rset);

    if (in_max_fd < device_fd)
        return device_fd;

    return in_max_fd;
}

int SerialClientV2::Poll(fd_set& in_rset, fd_set& in_wset) {
    stringstream msg;

    uint8_t *buf;
    size_t len;
    ssize_t ret, iret;

    if (device_fd < 0)
        return 0;

    if (FD_ISSET(device_fd, &in_rset)) {
        // Allocate the biggest buffer we can fit in the ring, read as much
        // as we can at once.
        
        len = handler->GetReadBufferFree();
        buf = new uint8_t[len];

        if ((ret = read(device_fd, buf, len)) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                // Push the error upstream if we failed to read here
                msg << "Serial client error reading from " << device << "@" << baud;
                if (strerror_r(errno, strerrbuf, 1024) == 0) { 
                    msg << " - " << strerrbuf;
                }
                handler->BufferError(msg.str());
                delete[] buf;
                Close();
                return 0;
            }
        } else {
            // Insert into buffer
            iret = handler->PutReadBufferData(buf, ret, true);

            if (iret != ret) {
                // Die if we couldn't insert all our data, the error is already going
                // upstream.
                delete[] buf;
                Close();
                return 0;
            }
        }

        delete[] buf;
    }

    if (FD_ISSET(device_fd, &in_wset)) {
        len = handler->GetWriteBufferUsed();
        buf = new uint8_t[len];

        // Peek the data into our buffer
        ret = handler->PeekWriteBufferData(buf, len);

        if ((iret = write(device_fd, buf, len)) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                // Push the error upstream
                msg << "Serial client error writing to " << device << "@" << baud;
                if (strerror_r(errno, strerrbuf, 1024) == 0) { 
                    msg << " - " << strerrbuf;
                }
                handler->BufferError(msg.str());
                delete[] buf;
                Close();
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

void SerialClientV2::Close() {
    if (device_fd > -1) {
        close(device_fd);
    }

    device_fd = -1;

    globalreg->RemovePollableSubsys(this);
}

