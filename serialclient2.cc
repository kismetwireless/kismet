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

serial_client_v2::serial_client_v2(std::shared_ptr<buffer_pair> in_rbhandler) :
    handler {in_rbhandler},
    device_fd {-1} { }

serial_client_v2::~serial_client_v2() {
    close_device();
}

int serial_client_v2::open_device(std::string in_device, unsigned int in_baud) {
    if (device_fd > -1) {
        _MSG_ERROR("Serial client tried to open device '{}'@{} baud, but there is "
                "already a device open ({})", in_device, in_baud, device);

        return -1;
    }


    device_fd = open(in_device.c_str(), O_RDWR | O_NONBLOCK | O_NOCTTY | O_CLOEXEC);

    if (device_fd < 0) {
        _MSG_ERROR("Serial client failed to open device '{}'@{} baud: {} (errno {})",
                in_device, in_baud, kis_strerror_r(errno), errno);
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
        _MSG_ERROR("Serial client failed to set baud rate {} on device '{}': {} (errno {})",
                in_baud, in_device, kis_strerror_r(errno), errno);
        return -1;
    }

    device = in_device;
    baud = in_baud;

    return 0;
}

bool serial_client_v2::get_connected() {
    return device_fd > -1;
}

int serial_client_v2::pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    if (device_fd < 0)
        return in_max_fd;

    // If we have data waiting to be written, fill it in
    if (handler->used_wbuf())
        FD_SET(device_fd, out_wset);

    // We always want to read data if we have any space
    if (handler->used_rbuf() > 0)
        FD_SET(device_fd, out_rset);

    if (in_max_fd < device_fd)
        return device_fd;

    return in_max_fd;
}

int serial_client_v2::pollable_poll(fd_set& in_rset, fd_set& in_wset) {
    char *buf;
    size_t len;
    ssize_t ret, iret;

    if (device_fd < 0)
        return 0;

    if (FD_ISSET(device_fd, &in_rset)) {
        ssize_t avail;

        while ((avail = handler->available_rbuf()) > 0) {
            len = handler->zero_copy_peek_rbuf(&buf, avail);

            if ((ret = read(device_fd, buf, len)) <= 0) {
                if (errno != EINTR && errno != EAGAIN && errno != EWOULDBLOCK) {
                    // Push the error upstream if we failed to read here
                    if (ret == 0) {
                        try {
                            throw std::runtime_error(fmt::format("Serial device '{}' closed or "
                                        "device removed", device));
                        } catch (const std::exception& e) {
                            handler->throw_error(std::current_exception());
                        }
                    } else {
                        try {
                            throw std::runtime_error(fmt::format("Error reading from serial "
                                        "device '{}': {} (errno {})",
                                        device, kis_strerror_r(errno), errno));
                        } catch (const std::exception& e) {
                            handler->throw_error(std::current_exception());
                        }
                    }

                    handler->commit_rbuf(buf, 0);

                    close_device();
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
                        throw std::runtime_error(fmt::format("Error reading from serial "
                                    "device '{}', could not commit read data", device));
                    } catch (const std::exception& e) {
                        handler->throw_error(std::current_exception());
                    }

                    close_device();
                    return 0;
                }
            }
        }
    }

    auto w_avail = handler->used_wbuf();

    if (FD_ISSET(device_fd, &in_wset) && w_avail > 0) {
        len = handler->zero_copy_peek_wbuf(&buf, w_avail);

        if ((iret = write(device_fd, buf, ret)) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                try {
                    throw std::runtime_error(fmt::format("Error writing to serial "
                                "device '{}': {} (errno {})", device, kis_strerror_r(errno), errno));
                } catch (const std::exception& e) {
                    handler->throw_error(std::current_exception());
                }

                close_device();
                return 0;
            }
        } else {
            handler->peek_free_wbuf(buf);
            handler->consume_wbuf(iret);
        }
    }

    return 0;
}

void serial_client_v2::close_device() {
    if (device_fd > -1) {
        close(device_fd);
    }

    device_fd = -1;
}

