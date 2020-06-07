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
#include "tcpserver2.h"
#include "ringbuf2.h"

tcp_server_v2::tcp_server_v2() :
    valid {false},
    server_fd {-1} {
    tcp_mutex.set_name("tcp_server_v2");    
}

tcp_server_v2::~tcp_server_v2() {
    shutdown();
}

void tcp_server_v2::set_new_connection_cb(std::function<void (int)> in_cb) {
    local_locker l(&tcp_mutex);
    new_connection_cb = in_cb;
}

void tcp_server_v2::remove_new_connection_cb() {
    local_locker l(&tcp_mutex);
    new_connection_cb = nullptr;
}

int tcp_server_v2::configure_server(short int in_port, unsigned int in_maxcli,
        std::string in_bindaddress, std::vector<std::string> in_filtervec) {
    local_locker l(&tcp_mutex);

    port = in_port;
    maxcli = in_maxcli;

    // Parse the filters
    for (auto i = in_filtervec.begin(); i != in_filtervec.end(); ++i) {
        auto fv = str_tokenize(*i, "/");

        ipfilter ipf;

        if (inet_aton(fv[0].c_str(), &(ipf.network)) != 1) {
            _MSG_ERROR("Unable to configure TCP server for port {}:  Unable to parse "
                    "allowed network range '{}'", in_port, fv[0]);
            return -1;
        }

        if (fv.size() == 2) {
            if (inet_aton(fv[1].c_str(), &(ipf.mask)) != 1) {
                _MSG_ERROR("Unable to configure TCP server for port {}:  Unable to parse "
                        "allowed network mask '{}'", in_port, fv[0]);
                return -1;
            }
        } else {
            inet_aton("255.255.255.255", &(ipf.mask));
        }

        ipfilter_vec.push_back(ipf);
    }

    if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
        _MSG_ERROR("Unable to configure TCP server for port {}, unable to fetch "
                "local hostname: {}", in_port, kis_strerror_r(errno));
        return -1;
    }

    memset(&serv_sock, 0, sizeof(serv_sock));
    serv_sock.sin_family = AF_INET;
    serv_sock.sin_port = htons(in_port);
    
    if (inet_pton(AF_INET, in_bindaddress.c_str(), &(serv_sock.sin_addr.s_addr)) == 0) {
        serv_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    // Make a socket that closes on execve
#ifdef SOCK_CLOEXEC
    if ((server_fd = socket(AF_INET, SOCK_CLOEXEC | SOCK_STREAM, 0)) < 0) {
        _MSG_ERROR("Unable to configure TCP server for port {}, unable to make socket: {}",
                in_port, kis_strerror_r(errno));
        return -1;
    }
#else
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        _MSG_ERROR("Unable to configure TCP server for port {}, unable to make socket: {}",
                in_port, kis_strerror_r(errno));
        return -1;
    }
    fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_CLOEXEC);
#endif

    // Set reuse addr
    int i = 2;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1) {
        _MSG_ERROR("Unable to configure TCP server for port {}, unable to set socket options: {}",
                in_port, kis_strerror_r(errno));
        close(server_fd);
        return -1;
    }

    if (::bind(server_fd, (struct sockaddr *) &serv_sock, sizeof(serv_sock)) < 0) {
        _MSG_ERROR("Unable to configure TCP server for port {}, unable to bind socket: {}",
                in_port, kis_strerror_r(errno));
        close(server_fd);
        return -1;
    }

    // Enable listening
    if (listen(server_fd, 20) < 0) {
        _MSG_ERROR("Unable to configure TCP server for port {}, unable to listen on socket: {}",
                in_port, kis_strerror_r(errno));
        close(server_fd);
        return -1;
    }

    // Set it to nonblocking 
    fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_NONBLOCK);

    valid = true;

    return 1;
}

int tcp_server_v2::pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    local_locker l(&tcp_mutex);

    int maxfd = in_max_fd;

    if (!valid)
        return -1;

    if (server_fd >= 0) {
        FD_SET(server_fd, out_rset);
        if (maxfd < server_fd)
            maxfd = server_fd;
    }

    return maxfd;
}


int tcp_server_v2::pollable_poll(fd_set& in_rset, fd_set& in_wset) {
    local_locker l(&tcp_mutex);

    if (!valid)
        return -1;

    int accept_fd = 0;
    if (server_fd >= 0 && FD_ISSET(server_fd, &in_rset)) {
        if ((accept_fd = accept_connection()) <= 0)
            return 0;

        if (!allow_connection(accept_fd)) {
            close(accept_fd);
            return 0;
        }

        if (new_connection_cb == nullptr) {
            close(accept_fd);
            _MSG_ERROR("TCP server on port {} cannot accept new connections as "
                    "no new connection callback has been registered.", port);
            return 0;
        }

        new_connection_cb(accept_fd);
    }

    return 0;
}

int tcp_server_v2::accept_connection() {
    int new_fd;
    struct sockaddr_in client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    client_len = sizeof(struct sockaddr_in);

    // Accept it as a socket which closes on execve
#ifdef SOCK_CLOEXEC
    if ((new_fd = accept4(server_fd, (struct sockaddr *) &client_addr, 
                    &client_len, SOCK_CLOEXEC)) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            _MSG_ERROR("TCP server on port {}, unable to accept connection: {}",
                    port, kis_strerror_r(errno));
            return -1;
        }

        return 0;
    }
#else
    if ((new_fd = accept(server_fd, (struct sockaddr *) &client_addr, 
                    &client_len)) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            _MSG_ERROR("TCP server on port {}, unable to accept connection: {}",
                    port, kis_strerror_r(errno));
            return -1;
        }

        return 0;
    }

    fcntl(new_fd, F_SETFL, fcntl(new_fd, F_GETFL, 0) | O_CLOEXEC);
#endif

    // Nonblocking, don't clone
    fcntl(new_fd, F_SETFL, fcntl(new_fd, F_GETFL, 0) | O_NONBLOCK);

    // Return the new fd; it is validated elsewhere and the buffer and handler
    // is made for it elsewhere
    return new_fd;
}

bool tcp_server_v2::allow_connection(int in_fd) {
    struct sockaddr_in client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    client_len = sizeof(struct sockaddr_in);

    if (getsockname(in_fd, (struct sockaddr *) &client_addr, &client_len) < 0) {
        _MSG_ERROR("TCP server on port {}, unable to accept connection, could not get socket name: {}",
                port, kis_strerror_r(errno));
        return false;
    }

    // No filtering = valid
    if (ipfilter_vec.size() == 0)
        return true;

    for (auto i = ipfilter_vec.begin(); i != ipfilter_vec.end(); ++i) {
        if ((client_addr.sin_addr.s_addr & (*i).mask.s_addr) ==
                ((*i).network.s_addr & (*i).mask.s_addr)) {
            return true;
        }
    }

    _MSG_ERROR("TCP server on port {}, refusing connection from unauthorized address {}",
            port, inet_ntoa(client_addr.sin_addr));

    return false;
}

void tcp_server_v2::shutdown() {
    local_locker l(&tcp_mutex);

    close(server_fd);

    valid = false;
}

