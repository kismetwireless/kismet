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

TcpServerV2::TcpServerV2(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;
    valid = false;
    
    server_fd = -1;

    ringbuf_size = 128 * 1024;
}

TcpServerV2::~TcpServerV2() {
    Shutdown();
}

void TcpServerV2::SetRingbufSize(unsigned int in_sz) {
    ringbuf_size = in_sz;
}

int TcpServerV2::ConfigureServer(short int in_port, unsigned int in_maxcli,
        string in_bindaddress, vector<string> in_filtervec) {
    port = in_port;
    maxcli = in_maxcli;

    // Parse the filters
    for (auto i = in_filtervec.begin(); i != in_filtervec.end(); ++i) {
        vector<string> fv = StrTokenize(*i, "/");

        ipfilter ipf;

        if (inet_aton(fv[0].c_str(), &(ipf.network)) != 1) {
            _MSG("TCP server unable to parse allowed network range '" + 
                    fv[0] + "'", MSGFLAG_ERROR);
            return -1;
        }

        if (fv.size() == 2) {
            if (inet_aton(fv[1].c_str(), &(ipf.mask)) != 1) {
                _MSG("TCP server unable to parse allowed network mask '" +
                        fv[1] + "'", MSGFLAG_ERROR);
                return -1;
            }
        } else {
            inet_aton("255.255.255.255", &(ipf.mask));
        }

        ipfilter_vec.push_back(ipf);
    }

    if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
        _MSG("TCP server gethostname() failed: " + kis_strerror_r(errno),
                MSGFLAG_ERROR);
        return -1;
    }

    memset(&serv_sock, 0, sizeof(serv_sock));
    serv_sock.sin_family = AF_INET;
    serv_sock.sin_port = htons(in_port);
    
    if (inet_pton(AF_INET, in_bindaddress.c_str(), &(serv_sock.sin_addr.s_addr)) == 0) {
        serv_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        _MSG("TCP server socket() failed: " + kis_strerror_r(errno),
                MSGFLAG_ERROR);
        return -1;
    }

    // Set reuse addr
    int i = 2;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1) {
        _MSG("TCP server setsockopt(REUSEADDR) failed: " + kis_strerror_r(errno),
                MSGFLAG_ERROR);
        close(server_fd);
        return -1;
    }

    if (::bind(server_fd, (struct sockaddr *) &serv_sock, sizeof(serv_sock)) < 0) {
        _MSG("TCP server bind() failed: " + kis_strerror_r(errno),
                MSGFLAG_ERROR);
        close(server_fd);
        return -1;
    }

    // Set it to nonblocking and close it when we exec
    fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_NONBLOCK | FD_CLOEXEC);

    // Enable listening
    if (listen(server_fd, 20) < 0) {
        _MSG("TCP server listen() failed : " + kis_strerror_r(errno),
                MSGFLAG_ERROR);
        close(server_fd);
        return -1;
    }

    valid = true;

    return 1;
}

int TcpServerV2::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    int maxfd = in_max_fd;

    if (server_fd >= 0) {
        FD_SET(server_fd, out_rset);
        if (maxfd < server_fd)
            maxfd = server_fd;
    }

    for (auto i = handler_map.begin(); i != handler_map.end(); ++i) {
        if (i->second->GetReadBufferFree() != 0) {
            FD_SET(i->first, out_rset);

            if (maxfd < i->first)
                maxfd = i->first;
        }

        if (i->second->GetWriteBufferUsed() != 0) {
            FD_SET(i->first, out_wset);

            if (maxfd < i->first)
                maxfd = i->first;
        }
    }

    return maxfd;
}


int TcpServerV2::Poll(fd_set& in_rset, fd_set& in_wset) {
    stringstream msg;
    int ret, iret;
    size_t len;
    uint8_t *buf;

    if (valid)
        return -1;

    int accept_fd = 0;
    if (server_fd >= 0 && FD_ISSET(server_fd, &in_rset)) {
        if ((accept_fd = AcceptConnection()) < 0)
            return 0;

        if (!AllowConnection(accept_fd)) {
            KillConnection(accept_fd);
            return 0;
        }

        shared_ptr<RingbufferHandler> con_handler = AllocateConnection(accept_fd);

        if (con_handler == NULL) {
            KillConnection(accept_fd);
            return 0;
        }

        handler_map.emplace(accept_fd, con_handler);

        NewConnection(con_handler);
    }

    for (auto i = handler_map.begin();
            i != handler_map.end(); ++i) {

        // Process incoming data
        if (FD_ISSET(i->first, &in_rset)) {
            // Read only as much as we have free in the buffer
            len = i->second->GetReadBufferFree();
            buf = new uint8_t[len];

            if ((ret = read(i->first, buf, len)) < 0) {
                if (errno != EINTR && errno != EAGAIN) {
                    // Push the error upstream if we failed to read here
                    msg << "TCP server error reading from client " << i->first << 
                        " - " << kis_strerror_r(errno);
                    i->second->BufferError(msg.str());
                    delete[] buf;
                    KillConnection(i->first);
                    return 0;
                }
            } else {
                // Insert into buffer
                iret = i->second->PutReadBufferData(buf, ret, true);

                if (iret != ret) {
                    // Die if we somehow couldn't insert all our data once we
                    // read it from the socket since we can't put it back on the
                    // input queue.  This should never happen because we're the
                    // only input source but we'll handle it
                    delete[] buf;
                    KillConnection(i->first);
                    return 0;
                }
            }

            delete[] buf;
        }

        if (FD_ISSET(i->first, &in_wset)) {
            len = i->second->GetWriteBufferUsed();
            buf = new uint8_t[len];

            // Peek the data into our buffer
            ret = i->second->PeekWriteBufferData(buf, len);

            if ((iret = write(i->first, buf, len)) < 0) {
                if (errno != EINTR && errno != EAGAIN) {
                    // Push the error upstream
                    msg << "TCP server error writing to client " << i->first <<
                        " - " << kis_strerror_r(errno);
                    i->second->BufferError(msg.str());
                    delete[] buf;
                    KillConnection(i->first);
                    return 0;
                }
            } else {
                // Consume whatever we managed to write
                i->second->GetWriteBufferData(NULL, iret);
            }

            delete[] buf;
        }
    }

    return 0;
}

void TcpServerV2::KillConnection(int in_fd) {
    if (in_fd < 0)
        return;

    auto i = handler_map.find(in_fd);

    if (i != handler_map.end()) {
        i->second->BufferError("TCP connection closed");
        handler_map.erase(i);
    }

    close(in_fd);
}

void TcpServerV2::KillConnection(shared_ptr<RingbufferHandler> in_handler) {
    for (auto i = handler_map.begin(); i != handler_map.end(); ++i) {
        if (i->second == in_handler) {
            close(i->first);
            handler_map.erase(i);
            i->second->BufferError("TCP connection closed");
            return;
        }
    }
}

int TcpServerV2::AcceptConnection() {
    int new_fd;
    struct sockaddr_in client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    client_len = sizeof(struct sockaddr_in);

    if ((new_fd = accept(server_fd, (struct sockaddr *) &client_addr, 
                    &client_len)) < 0) {
        _MSG("TCP server accept() failed: " + kis_strerror_r(errno),
                MSGFLAG_ERROR);
        return -1;
    }

    if (handler_map.size() >= maxcli) {
        _MSG("TCP server maximum number of clients reached, cannot accept new "
                "connection.", MSGFLAG_ERROR);
        close(new_fd);
        return -1;
    }

    // Nonblocking, don't clone
    fcntl(new_fd, F_SETFL, fcntl(new_fd, F_GETFL, 0) | O_NONBLOCK | FD_CLOEXEC);

    // Return the new fd; it is validated elsewhere and the ringbuffer and handler
    // is made for it elsewhere
    return new_fd;
}

bool TcpServerV2::AllowConnection(int in_fd) {
    struct sockaddr_in client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    client_len = sizeof(struct sockaddr_in);

    if (getsockname(in_fd, (struct sockaddr *) &client_addr, &client_len) < 0) {
        _MSG("TCP server failed getsockname(): " + kis_strerror_r(errno),
                MSGFLAG_ERROR);
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

    string reject = string(inet_ntoa(client_addr.sin_addr));
    _MSG("TCP server rejected connection from untrusted IP " + reject,
            MSGFLAG_ERROR);

    return false;
}

shared_ptr<RingbufferHandler> TcpServerV2::AllocateConnection(int in_fd __attribute__((unused))) {
    // Basic allocation
    shared_ptr<RingbufferHandler> rbh(new RingbufferHandler(ringbuf_size, 
                ringbuf_size));  

    // Protocol errors kill the connection
    rbh->SetProtocolErrorCb([this, in_fd]() {
        KillConnection(in_fd);
    });

    return rbh;
}

void TcpServerV2::Shutdown() {
    for (auto i = handler_map.begin(); i != handler_map.end(); ++i) {
        KillConnection(i->first);
    }

    close(server_fd);

    valid = false;
}

