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

TcpServerV2::TcpServerV2(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;
    valid = false;
    
    server_fd = -1;

    ringbuf_size = 128 * 1024;
}

TcpServerV2::~TcpServerV2() {
    Shutdown();
}

void TcpServerV2::SetBufferSize(unsigned int in_sz) {
    ringbuf_size = in_sz;
}

int TcpServerV2::ConfigureServer(short int in_port, unsigned int in_maxcli,
        std::string in_bindaddress, std::vector<std::string> in_filtervec) {
    port = in_port;
    maxcli = in_maxcli;

    // Parse the filters
    for (auto i = in_filtervec.begin(); i != in_filtervec.end(); ++i) {
        std::vector<std::string> fv = StrTokenize(*i, "/");

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

    // Make a socket that closes on execve
#ifdef SOCK_CLOEXEC
    if ((server_fd = socket(AF_INET, SOCK_CLOEXEC | SOCK_STREAM, 0)) < 0) {
        _MSG("TCP server socket() failed: " + kis_strerror_r(errno),
                MSGFLAG_ERROR);
        return -1;
    }
#else
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        _MSG("TCP server socket() failed: " + kis_strerror_r(errno),
                MSGFLAG_ERROR);
        return -1;
    }
    fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_CLOEXEC);
#endif

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

    // Enable listening
    if (listen(server_fd, 20) < 0) {
        _MSG("TCP server listen() failed : " + kis_strerror_r(errno),
                MSGFLAG_ERROR);
        close(server_fd);
        return -1;
    }

    // Set it to nonblocking 
    fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_NONBLOCK);

    valid = true;

    return 1;
}

int TcpServerV2::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    int maxfd = in_max_fd;

    if (!valid)
        return -1;

    if (server_fd >= 0) {
        FD_SET(server_fd, out_rset);
        if (maxfd < server_fd)
            maxfd = server_fd;
    }

    for (auto i = handler_map.begin(); i != handler_map.end(); ++i) {
        if (i->second->GetReadBufferAvailable() > 0) {
            FD_SET(i->first, out_rset);

            if (maxfd < i->first)
                maxfd = i->first;
        }

        if (i->second->GetWriteBufferUsed() > 0) {
            FD_SET(i->first, out_wset);

            if (maxfd < i->first)
                maxfd = i->first;
        }
    }

    return maxfd;
}


int TcpServerV2::Poll(fd_set& in_rset, fd_set& in_wset) {
    std::stringstream msg;
    int ret, iret;
    size_t len;
    unsigned char *buf;
    ssize_t r_sz;

    if (!valid)
        return -1;

    // Reap any pending closures
    for (auto i = kill_map.begin(); i != kill_map.end(); ++i) {
        auto h = handler_map.find(i->first);
        
        if (h != kill_map.end()) {
            close(h->first);
            handler_map.erase(h);
        }
    }
    kill_map.clear();

    int accept_fd = 0;
    if (server_fd >= 0 && FD_ISSET(server_fd, &in_rset)) {
        if ((accept_fd = AcceptConnection()) <= 0)
            return 0;

        if (!AllowConnection(accept_fd)) {
            KillConnection(accept_fd);
            return 0;
        }

        std::shared_ptr<BufferHandlerGeneric> con_handler = AllocateConnection(accept_fd);

        if (con_handler == NULL) {
            KillConnection(accept_fd);
            return 0;
        }

        handler_map[accept_fd] = con_handler;

        NewConnection(con_handler);
    }

    for (auto i = handler_map.begin(); i != handler_map.end(); ++i) {
        // Process incoming data
        if (FD_ISSET(i->first, &in_rset)) {

            while (i->second->GetReadBufferAvailable() > 0) {
                // Read only as much as we can get w/ a direct reference
                r_sz = i->second->ZeroCopyReserveReadBufferData((void **) &buf, 
                        i->second->GetReadBufferAvailable());

                if (r_sz < 0) {
                    break;
                }


                ret = recv(i->first, buf, r_sz, MSG_DONTWAIT);

                if (ret < 0) {
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                        // Dump the commit, we didn't get any data
                        i->second->CommitReadBufferData(buf, 0);

                        break;
                    } else {
                        // Push the error upstream if we failed to read here

                        // Dump the commit
                        i->second->CommitReadBufferData(buf, 0);
                        i->second->BufferError(msg.str());

                        KillConnection(i->first);

                        break;
                    }
                } else if (ret == 0) {
                    msg << "TCP server closing connection from client " << i->first <<
                        " - connection closed by remote side";
                    _MSG(msg.str(), MSGFLAG_ERROR);
                    // Dump the commit
                    i->second->CommitReadBufferData(buf, 0);
                    i->second->BufferError(msg.str());

                    KillConnection(i->first);

                    break;
                } else {
                    // Commit the data
                    iret = i->second->CommitReadBufferData(buf, ret);

                    if (!iret) {
                        // Die if we somehow couldn't insert all our data once we
                        // read it from the socket since we can't put it back on the
                        // input queue.  This should never happen because we're the
                        // only input source but we'll handle it
                        msg << "Could not commit read data for client " << i->first;
                        _MSG(msg.str(), MSGFLAG_ERROR);

                        KillConnection(i->first);
                        break;
                    }
                }
            }
        }

        if (FD_ISSET(i->first, &in_wset)) {
            len = i->second->ZeroCopyPeekWriteBufferData((void **) &buf, 
                    i->second->GetWriteBufferUsed());

            if (len > 0) {
                ret = send(i->first, buf, len, MSG_DONTWAIT);

                if (ret < 0) {
                    if (errno == EINTR || errno == EAGAIN || errno == EWOULDBLOCK) {
                        i->second->PeekFreeWriteBufferData(buf);
                        continue;
                    } else {
                        msg << "TCP server error writing to client " << i->first <<
                            " - " << kis_strerror_r(errno);

                        i->second->PeekFreeWriteBufferData(buf);
                        i->second->BufferError(msg.str());

                        KillConnection(i->first);
                        continue;
                    }
                } else if (ret == 0) {
                    msg << "TCP server closing client " << i->first <<
                        " - connection closed by remote side.";
                    i->second->PeekFreeWriteBufferData(buf);
                    i->second->BufferError(msg.str());
                    KillConnection(i->first);
                    continue;
                } else {
                    // Consume whatever we managed to write
                    i->second->PeekFreeWriteBufferData(buf);
                    i->second->ConsumeWriteBufferData(ret);
                }
            }
        }
    }

    // Reap any pending closures
    for (auto i = kill_map.begin(); i != kill_map.end(); ++i) {
        auto h = handler_map.find(i->first);
        
        if (h != kill_map.end()) {
            close(h->first);
            handler_map.erase(h);
        }
    }
    kill_map.clear();

    return 0;
}

void TcpServerV2::KillConnection(int in_fd) {
    if (in_fd < 0)
        return;

    auto i = handler_map.find(in_fd);

    if (i != handler_map.end()) {
        kill_map[i->first] = i->second;
        i->second->BufferError("TCP connection closed");
    }
}

void TcpServerV2::KillConnection(std::shared_ptr<BufferHandlerGeneric> in_handler) {
    for (auto i : handler_map) {
        if (i.second == in_handler) {
            kill_map[i.first] = i.second;
            i.second->BufferError("TCP connection closed");
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

    // Accept it as a socket which closes on execve
#ifdef SOCK_CLOEXEC
    if ((new_fd = accept4(server_fd, (struct sockaddr *) &client_addr, 
                    &client_len, SOCK_CLOEXEC)) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            _MSG("TCP server accept() failed: " + kis_strerror_r(errno), MSGFLAG_ERROR);
            return -1;
        }

        return 0;
    }
#else
    if ((new_fd = accept(server_fd, (struct sockaddr *) &client_addr, 
                    &client_len)) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            _MSG("TCP server accept() failed: " + kis_strerror_r(errno), MSGFLAG_ERROR);
            return -1;
        }

        return 0;
    }

    fcntl(new_fd, F_SETFL, fcntl(new_fd, F_GETFL, 0) | O_CLOEXEC);
#endif

    if (handler_map.size() >= maxcli) {
        _MSG("TCP server maximum number of clients reached, cannot accept new "
                "connection.", MSGFLAG_ERROR);
        close(new_fd);
        return -1;
    }

    // Nonblocking, don't clone
    fcntl(new_fd, F_SETFL, fcntl(new_fd, F_GETFL, 0) | O_NONBLOCK);

    // Return the new fd; it is validated elsewhere and the buffer and handler
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

    _MSG_ERROR("TCP server refusing connection from unauthorized address {}", 
            inet_ntoa(client_addr.sin_addr));

    return false;
}

std::shared_ptr<BufferHandlerGeneric> TcpServerV2::AllocateConnection(int in_fd) {
    // Basic allocation
    std::shared_ptr<BufferHandlerGeneric> rbh(new BufferHandler<RingbufV2>(ringbuf_size, ringbuf_size));  

    // Protocol errors kill the connection
    auto fd_alias = in_fd;
    rbh->SetProtocolErrorCb([this, fd_alias]() {
        KillConnection(fd_alias);
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

