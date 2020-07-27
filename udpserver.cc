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
#include "ringbuf3.h"
#include "udpserver.h"
#include "timetracker.h"

udp_dgram_server::udp_dgram_server(dgram_cb datagramcb, cancel_cb cancelcb) :
    packet {nullptr},
    server_fd {-1},
    datagramcb {datagramcb},
    cancelcb {cancelcb},
    timeout_id {-1} {

    timetracker =
        Globalreg::fetch_mandatory_global_as<time_tracker>();

    udp_mutex.set_name("udp_dgram_server");
}

udp_dgram_server::~udp_dgram_server() {
    timetracker->remove_timer(timeout_id);

    shutdown();
}

int udp_dgram_server::configure_server(short int in_port, const std::string& in_bindaddress,
        const std::vector<std::string>& in_filtervec, std::chrono::seconds in_timeout,
        size_t in_max_packet, size_t in_wbuf_sz) {
    local_locker l(&udp_mutex, "udp_dgram_server::configure_server");

    max_packet = in_max_packet;

    if (packet != nullptr)
        delete[] packet;

    packet = new char[max_packet];

    port = in_port;
    timeout = in_timeout;

    timetracker->remove_timer(timeout_id);

    for (auto i : in_filtervec) {
        auto fv = str_tokenize(i, "/");

        ipfilter ipf;

        if (inet_aton(fv[0].c_str(), &(ipf.network)) != 1) {
            _MSG_ERROR("Unable to configure UDP server for port {}:  Unable to parse "
                    "allowed network range '{}'", in_port, fv[0]);
            return -1;
        }

        if (fv.size() == 2) {
            if (inet_aton(fv[1].c_str(), &(ipf.mask)) != 1) {
                _MSG_ERROR("Unable to configure UDP server for port {}:  Unable to parse "
                        "allowed network mask '{}'", in_port, fv[0]);
                return -1;
            }
        } else {
            inet_aton("255.255.255.255", &(ipf.mask));
        }

        ipfilter_vec.push_back(ipf);
    }

    struct sockaddr_in servaddr;

#ifdef SOCK_CLOEXEC
    if ((server_fd = socket(AF_INET, SOCK_CLOEXEC | SOCK_DGRAM, 0)) < 0) {
        _MSG_ERROR("Unable to configure UDP server for port {}, unable to make socket: {}",
                in_port, kis_strerror_r(errno));
        return -1;
    }
#else
    if ((server_fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        _MSG_ERROR("Unable to configure UDP server for port {}, unable to make socket: {}",
                in_port, kis_strerror_r(errno));
        return -1;
    }
    fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_CLOEXEC);
#endif

    memset(&servaddr, 0, sizeof(servaddr)); 
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(in_port);

    if (::bind(server_fd, (struct sockaddr *) &servaddr, sizeof(servaddr)) < 0) {
        _MSG_ERROR("Unable to configure UDP server for port {}, unable to bind socket: {}",
                in_port, kis_strerror_r(errno));
        close(server_fd);
        return -1;
    }
    
    if (inet_pton(AF_INET, in_bindaddress.c_str(), &(servaddr.sin_addr.s_addr)) == 0) 
        servaddr.sin_addr.s_addr = htonl(INADDR_ANY);

    fcntl(server_fd, F_SETFL, fcntl(server_fd, F_GETFL, 0) | O_NONBLOCK);

    timeout_id = 
        timetracker->register_timer(std::chrono::seconds(in_timeout),
                true,
                [this, in_timeout](int) -> int {
                    local_locker l(&udp_mutex, "udp_dgram_server::timeout timer");

                    auto now = time(0);
                    auto purgelist = std::list<uint32_t>();

                    for (auto c : client_map) {
                        if (c.second->last_time < (now - in_timeout.count())) 
                            purgelist.push_back(c.first);
                    }

                    for (auto p : purgelist) {
                        auto c = client_map.find(p);

                        if (cancelcb)
                            cancelcb(c->first, true, "connection idle");

                        client_map.erase(c);
                    }

                    return 1;
                });

    return 1;
}

int udp_dgram_server::pollable_merge_set(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    local_locker l(&udp_mutex, "udp_dgram_server::pollable_merge_set");

    int maxfd = in_max_fd;

    if (server_fd < 0)
        return -1;

    FD_SET(server_fd, out_rset);
    if (maxfd < server_fd)
        maxfd = server_fd;

    return maxfd;
}

int udp_dgram_server::pollable_poll(fd_set& in_rset, fd_set& in_wset) {
    local_locker l(&udp_mutex, "udp_dgram_server::pollable_poll");

    if (server_fd < 0)
        return -1;

    struct sockaddr_in cliaddr;
    socklen_t addr_len;
    ssize_t r_len;

    if (FD_ISSET(server_fd, &in_rset)) {
        while (1) {
            memset(&cliaddr, 0, sizeof(cliaddr));

            addr_len = sizeof(cliaddr);

            r_len = recvfrom(server_fd, packet, max_packet,  MSG_DONTWAIT, 
                    (struct sockaddr *) &cliaddr, &addr_len); 

            if (r_len < 0) {
                if (errno != EAGAIN && errno != EWOULDBLOCK) {
                    for (auto c : client_map) {
                        auto err = fmt::format("UDP server socket error {} (errno {})",
                                kis_strerror_r(errno), errno);

                        if (cancelcb)
                            cancelcb(c.first, false, err);
                    }

                    shutdown();
                    return -1;
                }

                break;
            }

            // We could have a zero-length dgram, i guess?  We don't do anything with it
            // if we get it tho.
            if (r_len > 0) {
                auto cli_csum = adler32_checksum(&cliaddr, addr_len);
                std::shared_ptr<client> client_rec;

                auto client_key = client_map.find(cli_csum);
                if (client_key == client_map.end()) {
                    bool pass = true;

                    if (ipfilter_vec.size() > 0) {
                        pass = false;

                        for (auto ipi : ipfilter_vec) {
                            if ((cliaddr.sin_addr.s_addr & ipi.mask.s_addr) ==
                                    (ipi.network.s_addr & ipi.mask.s_addr)) {
                                pass = true;
                                break;
                            }
                        }
                    }

                    // Typically we silently drop packets which don't pass the IP filter
                    // or we'd get absolutely flooded with bogus messages

                    if (pass) {
                        client_rec = std::make_shared<client>();
                        client_rec->addr.sin_addr.s_addr = cliaddr.sin_addr.s_addr;

                        client_map[cli_csum] = client_rec;
                    }
                } else {
                    client_rec = client_key->second;
                }

                if (client_rec != nullptr) {
                    client_rec->last_time = time(0);

                    if (datagramcb != nullptr) 
                        datagramcb((const struct sockaddr_storage *) &cliaddr, addr_len, cli_csum, packet, r_len);
                }
            }
        }
    }

    return 0;
}

void udp_dgram_server::shutdown() {
    local_locker l(&udp_mutex, "udp_dgram_server::shutdown");

    datagramcb = nullptr;

    if (server_fd >= 0)
        close(server_fd);

    if (cancelcb)
        for (auto c : client_map)
            cancelcb(c.first, false, "UDP server shutting down");
}

