#include "tcpserver.h"
#include "configfile.h"

TcpServer::TcpServer() {
    fprintf(stderr, "*** TcpServer() called with no global registry\n");
}

TcpServer::TcpServer(GlobalRegistry *in_globalreg) : NetworkServer(in_globalreg) {
    globalreg = in_globalreg;
    // Init stuff
    sv_valid = 0;

    serv_fd = 0;
    max_fd = 0;

    if (globalreg->kistcpport == -1) {
        if (globalreg->kismet_config->FetchOpt("tcpport") == "") {
            globalreg->messagebus->InjectMessage("No TCP port given for UI server",
                                                 MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return;
        } else if (sscanf(globalreg->kismet_config->FetchOpt("tcpport").c_str(), 
                          "%d", &globalreg->kistcpport) != 1) {
            globalreg->messagebus->InjectMessage("Invalid value for 'tcpport' in config file",
                                                      MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
        }
    }

    if (globalreg->kismet_config->FetchOpt("maxclients") == "") {
        globalreg->messagebus->InjectMessage("No maximum number of UI clients given",
                                                  MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return;
    } else if (sscanf(globalreg->kismet_config->FetchOpt("maxclients").c_str(), "%d", 
                      &globalreg->kistcpmaxcli) != 1) {
        globalreg->messagebus->InjectMessage("Invalid value for 'maxclients' in config file",
                                                  MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return;
    }

    if (globalreg->kisallowedhosts.length() == 0) {
        if (globalreg->kismet_config->FetchOpt("allowedhosts") == "") {
            globalreg->messagebus->InjectMessage("No list of allowed hosts for UI connections",
                                                      MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return;
        }

        globalreg->kisallowedhosts = globalreg->kismet_config->FetchOpt("allowedhosts");
    }

    vector<string> hostsvec = StrTokenize(globalreg->kisallowedhosts, ",");

    for (size_t hostcomp = 0; hostcomp < hostsvec.size(); hostcomp++) {
        TcpServer::client_ipfilter *ipb = new TcpServer::client_ipfilter;
        string hoststr = hostsvec[hostcomp];

        // Find the netmask divider, if one exists
        size_t masksplit = hoststr.find("/");
        if (masksplit == string::npos) {
            // Handle hosts with no netmask - they're treated as single hosts
            inet_aton("255.255.255.255", &(ipb->mask));

            if (inet_aton(hoststr.c_str(), &(ipb->network)) == 0) {
                snprintf(errstr, STATUS_MAX, "Illegal IP address '%s' in allowed hosts list.",
                         hoststr.c_str());
                globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                globalreg->fatal_condition = 1;
                return;
            }
        } else {
            // Handle pairs
            string hosthalf = hoststr.substr(0, masksplit);
            string maskhalf = hoststr.substr(masksplit + 1, hoststr.length() - (masksplit + 1));

            if (inet_aton(hosthalf.c_str(), &(ipb->network)) == 0) {
                snprintf(errstr, STATUS_MAX, "Illegal IP address '%s' in allowed hosts list.",
                         hosthalf.c_str());
                globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                globalreg->fatal_condition = 1;
                return;
            }

            int validmask = 1;
            if (maskhalf.find(".") == string::npos) {
                // If we have a single number (ie, /24) calculate it and put it into
                // the mask.
                long masklong = strtol(maskhalf.c_str(), (char **) NULL, 10);

                if (masklong < 0 || masklong > 32) {
                    validmask = 0;
                } else {
                    if (masklong == 0)
                        masklong = 32;

                    ipb->mask.s_addr = htonl((-1 << (32 - masklong)));
                }
            } else {
                // We have a dotted quad mask (ie, 255.255.255.0), convert it
                if (inet_aton(maskhalf.c_str(), &(ipb->mask)) == 0)
                    validmask = 0;
            }

            if (validmask == 0) {
                snprintf(errstr, STATUS_MAX, "Illegal IP netmask '%s' in allowed hosts list.",
                         maskhalf.c_str());
                globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
                globalreg->fatal_condition = 1;
                return;
            }
        }

        // Catch 'network' addresses that aren't network addresses.
        if ((ipb->network.s_addr & ipb->mask.s_addr) != ipb->network.s_addr) {
            snprintf(errstr, STATUS_MAX, "Illegal network '%s' in allowed hosts list.",
                     inet_ntoa(ipb->network));
            globalreg->messagebus->InjectMessage(errstr, MSGFLAG_FATAL);
            globalreg->fatal_condition = 1;
            return;
        }

        // Add it to our vector
        ipfilter_vec.push_back(ipb);
    }
}

TcpServer::~TcpServer() {
}

int TcpServer::EnableServer() {
    // Find local host
    if (gethostname(hostname, MAXHOSTNAMELEN) < 0) {
        snprintf(errstr, STATUS_MAX, "TCP server gethostname() failed: %s",
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    // Set up socket stuff
    memset(&serv_sock, 0, sizeof(serv_sock));
    serv_sock.sin_family = AF_INET;
    serv_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_sock.sin_port = htons(globalreg->kistcpport);

    if ((serv_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        snprintf(errstr, STATUS_MAX, "TCP server socket() failed: %s",
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    // Reuse the addr
    int i = 2;
    if (setsockopt(serv_fd, SOL_SOCKET, SO_REUSEADDR, &i, sizeof(i)) == -1) {
        snprintf(errstr, STATUS_MAX, "TCP server setsockopt(REUSEADDR) failed: %s",
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    // Bind the socket
    if (bind(serv_fd, (struct sockaddr *) &serv_sock, sizeof(serv_sock)) < 0) {
        snprintf(errstr, STATUS_MAX, "TCP server bind() failed: %s",
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    // Listen for connections
    if (listen(serv_fd, 5) < 0) {
        snprintf(errstr, STATUS_MAX, "TCP server listen() failed: %s",
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    // Zero and set the FDs and maxfd
    FD_ZERO(&server_fdset);

    if (serv_fd > (int) max_fd)
        max_fd = serv_fd;

    // We're valid
    sv_valid = 1;

    snprintf(errstr, STATUS_MAX, "Listening on port %d.", globalreg->kistcpport);
    globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);
    for (unsigned int ipvi = 0; ipvi < ipfilter_vec.size(); ipvi++) {
        char *netaddr = strdup(inet_ntoa(ipfilter_vec[ipvi]->network));
        char *maskaddr = strdup(inet_ntoa(ipfilter_vec[ipvi]->mask));

        snprintf(errstr, STATUS_MAX,  "Allowing connections from %s/%s", 
                 netaddr, maskaddr);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_INFO);

        free(netaddr);
        free(maskaddr);
    }

    return 1;
}

// Merge our file descriptors into an existing set
unsigned int TcpServer::MergeSet(fd_set in_rset, fd_set in_wset,
                                 unsigned int in_max_fd,
                                 fd_set *out_rset, fd_set *out_wset) {
    unsigned int max;

    FD_ZERO(out_rset);
    FD_ZERO(out_wset);
   
    if (in_max_fd < max_fd) {
        max = max_fd;
    } else {
        max = in_max_fd;
    }

    // Set the server fd
    FD_SET(serv_fd, out_rset);
    
    for (unsigned int x = 0; x <= max; x++) {
        // Incoming read or our own clients
        if (FD_ISSET(x, &in_rset) || FD_ISSET(x, &server_fdset))
            FD_SET(x, out_rset);
        // Incoming write or any clients with a pending write ring
        if (FD_ISSET(x, &in_wset) || 
            (write_buf_map.find(x) != write_buf_map.end() &&
             write_buf_map[x]->FetchLen() > 0))
            FD_SET(x, out_wset);
    }
   
    return max;
}

void TcpServer::KillConnection(int in_fd) {
    NetworkServer::KillConnection(in_fd);
    
    // Close the fd
    if (in_fd)
        close(in_fd);

}

void TcpServer::Shutdown() {
    for (map<int, RingBuffer *>::iterator miter = read_buf_map.begin();
         miter != read_buf_map.end(); miter++)
        KillConnection(miter->first);

    sv_valid = 0;

    if (serv_fd)
        close(serv_fd);

    max_fd = 0;
}

int TcpServer::TcpAccept() {
    unsigned int new_fd;
    struct sockaddr_in client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    client_len = sizeof(struct sockaddr_in);

    // Socket accept
    if ((new_fd = accept(serv_fd, (struct sockaddr *) &client_addr,
                         &client_len)) < 0) {
        snprintf(errstr, STATUS_MAX, "TCP server accept() failed: %s",
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    // Bail right now if we have too many connections
    if (FetchNumClients() >= (int) globalreg->kistcpmaxcli) {
        snprintf(errstr, STATUS_MAX, "TCP server maximum clients (%d) already reached.",
                 globalreg->kistcpmaxcli);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        close(new_fd);
        return -1;
    }

    // Set it to nonblocking
    int save_mode = fcntl(new_fd, F_GETFL, 0);
    fcntl(new_fd, F_SETFL, save_mode | O_NONBLOCK);
    
    if (new_fd > max_fd)
        max_fd = new_fd;

    FD_SET(new_fd, &server_fdset);

    // There should never be overlapping fds and there should never be
    // remnants of an old person here, so we'll make the connection 
    // lightweight and not do more tree searching.  If this ever proves
    // wrong, we need to reevaluate
    write_buf_map[new_fd] = new RingBuffer(SRV_RING_LEN);
    read_buf_map[new_fd] = new RingBuffer(SRV_RING_LEN);

    return new_fd;
}

int TcpServer::Accept() {
    // Just handle the TCP acceptance stuff
    return TcpAccept();
}

int TcpServer::ValidateIPFilter(int in_fd) {
    struct sockaddr_in client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    client_len = sizeof(struct sockaddr_in);

    if (getsockname(in_fd, (struct sockaddr *) &client_addr, &client_len) < 0) {
        snprintf(errstr, STATUS_MAX, "TCP server unable to get sockname for validation: %s",
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    // No filtering = valid
    if (ipfilter_vec.size() == 0)
        return 1;

    char inhost[16];
    snprintf(inhost, 16, "%s", inet_ntoa(client_addr.sin_addr));

    int legal_ip = 0;
    for (unsigned int ibvi = 0; ibvi < ipfilter_vec.size(); ibvi++) {
        if ((client_addr.sin_addr.s_addr & ipfilter_vec[ibvi]->mask.s_addr) ==
            ipfilter_vec[ibvi]->network.s_addr) {
            legal_ip = 1;
            break;
        }
    }

    if (legal_ip == 0) {
        snprintf(errstr, STATUS_MAX, "TCP server client fd %d from untrusted host %s refused",
                 in_fd, inhost);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        KillConnection(in_fd);
        return -1;
    }

    return 1;
}

int TcpServer::Validate(int in_fd) {
    // Just validate based on IP block
    return ValidateIPFilter(in_fd);
}

int TcpServer::ReadBytes(int in_fd) {
    uint8_t recv_bytes[1024];
    int ret;

    if ((ret = read(in_fd, recv_bytes, 1024)) < 0) {
        snprintf(errstr, STATUS_MAX, "TCP server client fd %d read() error: %s", 
                 in_fd, strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    if (ret == 0) {
        snprintf(errstr, STATUS_MAX, "TCP server client fd %d read() returned end of file",
                 in_fd);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    if (read_buf_map[in_fd]->InsertData(recv_bytes, ret) == 0) {
        snprintf(errstr, STATUS_MAX, "TCP server client fd %d read error, ring buffer full",
                 in_fd);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    return ret;
}

int TcpServer::WriteBytes(int in_fd) {
    uint8_t dptr[1024];
    int dlen, ret;

    // This can't get called on invalid fds, so save some time and
    // don't check
    write_buf_map[in_fd]->FetchPtr(dptr, 1024, &dlen);

    if ((ret = write(in_fd, dptr, dlen)) <= 0) {
        snprintf(errstr, STATUS_MAX, "TCP server: Killing client fd %d write error %s",
                 in_fd, strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        KillConnection(in_fd);
        return -1;
    }

    write_buf_map[in_fd]->MarkRead(ret);

    return ret;
}

