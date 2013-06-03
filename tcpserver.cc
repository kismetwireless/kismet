#include "tcpserver.h"
#include "configfile.h"

TcpServer::TcpServer() {
    fprintf(stderr, "*** TcpServer() called with no global registry\n");
}

TcpServer::TcpServer(GlobalRegistry *in_globalreg) : NetworkServer(in_globalreg) {
    globalreg = in_globalreg;
    // Init stuff
    sv_valid = 0;
    sv_configured = 0;

    serv_fd = 0;
    max_fd = 0;

	int_ring_len = SRV_RING_LEN;

    FD_ZERO(&server_fdset);
}

TcpServer::~TcpServer() {
}

// Set up the TCP socket and listening
int TcpServer::SetupServer(short int in_port, unsigned int in_maxcli, 
						   string in_bindaddr, string in_filterstr) {
	(void) in_filterstr;

    port = in_port;
    maxcli = in_maxcli;
	bindaddr = in_bindaddr;

    sv_configured = 1;

	globalreg->RegisterPollableSubsys(this);

    return 1;
}

// Set the length of the rings for new connections
void TcpServer::SetRingSize(int in_sz) {
	int_ring_len = in_sz;
}

int TcpServer::EnableServer() {
    if (sv_configured == 0) {
        _MSG("Attempted to enable unconfigured TCP server", MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }

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
    if (inet_pton(AF_INET, bindaddr.c_str(), &serv_sock.sin_addr.s_addr) == 0) {
        serv_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    }
    // serv_sock.sin_addr.s_addr = htonl(INADDR_ANY);
    serv_sock.sin_port = htons(port);

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

    for (unsigned int ipvi = 0; ipvi < ipfilter_vec.size(); ipvi++) {
        char *netaddr = strdup(inet_ntoa(ipfilter_vec[ipvi]->network));
        char *maskaddr = strdup(inet_ntoa(ipfilter_vec[ipvi]->mask));

        free(netaddr);
        free(maskaddr);
    }

    snprintf(errstr, 1024, "Created TCP listener on port %d", 
        FetchPort());
    _MSG(errstr, MSGFLAG_INFO);
    return 1;
}

void TcpServer::KillConnection(int in_fd) {
    NetworkServer::KillConnection(in_fd);
    
    // Close the fd
    if (in_fd)
        close(in_fd);
}

void TcpServer::Shutdown() {
    for (map<int, RingBuffer *>::iterator miter = read_buf_map.begin();
         miter != read_buf_map.end(); ++miter) {
        KillConnection(miter->first);
		// Reset the iterator since we cascade through the generic
		// netserver::killconnection which removes the ringbuf and
		// iterator
		miter = read_buf_map.begin();
		if (miter == read_buf_map.end())
			break;
	}

    sv_valid = 0;

    if (serv_fd)
        close(serv_fd);

    max_fd = 0;
}

int TcpServer::FetchClientConnectInfo(int in_clid, void *ret_info) {
    struct sockaddr_in client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    client_len = sizeof(struct sockaddr_in);

    if (getsockname(in_clid, (struct sockaddr *) &client_addr, &client_len) < 0) {
        snprintf(errstr, STATUS_MAX, "TCP server unable to get sockname for "
				 "client info: %s", strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    memcpy(ret_info, &client_addr, client_len);
    
    return 1;
}

int TcpServer::TcpAccept() {
    int new_fd;
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
    if (FetchNumClients() >= (int) maxcli) {
        snprintf(errstr, STATUS_MAX, "TCP server maximum clients (%d) already "
				 "reached.", maxcli);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        close(new_fd);
        return -1;
    }

    // Set it to nonblocking
    int save_mode = fcntl(new_fd, F_GETFL, 0);
    fcntl(new_fd, F_SETFL, save_mode | O_NONBLOCK);
    
    if (new_fd > (int) max_fd)
        max_fd = new_fd;

    FD_SET(new_fd, &server_fdset);

    // There should never be overlapping fds and there should never be
    // remnants of an old person here, so we'll make the connection 
    // lightweight and not do more tree searching.  If this ever proves
    // wrong, we need to reevaluate
    write_buf_map[new_fd] = new RingBuffer(int_ring_len);
    read_buf_map[new_fd] = new RingBuffer(int_ring_len);

    return new_fd;
}

string TcpServer::GetRemoteAddr(int in_fd) {
    struct sockaddr_in client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    memset(&client_addr, 0, sizeof(struct sockaddr_in));
    client_len = sizeof(struct sockaddr_in);

    if (getsockname(in_fd, (struct sockaddr *) &client_addr, &client_len) < 0) {
        snprintf(errstr, STATUS_MAX, "TCP server unable to get sockname: %s",
				 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		return "0.0.0.0";
    }

    return string(inet_ntoa(client_addr.sin_addr));
}

int TcpServer::Accept() {
	// Handle the TCP accept stuff
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
        snprintf(errstr, STATUS_MAX, "TCP server unable to get sockname: %s",
				 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		return -1;
    }

    // No filtering = valid
    if (ipfilter_vec.size() == 0)
        return 1;


    int legal_ip = 0;
    for (unsigned int ibvi = 0; ibvi < ipfilter_vec.size(); ibvi++) {
        if ((client_addr.sin_addr.s_addr & ipfilter_vec[ibvi]->mask.s_addr) ==
            ipfilter_vec[ibvi]->network.s_addr) {
            legal_ip = 1;
            break;
        }
    }

    if (legal_ip == 0) {
        snprintf(errstr, STATUS_MAX, "TCP server client from untrusted host "
				 "%s refused", GetRemoteAddr(in_fd).c_str());
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
		if (errno == EINTR || errno == EAGAIN)
			return 0;

        snprintf(errstr, STATUS_MAX, "TCP server client read() error for %s: %s", 
                 GetRemoteAddr(in_fd).c_str(), strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    if (ret <= 0) {
        snprintf(errstr, STATUS_MAX, "TCP server client read() ended for %s",
				 GetRemoteAddr(in_fd).c_str());
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    if (read_buf_map[in_fd]->InsertData(recv_bytes, ret) == 0) {
        snprintf(errstr, STATUS_MAX, "TCP server client %s read error, ring "
				 "buffer full", GetRemoteAddr(in_fd).c_str());
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
	pthread_mutex_lock(&write_mutex);

    write_buf_map[in_fd]->FetchPtr(dptr, 1024, &dlen);

    if ((ret = write(in_fd, dptr, dlen)) <= 0) {
		pthread_mutex_unlock(&write_mutex);

		if (errno == EINTR || errno == EAGAIN)
			return 0;

        snprintf(errstr, STATUS_MAX, "TCP server: Killing client %s, write "
				 "error %s", GetRemoteAddr(in_fd).c_str(), strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        KillConnection(in_fd);
        return -1;
    }

    write_buf_map[in_fd]->MarkRead(ret);

	if (srvframework->BufferDrained(in_fd) < 0) {
		pthread_mutex_unlock(&write_mutex);

		snprintf(errstr, STATUS_MAX, "TCP server: Error occured calling framework "
				 "buffer drain notification on client %s", 
				 GetRemoteAddr(in_fd).c_str());
		_MSG(errstr, MSGFLAG_ERROR);
		KillConnection(in_fd);
		return -1;
	}

	pthread_mutex_unlock(&write_mutex);

    return ret;
}

