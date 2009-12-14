#include "unixdomainserver.h"
#include "configfile.h"
#include <limits.h>

UnixDomainServer::UnixDomainServer() {
    fprintf(stderr, "*** FATAL OOPS: UnixDomainServer()\n");
    exit(1);
}

UnixDomainServer::UnixDomainServer(GlobalRegistry *in_globalreg) : 
    NetworkServer(in_globalreg) {
    globalreg = in_globalreg;
    // Init stuff
    sv_valid = 0;
    sv_configured = 0;

    serv_fd = 0;
    max_fd = 0;

    int_ring_len = UNIX_SRV_RING_LEN;

    FD_ZERO(&server_fdset);
}

UnixDomainServer::~UnixDomainServer() {
    if(serv_fd)
        ::unlink(socket_path.c_str());
}

// Set up the Unix-domain socket and listening
int UnixDomainServer::SetupServer(const std::string& path, int mode, 
                                  bool force, unsigned int in_maxcli) {
    socket_path = path;
    maxcli = in_maxcli;
    sv_configured = 1;
    socket_mode = mode;
    if(force)
        ::unlink(path.c_str());
    globalreg->RegisterPollableSubsys(this);
    return 1;
}

// Set the length of the rings for new connections
void UnixDomainServer::SetRingSize(int in_sz) {
    int_ring_len = in_sz;
}

int UnixDomainServer::EnableServer() {
    if (sv_configured == 0) {
        _MSG("Attempted to enable unconfigured Unix domain server", MSGFLAG_FATAL);
        globalreg->fatal_condition = 1;
        return -1;
    }

    // Set up socket stuff
    memset(&serv_sock, 0, sizeof(serv_sock));
    serv_sock.sun_family = AF_UNIX;
    strncpy(serv_sock.sun_path, socket_path.c_str(), UNIX_PATH_MAX);

    if ((serv_fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0) {
        _MSG("Unix domain server socket() failed: " + string(strerror(errno)),
             MSGFLAG_ERROR);
        return -1;
    }

    // Bind the socket
    if (bind(serv_fd, (struct sockaddr *) &serv_sock, sizeof(serv_sock)) < 0) {
        _MSG("Unix domain server bind() failed: " + string(strerror(errno)),
             MSGFLAG_ERROR);
        return -1;
    }

    // Listen for connections
    if (listen(serv_fd, 5) < 0) {
        _MSG("Unix domain server listen() failed: " + string(strerror(errno)), 
             MSGFLAG_ERROR);
        return -1;
    }

    // Zero and set the FDs and maxfd
    FD_ZERO(&server_fdset);

    if (serv_fd > (int) max_fd)
        max_fd = serv_fd;

    // We're valid
    sv_valid = 1;

    ::chmod(socket_path.c_str(), socket_mode);
    _MSG("Created Unix-domain listener at " + socket_path, MSGFLAG_INFO);
    return 1;
}

void UnixDomainServer::KillConnection(int in_fd) {
    NetworkServer::KillConnection(in_fd);

    // Close the fd
    if (in_fd)
        close(in_fd);
}

void UnixDomainServer::Shutdown() {
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

int UnixDomainServer::FetchClientConnectInfo(int in_clid, void *ret_info) {
    struct sockaddr_un client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    memset(&client_addr, 0, sizeof(client_addr));
    client_len = sizeof(client_addr);

    if (getsockname(in_clid, (struct sockaddr *) &client_addr, &client_len) < 0) {
        _MSG("Unix domain server unable to get sockname for client info: " +
             string(strerror(errno)), MSGFLAG_ERROR);
        return -1;
    }

    memcpy(ret_info, &client_addr, client_len);
    
    return 1;
}

string UnixDomainServer::GetRemoteAddr(int in_fd) {
    struct sockaddr_un client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    memset(&client_addr, 0, sizeof(client_addr));
    client_len = sizeof(client_addr);

    if (getsockname(in_fd, (struct sockaddr *) &client_addr, &client_len) < 0) {
        _MSG("Unix domain server unable to get sockname: " + string(strerror(errno)),
             MSGFLAG_ERROR);
        return "";
    }

    return client_addr.sun_path;
}

int UnixDomainServer::Accept() {
    int new_fd;
    struct sockaddr_un client_addr;
#ifdef HAVE_SOCKLEN_T
    socklen_t client_len;
#else
    int client_len;
#endif

    memset(&client_addr, 0, sizeof(client_addr));
    client_len = sizeof(client_addr);

    // Socket accept
    if ((new_fd = accept(serv_fd, (struct sockaddr *) &client_addr,
                         &client_len)) < 0) {
        _MSG("Unix-domain server accept() failed: " + string(strerror(errno)),
             MSGFLAG_ERROR);
        return -1;
    }

    // Bail right now if we have too many connections
    if (FetchNumClients() >= (int) maxcli) {
        _MSG("Unix-domain server maximum clients (" + IntToString(maxcli) + ") already "
             "reached.", MSGFLAG_ERROR);
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

int UnixDomainServer::Validate(int in_fd) {
    return 1; // Perhaps check remote user?
}

int UnixDomainServer::ReadBytes(int in_fd) {
    uint8_t recv_bytes[1024];
    int ret;

    if ((ret = read(in_fd, recv_bytes, 1024)) < 0) {
        if (errno == EINTR || errno == EAGAIN)
            return 0;

        _MSG("Unix domain server client read() error for " + 
             GetRemoteAddr(in_fd) + ": " + string(strerror(errno)), MSGFLAG_ERROR);
        return -1;
    }

    if (ret == 0) {
        _MSG("Unix domain server client read() ended for " + GetRemoteAddr(in_fd),
             MSGFLAG_ERROR);
        return -1;
    }

    if (read_buf_map[in_fd]->InsertData(recv_bytes, ret) == 0) {
        _MSG("Unix domain server client " + GetRemoteAddr(in_fd) + " read error, "
             "ring buffer full", MSGFLAG_ERROR);
        return -1;
    }

    return ret;
}

int UnixDomainServer::WriteBytes(int in_fd) {
    uint8_t dptr[1024];
    int dlen, ret;

    // This can't get called on invalid fds, so save some time and
    // don't check
    write_buf_map[in_fd]->FetchPtr(dptr, 1024, &dlen);

    if ((ret = write(in_fd, dptr, dlen)) <= 0) {
        if (errno == EINTR || errno == EAGAIN)
            return 0;

        _MSG("Unix domain server: Killing client " + GetRemoteAddr(in_fd) + ", write "
             "error: " + string(strerror(errno)), MSGFLAG_ERROR);
        KillConnection(in_fd);
        return -1;
    }

    write_buf_map[in_fd]->MarkRead(ret);

    if (srvframework->BufferDrained(in_fd) < 0) {
        _MSG("Unix domain server: Error occured calling framework buffer drain "
             "notification on client " + GetRemoteAddr(in_fd), MSGFLAG_ERROR);
        KillConnection(in_fd);
        return -1;
    }

    return ret;
}

