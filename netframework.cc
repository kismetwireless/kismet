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

#include "netframework.h"

NetworkServer::NetworkServer() {
    fprintf(stderr, "*** NetworkServer() not called with global registry\n");
}

NetworkServer::NetworkServer(GlobalRegistry *in_reg) {
    globalreg = in_reg;

    sv_valid = 0;

    serv_fd = 0;
    max_fd = 0;

    srvframework = NULL;

	pthread_mutex_init(&write_mutex, NULL);
}

int NetworkServer::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    int max;

    if (in_max_fd < max_fd) {
        max = max_fd;
    } else {
        max = in_max_fd;
    }

    // Set the server fdif we're not in spindown, if we are spinning down,
	// stop listening and shut down
	if (globalreg->spindown && serv_fd >= 0) {
		close(serv_fd);
		serv_fd = -1;
	} else if (serv_fd >= 0) {
		FD_SET(serv_fd, out_rset);
	}
    
    for (int x = 0; x <= max; x++) {
        // Incoming read or our own clients
        if (FD_ISSET(x, &server_fdset))
            FD_SET(x, out_rset);
        // Incoming write or any clients with a pending write ring
        if (write_buf_map.find(x) != write_buf_map.end() && 
			write_buf_map[x]->FetchLen() > 0)
            FD_SET(x, out_wset);
    }
   
    return max;
}

int NetworkServer::Poll(fd_set& in_rset, fd_set& in_wset) {
    int ret;

    if (!sv_valid)
        return -1;

    // Look for new connections we need to accept
    int accept_fd = 0;
    if (serv_fd >= 0 && FD_ISSET(serv_fd, &in_rset)) {
        // Accept an inbound connection.  This is non-fatal if it fails
        if ((accept_fd = Accept()) < 0)
            return 0;
        // Validate them and see if they're allowed to remain
        // Bounce back a 0 so we can log the refusal
        if (Validate(accept_fd) < 0) {
            KillConnection(accept_fd);
            return 0;
        }
        // Pass them to the framework accept
        if (srvframework->Accept(accept_fd) < 0) {
            KillConnection(accept_fd);
            return 0;
        }
    }

    // Handle input and output, dispatching to our other functions so we can
    // be overridden
    for (int x = 0; x <= max_fd; x++) {
        // Handle reading data.  Accept() should have made them a 
        // ringbuffer.
        if (FD_ISSET(x, &in_rset) && FD_ISSET(x, &server_fdset)) {
            if ((ret = ReadBytes(x)) < 0) {
                KillConnection(x);
                continue;
            }

            // Try to parse it.  We only do this when its changed since
            // if it couldn't parse a fragment before it's not going to be
            // able to parse a fragment still
            if (ret > 0 && srvframework->ParseData(x) < 0) {
                KillConnection(x);
                continue;
            }
        }

        // Handle writing data.  The write FD would never have gotten set
        // for checking if there wasn't data in the ring buffer, so we don't
        // have to check for that.
        if (FD_ISSET(x, &in_wset) && FD_ISSET(x, &server_fdset)) {
            if ((ret = WriteBytes(x)) < 0)
                continue;
        }

    }

    return 1;
}

int NetworkServer::FlushRings() {
    if (!sv_valid)
        return -1;

    if (FetchNumClients() < 1)
        return 0;
    
    fd_set rset, wset;
    int max;
    
    // Use a large granularity 2-second timer, what the hell
    time_t flushtime = time(0);

    // Nuke the fatal conditon so we can track our own failures
    int old_fcon = globalreg->fatal_condition;
    globalreg->fatal_condition = 0;
    
    while ((time(0) - flushtime) < 2) {
        // See if we have any data in any of our ring buffers
        int allflushed = 1;
        for (map<int, RingBuffer *>::iterator x = write_buf_map.begin();
             x != write_buf_map.end(); ++x) {
            if (x->second->FetchLen() > 0) {
                allflushed = 0;
                break;
            }
        }
   
        if (allflushed)
            return 1;

        max = 0;
        FD_ZERO(&rset);
        FD_ZERO(&wset);
       
        max = MergeSet(max, &rset, &wset);

        struct timeval tm;
        tm.tv_sec = 0;
        tm.tv_usec = 100000;

        if (select(max + 1, &rset, &wset, NULL, &tm) < 0) {
            if (errno != EINTR && errno != EAGAIN) {
                globalreg->fatal_condition = 1;
                return -1;
            }
        }

        if (Poll(rset, wset) < 0 || globalreg->fatal_condition != 0)
            return -1;
    }

    globalreg->fatal_condition = old_fcon;

    return 1;
}

void NetworkServer::KillConnection(int in_fd) {
    // Let the framework clear any state info
    srvframework->KillConnection(in_fd);

	if (in_fd < 0)
		return;
  
    // Nuke descriptors
    FD_CLR(in_fd, &server_fdset);
    FD_CLR(in_fd, &pending_readset);

    // Nuke ringbuffers
    map<int, RingBuffer *>::iterator miter = read_buf_map.find(in_fd);
    if (miter != read_buf_map.end()) {
        delete read_buf_map[in_fd];
        read_buf_map.erase(miter);
    }

    miter = write_buf_map.find(in_fd);
    if (miter != write_buf_map.end()) {
        delete write_buf_map[in_fd];
        write_buf_map.erase(miter);
    }
}

int NetworkServer::WriteData(int in_clid, void *in_data, int in_len) {
    if (write_buf_map.find(in_clid) == write_buf_map.end()) {
        snprintf(errstr, STATUS_MAX, "NetworkServer::WriteData called with invalid "
                 "client ID %d", in_clid);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

	pthread_mutex_lock(&write_mutex);
    
    RingBuffer *write_buf = write_buf_map[in_clid];

    if (write_buf->InsertDummy(in_len) == 0) {
		pthread_mutex_unlock(&write_mutex);
        return -2;
    }

    write_buf->InsertData((uint8_t *) in_data, in_len);

	pthread_mutex_unlock(&write_mutex);
    
    return 1;
}

int NetworkServer::FetchReadLen(int in_clid) {
    if (read_buf_map.find(in_clid) == read_buf_map.end()) {
        snprintf(errstr, STATUS_MAX, "NetworkServer::ReadDataLen called with "
                 "invalid client ID %d", in_clid);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    RingBuffer *read_buf = read_buf_map[in_clid];

    return (int) read_buf->FetchLen();
}

int NetworkServer::ReadData(int in_clid, void *ret_data, int in_max, int *ret_len) {
    if (read_buf_map.find(in_clid) == read_buf_map.end()) {
        snprintf(errstr, STATUS_MAX, "NetworkServer::ReadDataLen called with "
                 "invalid client ID %d", in_clid);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    RingBuffer *read_buf = read_buf_map[in_clid];

    read_buf->FetchPtr((uint8_t *) ret_data, in_max, ret_len);

    return (*ret_len);
}

int NetworkServer::MarkRead(int in_clid, int in_readlen) {
    if (read_buf_map.find(in_clid) == read_buf_map.end()) {
        snprintf(errstr, STATUS_MAX, "NetworkServer::ReadDataLen called with "
                 "invalid client ID %d", in_clid);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    RingBuffer *read_buf = read_buf_map[in_clid];
   
    read_buf->MarkRead(in_readlen);

    return 1;
}

int NetworkServer::FetchClientVector(vector<int> *ret_vec) {
    ret_vec->reserve(write_buf_map.size());

    for (map<int, RingBuffer *>::iterator x = write_buf_map.begin(); 
         x != write_buf_map.end(); ++x)
        ret_vec->push_back(x->first);

    return ret_vec->size();
}

int ServerFramework::Shutdown() {
    // Initiate a shutdown of the components
    if (netserver != NULL) {
        netserver->FlushRings();
        netserver->Shutdown();
    }

    return 1;
}

int ServerFramework::BufferDrained(int in_fd) {
	(void) in_fd;

	return 0;
}

