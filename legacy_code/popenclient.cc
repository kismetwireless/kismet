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
#include "popenclient.h"

PopenClient::PopenClient() {
    fprintf(stderr, "*** PopenClient() called with no global registry reference\n");
}

PopenClient::PopenClient(GlobalRegistry *in_globalreg) : 
	NetworkClient(in_globalreg) {

	childpid = 0;
}

PopenClient::~PopenClient() {
	KillConnection();
}

int PopenClient::CheckPidVec() {
	if (childpid <= 0)
		return 0;

	for (unsigned int x = 0; x < globalreg->sigchild_vec.size(); x++) {
		if (globalreg->sigchild_vec[x].pid == childpid) {
			// Run a final data parse to get any terminating info
			if (cliframework != NULL) {
				ReadBytes(); 
				ReadEBytes();
				cliframework->ParseData();
			}

			_MSG("Opened process pid " + IntToString(childpid) + " failed: " +
				 IntToString(globalreg->sigchild_vec[x].status), MSGFLAG_ERROR);

			KillConnection();
			globalreg->sigchild_vec.erase(globalreg->sigchild_vec.begin() + x);
			return -1;
		}
	}

	return 0;
}

int PopenClient::Connect(const char *in_remotehost, short int in_port,
						 netcli_connect_cb in_connect_cb, void *in_con_aux) {
	(void) in_port;

	if (pipe(ipipe) != 0 || pipe(opipe) != 0 || pipe(epipe) != 0) {
		_MSG("Unable to create pipe: " + string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

	if ((childpid = fork()) < 0) {
		_MSG("Failed to fork: " + string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	} else if (childpid == 0) {
		usleep(500);

		vector<string> args = QuoteStrTokenize(in_remotehost, " ");
		char **eargv;

		eargv = (char **) malloc(sizeof(char *) * (args.size() + 1));

		for (unsigned int x = 0; x < args.size(); x++)  {
			eargv[x] = strdup(args[x].c_str());
		}

		eargv[args.size()] = NULL;

		dup2(ipipe[0], STDIN_FILENO);
		dup2(opipe[1], STDOUT_FILENO);
		dup2(epipe[1], STDERR_FILENO);

		/* We don't need these copies anymore */
		close(ipipe[0]);
		close(ipipe[1]);
		close(opipe[0]);
		close(opipe[1]);
		close(epipe[0]);
		close(epipe[1]);

		execvp(eargv[0], eargv);

		fprintf(stderr, "Launching '%s' failed: %s\n", eargv[0], strerror(errno));

		exit(255);
	}

	// write-only pipe
	close(ipipe[0]);
	// Read-only pipes
	close(opipe[1]);
	close(epipe[1]);

	// Set them to be nonblocking
	fcntl(opipe[0], F_SETFL, (fcntl(opipe[0], F_GETFL, 0) | O_NONBLOCK));
	fcntl(epipe[0], F_SETFL, (fcntl(opipe[0], F_GETFL, 0) | O_NONBLOCK));

	cl_valid = 1;

	write_buf = new RingBuffer(POPEN_RING_LEN);
	read_buf = new RingBuffer(POPEN_RING_LEN);

	// Just put something valid in here
	cli_fd = ipipe[1];

    return 1;
}

void PopenClient::KillConnection() {
	if (childpid > 0) {
		kill(childpid, SIGQUIT);

		close(ipipe[1]);
		close(opipe[0]);
		close(epipe[0]);

		childpid = 0;
	}

	cli_fd = -1;

	// fprintf(stderr, "debug - popenclient calling networkclient killonnection\n");
	NetworkClient::KillConnection();
}

void PopenClient::SoftKillConnection() {
	// Send a soft kill and let it die on it's own, so we can capture the
	// output if any
	if (childpid > 0) {
		kill(childpid, SIGTERM);
	}
}

void PopenClient::DetatchConnection() {
	if (childpid > 0) {
		close(ipipe[1]);
		close(opipe[0]);
		close(epipe[0]);

		childpid = 0;
	}

	cl_valid = 0;
}

int PopenClient::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    int max;

	if (CheckPidVec() < 0 || !cl_valid)
		return in_max_fd;

	max = in_max_fd;

    if (max < ipipe[1])
        max = ipipe[1];

    if (max < opipe[0])
        max = opipe[0];

    if (max < epipe[0])
        max = epipe[0];

	// opipe is connected to stdout so we treat it as read, same with epipe
	FD_SET(opipe[0], out_rset);
	FD_SET(epipe[0], out_rset);

	if (write_buf != NULL && write_buf->FetchLen() > 0) {
		FD_SET(ipipe[1], out_wset);
	}

    return max;
}

int PopenClient::Poll(fd_set& in_rset, fd_set& in_wset) {
    int ret = 0;

    if (CheckPidVec() < 0 || !cl_valid)
        return 0;

    // Look for stuff to read, opipe and epipe are where we read from
    if (FD_ISSET(opipe[0], &in_rset)) {
        // If we failed reading, die.
        if ((ret = ReadBytes()) < 0) {
            KillConnection();
            return ret;
		}

        // If we've got new data, try to parse.  if we fail, die.
        if (ret != 0 && cliframework->ParseData() < 0) {
            KillConnection();
            return -1;
        }
    }

    if (FD_ISSET(epipe[0], &in_rset)) {
        // If we failed reading, die.
        if ((ret = ReadEBytes()) < 0) {
            KillConnection();
            return ret;
		}

        // If we've got new data, try to parse.  If we fail, die.
        if (ret != 0 && cliframework->ParseData() < 0) {
            KillConnection();
            return -1;
        }
    }

    // Look for stuff to write
    if (FD_ISSET(ipipe[1], &in_wset)) {
        // If we can't write data, die.
        if ((ret = WriteBytes()) < 0)
            KillConnection();
            return ret;
    }
    
    return ret;
}

int PopenClient::ReadBytes() {
	if (read_buf == NULL)
		return 0;

    uint8_t recv_bytes[1024];
    int ret;

    if ((ret = read(opipe[0], recv_bytes, 1024)) < 0) {
		if (errno == EINTR || errno == EAGAIN) 
			return 0;

		snprintf(errstr, 1024, "Popen client read() error: %s", 
				 strerror(errno));
		globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
		return -1;
    }

    if (ret <= 0) {
        snprintf(errstr, 1024, "Popen application closed");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
        return -1;
    }

    if (read_buf->InsertData(recv_bytes, ret) == 0) {
        snprintf(errstr, 1024, "Popen client fd read error, ring buffer full");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    return ret;
}

int PopenClient::ReadEBytes() {
	if (read_buf == NULL)
		return 0;

    uint8_t recv_bytes[1024];
    int ret;

    if ((ret = read(epipe[0], recv_bytes, 1024)) < 0) {
		if (errno == EINTR || errno == EAGAIN) 
			return 0;

        snprintf(errstr, 1024, "Popen client read() error: %s", 
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    if (ret == 0) {
        snprintf(errstr, 1024, "Popen application closed");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    if (read_buf->InsertData(recv_bytes, ret) == 0) {
        snprintf(errstr, 1024, "Popen client fd read error, ring buffer full");
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    return ret;
}

int PopenClient::WriteBytes() {
	if (write_buf == NULL)
		return 0;

    uint8_t dptr[1024];
    int dlen, ret;

    write_buf->FetchPtr(dptr, 1024, &dlen);

    if ((ret = write(ipipe[1], dptr, dlen)) <= 0) {
        snprintf(errstr, 1024, "Popen client: Killing client write error %s",
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    write_buf->MarkRead(ret);

    return ret;
}

