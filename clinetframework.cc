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
#include "clinetframework.h"

NetworkClient::NetworkClient() {
	fprintf(stderr, "FATAL OOPS:  Networkclient() called with no globalreg\n");
	exit(-1);
}

NetworkClient::NetworkClient(GlobalRegistry *in_globalreg) {
    globalreg = in_globalreg;
    cl_valid = 0;
    cli_fd = -1;
    read_buf = NULL;
    write_buf = NULL;
	connect_complete = -1;
	connect_cb = NULL;
	connect_aux = NULL;
}

NetworkClient::~NetworkClient() {
    KillConnection();
}

int NetworkClient::MergeSet(int in_max_fd, fd_set *out_rset, fd_set *out_wset) {
    int max;

	// fprintf(stderr, "debug - networkclient mergeset valid %d clifd %d\n", cl_valid, cli_fd); fflush(stderr);
	if (connect_complete == 0 && cli_fd >= 0) {
		// fprintf(stderr, "debug - mergeing deferred %d\n", cli_fd);
		FD_SET(cli_fd, out_wset);
		if (in_max_fd < cli_fd)
			max = cli_fd;
		else
			max = in_max_fd;

		return max;
	}

    if (in_max_fd < cli_fd && cl_valid)
        max = cli_fd;
    else
        max = in_max_fd;

    if (cl_valid) {
        FD_SET(cli_fd, out_rset);

        if ((write_buf != NULL && write_buf->FetchLen() > 0)) {
            FD_SET(cli_fd, out_wset);
		}
    }

    return max;
}

int NetworkClient::Poll(fd_set& in_rset, fd_set& in_wset) {
    int ret = 0;

	// fprintf(stderr, "debug - %d connect complete %d\n", cli_fd, connect_complete);
	
	if (cli_fd < 0)
		return 0;

	if (connect_complete == 0) {
		// printf("debug - poll query %d\n", cli_fd);
		if (FD_ISSET(cli_fd, &in_wset)) {
			int r, e;
			socklen_t l;

			e = 0;
			l = sizeof(int);

			r = getsockopt(cli_fd, SOL_SOCKET, SO_ERROR, &e, &l);

			// fprintf(stderr, "debug - deferred connect %d got r %d e %d l %d error %s\n", cli_fd, r, e, l, strerror(e));

			if (r < 0 || e != 0) {

				if (connect_cb != NULL)
					(*connect_cb)(globalreg, e, connect_aux);

				// fprintf(stderr, "debug - calling killconnection\n");
				KillConnection();

			} else {
				// fprintf(stderr, "debug - %d deferred connect worked\n", cli_fd);
				connect_complete = 1;
				cl_valid = 1;

				if (connect_cb != NULL)
					(*connect_cb)(globalreg, 0, connect_aux);

				return 0;
			}
		}

		return 0;
	}

    if (!cl_valid)
        return 0;

    // Look for stuff to read
    if (FD_ISSET(cli_fd, &in_rset)) {
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

	if (cli_fd < 0 || !cl_valid) {
		KillConnection();
		return -1;
	}

    // Look for stuff to write
    if (FD_ISSET(cli_fd, &in_wset)) {
		// fprintf(stderr, "debug - %d poll looks like something to write\n", cli_fd);
        // If we can't write data, die.
        if ((ret = WriteBytes()) < 0)
            KillConnection();
            return ret;
    }
    
    return ret;
}

int NetworkClient::FlushRings() {
    if (!cl_valid)
        return -1;

    fd_set rset, wset;
    int max;
    
    time_t flushtime = time(0);

    // Nuke the fatal condition so we can track our own failures
    int old_fcon = globalreg->fatal_condition;
    globalreg->fatal_condition = 0;
    
    while ((time(0) - flushtime) < 2) {
        if (write_buf == NULL || (write_buf != NULL && write_buf->FetchLen() <= 0))
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

			continue;
        }

        if (Poll(rset, wset) < 0 || globalreg->fatal_condition != 0)
            return -1;
    }

    globalreg->fatal_condition = old_fcon;

    return 1;
}

void NetworkClient::KillConnection() {
	// fprintf(stderr, "debug - nc killcon\n");

	connect_complete = -1;

	// fprintf(stderr, "debug - clearing buffers %p %p\n", read_buf, write_buf);
	if (read_buf != NULL)
		delete read_buf;
	if (write_buf != NULL)
		delete write_buf;
	read_buf = NULL;
	write_buf = NULL;

	// fprintf(stderr, "debug - closing fd %d\n", cli_fd);
    if (cli_fd >= 0)
        close(cli_fd);

	cli_fd = -1;

    cl_valid = 0;

	// fprintf(stderr, "debug - clienetframework kill %p\n", cliframework);

	if (cliframework != NULL)
		cliframework->KillConnection();

    return;
}

int NetworkClient::WriteData(void *in_data, int in_len) {
	if (write_buf == NULL)
		return 0;

    if (write_buf->InsertDummy(in_len) == 0) {
        snprintf(errstr, STATUS_MAX, "NetworkClient::WriateData no room in ring "
                 "buffer to insert %d bytes", in_len);
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    write_buf->InsertData((uint8_t *) in_data, in_len);
    
    return 1;
}

int NetworkClient::FetchReadLen() {
	if (read_buf == NULL)
		return 0;

    return (int) read_buf->FetchLen();
}

int NetworkClient::ReadData(void *ret_data, int in_max, int *ret_len) {
	if (read_buf == NULL)
		return 0;

    read_buf->FetchPtr((uint8_t *) ret_data, in_max, ret_len);

    return (*ret_len);
}

int NetworkClient::MarkRead(int in_readlen) {
	if (read_buf == NULL)
		return 1;

    read_buf->MarkRead(in_readlen);

    return 1;
}

int ClientFramework::Shutdown() {
    int ret = 0;

    if (netclient != NULL)
        ret = netclient->FlushRings();

    return ret;
}

