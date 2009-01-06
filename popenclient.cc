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

	ppipe = NULL;
}

PopenClient::~PopenClient() {
	if (ppipe != NULL)
		pclose(ppipe);
}

int PopenClient::Connect(const char *in_remotehost, short int in_port) {
	const char *mode = NULL;

	if (in_port == 'w')
		mode = "w";
	else
		mode = "r";

	if ((ppipe = popen(in_remotehost, mode)) == NULL) {
		_MSG("Popenclient::Connect() failed to execute program :" +
			 string(strerror(errno)), MSGFLAG_ERROR);
		return -1;
	}

	cl_valid = 1;

	if (in_port == 'w') {
		read_buf = NULL;
		write_buf = new RingBuffer(POPEN_RING_LEN);
	} else {
		read_buf = new RingBuffer(POPEN_RING_LEN);
		write_buf = NULL;
	}

	cli_fd = fileno(ppipe);

    return 1;
}

void PopenClient::KillConnection() {
	if (ppipe != NULL)
		pclose(ppipe);

	// Nix the clifd early so killcon doesn't close it out again
	cli_fd = -1;

	NetworkClient::KillConnection();
}


int PopenClient::ReadBytes() {
	if (read_buf == NULL)
		return 0;

    uint8_t recv_bytes[1024];
    int ret;

    if ((ret = read(cli_fd, recv_bytes, 1024)) < 0) {
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

    if ((ret = write(cli_fd, dptr, dlen)) <= 0) {
        snprintf(errstr, 1024, "Popen client: Killing client write error %s",
                 strerror(errno));
        globalreg->messagebus->InjectMessage(errstr, MSGFLAG_ERROR);
		KillConnection();
        return -1;
    }

    write_buf->MarkRead(ret);

    return ret;
}

