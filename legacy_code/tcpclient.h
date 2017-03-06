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

#ifndef __TCPCLIENT_H__
#define __TCPCLIENT_H__

#include "config.h"

#include <stdio.h>
#include <string>
#include <time.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>
#include <map>
#include <vector>

#include "ringbuf.h"
#include "messagebus.h"
#include "timetracker.h"
#include "clinetframework.h"

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

// Arbitrary 16k ring.
#define CLI_RING_LEN (16384)

class TcpClient : public NetworkClient {
public:
    TcpClient();
    TcpClient(GlobalRegistry *in_globalreg);
    virtual ~TcpClient();

    virtual int Connect(const char *in_remotehost, short int in_port,
						netcli_connect_cb in_connect_cb, void *in_con_aux);

    virtual int ConnectSync(const char *in_remotehost, short int in_port,
							netcli_connect_cb in_connect_cb, void *in_con_aux);

protected:
    virtual int Validate() {
        return 1;
    }

    virtual int ReadBytes();
    virtual int WriteBytes();
};

#endif

