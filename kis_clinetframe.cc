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
#include "util.h"
#include "configfile.h"
#include "kis_clinetframe.h"
#include "getopt.h"

KisNetClient::KisNetClient() {
	fprintf(stderr, "FATAL OOPS:  kisnetclient called with no globalreg\n");
	exit(-1);
}

KisNetClient::KisNetClient(GlobalRegistry *in_globalreg) :
	ClientFramework(in_globalreg) {

	// We only support tcpclients for now, so just generate it all now
	tcpcli = new TcpClient(globalreg);
	netclient = tcpcli;

	// Link it
	RegisterNetworkClient(tcpcli);
	tcpcli->RegisterClientFramework(this);
	
	globalreg->RegisterPollableSubsys(this);
}

KisNetClient::~KisNetClient() {
	globalreg->RemovePollableSubsys(this);

	if (tcpcli != NULL) {
		tcpcli->KillConnection();
		delete tcpcli;
		tcpcli = NULL;
	}
}

int KisNetClient::KillConnection() {
	if (tcpcli != NULL && tcpcli->Valid())
		tcpcli->KillConnection();

	return 1;
}

int KisNetClient::ShutDown() {
	if (tcpcli != NULL) {
		tcpcli->FlushRings();
		tcpcli->KillConnection();
	}

	return 1;
}

