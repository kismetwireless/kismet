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

/* Stubbed out class for the drone to link.  Many components expect the
 * netframe to be present, but the drone doesn't use it.  Linking this in
 * will stub out all the functions that the components expect.
 */

#include "config.h"
#include "util.h"
#include "configfile.h"
#include "packet.h"
#include "packetsourcetracker.h"
#include "packetchain.h"
#include "kis_netframe.h"
#include "tcpserver.h"
#include "getopt.h"

KisNetFramework::KisNetFramework() {
	return;
}

void KisNetFramework::Usage(char *name) {
	return;
}

KisNetFramework::KisNetFramework(GlobalRegistry *in_globalreg) {
	return;
}

int KisNetFramework::Shutdown() {
	return 0;
}

int KisNetFramework::Activate() {
	return 0;
}

KisNetFramework::~KisNetFramework() {
	return;
}

int KisNetFramework::Accept(int in_fd) {
	return 0;
}

int KisNetFramework::BufferDrained(int in_fd) {
	return 0;
}

int KisNetFramework::ParseData(int in_fd) {
	return 0;
}

int KisNetFramework::KillConnection(int in_fd) {
	return 0;
}

int KisNetFramework::RegisterClientCommand(string in_cmdword, ClientCommand in_cmd,
										   void *in_auxptr) {
	return 0;
}

int KisNetFramework::RemoveClientCommand(string in_cmdword) {
	return 0;
}

int KisNetFramework::SendToClient(int in_fd, int in_refnum, const void *in_data,
								 kis_protocol_cache *in_cache) {
	return 0;
}

int KisNetFramework::SendToAll(int in_refnum, const void *in_data) {
	return 0;
}

int KisNetFramework::RegisterProtocol(string in_header, int in_required, int in_cache,
									  const char **in_fields,
									  int (int_printer)(PROTO_PARMS),
									  void (*in_enable)(PROTO_ENABLE_PARMS),
									  void *in_auxdata) {
	return 0;
}

int KisNetFramework::RemoveProtocol(int in_protoref) {
	return 0;
}

int KisNetFramework::FetchProtocolRef(string in_header) {
	return 0;
}

KisNetFramework::server_protocol *KisNetFramework::FetchProtocol(int in_ref) {
	return 0;
}

int KisNetFramework::FetchNumClientRefs(int in_refnum) {
	return 0;
}

int KisNetFramework::FetchNumClients() {
	return 0;
}

void KisNetFramework::AddProtocolClient(int in_fd, int in_refnum, 
										vector<int> in_fields) {
	return;
}

void KisNetFramework::DelProtocolClient(int in_fd, int in_refnum) {
	return;
}


