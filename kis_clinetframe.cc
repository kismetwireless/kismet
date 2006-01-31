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

#include <sstream>

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

	reconnect = 0;
	reconid = -1;

	cmdid = 1;
	last_disconnect = 0;
	
	globalreg->RegisterPollableSubsys(this);
}

KisNetClient::~KisNetClient() {
	globalreg->RemovePollableSubsys(this);

	if (tcpcli != NULL) {
		tcpcli->KillConnection();
		delete tcpcli;
		tcpcli = NULL;
	}

	if (reconid > -1)
		globalreg->timetracker->RemoveTimer(reconid);

}

int KisNetClient::KillConnection() {
	if (tcpcli != NULL && tcpcli->Valid())
		tcpcli->KillConnection();

	return 1;
}

int KisNetClient::Shutdown() {
	if (tcpcli != NULL) {
		tcpcli->FlushRings();
		tcpcli->KillConnection();
	}

	return 1;
}

int KisNetClient::RegisterProtoHandler(string in_proto, string in_fieldlist,
									   CliProto_Callback in_cb, void *in_aux) {
	in_proto = StrLower(in_proto);

	if (handler_cb_map.find(in_proto) != handler_cb_map.end()) {
		_MSG("Handler for '" + in_proto + "' already registered.", MSGFLAG_ERROR);
		return -1;
	}

	// Do we know about this proto at all?
	map<string, map<string, int> >::iterator dmitr = proto_field_dmap.find(in_proto);

	if (dmitr == proto_field_dmap.end()) {
		_MSG("Trying to register for unknown protocol '" + in_proto + "'",
			 MSGFLAG_ERROR);
		return -1;
	}

	// Break down the fields and compare against the fields we know about, make
	// sure they can't enable something the server doesn't understand.  This is a 
	// cheap hack around our non-async behavior that keeps us from having a good
	// way to return a command failure condition
	vector<string> fields = StrTokenize(in_fieldlist, ",");

	for (unsigned int x = 0; x < fields.size(); x++) {
		if (dmitr->second.find(StrLower(fields[x])) == dmitr->second.end()) {
			_MSG("Unknown field '" + fields[x] + "' requested for protocol '" +
				 in_proto + "'", MSGFLAG_ERROR);
			return -1;
		}
	}

	kcli_handler_rec *rec = new kcli_handler_rec;
	rec->auxptr = in_aux;
	rec->callback = in_cb;
	rec->fields = in_fieldlist;

	// Send the command
	InjectCommand("ENABLE " + in_proto + " " + in_fieldlist);
	
	handler_cb_map[in_proto] = rec;

	return 1;
}

void KisNetClient::RemoveProtoHandler(string in_proto) {
	in_proto = StrLower(in_proto);

	map<string, kcli_handler_rec *>::iterator hitr =
		handler_cb_map.find(in_proto);

	if (hitr == handler_cb_map.end())
		return;

	InjectCommand("REMOVE " + in_proto);

	delete hitr->second;
	handler_cb_map.erase(hitr);
}

int KisNetClient::InjectCommand(string in_cmdtext) {
	if (tcpcli->Valid() == 0)
		return 0;

	int curid = cmdid++;
	ostringstream cmd;

	cmd << "!" << curid << " " << in_cmdtext << "\n";

	if (tcpcli->WriteData((void *) cmd.str().c_str(), cmd.str().length()) < 0 ||
		globalreg->fatal_condition) {
		last_disconnect = time(0);
		return -1;
	}

	return curid;
}

int KisNetClient::Reconnect() {

	return 1;
}

int KisNetClient::ParseData() {
    int len, rlen;
    char *buf;
    string strbuf;

    // Scratch variables for parsing data
    char header[65];

	if (netclient == NULL)
		return 0;

    len = netclient->FetchReadLen();
    buf = new char[len + 1];
    
    if (netclient->ReadData(buf, len, &rlen) < 0) {
		_MSG("Kismet protocol parser failed to get data from the TCP connection",
			 MSGFLAG_ERROR);
        return -1;
    }
    buf[len] = '\0';

    // Parse without including partials, so we don't get a fragmented command 
    // out of the buffer
    vector<string> inptok = StrTokenize(buf, "\n", 0);
    delete[] buf;

    // Bail on no useful data
    if (inptok.size() < 1) {
        return 0;
    }

    for (unsigned int it = 0; it < inptok.size(); it++) {
        // No matter what we've dealt with this data block
        netclient->MarkRead(inptok[it].length() + 1);

        // Pull the header out to save time -- cheaper to parse the header and 
		// then the data than to try to parse an entire data string just to find 
		// out what protocol we are
        // 
        // Protocol parsers should be dynamic so that we can have plugins in the 
		// framework able to handle a proto, but right now thats a hassle

        if (sscanf(inptok[it].c_str(), "*%64[^:]", header) < 1) {
            continue;
        }

        // Nuke the header off the string
        inptok[it].erase(0, (size_t) strlen(header) + 3);

		// Smarter tokenization to handle quoted field buffers
		vector<smart_word_token> net_toks = SmartStrTokenize(inptok[it], " ", 1);

        if (!strncmp(header, "TERMINATE", 64)) {
			_MSG("Kismet server '" + string(host) + "' terminated.", MSGFLAG_ERROR);
            netclient->KillConnection();
            continue;
		} else if (!strncmp(header, "PROTOCOLS", 64)) {
			// Vectorize the protocol list
			vector<string> protovec = StrTokenize(net_toks[0].word, ",");

			if (protovec.size() <= 0) {
				_MSG("Kismet server '" + string(host) + "' sent PROTOCOLS list "
					 "with nothing in it, something is broken.", MSGFLAG_ERROR);
				// We'll keep trying though
				continue;
			}

			// We expect that a protocol will never add fields once it's been
			// announced.  If this changes, this assumption will be broken
			for (unsigned int pro = 0; pro < protovec.size(); pro++) {
				if (proto_field_dmap.find(StrLower(protovec[pro])) ==
					proto_field_dmap.end()) {
					// Send a capabilities request for all of the protocols
					if (InjectCommand("CAPABILITY " + protovec[pro]) < 0) {
						_MSG("Failed queuing CAPABILITY command to get details "
							 "for protocol '" + protovec[pro] + "'", MSGFLAG_ERROR);
						return -1;
					}
				}
			}
		} else if (!strncmp(header, "CAPABILITY", 64)) {
			printf("debug - capability response\n");
		}

	}

	return 1;
}

