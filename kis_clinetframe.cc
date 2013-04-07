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

int KisNetClientReconEvent(TIMEEVENT_PARMS) {
	((KisNetClient *) auxptr)->Reconnect();
	return 1;
}

int KisNetClientTimeoutEvent(TIMEEVENT_PARMS) {
	((KisNetClient *) auxptr)->Timer();
	return 1;
}

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

	// Set to -1 so the reconnect auto-incr doesn't screw us up
	num_reconnects = -1;
	reconnect = 0;
	reconid = -1;

	cmdid = 1;
	last_disconnect = 0;

	last_read = 0;

	// Counter for configure level
	configured = 1;

	timerid =
		globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 5,
											  NULL, 1, &KisNetClientTimeoutEvent,
											  (void *) this);
}

KisNetClient::~KisNetClient() {
	KillConnection();

	if (tcpcli != NULL) {
		delete tcpcli;
		tcpcli = NULL;
	}

	if (reconid > -1)
		globalreg->timetracker->RemoveTimer(reconid);

	if (timerid > -1)
		globalreg->timetracker->RemoveTimer(timerid);

	globalreg->RemovePollableSubsys(this);
}

int KisNetClient::Connect(string in_host, int in_reconnect) {
	char proto[11];
	char temphost[129];
	short int temport;

	if (sscanf(in_host.c_str(), "%10[^:]://%128[^:]:%hu", 
			   proto, temphost, &temport) != 3) {
		_MSG("Kismet network client could not parse host, expected the form "
			 "proto://host:port, got '" + in_host + "'", MSGFLAG_ERROR);
		return -1;
	}

	if (StrLower(string(proto)) != "tcp") {
		_MSG("Kismet network client currently only supports the TCP protocol for "
			 "connecting to servers.", MSGFLAG_ERROR);
		return -1;
	}

	snprintf(host, MAXHOSTNAMELEN, "%s", temphost);
	port = temport;
	

	if (in_reconnect && reconid == -1) {
		reconid =
			globalreg->timetracker->RegisterTimer(SERVER_TIMESLICES_SEC * 5,
												  NULL, 1, &KisNetClientReconEvent,
												  (void *) this);
		reconnect = 1;
	}

	last_disconnect = 1;

	// Let the reconnect trigger handle the rest
	return Reconnect();
}

int KisNetClient::KillConnection() {
	ClientFramework::KillConnection();

	last_disconnect = time(0);

	// Remove all the configured protocols, they'll get re-registered by the 
	// configure callbacks
	map<string, kcli_configured_proto_rec>::iterator hitr;

	for (hitr = handler_cb_map.begin(); hitr != handler_cb_map.end(); ++hitr) {
		for (unsigned int x = 0; x < hitr->second.handler_vec.size(); x++) {
			delete(hitr->second.handler_vec[x]);
		}
	}

	handler_cb_map.clear();

	// Clear the supported fields
	proto_field_dmap.clear();

	// Clear the command callback map (all commands are dead)
	command_cb_map.clear();

	return 1;
}

int KisNetClient::Shutdown() {
	if (tcpcli != NULL) {
		tcpcli->FlushRings();
		tcpcli->KillConnection();
	}

	return 1;
}

void KisNetClient::AddConfCallback(CliConf_Callback in_cb, int in_recon,
								   void *in_aux) {
	kcli_conf_rec *rec = new kcli_conf_rec;

	rec->auxptr = in_aux;
	rec->callback = in_cb;
	rec->on_recon = in_recon;

	conf_cb_vec.push_back(rec);

	// Call the configure function if we're already configured
	if (configured < 0) {
		(*in_cb)(globalreg, this, 0, in_aux);
	}
}

void KisNetClient::RemoveConfCallback(CliConf_Callback in_cb) {
	for (unsigned int x = 0; x < conf_cb_vec.size(); x++) {
		if (conf_cb_vec[x]->callback == in_cb) {
			delete conf_cb_vec[x];
			conf_cb_vec.erase(conf_cb_vec.begin() + x);
			break;
		}
	}
}

int KisNetClient::RegisterProtoHandler(string in_proto, string in_fieldlist,
									   CliProto_Callback in_cb, void *in_aux,
									   CliCmd_Callback in_cmd_complete) {
	in_proto = StrLower(in_proto);

	/*
	if (handler_cb_map.find(in_proto) != handler_cb_map.end()) {
		_MSG("Handler for '" + in_proto + "' already registered.", MSGFLAG_ERROR);
		return -1;
	}
	*/

	// Do we know about this proto at all?
	map<string, vector<kcli_field_rec> >::iterator dmitr = 
		proto_field_dmap.find(in_proto);

	if (dmitr == proto_field_dmap.end()) {
		/*
		_MSG("Kis net client - trying to register for unknown protocol '" + 
			 in_proto + "'", MSGFLAG_ERROR);
		*/
		return -1;
	}

	// Break down the fields and compare against the fields we know about, make
	// sure they can't enable something the server doesn't understand.  This is a 
	// cheap hack around our non-async behavior that keeps us from having a good
	// way to return a command failure condition
	vector<string> fields = StrTokenize(in_fieldlist, ",");

	kcli_handler_rec *rec = new kcli_handler_rec;

	for (unsigned int x = 0; x < fields.size(); x++) {
		int matched = 0;
		fields[x] = StrLower(fields[x]);

		for (unsigned int fx = 0; fx < dmitr->second.size(); fx++) {
			if (dmitr->second[fx].fname == fields[x]) {
				matched = 1;

				// Stack the field numbers for this callback, in reference
				// to the absolute field number from the CAPABILITY field.
				rec->local_fnums.push_back(dmitr->second[fx].fnum);
			}
		}

		if (matched == 0) {
			_MSG("Unknown field '" + fields[x] + "' requested for protocol '" +
				 in_proto + "'", MSGFLAG_ERROR);
			delete rec;
			return -1;
		}
	}

	// Increase the use count for the fields we enabled, done here to preserve
	// fields if a compare fails
	for (unsigned int x = 0; x < rec->local_fnums.size(); x++) {
		dmitr->second[rec->local_fnums[x]].usecount++;
	}

	rec->auxptr = in_aux;
	rec->callback = in_cb;

	string combo_fieldlist;
	map<int, int> a_l_map;
	int cfpos = 0;
	for (unsigned int x = 0; x < dmitr->second.size(); x++) {
		if (dmitr->second[x].usecount > 0) {
			// Build a linkage of absolute field number to field num we
			// get in response to this specific CONFIGURE command
			a_l_map[dmitr->second[x].fnum] = cfpos++;
			combo_fieldlist += dmitr->second[x].fname + ",";
		}
	}

	// Send the command
	InjectCommand("ENABLE " + in_proto + " " + combo_fieldlist,
				  in_cmd_complete, in_aux);

	handler_cb_map[in_proto].fields = combo_fieldlist;
	handler_cb_map[in_proto].abs_to_conf_fnum_map = a_l_map;
	handler_cb_map[in_proto].handler_vec.push_back(rec);

	return 1;
}

void KisNetClient::RemoveProtoHandler(string in_proto, CliProto_Callback in_cb,
									  void *in_aux) {
	in_proto = StrLower(in_proto);
	int removeproto = 1;

	map<string, kcli_configured_proto_rec>::iterator hitr =
		handler_cb_map.find(in_proto);
	map<string, vector<kcli_field_rec> >::iterator dmitr =
		proto_field_dmap.find(in_proto);

	if (hitr == handler_cb_map.end() || dmitr == proto_field_dmap.end()) 
		return;

	for (unsigned int x = 0; x < hitr->second.handler_vec.size(); x++) {
		if (hitr->second.handler_vec[x]->callback == in_cb && 
			hitr->second.handler_vec[x]->auxptr == in_aux) {

			// Track use counts for fields, we won't remove this protocol if
			// we have anyone using it
			for (unsigned int fx = 0; 
				 fx < hitr->second.handler_vec[x]->local_fnums.size(); fx++) {
				dmitr->second[hitr->second.handler_vec[x]->local_fnums[fx]].usecount--;

				if (dmitr->second[hitr->second.handler_vec[x]->local_fnums[fx]].usecount > 0)
					removeproto = 0;
			}

			delete hitr->second.handler_vec[x];
			hitr->second.handler_vec.erase(hitr->second.handler_vec.begin() + x);
			break;
		}
	}

	if (hitr->second.handler_vec.size() == 0) {
		removeproto = 1;
		handler_cb_map.erase(hitr);
	}

	if (removeproto)
		InjectCommand("REMOVE " + in_proto);
}

int KisNetClient::FetchProtoCapabilities(string in_proto,
										 map<string, int> *ret_fields) {
	map<string, vector<kcli_field_rec> >::iterator pfi;

	pfi = proto_field_dmap.find(StrLower(in_proto));

	if (pfi == proto_field_dmap.end())
		return -1;

	for (unsigned int i = 0; i < pfi->second.size(); i++) {
		ret_fields->insert(make_pair(pfi->second[i].fname, 
									 pfi->second[i].fnum));
	}

	return 1;
}

int KisNetClient::InjectCommand(string in_cmdtext, CliCmd_Callback in_cb,
								void *in_aux) {
	if (tcpcli->Valid() == 0)
		return 0;

	int curid = cmdid++;
	ostringstream cmd;

	cmd << "!" << curid << " " << in_cmdtext << "\n";

	// fprintf(stderr, "debug - %p INJECTCMD %s\n", this, cmd.str().c_str());

	if (tcpcli->WriteData((void *) cmd.str().c_str(), cmd.str().length()) < 0 ||
		globalreg->fatal_condition) {
		KillConnection();
		return -1;
	}

	if (in_cb != NULL) {
		kcli_cmdcb_rec cbr;
		cbr.auxptr = in_aux;
		cbr.callback = in_cb;

		command_cb_map[curid] = cbr;
	}

	return curid;
}

void KisNetClient::RemoveAllCmdCallbacks(CliCmd_Callback in_cb, void *in_aux) {
	for (map<int, kcli_cmdcb_rec>::iterator x = command_cb_map.begin();
		 x != command_cb_map.end(); ++x) {
		if (x->second.auxptr == in_aux && x->second.callback == in_cb) {
			command_cb_map.erase(x);
			x = command_cb_map.begin();
		}
	}
}

int KisNetClient::Timer() {
	if (tcpcli == NULL)
		return -1;

	if (tcpcli->Valid() == 0)
		return 0;

	if (time(0) - last_read > 10) {
		_MSG("No data from Kismet server in over 10 seconds, disconnecting",
			 MSGFLAG_ERROR);
		KillConnection();
		return 1;
	}

	return 0;
}

void knc_connect_hook(GlobalRegistry *globalreg, int status, void *auxptr) {
	((KisNetClient *) auxptr)->ConnectCB(status);
}

void KisNetClient::ConnectCB(int status) {
	ostringstream osstr;

	if (status != 0) {
		osstr << "Could not connect to Kismet server '" << host << ":" << port <<
			"' (" + string(strerror(status)) + ") will attempt to reconnect in 5 "
			"seconds.";
		_MSG(osstr.str(), MSGFLAG_ERROR);
		last_disconnect = globalreg->timestamp.tv_sec;
		return;
	}

	osstr << "Established connection with Kismet server '" << host << 
		":" << port << "'";
	_MSG(osstr.str(), MSGFLAG_INFO);
	last_disconnect = 0;

	// Set the start time and initialize configured to 1
	last_read = time_connected = time(0);
	configured = 1;

	num_reconnects++;
}

int KisNetClient::Reconnect() {
	// fprintf(stderr, "debug - knc reconnect called\n");
	if (tcpcli == NULL) {
		return -1;
	}

	if (tcpcli->Valid() || last_disconnect == 0) {
		return 1;
	}

	tcpcli->KillConnection();

	ostringstream osstr;

	if (tcpcli->ConnectSync(host, port, knc_connect_hook, this) < 0) {
		return 0;
	}

	return 1;
}

int KisNetClient::ParseData() {
    int len, rlen;
    char *buf;
    string strbuf;
	ostringstream osstr;

    // Scratch variables for parsing data
    char header[65];

	// fprintf(stderr, "debug - knc::parsedata\n");

	if (netclient == NULL) {
		// fprintf(stderr, "debug - netclient null\n");
		return 0;
	}

	if (netclient->Valid() == 0) {
		// fprintf(stderr, "debug - netclient not valid\n");
		return 0;
	}

    len = netclient->FetchReadLen();
    buf = new char[len + 1];

	// fprintf(stderr, "debug - knc buflen %d\n", len); fflush(stderr);

    if (netclient->ReadData(buf, len, &rlen) < 0) {
		_MSG("Kismet protocol parser failed to get data from the TCP connection",
			 MSGFLAG_ERROR);
        delete[] buf;
        return -1;
    }
    buf[len] = '\0';

	last_read = time(0);

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
		if (netclient->Valid())
			netclient->MarkRead(inptok[it].length() + 1);

        // Pull the header out to save time -- cheaper to parse the header and 
		// then the data than to try to parse an entire data string just to find 
		// out what protocol we are

		// Throw out absurdly short lines
		if (inptok[it].length() < 4)
			continue;
		
        if (sscanf(inptok[it].c_str(), "*%64[^:]", header) < 1) {
            continue;
        }

        // Nuke the header off the string
        inptok[it].erase(0, (size_t) strlen(header) + 3);

		// Smarter tokenization to handle quoted field buffers
		vector<smart_word_token> net_toks = NetStrTokenize(inptok[it], " ", 1);

		// All protocols have to return something
		if (net_toks.size() == 0)
			continue;

		if (!strncmp(header, "KISMET", 7)) {
			// Decrement our configure counter
			configured--;

			// Parse the client stuff out, in a really ghetto way
			if (net_toks.size() >= 5) {
				int tint;

				sscanf(net_toks[1].word.c_str(), "%d", &tint);
				server_starttime = tint;

				server_name = net_toks[2].word;

				sscanf(net_toks[4].word.c_str(), "%d", &server_uid);

				_MSG("Connected to Kismet server \'" + server_name + "\'",
					 MSGFLAG_INFO);
			}

		} else if (!strncmp(header, "TERMINATE", 10)) {
			osstr << "Kismet server '" << host << ":" << port << "' has "
				"terminated";
			_MSG(osstr.str(), MSGFLAG_ERROR);
            netclient->KillConnection();
            continue;
		} else if (!strncmp(header, "PROTOCOLS", 10)) {
			// Vectorize the protocol list
			vector<string> protovec = StrTokenize(net_toks[0].word, ",");

			if (protovec.size() <= 0) {
				osstr << "Kismet server '" << host << ":" << port << "' sent a "
					"protocols list with nothing in it, something is broken";
				_MSG(osstr.str(), MSGFLAG_ERROR);
				// We'll keep trying though
				continue;
			}

			// We expect that a protocol will never add fields once it's been
			// announced.  If this changes, this assumption will be broken
			for (unsigned int pro = 0; pro < protovec.size(); pro++) {
				// Send a capabilities request for all of the protocols
				if (InjectCommand("CAPABILITY " + protovec[pro]) < 0) {
					osstr << "Kismet server '" << host << ":" << port << "' "
						"network failure while queuing a capability request";
					_MSG(osstr.str(), MSGFLAG_ERROR);
					KillConnection();
					return -1;
				}

				// Increment our configure counter
				configured++;
			}
		} else if (!strncmp(header, "CAPABILITY", 11)) {
			if (net_toks.size() != 2) {
				osstr << "Kismet server '" << host << ":" << port << "' "
					"sent a capability report without the proper fields";
				_MSG(osstr.str(), MSGFLAG_ERROR);
				continue;
			}

			// Vectorize the field list, error check it, and make sure we're
			// in the list of protocols
			vector<string> fieldvec = StrTokenize(net_toks[1].word, ",");

			if (fieldvec.size() <= 0) {
				osstr << "Kismet server '" << host << ":" << port << "' sent a "
					"protocol capability list with nothing in it, something is "
					"broken";
				_MSG(osstr.str(), MSGFLAG_ERROR);
				// We'll keep trying though
				continue;
			}

			map<string, vector<kcli_field_rec> >::iterator dmitr = 
				proto_field_dmap.find(StrLower(net_toks[0].word));

			// We assume protocols can't change runtime for now
			if (dmitr == proto_field_dmap.end()) {
				// Put them all in the map
				vector<kcli_field_rec> flvec;
				for (unsigned int fl = 0; fl < fieldvec.size(); fl++) {
					kcli_field_rec frec;
					frec.fname = StrLower(fieldvec[fl]);
					frec.fnum = fl;
					frec.usecount = 0;

					flvec.push_back(frec);
				}

				// Assign it
				proto_field_dmap[StrLower(net_toks[0].word)] = flvec;
			}

			// Decrement our configure count
			configured--;

		} else if (!strncmp(header, "ERROR", 6) && net_toks.size() >= 2) {
			int cmdnum;
			if (sscanf(net_toks[0].word.c_str(), "%d", &cmdnum) != 0) {
				map<int, kcli_cmdcb_rec>::iterator cbi;

				if ((cbi = command_cb_map.find(cmdnum)) != command_cb_map.end()) {
					(*(cbi->second.callback))(globalreg, this, 0, net_toks[1].word,
											  cbi->second.auxptr);
					command_cb_map.erase(cbi);
				}
			}
		} else if (!strncmp(header, "ACK", 4)) {
			int cmdnum;
			if (sscanf(net_toks[0].word.c_str(), "%d", &cmdnum) != 0) {
				map<int, kcli_cmdcb_rec>::iterator cbi;

				if ((cbi = command_cb_map.find(cmdnum)) != command_cb_map.end()) {
					(*(cbi->second.callback))(globalreg, this, 1, net_toks[1].word,
											  cbi->second.auxptr);
					command_cb_map.erase(cbi);
				}
			}
		} else if (!strncmp(header, "TIME", 5)) {
			// Graceful handling of junk time proto, set us to 0.
			int tint;
			if (sscanf(net_toks[0].word.c_str(), "%d", &tint) != 0)
				last_time = 0;
			else
				last_time = (time_t) tint;
		}

		// Call the registered handlers for this protocol, even if we handled
		// it internally
		map<string, kcli_configured_proto_rec>::iterator hi;
		hi = handler_cb_map.find(StrLower(header));
		if (hi != handler_cb_map.end()) {
			for (unsigned int hx = 0; hx < hi->second.handler_vec.size(); hx++) {
				vector<smart_word_token> cb_toks; 

				// Build a local vector of tokens for this protocol
				for (unsigned int nt = 0; 
					 nt < hi->second.handler_vec[hx]->local_fnums.size(); nt++) {
					// Map the absolute field number to the locally configured field
					// number
					int locfnum = hi->second.abs_to_conf_fnum_map[hi->second.handler_vec[hx]->local_fnums[nt]];

					// Something has gone poorly and we've got a token in our req
					// that isn't in our data
					if (locfnum >= (int) net_toks.size()) 
						continue;

					// Stack the field derived from the local field number
					cb_toks.push_back(net_toks[locfnum]);
				}

				CliProto_Callback cback = hi->second.handler_vec[hx]->callback;
				(*cback)(globalreg, inptok[it], &cb_toks, this,
						 hi->second.handler_vec[hx]->auxptr);
			}
		}
	}

	// If we're done configuring, set it to 0 and call the configured stuff
	// Make sure we've been running long enough to get all the data flushed
	// through.  This is safe to hardcode here because the TIME will always
	// wake us up.
	// fprintf(stderr, "debug - configured %d time delta %lu\n", configured, (time(0) - time_connected));
	if (configured == 0 && (globalreg->timestamp.tv_sec - time_connected) > 2) {
		for (unsigned int x = 0; x < conf_cb_vec.size(); x++) {
			if (conf_cb_vec[x]->on_recon == 0 && num_reconnects != 0)
				continue;

			CliConf_Callback cback = conf_cb_vec[x]->callback;
			(*cback)(globalreg, this, num_reconnects, conf_cb_vec[x]->auxptr);
		}
		configured = -1;
	}

	return 1;
}

