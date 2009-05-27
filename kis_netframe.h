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

#ifndef __KISNETFRAME_H__
#define __KISNETFRAME_H__

#include "config.h"

#include "util.h"
#include "messagebus.h"
#include "netframework.h"
#include "packetchain.h"

// Forward prototype
class KisNetFramework;

// Caching record for sending stuff to multiple clients, gets filled in with
// what needs to be sent via the protocol pointers
class kis_protocol_cache {
public:
	kis_protocol_cache() {
		numfields = 0;
	}
	~kis_protocol_cache() { }
	int Filled(int in_f) {
		if (CacheResize(in_f))
			return 0;
		return field_filled[in_f];
	}
	void Cache(int in_f, string in_val) {
		CacheResize(in_f);
		field_cache[in_f] = in_val;
		field_filled[in_f] = 1;
	}
	string GetCache(int in_f) {
		if (CacheResize(in_f))
			return "";
		return field_cache[in_f];
	}
protected:
	int CacheResize(int in_f) {
		if (in_f < numfields)
			return 0;

		field_cache.resize(in_f + 1, string(""));
		field_filled.resize(in_f + 1, 0);

		/*
		for (int x = numfields; x < in_f; x++) {
			field_filled[x] = 0;
		}
		*/
		numfields = in_f + 1;

		return 1;
	}

	vector<string> field_cache;
	vector<int> field_filled;
	int numfields;
};

// Client command structure for incoming commands.  Given the ID of the client
// and the parsed ID of the command, the server framework, the globals, and the
// remainder of the command line (after cmdid and command itself).  For extra
// fun we pass the cmdline we split apart
#define CLIENT_PARMS int in_clid, KisNetFramework *framework, \
                     GlobalRegistry *globalreg, char *errstr, string cmdline, \
                     vector<smart_word_token> *parsedcmdline, void *auxptr
typedef int (*ClientCommand)(CLIENT_PARMS);

// Protocol parameters
#define PROTO_PARMS string& out_string, const vector<int> *field_vec, \
        const void *data, const void *auxptr, kis_protocol_cache *cache, \
		GlobalRegistry *globalreg
typedef int (*ProtoCallback)(PROTO_PARMS);

#define PROTO_ENABLE_PARMS int in_fd, GlobalRegistry *globalreg, \
		const void *data
typedef void (*ProtoEnableCallback)(PROTO_ENABLE_PARMS);

// Lowlevel protocols that get inserted into the server during setup, these
// MUST be supported ASAP
enum KISMET_fields {
    KISMET_version, KISMET_starttime, KISMET_servername, 
	KISMET_dumpfiles, KISMET_uid,
	KISMET_max
};

enum ERROR_fields {
    ERROR_cmdid, ERROR_cmdtext
};

enum ACK_fields {
    ACK_cmdid, ACK_cmdtext
};

enum PROTOCOL_fields {
    PROTOCOL_protocols
};

enum CAPABILITY_fields {
    CAPABILITY_capabilities
};

enum TERMINATE_fields {
    TERMINATE_text
};

enum TIME_fields {
    TIME_timesec
};

enum STATUS_fields {
    STATUS_text, STATUS_flags
};

enum PACKET_fields {
    PACKET_type, PACKET_subtype, PACKET_timesec, PACKET_encrypted,
    PACKET_weak, PACKET_beaconrate, PACKET_sourcemac, PACKET_destmac,
    PACKET_bssid, PACKET_ssid, PACKET_prototype, PACKET_sourceip,
    PACKET_destip, PACKET_sourceport, PACKET_destport, PACKET_nbtype,
    PACKET_nbsource, PACKET_sourcename
};

// Client/server protocol data structures.  These get passed as void *'s to each 
// of the protocol functions.
// These are all done in two main ways - a var for each field, or a vector in the
// same order as the field names. 

struct PACKET_data {
    vector<string> pdvec;
};

struct STATUS_data {
	string text;
	int flags;
};

int Protocol_KISMET(PROTO_PARMS);
int Protocol_ERROR(PROTO_PARMS);
int Protocol_ACK(PROTO_PARMS);
int Protocol_PROTOCOLS(PROTO_PARMS);
int Protocol_CAPABILITY(PROTO_PARMS);
int Protocol_TERMINATE(PROTO_PARMS);
int Protocol_TIME(PROTO_PARMS);
int Protocol_STATUS(PROTO_PARMS); // STATUS_data
void Protocol_Packet2Data(const kis_packet *info, PACKET_data *data);
int Protocol_PACKET(PROTO_PARMS); // PACKET_data
int Protocol_WEPKEY(PROTO_PARMS); // wep_key_info

struct KISMET_data {
    string version;
    string starttime;
    string servername;
    string timestamp;
    string newversion;
	int uid;
};

struct CLIRESP_data {
    int cmdid;
    string resptext;
};

// Builtin commands we have to handle
int Clicmd_CAPABILITY(CLIENT_PARMS);
int Clicmd_ENABLE(CLIENT_PARMS);
int Clicmd_REMOVE(CLIENT_PARMS);
int Clicmd_LISTWEPKEYS(CLIENT_PARMS);
int Clicmd_ADDWEPKEY(CLIENT_PARMS);
int Clicmd_DELWEPKEY(CLIENT_PARMS);

// Messagebus subscriber to pass data to the client
class KisNetframe_MessageClient : public MessageClient {
public:
    KisNetframe_MessageClient(GlobalRegistry *in_globalreg, void *in_aux) :
        MessageClient(in_globalreg, in_aux) { };
	virtual ~KisNetframe_MessageClient() { }
    void ProcessMessage(string in_msg, int in_flags);
};

// Timer events
int KisNetFrame_TimeEvent(Timetracker::timer_event *evt, void *parm, 
						  GlobalRegistry *globalreg);

// Kismet server framework for sending data to clients and processing
// commands from clients
class KisNetFramework : public ServerFramework {
public:
    struct server_protocol {
        int ref_index;
        string header;
        int required;
		int cacheable;
        // Double-listed (burns a little extra ram but not much) to make 
		// mapping requested fields fast.
        map<string, int> field_map;
        vector<string> field_vec;
        int (*printer)(PROTO_PARMS);
        void (*enable)(PROTO_ENABLE_PARMS);
		void *auxptr;
    };

	struct client_command_rec {
		void *auxptr;
		ClientCommand cmd;
	};

    KisNetFramework();
    KisNetFramework(GlobalRegistry *in_globalreg);
    virtual ~KisNetFramework();

	// Activate the setup
	int Activate();
 
    virtual int Accept(int in_fd);
    virtual int ParseData(int in_fd);
    virtual int KillConnection(int in_fd);

	virtual int Shutdown();

	// Handle a buffer drain on a client
	virtual int BufferDrained(int in_fd);

    // Send a protocol to a specific client
    int SendToClient(int in_fd, int in_refnum, const void *in_data, 
					 kis_protocol_cache *in_cache);
    // Send to all clients
    int SendToAll(int in_refnum, const void *in_data);
    
    // Learn a client command
    int RegisterClientCommand(string in_cmdword, ClientCommand in_cmd, 
							  void *in_auxdata);
	int RemoveClientCommand(string in_cmdword);

    // Register an output sentence.  This needs:
    // * A header (ie, NETWORK)
    // * A NULL-terminated array of fields
    // * A pointer to a printer that takes a void * and a vector of field numbers
    //   and outputs a c++ string
    // * An optional pointer to a function that takes the file descriptor of a client
    //   that triggers whatever events should happen the the client enables this kind
    //   of protocol.  (ie, send all networks when the client enables the *NETWORK
    //   protocol)
    // It returns the index number of the sentence added.
    int RegisterProtocol(string in_header, int in_required, int in_cache, 
						 const char **in_fields,
						 int (*in_printer)(PROTO_PARMS),
						 void (*in_enable)(PROTO_ENABLE_PARMS),
						 void *in_auxdata);
	int RemoveProtocol(int in_protoref);
    int FetchProtocolRef(string in_header);
    KisNetFramework::server_protocol *FetchProtocol(int in_ref);

    // Manipulate client info
    void AddProtocolClient(int in_fd, int in_refnum, vector<int> in_fields);
    void DelProtocolClient(int in_fd, int in_refnum);
    
    // How many clients are using this protocol type?
    int FetchNumClientRefs(int in_refnum);

    // How many clients total?
    int FetchNumClients();

	// Usage
	static void Usage(char *name);

protected:
	int next_netprotoref;

    // Messagebus client
    KisNetframe_MessageClient *kisnet_msgcli;

    // Client options
    struct client_opt {
        // Map of sentence references to field lists
        map<int, vector<int> > protocols;
		vector<string> backlog;
    };

    // Client commands we understand
    map<string, KisNetFramework::client_command_rec *> client_cmd_map;

    // Map of reference numbers to sentences
    map<int, KisNetFramework::server_protocol *> protocol_map;
    // Map of headers to reference numbers
    map<string, int> ref_map;
    // Protocols clients are required to support
    vector<int> required_protocols;
    // Map of protocols to the number of clients using them
    map<int, int> client_mapped_protocols;

    // Client options
    map<int, KisNetFramework::client_opt *> client_optmap;

	// Server type (0 = tcp...)
	int server_type;

	// Max backlog
	int maxbacklog;

};

#endif

