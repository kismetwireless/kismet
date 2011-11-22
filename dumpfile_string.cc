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

#include "dumpfile_string.h"
#include "phy_80211.h"

int dumpfilestring_chain_hook(CHAINCALL_PARMS) {
	Dumpfile_String *auxptr = (Dumpfile_String *) auxdata;
	return auxptr->chain_handler(in_pack);
}

Dumpfile_String::Dumpfile_String() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_String called with no globalreg\n");
	exit(1);
}

Dumpfile_String::Dumpfile_String(GlobalRegistry *in_globalreg) : 
	Dumpfile(in_globalreg) {

	char errstr[STATUS_MAX];
	globalreg = in_globalreg;

	stringfile = NULL;

	type = "string";
	logclass = "string";

	if (globalreg->sourcetracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  Sourcetracker missing before "
				"Dumpfile_String\n");
		exit(1);
	}

#if 0
	if (globalreg->builtindissector == NULL) {
		fprintf(stderr, "FATAL OOPS:  Sourcetracker missing before "
				"Dumpfile_String\n");
		exit(1);
	}
#endif

	// Find the file name
	if ((fname = ProcessConfigOpt()) == "" ||
		globalreg->fatal_condition) {
		return;
	}

	stringfile = fopen(fname.c_str(), "w");
	if (stringfile == NULL) {
		snprintf(errstr, STATUS_MAX, "Failed to open string dump file '%s': %s",
				 fname.c_str(), strerror(errno));
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	_MSG("Opened string log file '" + fname + "'", MSGFLAG_INFO);

	globalreg->packetchain->RegisterHandler(&dumpfilestring_chain_hook, this,
											CHAINPOS_LOGGING, -100);

	globalreg->RegisterDumpFile(this);

//	globalreg->builtindissector->SetStringExtract(2);

	Kis_80211_Phy *dot11phy = 
		(Kis_80211_Phy *) globalreg->FetchGlobal("PHY_80211");
	if (dot11phy != NULL) {
		dot11phy->SetStringExtract(2);
		_MSG("Dumpfile_String - forced string extraction from packets at all times", 
			 MSGFLAG_INFO);
	}
}

Dumpfile_String::~Dumpfile_String() {
	globalreg->packetchain->RemoveHandler(&dumpfilestring_chain_hook,
										  CHAINPOS_LOGGING);

	// Close files
	if (stringfile != NULL) {
		Flush();
		fclose(stringfile);
	}

	stringfile = NULL;
}

int Dumpfile_String::Flush() {
	if (stringfile == NULL)
		return 0;

	fflush(stringfile);

	return 1;
}

int Dumpfile_String::chain_handler(kis_packet *in_pack) {
	if (stringfile == NULL)
		return 0;

	kis_string_info *stringinfo = NULL;

	if (in_pack->error)
		return 0;

	// Grab the 80211 info, compare, bail
    dot11_packinfo *packinfo;
	if ((packinfo = 
		 (dot11_packinfo *) in_pack->fetch(_PCM(PACK_COMP_80211))) == NULL)
		return 0;
	if (packinfo->corrupt)
		return 0;
	if (packinfo->type != packet_data || packinfo->subtype != packet_sub_data)
		return 0;

	// If it's encrypted and hasn't been decrypted, we can't do anything
	// smart with it, so toss.
	if (packinfo->cryptset != 0 && packinfo->decrypted == 0)
		return 0;
	// Grab the strings
	stringinfo = (kis_string_info *) in_pack->fetch(_PCM(PACK_COMP_STRINGS));

	if (stringinfo == NULL)
		return 0;

	for (unsigned int x = 0; x < stringinfo->extracted_strings.size(); x++) {
		fprintf(stringfile, "%s %s %s %s\n", 
				packinfo->bssid_mac.Mac2String().c_str(),
				packinfo->source_mac.Mac2String().c_str(),
				packinfo->dest_mac.Mac2String().c_str(),
				stringinfo->extracted_strings[x].c_str());
	}

	dumped_frames++;

	return 1;
}

