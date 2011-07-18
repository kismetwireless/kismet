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

#include "dumpfile_alert.h"

int dumpfilealert_chain_hook(CHAINCALL_PARMS) {
	Dumpfile_Alert *auxptr = (Dumpfile_Alert *) auxdata;
	return auxptr->chain_handler(in_pack);
}

Dumpfile_Alert::Dumpfile_Alert() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Alert called with no globalreg\n");
	exit(1);
}

Dumpfile_Alert::Dumpfile_Alert(GlobalRegistry *in_globalreg) : 
	Dumpfile(in_globalreg) {

	char errstr[STATUS_MAX];
	globalreg = in_globalreg;

	alertfile = NULL;

	type = "alert";
	logclass = "alert";

	if (globalreg->packetchain == NULL) {
		fprintf(stderr, "FATAL OOPS:  Packetchain missing before "
				"Dumpfile_Alert\n");
		exit(1);
	}

	if (globalreg->alertracker == NULL) {
		fprintf(stderr, "FATAL OOPS:  Alertracker missing before "
				"Dumpfile_Alert\n");
		exit(1);
	}

	// Find the file name
	if ((fname = ProcessConfigOpt()) == "" ||
		globalreg->fatal_condition) {
		return;
	}

	alertfile = fopen(fname.c_str(), "w");
	if (alertfile == NULL) {
		snprintf(errstr, STATUS_MAX, "Failed to open alert dump file '%s': %s",
				 fname.c_str(), strerror(errno));
		_MSG(errstr, MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	_MSG("Opened alert log file '" + fname + "'", MSGFLAG_INFO);

	globalreg->packetchain->RegisterHandler(&dumpfilealert_chain_hook, this,
											CHAINPOS_LOGGING, -100);

	globalreg->RegisterDumpFile(this);
}

Dumpfile_Alert::~Dumpfile_Alert() {
	globalreg->packetchain->RemoveHandler(&dumpfilealert_chain_hook, 
										  CHAINPOS_LOGGING);
	
	// Close files
	if (alertfile != NULL) {
		Flush();
		fclose(alertfile);
	}

	alertfile = NULL;
}

int Dumpfile_Alert::Flush() {
	if (alertfile == NULL)
		return 0;

	fflush(alertfile);

	return 1;
}

int Dumpfile_Alert::chain_handler(kis_packet *in_pack) {
	if (alertfile == NULL)
		return 0;

	kis_alert_component *alrtinfo = NULL;

	if (in_pack->error)
		return 0;

	// Grab the alerts
	alrtinfo = (kis_alert_component *) in_pack->fetch(_PCM(PACK_COMP_ALERT));

	if (alrtinfo == NULL)
		return 0;

	for (unsigned int x = 0; x < alrtinfo->alert_vec.size(); x++) {
		fprintf(alertfile, "%.24s %s %d %s %s %s %s %s\n", 
				ctime((const time_t *) &(alrtinfo->alert_vec[x]->tm.tv_sec)),
				alrtinfo->alert_vec[x]->header.c_str(),
				alrtinfo->alert_vec[x]->channel,
				alrtinfo->alert_vec[x]->bssid.Mac2String().c_str(),
				alrtinfo->alert_vec[x]->source.Mac2String().c_str(),
				alrtinfo->alert_vec[x]->dest.Mac2String().c_str(),
				alrtinfo->alert_vec[x]->other.Mac2String().c_str(),
				alrtinfo->alert_vec[x]->text.c_str());
	}

	dumped_frames++;

	return 1;
}

