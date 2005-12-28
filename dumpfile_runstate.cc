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

#include "dumpfile_runstate.h"

// No better place than here to handle the dumpfile segment
void runstate_dumpfile_cb(RUNSTATE_PARMS) {
	for (unsigned int x = 0; x < globalreg->subsys_dumpfile_vec.size(); x++) {
		fprintf(runfile, "dumpfile {\n"
				"    type=%s\n"
				"    path=%s\n"
				"    numdumped=%d\n"
				"}",
				globalreg->subsys_dumpfile_vec[x]->FetchFileType().c_str(),
				globalreg->subsys_dumpfile_vec[x]->FetchFileName().c_str(),
				globalreg->subsys_dumpfile_vec[x]->FetchNumDumped());
	}
}

Dumpfile_Runstate::Dumpfile_Runstate() {
	fprintf(stderr, "FATAL OOPS: Dumpfile_Runstate called with no globalreg\n");
	exit(1);
}

Dumpfile_Runstate::Dumpfile_Runstate(GlobalRegistry *in_globalreg) : 
	Dumpfile(in_globalreg) {
	ostringstream osstr;

	globalreg = in_globalreg;

	runfile = NULL;

	type = "runstate";

	// Find the file name
	if ((fname = ProcessConfigOpt("runstate")) == "" || 
		globalreg->fatal_condition) {
		return;
	}

	runfile = fopen(fname.c_str(), "w");
	if (runfile == NULL) {
		osstr << "Failed to open runstate dump file '" + fname + "': " +
			strerror(errno);
		_MSG(osstr.str(), MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return;
	}

	globalreg->RegisterDumpFile(this);

	// Register our local dumpfile callback
	RegisterRunstateCb(runstate_dumpfile_cb, this);

	_MSG("Opened runstate file '" + fname + "'", MSGFLAG_INFO);
}

Dumpfile_Runstate::~Dumpfile_Runstate() {
	int opened = 0;
	
	// Close files
	if (runfile != NULL) {
		Flush();
		fclose(runfile);
		opened = 1;
	}

	runfile = NULL;

	for (unsigned int x = 0; x < cb_vec.size(); x++) {
		delete cb_vec[x];
	}

	cb_vec.clear();

	if (opened) 
		_MSG("Closed runstate file '" + fname + "'", MSGFLAG_INFO);
}

int Dumpfile_Runstate::Flush() {
	if (runfile == NULL)
		return 0;

	rewind(runfile);

	// Put the standard header
	fprintf(runfile, "# Kismet (http://www.kismetwireless.net) runtime state file\n");
	fprintf(runfile, "# This file contains the freeze state info for a running\n"
			"# Kismet instance.  It should NOT be manually edited.\n\n");

	fprintf(runfile, "runstate_version=%d\n", RUNSTATE_VERSION);
	fprintf(runfile, "config_checksum=%u\n", 
			globalreg->kismet_config->FetchFileChecksum());
	fprintf(runfile, "launch_time=%u\n", globalreg->start_time);
	fprintf(runfile, "save_time=%u\n", globalreg->timestamp.tv_sec);
	fprintf(runfile, "kismet_version=%s.%s.%s\n",
			globalreg->version_major.c_str(),
			globalreg->version_minor.c_str(),
			globalreg->version_tiny.c_str());
	fprintf(runfile, "kismet_name=%s\n", globalreg->servername.c_str());

	fprintf(runfile, "\n");

	// Run all the callbacks and let them log
	for (unsigned int x = 0; x < cb_vec.size(); x++) {
		(*(cb_vec[x]->cb))(globalreg, cb_vec[x]->auxdata, runfile);
	}

	fflush(runfile);

	return 1;
}

int Dumpfile_Runstate::RegisterRunstateCb(RunstateCallback in_cb, void *in_aux) {
	// Make sure it isn't in the vec already
	for (unsigned int x = 0; x < cb_vec.size(); x++) {
		if (cb_vec[x]->cb == in_cb)
			return 0;
	}

	runstatecb_rec *newcb = new runstatecb_rec;
	newcb->cb = in_cb;
	newcb->auxdata = in_aux;

	cb_vec.push_back(newcb);

	return 1;
}

void Dumpfile_Runstate::RemoveRunstateCb(RunstateCallback in_cb) {
	for (unsigned int x = 0; x < cb_vec.size(); x++) {
		if (cb_vec[x]->cb == in_cb) {
			delete cb_vec[x];
			cb_vec.erase(cb_vec.begin() + x);
			return;
		}
	}
}

