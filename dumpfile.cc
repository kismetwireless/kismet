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
#include "dumpfile.h"
#include "getopt.h"

Dumpfile::Dumpfile() {
	fprintf(stderr, "FATAL OOPS: Dumpfile() called with no global registry\n");
	exit(1);
}

Dumpfile::Dumpfile(GlobalRegistry *in_globalreg) {
	globalreg = in_globalreg;
	resume = 0;
	dumped_frames = 0;
	log_volatile = 0;

	if (globalreg->kismet_config != NULL) {
		export_filter = new FilterCore(globalreg);
		vector<string> filterlines = 
			globalreg->kismet_config->FetchOptVec("filter_export");
		for (unsigned int fl = 0; fl < filterlines.size(); fl++) {
			if (export_filter->AddFilterLine(filterlines[fl]) < 0) {
				_MSG("Failed to add filter_export config line from the Kismet config "
					 "file.", MSGFLAG_FATAL);
				globalreg->fatal_condition = 1;
				return;
			}
		}
	}
}

Dumpfile::~Dumpfile() {
	if (fname != "") {
		if (log_volatile && dumped_frames == 0) {
			_MSG("Closed " + type + " log file '" + fname + "', no packets logged, "
				 "removing empty file.", MSGFLAG_INFO);
			unlink(fname.c_str());
		} else {
			_MSG("Closed " + type + " log file '" + fname + "', " + 
				 IntToString(dumped_frames) + " logged.", MSGFLAG_INFO);
		}
	}
}

void Dumpfile::Usage(char *name) {
	printf(" *** Dump/Logging Options ***\n");
	printf(" -T, --log-types <types>      Override activated log types\n"
		   " -t, --log-title <title>      Override default log title\n"
		   " -p, --log-prefix <prefix>    Directory to store log files\n"
		   " -n, --no-logging             Disable logging entirely\n");
}

string Dumpfile::ProcessConfigOpt() {
	string logtypes, logtemplate, logname;
	int option_idx = 0;
	string retfname;

	if (logclass == "")
		logclass = type;

	// longopts for the packetsourcetracker component
	static struct option logfile_long_options[] = {
		{ "log-types", required_argument, 0, 'T' },
		{ "log-title", required_argument, 0, 't' },
		{ "log-prefix", required_argument, 0, 'p' },
		{ "no-logging", no_argument, 0, 'n' },
		{ 0, 0, 0, 0 }
	};

	if ((logtemplate = globalreg->kismet_config->FetchOpt("logtemplate")) == "") {
		_MSG("No 'logtemplate' specified in the Kismet config file.", MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return "";
	}
	
	// Hack the extern getopt index
	optind = 0;

	while (1) {
		int r = getopt_long(globalreg->argc, globalreg->argv,
							"-T:t:np:", 
							logfile_long_options, &option_idx);
		if (r < 0) break;
		switch (r) {
			case 'T':
				logtypes = string(optarg);
				break;
			case 't':
				logname = string(optarg);
				break;
			case 'n':
				return "";
				break;
			case 'p':
				globalreg->log_prefix = string(optarg);
				break;
		}
	}

	if (logname.length() == 0 &&
		(logname = globalreg->kismet_config->FetchOpt("logdefault")) == "") {
		if ((logname = globalreg->kismet_config->FetchOpt("logname")) == "") {
			_MSG("No 'logdefault' specified on the command line or config file",
				 MSGFLAG_FATAL);
			globalreg->fatal_condition = 1;
			return "";
		}
	}

	globalreg->logname = logname;

	if (logtypes.length() == 0 &&
		(logtypes = globalreg->kismet_config->FetchOpt("logtypes")) == "") {
		_MSG("No 'logtypes' specified on the command line or config file", 
			 MSGFLAG_FATAL);
		globalreg->fatal_condition = 1;
		return "";
	}

	vector<string> typevec = StrTokenize(StrLower(logtypes), ",");
	logclass = StrLower(logclass);
	string ltype = StrLower(type);

	int factive = 0;
	for (unsigned int x = 0; x < typevec.size(); x++) {
		if (typevec[x] == logclass || typevec[x] == ltype ) {
			factive = 1;
			break;
		}
	}

	if (factive == 0) {
		return "";
	}

	// _MSG("Log file type '" + in_type + "' activated.", MSGFLAG_INFO);

	retfname = 
		globalreg->kismet_config->ExpandLogPath(logtemplate, logname, type, 0, 0);

	return retfname;
}

