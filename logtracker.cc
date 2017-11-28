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

#include "getopt.h"

#include "logtracker.h"
#include "globalregistry.h"
#include "messagebus.h"
#include "configfile.h"
#include "alertracker.h"

LogTracker::LogTracker(GlobalRegistry *in_globalreg) :
    tracker_component(in_globalreg, 0),
    Kis_Net_Httpd_CPPStream_Handler(in_globalreg),
    globalreg(in_globalreg) {

    streamtracker =
        Globalreg::FetchMandatoryGlobalAs<StreamTracker>(globalreg, "STREAMTRACKER");

    entrytracker =
        Globalreg::FetchMandatoryGlobalAs<EntryTracker>(globalreg, "ENTRY_TRACKER");

    register_fields();
    reserve_fields(NULL);

}

LogTracker::~LogTracker() {
    local_eol_locker lock(&tracker_mutex);

    globalreg->RemoveGlobal("LOGTRACKER");

    TrackerElementVector v(logfile_vec);

    for (auto i : v) {
        SharedLogfile f = std::static_pointer_cast<KisLogfile>(i);
        f->Log_Close();
    }

    logproto_vec.reset();
    logfile_vec.reset();
}

void LogTracker::register_fields() { 
    RegisterField("kismet.logtracker.drivers", TrackerVector,
            "supported log types", &logproto_vec);
    RegisterField("kismet.logtracker.logfiles", TrackerVector,
            "active log files", &logfile_vec);

    logproto_entry_id =
        entrytracker->RegisterField("kismet.logtracker.driver",
                SharedLogBuilder(new KisLogfileBuilder(globalreg, 0)),
                "Log driver");

    logfile_entry_id =
        entrytracker->RegisterField("kismet.logtracker.log",
                SharedLogfile(new KisLogfile(globalreg, 0)),
                "Log file");

    // Normally we'd have to register entity IDs here but we'll never snapshot
    // the log state so we don't care
    
    RegisterField("kismet.logtracker.logging_enabled", TrackerUInt8,
            "logging enabled", &logging_enabled);
    RegisterField("kismet.logtracker.title", TrackerString,
            "session title", &log_title);
    RegisterField("kismet.logtracker.prefix", TrackerString,
            "log prefix path", &log_prefix);
    RegisterField("kismet.logtracker.template", TrackerString,
            "log name template", &log_template);

    RegisterField("kismet.logtracker.log_types", TrackerVector,
            "enabled log types", &log_types_vec);
}

void LogTracker::reserve_fields(SharedTrackerElement e) {
    tracker_component::reserve_fields(e);

    // Normally we'd need to implement vector repair for the complex nested
    // types in logproto and logfile, but we don't snapshot state so we don't.
}

void LogTracker::Deferred_Startup() {
	int option_idx = 0;
	string retfname;

    // longopts for the packetsourcetracker component
    static struct option logfile_long_options[] = {
        { "log-types", required_argument, 0, 'T' },
        { "log-title", required_argument, 0, 't' },
        { "log-prefix", required_argument, 0, 'p' },
        { "no-logging", no_argument, 0, 'n' },
        { 0, 0, 0, 0 }
    };

    std::string argtypes, argtitle, argprefix;
    int arg_enable = -1;

	// Hack the extern getopt index
	optind = 0;

    while (1) {
        int r = getopt_long(globalreg->argc, globalreg->argv,
                "-T:t:np:", 
                logfile_long_options, &option_idx);
        if (r < 0) break;
        switch (r) {
            case 'T':
                argtypes = string(optarg);
                break;
            case 't':
                argtitle = string(optarg);
                break;
            case 'n':
                arg_enable = 0;
                break;
            case 'p':
                argprefix = string(optarg);
                break;
        }
    }

    if (!globalreg->kismet_config->FetchOptBoolean("log_config_present", false)) {
        shared_ptr<Alertracker> alertracker =
            Globalreg::FetchMandatoryGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");
        alertracker->RaiseOneShot("CONFIGERROR", "It looks like Kismet is missing "
                "the kismet_logging.conf config file.  This file was added recently "
                "in development.  Without it, logging will not perform as expected.  "
                "You should either install with 'make forceconfigs' from the Kismet "
                "source directory or manually reconcile your config files!", -1);
    }

    if (arg_enable < 0)
        set_int_logging_enabled(globalreg->kismet_config->FetchOptBoolean("enable_logging", true));
    else
        set_int_logging_enabled(false);

    if (argtitle.length() == 0)
        set_int_log_title(globalreg->kismet_config->FetchOptDfl("log_title", "Kismet"));
    else
        set_int_log_title(argtitle);

    if (argprefix.length() == 0) 
        set_int_log_prefix(globalreg->kismet_config->FetchOptDfl("log_prefix", "./"));
    else
        set_int_log_prefix(argprefix);

    set_int_log_template(globalreg->kismet_config->FetchOptDfl("log_template", 
                "%p/%n-%D-%t-%i.%l"));


    std::vector<std::string> types;
   
    if (argtypes.length() == 0)
        types = StrTokenize(globalreg->kismet_config->FetchOpt("log_types"), ",");
    else
        types = StrTokenize(argtypes, ",");
        

    TrackerElementVector v(log_types_vec);

    for (auto t : types) {
        SharedTrackerElement e(new TrackerElement(TrackerString, 0));
        e->set((std::string) t);
        v.push_back(e);
    }

    if (!get_logging_enabled()) {
        shared_ptr<Alertracker> alertracker =
            Globalreg::FetchMandatoryGlobalAs<Alertracker>(globalreg, "ALERTTRACKER");
        alertracker->RaiseOneShot("LOGDISABLED", "Logging has been disabled via the Kismet "
                "config files or the command line.  Pcap, database, and related logs "
                "will not be saved.", -1);
        _MSG("Logging disabled, not enabling any log drivers.", MSGFLAG_INFO);
        return;
    }

    TrackerElementVector builders(logproto_vec);
    TrackerElementVector logfiles(logfile_vec);

    for (auto t : v) {
        std::string logtype = GetTrackerValue<std::string>(t);

        // Scan all the builders and find a matching log type, build logfile for it
        for (auto b : builders) {
            std::shared_ptr<KisLogfileBuilder> builder =
                std::static_pointer_cast<KisLogfileBuilder>(b);
            if (builder->get_log_class() != logtype) 
                continue;

            // Generate the logfile using the builder an giving it the sharedptr
            // to itself because sharedptrs are funky
            SharedLogfile lf = builder->build_logfile(builder);
            lf->set_id(logfile_entry_id);

            logfiles.push_back(lf);
        }
    }

    for (auto l : logfiles) {
        SharedLogfile lf = std::static_pointer_cast<KisLogfile>(l);

        std::string logpath = 
            globalreg->kismet_config->ExpandLogPath(get_log_template(), 
                    get_log_title(),
                    lf->get_builder()->get_log_class(), 1, 0);

        if (!lf->Log_Open(logpath)) {
            _MSG("Failed to open " + lf->get_builder()->get_log_class() + " log " + logpath,
                    MSGFLAG_ERROR);
        }
    }

    return;
}

void LogTracker::Deferred_Shutdown() {
    TrackerElementVector logfiles(logfile_vec);

    for (auto l : logfiles) {
        SharedLogfile lf = std::static_pointer_cast<KisLogfile>(l);

        lf->Log_Close();
    }

    return;
}

int LogTracker::register_log(SharedLogBuilder in_builder) {
    local_locker lock(&tracker_mutex);

    TrackerElementVector vec(logproto_vec);

    for (auto i : vec) {
        SharedLogBuilder b = std::static_pointer_cast<KisLogfileBuilder>(i);

        if (StrLower(b->get_log_class()) == StrLower(in_builder->get_log_class())) {
            _MSG("A logfile driver has already been registered for '" + 
                    in_builder->get_log_class() + "', cannot register it twice.",
                    MSGFLAG_ERROR);
            return -1;
        }
    }

    vec.push_back(in_builder);

    return 1;
}

void LogTracker::Usage(const char *argv0) {
    printf(" *** Logging Options ***\n");
	printf(" -T, --log-types <types>      Override activated log types\n"
		   " -t, --log-title <title>      Override default log title\n"
		   " -p, --log-prefix <prefix>    Directory to store log files\n"
		   " -n, --no-logging             Disable logging entirely\n");
}

bool LogTracker::Httpd_VerifyPath(const char *path, const char *method) {

    return false;
}

void LogTracker::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream) {

}

int LogTracker::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {

    return 0;
}

