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

#include "logtracker.h"
#include "globalregistry.h"
#include "messagebus.h"
#include "configfile.h"

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
    set_int_logging_enabled(globalreg->kismet_config->FetchOptBoolean("enable_logging", true));
    set_int_log_title(globalreg->kismet_config->FetchOptDfl("log_title", "Kismet"));
    return;
}

void LogTracker::Deferred_Shutdown() {
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

bool LogTracker::Httpd_VerifyPath(const char *path, const char *method) {

    return false;
}

void LogTracker::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream) {

}

