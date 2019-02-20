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
#include "structured.h"
#include "kismet_json.h"
#include "base64.h"

LogTracker::LogTracker() :
    tracker_component(),
    Kis_Net_Httpd_CPPStream_Handler() {

    streamtracker =
        Globalreg::FetchMandatoryGlobalAs<StreamTracker>("STREAMTRACKER");

    register_fields();
    reserve_fields(NULL);
    
    Bind_Httpd_Server();
}

LogTracker::~LogTracker() {
    local_locker lock(&tracker_mutex);

    Globalreg::globalreg->RemoveGlobal("LOGTRACKER");

    for (auto i : *logfile_vec) {
        SharedLogfile f = std::static_pointer_cast<KisLogfile>(i);
        f->Log_Close();
    }

    logproto_vec.reset();
    logfile_vec.reset();
}

void LogTracker::register_fields() { 
    RegisterField("kismet.logtracker.drivers", "supported log types", &logproto_vec);
    RegisterField("kismet.logtracker.logfiles", "active log files", &logfile_vec);

    logproto_entry_id =
        Globalreg::globalreg->entrytracker->RegisterField("kismet.logtracker.driver",
                TrackerElementFactory<KisLogfileBuilder>(),
                "Log driver");

    logfile_entry_id =
        Globalreg::globalreg->entrytracker->RegisterField("kismet.logtracker.log",
                TrackerElementFactory<KisLogfile>(),
                "Log file");

    RegisterField("kismet.logtracker.logging_enabled", "logging enabled", &logging_enabled);
    RegisterField("kismet.logtracker.title", "session title", &log_title);
    RegisterField("kismet.logtracker.prefix", "log prefix path", &log_prefix);
    RegisterField("kismet.logtracker.template", "log name template", &log_template);
    RegisterField("kismet.logtracker.log_types", "enabled log types", &log_types_vec);
}

void LogTracker::reserve_fields(std::shared_ptr<TrackerElementMap> e) {
    tracker_component::reserve_fields(e);

    // Normally we'd need to implement vector repair for the complex nested
    // types in logproto and logfile, but we don't snapshot state so we don't.
}

void LogTracker::Deferred_Startup() {
	int option_idx = 0;
	std::string retfname;

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
        int r = getopt_long(Globalreg::globalreg->argc, Globalreg::globalreg->argv,
                "-T:t:np:", 
                logfile_long_options, &option_idx);
        if (r < 0) break;
        switch (r) {
            case 'T':
                argtypes = std::string(optarg);
                break;
            case 't':
                argtitle = std::string(optarg);
                break;
            case 'n':
                arg_enable = 0;
                break;
            case 'p':
                argprefix = std::string(optarg);
                break;
        }
    }

    if (!Globalreg::globalreg->kismet_config->FetchOptBoolean("log_config_present", false)) {
        std::shared_ptr<Alertracker> alertracker =
            Globalreg::FetchMandatoryGlobalAs<Alertracker>("ALERTTRACKER");
        alertracker->RaiseOneShot("CONFIGERROR", "It looks like Kismet is missing "
                "the kismet_logging.conf config file.  This file was added recently "
                "in development.  Without it, logging will not perform as expected.  "
                "You should either install with 'make forceconfigs' from the Kismet "
                "source directory or manually reconcile your config files!", -1);
    }

    if (arg_enable < 0)
        set_int_logging_enabled(Globalreg::globalreg->kismet_config->FetchOptBoolean("enable_logging", true));
    else
        set_int_logging_enabled(false);

    if (argtitle.length() == 0)
        set_int_log_title(Globalreg::globalreg->kismet_config->FetchOptDfl("log_title", "Kismet"));
    else
        set_int_log_title(argtitle);

    if (argprefix.length() == 0) 
        set_int_log_prefix(Globalreg::globalreg->kismet_config->FetchOptDfl("log_prefix", "./"));
    else
        set_int_log_prefix(argprefix);

    Globalreg::globalreg->log_prefix = get_log_prefix();

    set_int_log_template(Globalreg::globalreg->kismet_config->FetchOptDfl("log_template", 
                "%p/%n-%D-%t-%i.%l"));


    std::vector<std::string> types;
   
    if (argtypes.length() == 0)
        types = StrTokenize(Globalreg::globalreg->kismet_config->FetchOpt("log_types"), ",");
    else
        types = StrTokenize(argtypes, ",");
        

    for (auto t : types) {
        auto e = std::make_shared<TrackerElementString>();
        e->set(t);
        log_types_vec->push_back(e);
    }

    if (!get_logging_enabled()) {
        std::shared_ptr<Alertracker> alertracker =
            Globalreg::FetchMandatoryGlobalAs<Alertracker>("ALERTTRACKER");
        alertracker->RaiseOneShot("LOGDISABLED", "Logging has been disabled via the Kismet "
                "config files or the command line.  Pcap, database, and related logs "
                "will not be saved.", -1);
        _MSG("Logging disabled, not enabling any log drivers.", MSGFLAG_INFO);
        return;
    }

    // Open all of them
    for (auto t : *log_types_vec) {
        auto logtype = GetTrackerValue<std::string>(t);
        open_log(logtype);
    }

    return;
}

void LogTracker::Deferred_Shutdown() {
    for (auto l : *logfile_vec) {
        SharedLogfile lf = std::static_pointer_cast<KisLogfile>(l);

        lf->Log_Close();
    }

    return;
}

int LogTracker::register_log(SharedLogBuilder in_builder) {
    local_locker lock(&tracker_mutex);

    for (auto i : *logproto_vec) {
        auto b = std::static_pointer_cast<KisLogfileBuilder>(i);

        if (StrLower(b->get_log_class()) == StrLower(in_builder->get_log_class())) {
            _MSG("A logfile driver has already been registered for '" + 
                    in_builder->get_log_class() + "', cannot register it twice.",
                    MSGFLAG_ERROR);
            return -1;
        }
    }

    logproto_vec->push_back(in_builder);

    return 1;
}

SharedLogfile LogTracker::open_log(std::string in_class) {
    return open_log(in_class, get_log_title());
}

SharedLogfile LogTracker::open_log(std::string in_class, std::string in_title) {
    local_locker lock(&tracker_mutex);

    SharedLogBuilder target_builder;

    for (auto b : *logproto_vec) {
        auto builder = std::static_pointer_cast<KisLogfileBuilder>(b);

        if (builder->get_log_class() == in_class) {
            return open_log(builder, in_title);
        }
    }

    return 0;
}

SharedLogfile LogTracker::open_log(SharedLogBuilder in_builder) {
    return open_log(in_builder, get_log_title());
}

SharedLogfile LogTracker::open_log(SharedLogBuilder in_builder, std::string in_title) {
    local_locker lock(&tracker_mutex);

    if (in_builder == NULL)
        return NULL;

    // If it's a singleton, make sure we're the only one
    if (in_builder->get_singleton()) {
        for (auto l : *logfile_vec) {
            auto lf = std::static_pointer_cast<KisLogfile>(l);

            if (lf->get_builder()->get_log_class() == in_builder->get_log_class() &&
                    lf->get_log_open()) {
                _MSG("Failed to open " + in_builder->get_log_class() + ", log already "
                        "open at " + lf->get_log_path(), MSGFLAG_ERROR);
                return NULL;
            }
        }
    }

    SharedLogfile lf = in_builder->build_logfile(in_builder);
    lf->set_id(logfile_entry_id);
    logfile_vec->push_back(lf);

    std::string logpath =
        Globalreg::globalreg->kismet_config->ExpandLogPath(get_log_template(),
                in_title, lf->get_builder()->get_log_class(), 1, 0);

    if (!lf->Log_Open(logpath)) {
        _MSG("Failed to open " + lf->get_builder()->get_log_class() + " log " + logpath,
                MSGFLAG_ERROR);
    }

    return lf;
}

int LogTracker::close_log(SharedLogfile in_logfile) {
    local_locker lock(&tracker_mutex);

    in_logfile->Log_Close();

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
    if (strcmp(method, "GET") == 0) {
        if (!Httpd_CanSerialize(path))
            return false;

        std::string stripped = Httpd_StripSuffix(path);

        if (stripped == "/logging/drivers")
            return true;

        if (stripped == "/logging/active")
            return true;

        std::vector<std::string> tokenurl = StrTokenize(stripped, "/");

        // /logging/by-uuid/[foo]/stop 

        if (tokenurl.size() < 4)
            return false;

        if (tokenurl[1] != "logging")
            return false;

        if (tokenurl[2] == "by-uuid") {
            if (tokenurl[4] != "stop")
                return false;

            uuid u(tokenurl[3]);
            if (u.error)
                return false;

            local_locker lock(&tracker_mutex);

            for (auto lfi : *logfile_vec) {
                auto lf = std::static_pointer_cast<KisLogfile>(lfi);

                if (lf->get_log_uuid() == u)
                    return true;
            }
        } else if (tokenurl[2] == "by-class") {
            if (tokenurl[4] != "start")
                return false;

            local_locker lock(&tracker_mutex);

            for (auto lfi : *logproto_vec) {
                auto lfb = std::static_pointer_cast<KisLogfileBuilder>(lfi);

                if (lfb->get_log_class() == tokenurl[3])
                    return true;
            }
        }

    } else if (strcmp(method, "POST") == 0) {
        if (!Httpd_CanSerialize(path))
            return false;

        std::string stripped = Httpd_StripSuffix(path);

        std::vector<std::string> tokenurl = StrTokenize(stripped, "/");

        // /logging/by-class/[foo]/start + post vars

        if (tokenurl.size() < 4)
            return false;

        if (tokenurl[1] != "logging")
            return false;

        if (tokenurl[2] == "by-class") {
            if (tokenurl[4] != "start")
                return false;

            local_locker lock(&tracker_mutex);

            for (auto lfi : *logproto_vec) {
                auto lfb = std::static_pointer_cast<KisLogfileBuilder>(lfi);

                if (lfb->get_log_class() == tokenurl[3])
                    return true;
            }
        }
    }

    return false;
}

void LogTracker::Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream) {

    local_locker lock(&tracker_mutex);

    std::string stripped = Httpd_StripSuffix(url);

    if (stripped == "/logging/drivers") {
        Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(url), stream, 
                logproto_vec, NULL);
        return;
    } else if (stripped == "/logging/active") {
        Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(url), stream, 
                logfile_vec, NULL);
        return;
    }

    std::vector<std::string> tokenurl = StrTokenize(stripped, "/");

    // /logging/by-uuid/[foo]/stop + post vars

    if (tokenurl.size() < 4)
        return;

    if (tokenurl[1] != "logging")
        return;

    try {
        if (tokenurl[2] == "by-uuid") {
            uuid u(tokenurl[3]);
            if (u.error) {
                throw std::runtime_error("invalid uuid");
            }

            if (!httpd->HasValidSession(connection)) {
                connection->httpcode = 503;
                return;
            }

            local_locker lock(&tracker_mutex);

            std::shared_ptr<KisLogfile> logfile;

            for (auto lfi : *logfile_vec) {
                auto lf = std::static_pointer_cast<KisLogfile>(lfi);

                if (lf->get_log_uuid() == u) {
                    logfile = lf;
                    break;
                }
            }

            if (logfile == NULL) {
                throw std::runtime_error("invalid log uuid");
            }

            _MSG("Closing log file " + logfile->get_log_uuid().UUID2String() + " (" + 
                    logfile->get_log_path() + ")", MSGFLAG_INFO);

            logfile->Log_Close();

            stream << "OK";
            return;
        } else if (tokenurl[2] == "by-class") {
            local_locker lock(&tracker_mutex);

            std::shared_ptr<KisLogfileBuilder> builder;

            for (auto lfi : *logproto_vec) {
                auto lfb = std::static_pointer_cast<KisLogfileBuilder>(lfi);

                if (lfb->get_log_class() == tokenurl[3]) {
                    builder = lfb;
                    break;
                }
            }

            if (builder == NULL) 
                throw std::runtime_error("invalid logclass");

            if (tokenurl[4] == "start") {
                SharedLogfile logf;

                logf = open_log(builder);

                if (logf == NULL) 
                    throw std::runtime_error("unable to open log");

                Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(url), stream, 
                        logf, NULL);

                return;
            }
        } else {
            throw std::runtime_error("unknown url");
        }
    } catch(const std::exception& e) {
        stream << "Invalid request: ";
        stream << e.what();
        connection->httpcode = 400;
        return;
    }

}

int LogTracker::Httpd_PostComplete(Kis_Net_Httpd_Connection *concls) {
    SharedStructured structdata;

    // All the posts require login
    if (!httpd->HasValidSession(concls, true)) {
        return MHD_YES;
    }

    try {
        // Parse the json
        if (concls->variable_cache.find("json") != 
                concls->variable_cache.end()) {
            structdata.reset(new StructuredJson(concls->variable_cache["json"]->str()));
        } else {
            throw StructuredDataException("Missing data");
        }
    } catch(const StructuredDataException& e) {
        concls->response_stream << "Invalid request: ";
        concls->response_stream << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }

    std::string stripped = Httpd_StripSuffix(concls->url);

    std::vector<std::string> tokenurl = StrTokenize(stripped, "/");

    // /logging/by-class/[foo]/start + post vars

    if (tokenurl.size() < 4)
        return false;

    if (tokenurl[1] != "logging")
        return false;

    try {
        if (tokenurl[2] == "by-class") {
            local_locker lock(&tracker_mutex);

            std::shared_ptr<KisLogfileBuilder> builder;

            for (auto lfi : *logproto_vec) {
                auto lfb = std::static_pointer_cast<KisLogfileBuilder>(lfi);

                if (lfb->get_log_class() == tokenurl[3]) {
                    builder = lfb;
                    break;
                }
            }

            if (builder == NULL) 
                throw std::runtime_error("invalid logclass");

            if (tokenurl[4] == "start") {
                std::string title = structdata->getKeyAsString("title", "");

                if (title == "")
                    title = get_log_title();

                SharedLogfile logf;

                logf = open_log(builder, title);

                if (logf == NULL) 
                    throw std::runtime_error("unable to open log");

                Globalreg::globalreg->entrytracker->Serialize(httpd->GetSuffix(concls->url),
                        concls->response_stream, logf, NULL);
                return MHD_YES;
            }
        }
    } catch(const std::exception& e) {
        concls->response_stream << "Invalid request: ";
        concls->response_stream << e.what();
        concls->httpcode = 400;
        return MHD_YES;
    }


    return 0;
}

