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

#include <getopt.h>

#include "logtracker.h"
#include "globalregistry.h"
#include "messagebus.h"
#include "configfile.h"
#include "alertracker.h"
#include "base64.h"

log_tracker::log_tracker() :
    tracker_component(),
    lifetime_global() {

    streamtracker =
        Globalreg::fetch_mandatory_global_as<stream_tracker>("STREAMTRACKER");

    register_fields();
    reserve_fields(NULL);
}

log_tracker::~log_tracker() {
    kis_lock_guard<kis_mutex> lk(tracker_mutex);

    Globalreg::globalreg->remove_global("LOGTRACKER");

    for (auto i : *logfile_vec) {
        shared_logfile f = std::static_pointer_cast<kis_logfile>(i);
        f->close_log();
    }

    logproto_vec.reset();
    logfile_vec.reset();
}

void log_tracker::register_fields() { 
    register_field("kismet.logtracker.drivers", "supported log types", &logproto_vec);
    register_field("kismet.logtracker.logfiles", "active log files", &logfile_vec);

    logproto_entry_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.logtracker.driver",
                tracker_element_factory<kis_logfile_builder>(),
                "Log driver");

    logfile_entry_id =
        Globalreg::globalreg->entrytracker->register_field("kismet.logtracker.log",
                tracker_element_factory<kis_logfile>(),
                "Log file");

    register_field("kismet.logtracker.logging_enabled", "logging enabled", &logging_enabled);
    register_field("kismet.logtracker.title", "session title", &log_title);
    register_field("kismet.logtracker.prefix", "log prefix path", &log_prefix);
    register_field("kismet.logtracker.template", "log name template", &log_template);
    register_field("kismet.logtracker.log_types", "enabled log types", &log_types_vec);
}

void log_tracker::reserve_fields(std::shared_ptr<tracker_element_map> e) {
    tracker_component::reserve_fields(e);

    // Normally we'd need to implement vector repair for the complex nested
    // types in logproto and logfile, but we don't snapshot state so we don't.
}

void log_tracker::trigger_deferred_startup() {
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

    if (!Globalreg::globalreg->kismet_config->fetch_opt_bool("log_config_present", false)) {
        std::shared_ptr<alert_tracker> alertracker =
            Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
        alertracker->raise_one_shot("CONFIGERROR", 
                "SYSTEM", kis_alert_severity::high,
                "It looks like Kismet is missing the kismet_logging.conf config file.  This "
                "file was added recently in development.  Without it, logging will not perform "
                "as expected.  You should either install with 'make forceconfigs' from the Kismet "
                "source directory or manually reconcile your config files!", -1);
    }

    if (arg_enable < 0)
        set_int_logging_enabled(Globalreg::globalreg->kismet_config->fetch_opt_bool("enable_logging", true));
    else
        set_int_logging_enabled(false);

    if (argtitle.length() == 0)
        set_int_log_title(Globalreg::globalreg->kismet_config->fetch_opt_dfl("log_title", "Kismet"));
    else
        set_int_log_title(argtitle);

    if (argprefix.length() == 0) 
        set_int_log_prefix(Globalreg::globalreg->kismet_config->fetch_opt_dfl("log_prefix", "./"));
    else
        set_int_log_prefix(argprefix);

    Globalreg::globalreg->log_prefix = get_log_prefix();

    set_int_log_template(Globalreg::globalreg->kismet_config->fetch_opt_dfl("log_template", 
                "%p/%n-%D-%t-%i.%l"));


    std::vector<std::string> types;
   
    if (argtypes.length() == 0) {
        auto tv = Globalreg::globalreg->kismet_config->fetch_opt_vec("log_types");

        for (const auto& t : tv) {
            auto subtypes = str_tokenize(t, ",");

            for (const auto& st : subtypes)
                types.push_back(st);
        }
    } else {
        types = str_tokenize(argtypes, ",");
    }
        

    for (auto t : types) {
        auto e = std::make_shared<tracker_element_string>();
        e->set(t);
        log_types_vec->push_back(e);
    }

    auto httpd = Globalreg::fetch_global_as<kis_net_beast_httpd>();

    httpd->register_route("/logging/drivers", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(logproto_vec, tracker_mutex));
    httpd->register_route("/logging/active", {"GET", "POST"}, httpd->RO_ROLE, {},
            std::make_shared<kis_net_web_tracked_endpoint>(logfile_vec, tracker_mutex));

    httpd->register_route("/logging/by-uuid/:uuid/stop", {"GET", "POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_function_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    std::ostream stream(&con->response_stream());

                    auto u = string_to_n<uuid>(con->uri_params()[":uuid"]);

                    if (u.error)
                        throw std::runtime_error("invalid uuid");

                    kis_lock_guard<kis_mutex> lk(tracker_mutex, static_cast<std::string>(con->uri()));

                    std::shared_ptr<kis_logfile> logfile;
                    for (auto lfi : *logfile_vec) {
                        auto lf = std::static_pointer_cast<kis_logfile>(lfi);

                        if (lf->get_log_uuid() == u) {
                            logfile = lf;
                            break;
                        }
                    }

                    if (logfile == nullptr)
                        throw std::runtime_error("no such log");

                    _MSG_INFO("Closing log file {} ({})", logfile->get_log_uuid(), logfile->get_log_path());
                    logfile->close_log();

                    stream << "OK\n";
                }));

    httpd->register_route("/logging/by-class/:class/start", {"GET", "POST"}, httpd->LOGON_ROLE, {"cmd"},
            std::make_shared<kis_net_web_tracked_endpoint>(
                [this](std::shared_ptr<kis_net_beast_httpd_connection> con) {
                    auto builder = std::shared_ptr<kis_logfile_builder>();
                    auto lclass = con->uri_params()[":class"];

                    for (auto lfi : *logproto_vec) {
                        auto lfb = std::static_pointer_cast<kis_logfile_builder>(lfi);

                        if (lfb->get_log_class() == lclass) {
                            builder = lfb;
                            break;
                        }
                    }

                    if (builder == nullptr)
                        throw std::runtime_error("invalid logclass");

                    shared_logfile logf = open_log(builder);

                    if (logf == nullptr)
                        throw std::runtime_error("unable to open log");

                    return logf;
                }, tracker_mutex));

    if (!get_logging_enabled()) {
        std::shared_ptr<alert_tracker> alertracker =
            Globalreg::fetch_mandatory_global_as<alert_tracker>("ALERTTRACKER");
        alertracker->raise_one_shot("LOGDISABLED", 
                "SYSTEM", kis_alert_severity::critical,
                "Logging has been disabled via the Kismet "
                "config files or the command line.  Pcap, database, and related logs "
                "will not be saved.", -1);
        _MSG("Logging disabled, not enabling any log drivers.", MSGFLAG_INFO);
        return;
    }

    // Open all of them
    for (auto t : *log_types_vec) {
        auto logtype = get_tracker_value<std::string>(t);
        open_log(logtype);
    }

    return;
}

void log_tracker::trigger_deferred_shutdown() {
    for (auto l : *logfile_vec) {
        shared_logfile lf = std::static_pointer_cast<kis_logfile>(l);

        lf->close_log();
    }

    return;
}

int log_tracker::register_log(shared_log_builder in_builder) {
    kis_lock_guard<kis_mutex> lk(tracker_mutex);

    for (auto i : *logproto_vec) {
        auto b = std::static_pointer_cast<kis_logfile_builder>(i);

        if (str_lower(b->get_log_class()) == str_lower(in_builder->get_log_class())) {
            _MSG("A logfile driver has already been registered for '" + 
                    in_builder->get_log_class() + "', cannot register it twice.",
                    MSGFLAG_ERROR);
            return -1;
        }
    }

    logproto_vec->push_back(in_builder);

    return 1;
}

shared_logfile log_tracker::open_log(std::string in_class) {
    return open_log(in_class, get_log_title());
}

shared_logfile log_tracker::open_log(std::string in_class, std::string in_title) {
    kis_lock_guard<kis_mutex> lk(tracker_mutex);

    shared_log_builder target_builder;

    for (auto b : *logproto_vec) {
        auto builder = std::static_pointer_cast<kis_logfile_builder>(b);

        if (builder->get_log_class() == in_class) {
            return open_log(builder, in_title);
        }
    }

    return 0;
}

shared_logfile log_tracker::open_log(shared_log_builder in_builder) {
    return open_log(in_builder, get_log_title());
}

shared_logfile log_tracker::open_log(shared_log_builder in_builder, std::string in_title) {
    kis_lock_guard<kis_mutex> lk(tracker_mutex);

    if (in_builder == NULL)
        return NULL;

    // If it's a singleton, make sure we're the only one
    if (in_builder->get_singleton()) {
        for (auto l : *logfile_vec) {
            auto lf = std::static_pointer_cast<kis_logfile>(l);

            if (lf->get_builder()->get_log_class() == in_builder->get_log_class() &&
                    lf->get_log_open()) {
                _MSG("Failed to open " + in_builder->get_log_class() + ", log already "
                        "open at " + lf->get_log_path(), MSGFLAG_ERROR);
                return NULL;
            }
        }
    }

    shared_logfile lf = in_builder->build_logfile(in_builder);
    lf->set_id(logfile_entry_id);

    std::string logpath =
        Globalreg::globalreg->kismet_config->expand_log_path(get_log_template(),
                in_title, lf->get_builder()->get_log_class(), 1, 0);

    if (logpath.length() == 0) {
        _MSG_ERROR("Failed to resolve a log path for {}", 
                   lf->get_builder()->get_log_class());
        return nullptr;
    }

    if (!lf->open_log(get_log_template(), logpath)) {
        _MSG("Failed to open " + lf->get_builder()->get_log_class() + " log " + logpath,
                MSGFLAG_ERROR);
        return nullptr;
    }

    logfile_vec->push_back(lf);

    return lf;
}

std::string log_tracker::expand_template(const std::string& in_template, const std::string& log_class) {
    return Globalreg::globalreg->kismet_config->expand_log_path(get_log_template(),
            get_log_title(), log_class, 1, 0);

}

int log_tracker::close_log(shared_logfile in_logfile) {
    kis_lock_guard<kis_mutex> lk(tracker_mutex);

    in_logfile->close_log();

    return 1;
}

void log_tracker::usage(const char *argv0) {
    printf(" *** Logging Options ***\n");
	printf(" -T, --log-types <types>      Override activated log types\n"
		   " -t, --log-title <title>      Override default log title\n"
		   " -p, --log-prefix <prefix>    Directory to store log files\n"
		   " -n, --no-logging             Disable logging entirely\n");
}

