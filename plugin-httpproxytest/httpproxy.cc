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

#include <config.h>
#include <string>
#include <errno.h>
#include <time.h>

#include <pthread.h>

#include <sstream>
#include <iomanip>
#include <syslog.h>

#include <util.h>
#include <messagebus.h>
#include <packet.h>
#include <packetchain.h>
#include <timetracker.h>
#include <configfile.h>
#include <plugintracker.h>
#include <globalregistry.h>
#include <alertracker.h>
#include <version.h>

#include <kis_external.h>

GlobalRegistry *globalreg = NULL;

class ExternalProxyTest : public KisExternalHttpInterface {
public:
    ExternalProxyTest(GlobalRegistry *in_globalreg) :
        KisExternalInterface(in_globalreg) {

            printf("debug - initializing proxytest interface\n");

            external_binary = "kismet_proxytest";

            // Make a new handler and new ipc.  Give a generous buffer.
            ringbuf_handler.reset(new BufferHandler<RingbufV2>((1024 * 1024), (1024 * 1024)));
            ringbuf_handler->SetReadBufferInterface(this);

            ipc_remote.reset(new IPCRemoteV2(globalreg, ringbuf_handler));

            // Get allowed paths for binaries
            std::vector<std::string> bin_paths = 
                globalreg->kismet_config->FetchOptVec("helper_binary_path");

            if (bin_paths.size() == 0) {
                _MSG("No helper_binary_path found in kismet.conf, make sure your config "
                        "files are up to date; using the default binary path where Kismet "
                        "is installed.", MSGFLAG_ERROR);
                bin_paths.push_back("%B");
            }

            // Explode any expansion macros in the path and add it to the list we search
            for (auto i = bin_paths.begin(); i != bin_paths.end(); ++i) {
                ipc_remote->add_path(globalreg->kismet_config->ExpandLogPath(*i, "", "", 0, 1));
            }

            int ret = ipc_remote->launch_kis_binary(external_binary, std::vector<std::string>());

            if (ret < 0) {
                _MSG(std::string("Failed to launch ") + external_binary, MSGFLAG_ERROR);
                return;
            }
        }
};

extern "C" {
    int kis_plugin_version_check(struct plugin_server_info *si) {
        si->plugin_api_version = KIS_PLUGINTRACKER_VERSION;
        si->kismet_major = VERSION_MAJOR;
        si->kismet_minor = VERSION_MINOR;
        si->kismet_tiny = VERSION_TINY;

        return 1;
    }

    int kis_plugin_activate(GlobalRegistry *in_globalreg) {
        return 1;
    }

    int kis_plugin_finalize(GlobalRegistry *in_globalreg) {
        ExternalProxyTest *ept = new ExternalProxyTest(in_globalreg);

        return 1;
    }

}

