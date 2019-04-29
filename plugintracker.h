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

#ifndef __PLUGINTRACKER_H__
#define __PLUGINTRACKER_H__

// Plugin handler
//
// Plugins are installed into [LIB_LOC]/kismet/[plugin-name]/ or
// ~/.kismet/[plugins]/[plugin-name]/
//
// A plugin directory should contain:
//
//  httpd/
//      Any HTTP content the plugin serves, this will be made available
//      on the webserver as /plugin/[plugin-name]/
//
//  foo.so
//      A shared object containing the plugin code, if this plugin requires
//      code.  If the plugin contains HTTP data only a manifest is sufficient
//
//  manifest.conf
//      A manifest file containing information about the plugin to be loaded
//      See docs/dev/plugin.md for more information about the format of the
//      manifest file
//
//
// Plugins are responsible for completing the record passed to them
// from Kismet and filling in the PluginRegistrationData record
// 
// Plugins must define two core functions, in the C name space:
//
// int kis_plugin_version_check(struct plugin_server_info *)
//
// will be passed an empty plugin_server_info struct and is expected
// to fill in all fields available.
//
// Plugins should return negative on failure, non-negative on success
//
// and
//
// int kis_plugin_activate(GlobalRegistry *)
//      
// which is responsible for activating the plugin and registering it
// with the system.
//
// Plugins should return negative on failure, non-negative on success
//
// Plugins which need system components which may not be active at plugin
// activation time may include a third function:
//
// int kis_plugin_finalize(GloablRegistry *)
//
// which will be called at the final stage of Kismet initialization before
// entry into the main loop.
//
// Even when including a kis_plugin_finalize function, plugins MUST 
// return success during initial activation to receive the finalization
// event.
//
// Plugins should return negative on failure, non-negative on success.
//
//
// Kismet plugins are first-order citizens in the ecosystem - a plugin
// is passed the global registry and is able to look up and interact
// with all registered components, including other plugins.
//
// This is a blessing and a curse - plugins are very tied to the kismet
// ABI, but are equally capable of performing ANYTHING kismet can
// do already.
//
// A secondary, abstracted plugin interface may come in the future to
// provide a more stable plugin interface.

#include "config.h"

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <vector>
#include <algorithm>
#include <string>
#include <sys/types.h>
#include <dlfcn.h>
#include <dirent.h>

#include "globalregistry.h"
#include "kis_mutex.h"

#include "configfile.h"
#include "kis_external.h"
#include "kis_net_microhttpd.h"
#include "trackedelement.h"
#include "trackedcomponent.h"

class ExternalHttpPluginHarness;

// The registration object is created by the plugintracker and given to
// a Kismet plugin; the plugin fills in the relevant information during
// the registration process
class PluginRegistrationData : public tracker_component {
public:
    PluginRegistrationData() :
        tracker_component() {
        register_fields();
        reserve_fields(NULL);
        dlfile = NULL;
    }

    PluginRegistrationData(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);

        dlfile = NULL;
    }

    PluginRegistrationData(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {

        register_fields();
        reserve_fields(e);

        dlfile = NULL;
    }

    virtual ~PluginRegistrationData() {
        if (dlfile != NULL)
            dlclose(dlfile);
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("PluginRegistrationData");
    }

    virtual std::unique_ptr<TrackerElement> clone_type() override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t());
        return std::move(dup);
    }

    virtual std::unique_ptr<TrackerElement> clone_type(int in_id) override {
        using this_t = std::remove_pointer<decltype(this)>::type;
        auto dup = std::unique_ptr<this_t>(new this_t(in_id));
        return std::move(dup);
    }

    __Proxy(plugin_name, std::string, std::string, std::string, plugin_name);
    __Proxy(plugin_description, std::string, std::string, std::string, plugin_description);
    __Proxy(plugin_author, std::string, std::string, std::string, plugin_author);
    __Proxy(plugin_version, std::string, std::string, std::string, plugin_version);

    __Proxy(plugin_so, std::string, std::string, std::string, plugin_so);
    __Proxy(plugin_dirname, std::string, std::string, std::string, plugin_dirname);
    __Proxy(plugin_path, std::string, std::string, std::string, plugin_path);

    __Proxy(plugin_js, std::string, std::string, std::string, plugin_js);
    __Proxy(plugin_http_external, std::string, std::string, std::string, plugin_http_external);

    void set_plugin_dlfile(void *in_dlfile) {
        dlfile = in_dlfile;
    }

    void *get_plugin_dlfile() {
        return dlfile;
    }

    void activate_external_http();

protected:
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("kismet.plugin.name", "plugin name", &plugin_name);
        RegisterField("kismet.plugin.description", "plugin description", &plugin_description);
        RegisterField("kismet.plugin.author", "plugin author", &plugin_author);
        RegisterField("kismet.plugin.version", "plugin version", &plugin_version);

        RegisterField("kismet.plugin.shared_object", "plugin shared object filename", &plugin_so);
        RegisterField("kismet.plugin.http_helper", "plugin http helper", &plugin_http_external);

        RegisterField("kismet.plugin.dirname", "plugin directory name", &plugin_dirname);
        RegisterField("kismet.plugin.path", "path to plugin content", &plugin_path);
        RegisterField("kismet.plugin.jsmodule", "Plugin javascript module", &plugin_js);

    }

    std::shared_ptr<TrackerElementString> plugin_name;
    std::shared_ptr<TrackerElementString> plugin_author;
    std::shared_ptr<TrackerElementString> plugin_description;
    std::shared_ptr<TrackerElementString> plugin_version;

    std::shared_ptr<TrackerElementString> plugin_so;
    std::shared_ptr<TrackerElementString> plugin_http_external;

    std::shared_ptr<TrackerElementString> plugin_dirname;
    std::shared_ptr<TrackerElementString> plugin_path;

    std::shared_ptr<TrackerElementString> plugin_js;

    void *dlfile;

    std::shared_ptr<ExternalHttpPluginHarness> external_http;
};
typedef std::shared_ptr<PluginRegistrationData> SharedPluginData;

// Plugin activation and final activation function
typedef int (*plugin_activation)(GlobalRegistry *);

#define KIS_PLUGINTRACKER_VERSION   1

// Server information record
// The plugin should fill in this data and return it in the kis_plugin_version_check
// callback.  It will be given a plugin_api_version which it must respect.
struct plugin_server_info {
    // V1 server info
    
    // Plugin API version; plugins can not expect fields to be present
    // in this struct from a future version of the plugin revision.  This
    // value is unlikely to change, but it may become necessary in the
    // future to expand the versioning
    unsigned int plugin_api_version;

    std::string kismet_major;
    std::string kismet_minor;
    std::string kismet_tiny;

    // End V1 info
};

// Plugin function called with an allocated plugin_server_info which complies with
// the version specified in plugin_api_version.
//
// Plugins should fill in all fields relevant to that version, or if there is a
// version mismatch, immediately return -1.
typedef int (*plugin_version_check)(plugin_server_info *);

// Plugin management class
class Plugintracker : public LifetimeGlobal,
    public Kis_Net_Httpd_CPPStream_Handler {
public:
    static std::shared_ptr<Plugintracker> create_plugintracker(GlobalRegistry *in_globalreg) {
        std::shared_ptr<Plugintracker> mon(new Plugintracker(in_globalreg));
        in_globalreg->RegisterLifetimeGlobal(mon);
        in_globalreg->InsertGlobal("PLUGINTRACKER", mon);
        return mon;
    }

private:
	Plugintracker(GlobalRegistry *in_globalreg);

public:
	static void Usage(char *name);

	virtual ~Plugintracker();

    // Look for plugins
    int ScanPlugins();

    // First-pass at activating plugins
	int ActivatePlugins();

    // Final chance at activating plugins
    int FinalizePlugins();

	// Shut down the plugins and close the shared files
	int ShutdownPlugins();

    // HTTP API
    virtual bool Httpd_VerifyPath(const char *path, const char *method);

    virtual void Httpd_CreateStreamResponse(Kis_Net_Httpd *httpd,
            Kis_Net_Httpd_Connection *connection,
            const char *url, const char *method, const char *upload_data,
            size_t *upload_data_size, std::stringstream &stream);

protected:
    kis_recursive_timed_mutex plugin_lock;

	GlobalRegistry *globalreg;
	int plugins_active;

	int ScanDirectory(DIR *in_dir, std::string in_path);

    // Final vector of registered activated plugins
    std::shared_ptr<TrackerElementVector> plugin_registry_vec;

    // List of plugins before they're loaded
    std::vector<SharedPluginData> plugin_preload;
};

/* External plugin loader for plugins only using the external http interface; no need for them
 * to implement a C++ component; this will get instantiated in the plugin finalization layer */
class ExternalHttpPluginHarness : public KisExternalHttpInterface {
public:
    ExternalHttpPluginHarness(std::string plugin_name, std::string binary) : 
        KisExternalHttpInterface() {

        // Look for someone playing hijinks
        if (binary.find("/") != std::string::npos) {
            _MSG_FATAL("Invalid plugin binary {}; binary must not contain a path.", binary);
            Globalreg::globalreg->fatal_condition = 1;
            return;
        }

        external_binary = binary;

        // Grow the IPC buffer
        ringbuf_handler.reset(new BufferHandler<RingbufV2>((1024*1024), (1024*1024)));
        ringbuf_handler->SetReadBufferInterface(this);

        ipc_remote.reset(new IPCRemoteV2(Globalreg::globalreg, ringbuf_handler));

        // Get the allowed paths for binaries and populate
        auto bin_paths = Globalreg::globalreg->kismet_config->FetchOptVec("helper_binary_path");

        if (bin_paths.size() == 0) {
            _MSG_ERROR("No 'helper_binary_path' found in kismet.conf; make sure your config files are up "
                    "to date.  Using the default binary path where Kismet was installed, instead.");
            bin_paths.push_back("%B");
        }

        for (auto p : bin_paths) 
            ipc_remote->add_path(Globalreg::globalreg->kismet_config->ExpandLogPath(p, "", "", 0, 1));

        auto ret = ipc_remote->launch_kis_binary(external_binary, {});

        if (ret < 0) {
            _MSG_ERROR("{} failed to launch helper binary '{}'", plugin_name, binary);
            return;
        }
    }
};

#endif
