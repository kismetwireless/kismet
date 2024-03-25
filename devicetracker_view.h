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

#ifndef __DEVICE_VIEW_H__
#define __DEVICE_VIEW_H__

#include "config.h"

#include <functional>
#include <unordered_map>

#include "uuid.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "devicetracker_component.h"
#include "devicetracker_view_workers.h"
#include "kis_net_beast_httpd.h"

// Common view holder mechanism which handles view endpoints, view filtering, and so on.
//
// Views are optimized for maintaining independent, sorted lists of devices.  For a view to work,
// it requires assisting code in the appropriate areas (such as adding a SSID to a dot11 device).
//
// Views can be populated either by callbacks in the packet stream or by direct calls to
// add_device_direct and addRemoveDirect, depending on how the view population code is written.
//
// Views are best suited to long-term alternate representations of data, such as 'all access points',
// 'all devices of a given phy type', and so on.  The vector-backed system is not well optimized
// for frequent eviction of devices from the view.
//
// Views live under the devices tree in:
// /devices/view/[view id]/...
//
// Main device sorting/filtering/datatables view lives under:
// /devices/view/[view id]/devices.json

class kis_tracked_device;
class device_tracker_view;

class device_tracker_view : public tracker_component {
public:
    // The new device callback is called whenever a new device is created by the devicetracker;
    // it's also called for every device when a new view is created, to perform the initial 
    // population

    // The updated device callback is called whenever a change event occurs.  Change events
    // are triggered by specific code, make sure you've integrated a change trigger for
    // the filtering you're performing.
    // Returning 'false' removes the device from the list.  This is expensive, so 
    // removing devices from filtering should be a relatively rare event
    
    using new_device_cb = std::function<bool (std::shared_ptr<kis_tracked_device_base>)>;
    using updated_device_cb = std::function<bool (std::shared_ptr<kis_tracked_device_base>)>;

    // Primary method; where the ID is the core access of the view
    device_tracker_view(const std::string& in_id, const std::string& in_description,
            new_device_cb in_new_cb, updated_device_cb in_upd_cb);

    // Secondary method, where you can specify alternate paths to access; this is used for 
    // things like the per-source view organized by uuid (/devices/views/by-uuid/[uuid]/...)
    device_tracker_view(const std::string& in_id, const std::string& in_description,
            const std::vector<std::string>& in_aux_path, 
            new_device_cb in_new_cb, updated_device_cb in_upd_cb);

    virtual ~device_tracker_view() { }

    __ProxyGet(view_id, std::string, std::string, view_id);
    __ProxyGet(view_description, std::string, std::string, view_description);
    __ProxyGet(list_sz, uint64_t, uint64_t, list_sz);
    __ProxyGet(view_indexed, bool, bool, view_indexed);

    virtual void pre_serialize() override;
    virtual void post_serialize() override;

    // Do work on the base list of all devices in this view; this makes an immutable copy
    // before performing work
    virtual std::shared_ptr<tracker_element_vector> do_device_work(device_tracker_view_worker& worker);
    // Do read-only work; this MAY NOT modify devices in the worker!
    virtual std::shared_ptr<tracker_element_vector> do_readonly_device_work(device_tracker_view_worker& worker);

    // Do work on a specific vector; this does NOT make an immutable copy of the vector.  You
    // must not call this on a vector which can be altered in another thread.
    virtual std::shared_ptr<tracker_element_vector> do_device_work(device_tracker_view_worker& worker,
            std::shared_ptr<tracker_element_vector> vec);
    // Do read-only work; this MAY NOT modify devices in the worker!
    virtual std::shared_ptr<tracker_element_vector> do_readonly_device_work(device_tracker_view_worker& worker,
            std::shared_ptr<tracker_element_vector> vec);

    // Called when a device undergoes a change that might make it eligible for inclusion
    // into a view; Integration with view filtering needs to be added to other locations
    // to activate this.
    virtual void update_device(std::shared_ptr<kis_tracked_device_base> device);

    // Direct calls to views that do not participate in the traditional view population 
    // and are instead directly manipulated by another component (such as the ssidscan system which
    // maintains a view by directly adding target devices)
    virtual void add_device_direct(std::shared_ptr<kis_tracked_device_base> device);
    virtual void remove_device_direct(std::shared_ptr<kis_tracked_device_base> device);

	// Look for an existing device record under read-only shared lock
    std::shared_ptr<kis_tracked_device_base> fetch_device(device_key in_key);

    // Set view to non-indexed so the UI knows not to show it in the primary list
    virtual void set_indexed(bool indexed) {
        view_indexed->set(indexed);
    }

protected:
    std::shared_ptr<device_tracker> devicetracker;

    virtual void register_fields() override {
        tracker_component::register_fields();

        register_field("kismet.devices.view.id", "View ID/Endpoint", &view_id);
        register_field("kismet.devices.view.description", "List description", &view_description);
        register_field("kismet.devices.view.size", "Number of devices in list", &list_sz);
        register_field("kismet.devices.view.indexed", "Index view in normal displays", &view_indexed);

        // We don't register device_list as a field because we never want to dump it 
        // un-processed; use the view APIs for managing that
    }

    std::shared_ptr<tracker_element_string> view_id;
    std::shared_ptr<tracker_element_uint8> view_indexed;
    std::shared_ptr<tracker_element_uuid> view_uuid;
    std::shared_ptr<tracker_element_string> view_description;
    std::shared_ptr<tracker_element_uint64> list_sz;

    new_device_cb new_cb;
    updated_device_cb update_cb;

    // Main vector of devices
    std::shared_ptr<tracker_element_vector> device_list;
    // Map of device presence in our list for fast reference during updates
    std::unordered_map<device_key, bool> device_presence_map;

    void device_endpoint_handler(std::shared_ptr<kis_net_beast_httpd_connection> con);
    std::shared_ptr<tracker_element> device_time_endpoint(std::shared_ptr<kis_net_beast_httpd_connection> con);

    // Build the URLs
    void register_urls(const std::string& in_id);

    // device_tracker has direct access to protected methods for new devices and purging devices,
    // nobody else should be calling those
    friend class device_tracker;

    // Called when a device is created; this should only be called by devicetracker itself.
    virtual void new_device(std::shared_ptr<kis_tracked_device_base> device);

    // Remove a device from any views; this is called when the devicetracker times out a 
    // device record.
    virtual void remove_device(std::shared_ptr<kis_tracked_device_base> device);

};

#endif

