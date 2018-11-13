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

#ifndef __DEVICE_VIEW_WORKER_H__
#define __DEVICE_VIEW_WORKER_H__

#include "config.h"

#include <functional>

#include "kis_mutex.h"
#include "uuid.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "devicetracker_component.h"

#ifdef HAVE_LIBPCRE
#include <pcre.h>
#endif

class DevicetrackerViewWorker {
public:
    virtual ~DevicetrackerViewWorker() { }

    virtual bool matchDevice(std::shared_ptr<kis_tracked_device_base> device) = 0;
    virtual std::shared_ptr<TrackerElementVector> getMatchedDevices() {
        return matched;
    }

protected:
    friend class DevicetrackerView;

    virtual void setMatchedDevices(std::shared_ptr<TrackerElementVector> devices);

    kis_recursive_timed_mutex mutex;
    std::shared_ptr<TrackerElementVector> matched;
};

class DevicetrackerViewFunctionWorker : public DevicetrackerViewWorker {
public:
    using filter_cb = std::function<bool (std::shared_ptr<kis_tracked_device_base>)>;

    DevicetrackerViewFunctionWorker(filter_cb cb);
    virtual ~DevicetrackerViewFunctionWorker() { }

    virtual bool matchDevice(std::shared_ptr<kis_tracked_device_base> device) override;

protected:
    filter_cb filter;
};


#endif
