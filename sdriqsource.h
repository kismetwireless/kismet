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

#ifndef __SDRIQSOURCE_H__
#define __SDRIQSOURCE_H__

#include "config.h"

#include "trackedcomponent.h"

class SdrIQsource;

class SdrIQsourceBuilder : public tracker_component { 
public:
    SdrIQsourceBuilder() :
        tracker_component(0) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    SdrIQsourceBuilder(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
        initialize();
    }

    SdrIQsourceBuilder(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("SdrIQsourceBuilder");
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

    virtual ~SdrIQsourceBuilder() { };

    virtual void initialize() { };

    // Build the actual data source; when subclassing this MUST fill in the prototype!
    // Due to semantics of shared_pointers we can't simply pass a 'this' sharedptr 
    // to the instantiated datasource, so we need to take a pointer to ourselves 
    // in the input.
    // Typical implementation:
    // return SharedDatasource(new SomeKismetDatasource(globalreg, in_shared_builder));
    virtual std::shared_ptr<SdrIQsource> build_datasource(std::shared_ptr<SdrIQsourceBuilder>
            in_shared_builder __attribute__((unused))) { return nullptr; };

    __Proxy(iqsource_type, std::string, std::string, std::string, iqsource_type);
    __Proxy(iqsource_description, std::string, std::string, std::string, iqsource_description);
    __Proxy(probe_capable, uint8_t, bool, bool, probe_capable);

protected:
    std::shared_ptr<TrackerElementString> iqsource_type;
    std::shared_ptr<TrackerElementString> iqsource_description;

    // Can we scan for this radio?
    std::shared_ptr<TrackerElementString> probe_capable;

    // We don't enumerate most other characteristics like hardware freq/capture limits
    // because we might have multiple radios under one phy
    
    virtual void register_fields() override {
        tracker_component::register_fields();

        set_local_name("kismet.iqsource.type_driver");

        RegisterField("kismet.iqsource.driver.type", "IQ type", &iqsource_type);
        RegisterField("kismet.iqsource.driver.description", "IQ description", &iqsource_description);
    }
};

class SdrIQsource : public tracker_component {
public:
    SdrIQsource(std::shared_ptr<SdrIQsourceBuilder> in_builder);

    SdrIQsource() :
        tracker_component(0) {
        register_fields();
        reserve_fields(nullptr);
        initialize();
    }

    SdrIQsource(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(nullptr);
        initialize();
    }

    SdrIQsource(int in_id, std::shared_ptr<TrackerElementMap> e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
        initialize();
    }

    virtual uint32_t get_signature() const override {
        return Adler32Checksum("SdrIQsource");
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

    virtual ~SdrIQsource() { };

    virtual void initialize() { };

    // Build the actual data source; when subclassing this MUST fill in the prototype!
    // Due to semantics of shared_pointers we can't simply pass a 'this' sharedptr 
    // to the instantiated datasource, so we need to take a pointer to ourselves 
    // in the input.
    // Typical implementation:
    // return SharedDatasource(new SomeKismetDatasource(globalreg, in_shared_builder));
    virtual std::shared_ptr<SdrIQsource> build_datasource(std::shared_ptr<SdrIQsourceBuilder>
            in_shared_builder __attribute__((unused))) { return nullptr; };

    __Proxy(iqsource_name, std::string, std::string, std::string, iqsource_name);
    __Proxy(hw_min_freq_khz, double, double, double, hw_min_freq_khz);
    __Proxy(hw_max_freq_khz, double, double, double, hw_max_freq_khz);
    __Proxy(hw_min_bw_khz, double, double, double, hw_min_bw_khz);
    __Proxy(hw_max_bw_khz, double, double, double, hw_max_bw_khz);

protected:
    std::shared_ptr<TrackerElementString> iqsource_name;

    // Here we implement the hardware limit records
    std::shared_ptr<TrackerElementDouble> hw_min_freq_khz;
    std::shared_ptr<TrackerElementDouble> hw_max_freq_khz;
    std::shared_ptr<TrackerElementDouble> hw_min_bw_khz;
    std::shared_ptr<TrackerElementDouble> hw_max_bw_khz;
    
    virtual void register_fields() override {
        tracker_component::register_fields();

        RegisterField("kismet.iqsource.name", "Name", &iqsource_name);
        RegisterField("kismet.iqsource.hw_min_freq_khz", 
                "Minimum hw supported frequency, KHz", &hw_min_freq_khz);
        RegisterField("kismet.iqsource.hw_max_freq_khz",
                "Maximum hw supported frequency, KHz", &hw_max_freq_khz);
        RegisterField("kismet.iqsource.hw_min_bw_khz", 
                "Minimum hw supported bandwidth, KHz", &hw_min_bw_khz);
        RegisterField("kismet.iqsource.hw_max_bw_khz",
                "Maximum hw supported bandwidth, KHz", &hw_max_bw_khz);
    }

};



#endif

