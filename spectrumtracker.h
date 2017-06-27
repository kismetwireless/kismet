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

#ifndef __SPECTRUMTRACKER_H__
#define __SPECTRUMTRACKER_H__

#include "config.h"
#include "trackedelement.h"

// Sweep record with full data
class Spectrumtracker_Sweep : public tracker_component {
public:
    Spectrumtracker_Sweep(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    Spectrumtracker_Sweep(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new Spectrumtracker_Sweep(globalreg, get_id()));
    }

    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.spectrum.sweep.num_samples", TrackerUInt64,
                "Number of samples per sweep record", &num_samples_sweep);
        RegisterField("kismet.spectrum.sweep.start_hz", TrackerUInt64,
                "Starting frequency of sweep (Hz)", &start_hz);
        RegisterField("kismet.spectrum.sweep.bin_hz", TrackerUInt64,
                "Sample width / Bin size (Hz)", &sample_hz_width);

        RegisterField("kismet.spectrum.samples", TrackerVector, 
                "Vector of sample data, in dbm", &sample_vec);

    }

    __Proxy(num_samples, uint64_t, uint64_t, uint64_t, num_samples_sweep);
    __Proxy(start_hz, uint64_t, uint64_t, uint64_t, start_hz);
    __Proxy(bin_hz, uint64_t, uint64_t, uint64_t, sample_hz_width);

protected:

    SharedTrackerElement num_samples_sweep;
    SharedTrackerElement start_hz;
    SharedTrackerElement sample_hz_width;
    SharedTrackerElement sample_vec;

};

// Spectrum device record to be added to a device record
class Spectrumtracker_Device : public tracker_component {
public:
    Spectrumtracker_Device(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    Spectrumtracker_Device(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new Spectrumtracker_Device(globalreg, get_id()));
    }

    __Proxy(spectrum_configurable, uint8_t, bool, bool, spectrum_configurable);
    __Proxy(spectrum_min_hz, uint64_t, uint64_t, uint64_t, spectrum_min_hz);
    __Proxy(spectrum_max_hz, uint64_t, uint64_t, uint64_t, spectrum_max_hz);
    __Proxy(spectrum_min_bin_hz, uint64_t, uint64_t, uint64_t, spectrum_min_bin_hz);
    __Proxy(spectrum_max_bin_hz, uint64_t, uint64_t, uint64_t, spectrum_max_bin_hz);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.spectrum.device.configurable", TrackerUInt8,
                "spectrum range is configurable (bool)", &spectrum_configurable);

        RegisterField("kismet.spectrum.device.min_hz", TrackerUInt64,
                "minimum frequency of spectrum sweep (Hz)", &spectrum_min_hz);
        RegisterField("kismet.spectrum.device.max_hz", TrackerUInt64,
                "maximum frequency of spectrum sweep (Hz)", &spectrum_max_hz);
        RegisterField("kismet.spectrum.device.min_bin_hz", TrackerUInt64,
                "minimum size of frequency bin (Hz)", &spectrum_min_bin_hz);
        RegisterField("kismet.spectrum.device.max_bin_hz", TrackerUInt64,
                "maximum size of frequency bin (Hz)", &spectrum_max_bin_hz);

    }

    SharedTrackerElement spectrum_configurable;

    SharedTrackerElement spectrum_min_hz;
    SharedTrackerElement spectrum_max_hz;
    SharedTrackerElement spectrum_min_bin_hz;
    SharedTrackerElement spectrum_max_bin_hz;
    
};

#endif

