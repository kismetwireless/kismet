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

#ifndef __KIS_SPECTRUM_H__
#define __KIS_SPECTRUM_H__

#include "config.h"
#include "trackedelement.h"
#include "kis_datasource.h"

// Sweep record with full data
class Spectrum_Sweep : public tracker_component {
public:
    Spectrum_Sweep(GlobalRegistry *in_globalreg, int in_id) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    Spectrum_Sweep(GlobalRegistry *in_globalreg, int in_id, SharedTrackerElement e) :
        tracker_component(in_globalreg, in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual SharedTrackerElement clone_type() {
        return SharedTrackerElement(new Spectrum_Sweep(globalreg, get_id()));
    }

    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.spectrum.sweep.num_samples", TrackerUInt64,
                "Number of samples per sweep record", &num_samples_sweep);
        RegisterField("kismet.spectrum.sweep.start_mhz", TrackerUInt64,
                "Starting frequency of sweep (MHz)", &start_mhz);
        RegisterField("kismet.spectrum.sweep.bin_hz", TrackerUInt64,
                "Sample width / Bin size (Hz)", &sample_hz_width);
        RegisterField("kismet.spectrum.sweep.samples_per_freq,", TrackerUInt64,
                "Samples per frequency", &samples_per_freq);

        RegisterField("kismet.spectrum.samples", TrackerVector, 
                "Vector of sample data, in dbm", &sample_vec);

    }

    __Proxy(num_samples, uint64_t, uint64_t, uint64_t, num_samples_sweep);
    __Proxy(start_mhz, uint64_t, uint64_t, uint64_t, start_mhz);
    __Proxy(bin_hz, uint64_t, uint64_t, uint64_t, sample_hz_width);
    __Proxy(samples_per_freq, uint64_t, uint64_t, uint64_t, samples_per_freq);

protected:

    SharedTrackerElement num_samples_sweep;
    SharedTrackerElement start_mhz;
    SharedTrackerElement sample_hz_width;
    SharedTrackerElement samples_per_freq;

    SharedTrackerElement sample_vec;

};

// Spectrum-specific sub-type of Kismet data sources
class SpectrumDatasource : public KisDatasource {
public:
    SpectrumDatasource(GlobalRegistry *in_globalreg, SharedDatasourceBuilder in_builder);

    // Configure sweeping
    virtual void set_sweep(uint64_t in_start_mhz, uint64_t in_end_mhz, uint64_t in_num_per_freq,
            uint64_t in_bin_width) = 0;

    // Configure sweeping with amplification
    virtual void set_sweep_amp(uint64_t in_start_mhz, uint64_t in_end_mhz, 
            uint64_t in_num_per_freq, uint64_t in_bin_width, bool in_amp,
            uint64_t in_if_amp, uint64_t in_baseband_amp) = 0;

    __ProxyGet(spectrum_configurable, uint8_t, bool, spectrum_configurable);

    __ProxyGet(spectrum_min_mhz, uint64_t, uint64_t, spectrum_min_mhz);
    __ProxyGet(spectrum_max_mhz, uint64_t, uint64_t, spectrum_max_mhz);

    __ProxyGet(spectrum_min_bin_hz, uint64_t, uint64_t, spectrum_min_bin_hz);
    __ProxyGet(spectrum_max_bin_hz, uint64_t, uint64_t, spectrum_max_bin_hz);

    __ProxyGet(spectrum_amp, uint8_t, bool, spectrum_amp);

    __ProxyGet(spectrum_gain_if, uint64_t, uint64_t, spectrum_gain_if);
    __ProxyGet(spectrum_gain_if_min, uint64_t, uint64_t, spectrum_gain_if_min);
    __ProxyGet(spectrum_gain_if_max, uint64_t, uint64_t, spectrum_gain_if_max);
    __ProxyGet(spectrum_gain_if_step, uint64_t, uint64_t, spectrum_gain_if_step);

    __ProxyGet(spectrum_gain_baseband, uint64_t, uint64_t, spectrum_gain_baseband);
    __ProxyGet(spectrum_gain_baseband_min, uint64_t, uint64_t, spectrum_gain_baseband_min);
    __ProxyGet(spectrum_gain_baseband_max, uint64_t, uint64_t, spectrum_gain_baseband_max);
    __ProxyGet(spectrum_gain_baseband_step, uint64_t, uint64_t, spectrum_gain_baseband_step);

protected:
    virtual void register_fields() {
        tracker_component::register_fields();

        RegisterField("kismet.spectrum.device.configurable", TrackerUInt8,
                "spectrum range is configurable (bool)", &spectrum_configurable);

        RegisterField("kismet.spectrum.device.min_mhz", TrackerUInt64,
                "minimum frequency of spectrum sweep (Hz)", &spectrum_min_mhz);
        RegisterField("kismet.spectrum.device.max_mhz", TrackerUInt64,
                "maximum frequency of spectrum sweep (Hz)", &spectrum_max_mhz);
        RegisterField("kismet.spectrum.device.min_bin_mhz", TrackerUInt64,
                "minimum size of frequency bin (Hz)", &spectrum_min_bin_mhz);
        RegisterField("kismet.spectrum.device.max_bin_mhz", TrackerUInt64,
                "maximum size of frequency bin (Hz)", &spectrum_max_bin_mhz);
        RegisterField("kismet.spectrum.device.min_num_samples_per", TrackerUInt64,
                "minimum number of samples per frequency bin", &spectrum_min_num_samples_per);
        RegisterField("kismet.spectrum.device.max_num_samples_per", TrackerUInt64,
                "maximum number of samples per frequency bin", &spectrum_max_num_samples_per);

        RegisterField("kismet.spectrum.device.amp", TrackerUInt8,
                "amplifier enabled", &spectrum_amp);

        RegisterField("kismet.spectrum.device.gain_if", TrackerUInt64,
                "lna/if gain", &spectrum_gain_if);
        RegisterField("kismet.spectrum.device.gain_if_min", TrackerUInt64,
                "lna/if minimum gain", &spectrum_gain_if_min);
        RegisterField("kismet.spectrum.device.gain_if_max", TrackerUInt64,
                "lna/if maximum gain", &spectrum_gain_if_max);
        RegisterField("kismet.spectrum.device.gain_if_step", TrackerUInt64,
                "lna/if gain step", &spectrum_gain_if_step);

        RegisterField("kismet.spectrum.device.gain_baseband", TrackerUInt64,
                "VGA/baseband gain", &spectrum_gain_baseband);
        RegisterField("kismet.spectrum.device.gain_baseband_min", TrackerUInt64,
                "VGA/baseband minimum gain", &spectrum_gain_baseband_min);
        RegisterField("kismet.spectrum.device.gain_baseband_max", TrackerUInt64,
                "VGA/baseband maximum gain", &spectrum_gain_baseband_max);
        RegisterField("kismet.spectrum.device.gain_baseband_step", TrackerUInt64,
                "VGA/baseband gain step", &spectrum_gain_baseband_step);

    }

    __ProxySet(spectrum_configurable, uint8_t, bool, spectrum_configurable);

    __ProxySet(spectrum_min_mhz, uint64_t, uint64_t, spectrum_min_mhz);
    __ProxySet(spectrum_max_mhz, uint64_t, uint64_t, spectrum_max_mhz);

    __ProxySet(spectrum_min_bin_hz, uint64_t, uint64_t, spectrum_min_bin_hz);
    __ProxySet(spectrum_max_bin_hz, uint64_t, uint64_t, spectrum_max_bin_hz);

    __ProxySet(spectrum_amp, uint8_t, bool, spectrum_amp);

    __ProxySet(int_spectrum_gain_if, uint64_t, uint64_t, spectrum_gain_if);
    __ProxySet(int_spectrum_gain_if_min, uint64_t, uint64_t, spectrum_gain_if_min);
    __ProxySet(int_spectrum_gain_if_max, uint64_t, uint64_t, spectrum_gain_if_max);
    __ProxySet(int_spectrum_gain_if_step, uint64_t, uint64_t, spectrum_gain_if_step);

    __ProxySet(int_spectrum_gain_baseband, uint64_t, uint64_t, spectrum_gain_baseband);
    __ProxySet(int_spectrum_gain_baseband_min, uint64_t, uint64_t, spectrum_gain_baseband_min);
    __ProxySet(int_spectrum_gain_baseband_max, uint64_t, uint64_t, spectrum_gain_baseband_max);
    __ProxySet(int_spectrum_gain_baseband_step, uint64_t, uint64_t, spectrum_gain_baseband_step);

    SharedTrackerElement spectrum_configurable;

    SharedTrackerElement spectrum_min_mhz;
    SharedTrackerElement spectrum_max_mhz;
    SharedTrackerElement spectrum_min_bin_hz;
    SharedTrackerElement spectrum_max_bin_hz;
    SharedTrackerElement spectrum_min_num_samples_per;
    SharedTrackerElement spectrum_max_num_samples_per;

    SharedTrackerElement spectrum_amp;

    SharedTrackerElement spectrum_gain_if;
    SharedTrackerElement spectrum_gain_if_min;
    SharedTrackerElement spectrum_gain_if_max;
    SharedTrackerElement spectrum_gain_if_step;

    SharedTrackerElement spectrum_gain_baseband;
    SharedTrackerElement spectrum_gain_baseband_min;
    SharedTrackerElement spectrum_gain_baseband_max;
    SharedTrackerElement spectrum_gain_baseband_step;
    
    
};

#endif

