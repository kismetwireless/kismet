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
class spectrum_sweep : public tracker_component {
public:
    spectrum_sweep(int in_id) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(NULL);
    }

    spectrum_sweep(int in_id, shared_tracker_element e) :
        tracker_component(in_id) {
        register_fields();
        reserve_fields(e);
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    virtual void register_fields() {
        tracker_component::register_fields();

        register_field("kismet.spectrum.sweep.num_samples", tracker_uint64,
                "Number of samples per sweep record", &num_samples_sweep);
        register_field("kismet.spectrum.sweep.start_mhz", tracker_uint64,
                "Starting frequency of sweep (MHz)", &start_mhz);
        register_field("kismet.spectrum.sweep.bin_hz", tracker_uint64,
                "Sample width / Bin size (Hz)", &sample_hz_width);
        register_field("kismet.spectrum.sweep.samples_per_freq,", tracker_uint64,
                "Samples per frequency", &samples_per_freq);

        register_field("kismet.spectrum.samples", tracker_vector, 
                "Vector of sample data, in dbm", &sample_vec);

    }

    __Proxy(num_samples, uint64_t, uint64_t, uint64_t, num_samples_sweep);
    __Proxy(start_mhz, uint64_t, uint64_t, uint64_t, start_mhz);
    __Proxy(bin_hz, uint64_t, uint64_t, uint64_t, sample_hz_width);
    __Proxy(samples_per_freq, uint64_t, uint64_t, uint64_t, samples_per_freq);

protected:

    shared_tracker_element num_samples_sweep;
    shared_tracker_element start_mhz;
    shared_tracker_element sample_hz_width;
    shared_tracker_element samples_per_freq;

    shared_tracker_element sample_vec;

};

// Spectrum-specific sub-type of Kismet data sources
class spectrum_datasource : public kis_datasource {
public:
    spectrum_datasource(shared_datasource_builder in_builder);

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

        register_field("kismet.spectrum.device.configurable", tracker_uint8,
                "spectrum range is configurable (bool)", &spectrum_configurable);

        register_field("kismet.spectrum.device.min_mhz", tracker_uint64,
                "minimum frequency of spectrum sweep (Hz)", &spectrum_min_mhz);
        register_field("kismet.spectrum.device.max_mhz", tracker_uint64,
                "maximum frequency of spectrum sweep (Hz)", &spectrum_max_mhz);
        register_field("kismet.spectrum.device.min_bin_mhz", tracker_uint64,
                "minimum size of frequency bin (Hz)", &spectrum_min_bin_mhz);
        register_field("kismet.spectrum.device.max_bin_mhz", tracker_uint64,
                "maximum size of frequency bin (Hz)", &spectrum_max_bin_mhz);
        register_field("kismet.spectrum.device.min_num_samples_per", tracker_uint64,
                "minimum number of samples per frequency bin", &spectrum_min_num_samples_per);
        register_field("kismet.spectrum.device.max_num_samples_per", tracker_uint64,
                "maximum number of samples per frequency bin", &spectrum_max_num_samples_per);

        register_field("kismet.spectrum.device.amp", tracker_uint8,
                "amplifier enabled", &spectrum_amp);

        register_field("kismet.spectrum.device.gain_if", tracker_uint64,
                "lna/if gain", &spectrum_gain_if);
        register_field("kismet.spectrum.device.gain_if_min", tracker_uint64,
                "lna/if minimum gain", &spectrum_gain_if_min);
        register_field("kismet.spectrum.device.gain_if_max", tracker_uint64,
                "lna/if maximum gain", &spectrum_gain_if_max);
        register_field("kismet.spectrum.device.gain_if_step", tracker_uint64,
                "lna/if gain step", &spectrum_gain_if_step);

        register_field("kismet.spectrum.device.gain_baseband", tracker_uint64,
                "VGA/baseband gain", &spectrum_gain_baseband);
        register_field("kismet.spectrum.device.gain_baseband_min", tracker_uint64,
                "VGA/baseband minimum gain", &spectrum_gain_baseband_min);
        register_field("kismet.spectrum.device.gain_baseband_max", tracker_uint64,
                "VGA/baseband maximum gain", &spectrum_gain_baseband_max);
        register_field("kismet.spectrum.device.gain_baseband_step", tracker_uint64,
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

    shared_tracker_element spectrum_configurable;

    shared_tracker_element spectrum_min_mhz;
    shared_tracker_element spectrum_max_mhz;
    shared_tracker_element spectrum_min_bin_hz;
    shared_tracker_element spectrum_max_bin_hz;
    shared_tracker_element spectrum_min_num_samples_per;
    shared_tracker_element spectrum_max_num_samples_per;

    shared_tracker_element spectrum_amp;

    shared_tracker_element spectrum_gain_if;
    shared_tracker_element spectrum_gain_if_min;
    shared_tracker_element spectrum_gain_if_max;
    shared_tracker_element spectrum_gain_if_step;

    shared_tracker_element spectrum_gain_baseband;
    shared_tracker_element spectrum_gain_baseband_min;
    shared_tracker_element spectrum_gain_baseband_max;
    shared_tracker_element spectrum_gain_baseband_step;
    
    
};

#endif

