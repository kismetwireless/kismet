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

#ifndef __ADSB_ICAO_H__
#define __ADSB_ICAO_H__

#include "config.h"

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif

#include <zlib.h>

#include <string>

#include "util.h"
#include "globalregistry.h"

#include "unordered_dense.h"
#include "trackedelement.h"
#include "trackedcomponent.h"

// Tracked icao for export; we wedge the type field in from an array of 
// predefined types in the icao indexer to save ram
class tracked_adsb_icao : public tracker_component {
public:
    tracked_adsb_icao() :
        tracker_component() {

            register_fields();
            reserve_fields(nullptr);
        }

    tracked_adsb_icao(int in_id) :
        tracker_component(in_id) {
            register_fields();
            reserve_fields(nullptr);
        }

    tracked_adsb_icao(int in_id, std::shared_ptr<tracker_element_map> e) :
        tracker_component(in_id, e) {
            register_fields();
            reserve_fields(e);
        }

    virtual uint32_t get_signature() const override {
        return adler32_checksum("tracked_adsb_icao");
    }

    virtual std::shared_ptr<tracker_element> clone_type() noexcept override {
        using this_t = typename std::remove_pointer<decltype(this)>::type;
        auto r = std::make_shared<this_t>();
        r->set_id(this->get_id());
        return r;
    }

    __Proxy(icao, uint32_t, uint32_t, uint32_t, icao);
    __Proxy(regid, std::string, std::string, std::string, regid);
    __Proxy(model_type, std::string, std::string, std::string, model_type);
    __Proxy(model, std::string, std::string, std::string, model);
    __Proxy(owner, std::string, std::string, std::string, owner);

    __Proxy(atype_short, uint8_t, uint8_t, uint8_t, atype_short);
    __ProxyTrackable(atype, tracker_element_string, atype);

protected:
    virtual void register_fields() override {
        register_field("adsb.icao.icao", "ICAO identifier", &icao);
        register_field("adsb.icao.regid", "Registration ID", &regid);
        register_field("adsb.icao.type", "Model type", &model_type);
        register_field("adsb.icao.model", "Aircraft model", &model);
        register_field("adsb.icao.owner", "Aircraft owner", &owner);
        register_field("adsb.icao.atype_short", "Aircraft type (short type)", &atype_short);
    }

    std::shared_ptr<tracker_element_uint32> icao;
    std::shared_ptr<tracker_element_string> regid;
    std::shared_ptr<tracker_element_string> model_type;
    std::shared_ptr<tracker_element_string> model;
    std::shared_ptr<tracker_element_string> owner;
    std::shared_ptr<tracker_element_string> atype;
    std::shared_ptr<tracker_element_uint8> atype_short;
};

class kis_adsb_icao {
public:
    kis_adsb_icao();

    void index();

    std::shared_ptr<tracked_adsb_icao> get_unknown_icao() const {
        return unknown_icao;
    }

    std::shared_ptr<tracked_adsb_icao> lookup_icao(uint32_t icao);
    std::shared_ptr<tracked_adsb_icao> lookup_icao(const std::string& icao) {
        return lookup_icao(string_to_n<uint32_t>(icao, std::hex));
    }

    struct index_pos {
        uint32_t icao;
        z_off_t pos;
    };

    struct icao_data {
        uint32_t icao;
        std::shared_ptr<tracked_adsb_icao> icao_record;
    };

protected:
    kis_mutex mutex;
    std::map<char, std::shared_ptr<tracker_element_string>> atype_map;

    gzFile zmfile;

    int icao_id;
    int icao_type_id;
    std::shared_ptr<tracked_adsb_icao> unknown_icao;

    std::vector<index_pos> index_vec;
    ankerl::unordered_dense::map<uint32_t, std::shared_ptr<tracked_adsb_icao>> icao_map;
};


#endif 
