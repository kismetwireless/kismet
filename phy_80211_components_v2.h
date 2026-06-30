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

#ifndef __PHY_80211_COMPONENTS_V2__
#define ____PHY_80211_COMPONENTS_V2__

#include "config.h"


#include "base64.h"
#include "globalregistry.h"
#include "json_adapter_v2.h"
#include "macaddr.h"
#include "packet.h"
#include "packet_v2.h"
#include "packinfo_signal.h"
#include "rrd_v2.h"
#include "trackedlocation_v2.h"

class dot11_tracked_eapol_v2 : public json_adapter_v2::jsonable {
public:
    dot11_tracked_eapol_v2() :
        json_adapter_v2::jsonable() {
        reset();
    }

    dot11_tracked_eapol_v2& operator =(const dot11_tracked_eapol_v2& e) {
        eapol_time_ = e.eapol_time_;
        eapol_dir_ = e.eapol_dir_;
        eapol_replay_counter_ = e.eapol_replay_counter_;
        eapol_msg_num_ = e.eapol_msg_num_;
        eapol_install_ = e.eapol_install_;
        eapol_nonce_ = e.eapol_nonce_;
        eapol_rsn_pmkid_ = e.eapol_rsn_pmkid_;
        packet_ = e.packet_;
        return *this;
    }

    void reset() {
        eapol_time_ = 0;
        eapol_dir_ = 0;
        eapol_replay_counter_ = 0;
        eapol_msg_num_ = 0;
        eapol_install_ = 0;
        eapol_nonce_ = {};
        eapol_rsn_pmkid_ = {};
        packet_ = {};
    }

    auto eapol_time() { return eapol_time_; }
    void set_eapol_time(auto time) { eapol_time_ = time; }

    auto eapol_dir() { return eapol_dir_; };
    void set_eapol_dir(auto dir) { eapol_dir_ = dir; }

    auto eapol_replay_counter() { return eapol_replay_counter_; }
    void set_eapol_replay_counter(auto c) { eapol_replay_counter_ = c; }

    auto eapol_msg_num() { return eapol_msg_num_; }
    void set_eapol_msg_num(auto num) { eapol_msg_num_ = num; }

    auto eapol_install() { return eapol_install_; }
    void set_eapol_install(auto i) { eapol_install_ = i; }

    const auto& eapol_nonce() { return eapol_nonce_; }
    void set_eapol_nonce(const auto& nonce) { eapol_nonce_ = base64::encode(nonce); }

    const auto& eapol_rsn_pmkid() { return eapol_rsn_pmkid_; }
    void set_eapol_rsn_pmkid(const auto& pmk) { eapol_rsn_pmkid_ = base64::encode(pmk); }

    const auto& packet() { return packet_; }
    void set_packet(const auto& packet) { packet_ = packet; }

    void as_json(std::ostream& os, json_adapter_v2::opts *opts) {
        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<double>{}(os, "dot11.eapol.timestamp", opts, eapol_time());
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.direction", opts, eapol_dir());
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "dot11.eapol.replay_counter", opts, eapol_replay_counter());
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.message_num", opts, eapol_msg_num());
        json_adapter_v2::json_encode_keyed<uint8_t>{}(os, "dot11.eapol.install", opts, eapol_install());
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.eapol.nonce", opts, eapol_nonce());
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "dot11.eapol.rsn_pmkid", opts, eapol_rsn_pmkid());
        json_adapter_v2::json_encode_keyed<kis_tracked_packet_v2>{}(os, "dot11.eapol.packet", opts, packet());

        opts->next_key_comma = sv_comma;

        fmt::print(os, "}}");
    }

    void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::field_group_map subgroup;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("dot11.eapol.timestamp"):
                    json_adapter_v2::json_encode_keyed<double>{}(os, f.second.rename, opts, eapol_time());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.direction"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_dir());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.replay_counter"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, eapol_replay_counter());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.message_num"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_msg_num());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.install"):
                    json_adapter_v2::json_encode_keyed<uint8_t>{}(os, f.second.rename, opts, eapol_install());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.nonce"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, eapol_nonce());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.rsn_pmkid"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, eapol_rsn_pmkid());
                    break;
                case json_adapter_v2::consthash("dot11.eapol.packet"):
                    json_adapter_v2::group_fields(f.second.subfields, subgroup);
                    json_adapter_v2::json_encode_keyed<kis_tracked_packet_v2>{}(os, f.second.rename, opts, packet(), subgroup);
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        fmt::print(os, "}}");
        opts->next_key_comma = sv_comma;
    }


protected:
    double eapol_time_;
    uint8_t eapol_dir_;
    uint64_t eapol_replay_counter_;
    uint8_t eapol_msg_num_;
    uint8_t eapol_install_;
    std::string eapol_nonce_;
    std::string eapol_rsn_pmkid_;
    kis_tracked_packet_v2 packet_;
};

template<> struct json_adapter_v2::json_encode<dot11_tracked_eapol_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, dot11_tracked_eapol_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};

class dot11_tracked_nonce_v2 : public json_adapter_v2::jsonable {
public:
    dot11_tracked_nonce_v2() :
        json_adapter_v2::jsonable() {
        reset();
    }

    dot11_tracked_nonce_v2& operator =(const dot11_tracked_nonce_v2& e) {
        eapol_time_ = e.eapol_time_;
        eapol_replay_counter_ = e.eapol_replay_counter_;
        eapol_msg_num_ = e.eapol_msg_num_;
        eapol_install_ = e.eapol_install_;
        eapol_nonce_ = e.eapol_nonce_;
        return *this;
    }

    void reset() {
        eapol_time_ = 0;
        eapol_replay_counter_ = 0;
        eapol_msg_num_ = 0;
        eapol_install_ = 0;
        eapol_nonce_ = {};
    }

    auto eapol_time() { return eapol_time_; }
    void set_eapol_time(auto time) { eapol_time_ = time; }

    auto eapol_replay_counter() { return eapol_replay_counter_; }
    void set_eapol_replay_counter(auto c) { eapol_replay_counter_ = c; }

    auto eapol_msg_num() { return eapol_msg_num_; }
    void set_eapol_msg_num(auto num) { eapol_msg_num_ = num; }

    auto eapol_install() { return eapol_install_; }
    void set_eapol_install(auto i) { eapol_install_ = i; }

    const auto& eapol_nonce() { return eapol_nonce_; }
    void set_eapol_nonce(const auto& nonce) { eapol_nonce_ = base64::encode(nonce); }

protected:
    double eapol_time_;
    uint8_t eapol_msg_num_;
    uint8_t eapol_install_;
    std::string eapol_nonce_;
    uint64_t eapol_replay_counter_;

};


#endif /* ____PHY_80211_COMPONENTS_V2__ */
