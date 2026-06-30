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

#ifndef __PACKET_V2_H__
#define __PACKET_V2_H__

#include "config.h"

#include "base64.h"
#include "json_adapter_v2.h"

class kis_tracked_packet_v2 : public json_adapter_v2::jsonable {
public:
    kis_tracked_packet_v2() :
        json_adapter_v2::jsonable() {
        reset();
    }

    kis_tracked_packet_v2(const kis_tracked_packet_v2& p) {
        ts_sec_ = p.ts_sec_;
        ts_usec_ = p.ts_usec_;
        dlt_ = p.dlt_;
        source_id_ = p.source_id_;
        data_ = p.data_;
    }

    kis_tracked_packet_v2(const kis_tracked_packet_v2&& p) {
        ts_sec_ = p.ts_sec_;
        ts_usec_ = p.ts_usec_;
        dlt_ = p.dlt_;
        source_id_ = p.source_id_;
        data_ = p.data_;
    }

    kis_tracked_packet_v2& operator =(const kis_tracked_packet_v2& p) {
        ts_sec_ = p.ts_sec_;
        ts_usec_ = p.ts_usec_;
        dlt_ = p.dlt_;
        source_id_ = p.source_id_;
        data_ = p.data_;
        return *this;
    }

    void reset() {
        ts_sec_ = 0;
        ts_usec_ = 0;
        dlt_ = 0;
        source_id_ = 0;
        data_ = {};
    }

    auto ts_sec() { return ts_sec_; }
    void set_ts_sec(auto time) { ts_sec_ = time; }

    auto ts_usec() { return ts_usec_; }
    void set_ts_usec(auto time) { ts_usec_ = time; }

    const auto time() { return std::make_pair(ts_sec_, ts_usec_); }
    void set_time(auto ts, auto us) {
        ts_sec_ = ts;
        ts_usec_ = us;
    }

    auto dlt() { return dlt_; }
    void set_dlt(auto dlt) { dlt_ = dlt; }

    auto source_id() { return source_id_; }
    void set_source_id(auto id) { source_id_ = id; }

    const auto& data() { return data_; }
    void set_data(auto data) { data_ = base64::encode(data); }

    virtual void as_json(std::ostream& os, json_adapter_v2::opts *opts) {
        fmt::print(os, "{{");

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.packet.ts_sec", opts, ts_sec());
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.packet.ts_usec", opts, ts_usec());
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.packet.dlt", opts, dlt());
        json_adapter_v2::json_encode_keyed<uint64_t>{}(os, "kismet.packet.source", opts, source_id());
        json_adapter_v2::json_encode_keyed<std::string>{}(os, "kismet.packet.data", opts, data());

        opts->next_key_comma = sv_comma;
    }

    virtual void filtered_as_json(std::ostream& os, json_adapter_v2::opts *opts, const json_adapter_v2::field_group_map& fields) {
        if (fields.size() == 0) {
            return as_json(os, opts);
        }

        auto sv_comma = opts->next_key_comma;
        opts->next_key_comma = false;

        fmt::print(os, "{{");
        for (const auto& f : fields) {
            switch (json_adapter_v2::consthash(f.first)) {
                case json_adapter_v2::consthash("kismet.packet.ts_sec"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, ts_sec());
                    break;
                case json_adapter_v2::consthash("kismet.packet.ts_usec"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, ts_usec());
                    break;
                case json_adapter_v2::consthash("kismet.packet.dlt"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, dlt());
                    break;
                case json_adapter_v2::consthash("kismet.packet.source"):
                    json_adapter_v2::json_encode_keyed<uint64_t>{}(os, f.second.rename, opts, source_id());
                    break;
                case json_adapter_v2::consthash("kismet.packet.data"):
                    json_adapter_v2::json_encode_keyed<std::string>{}(os, f.second.rename, opts, data());
                    break;
                default:
                    json_adapter_v2::json_encode_keyed<int>{}(os, f.second.rename, opts, 0);
            }
        }

        opts->next_key_comma = sv_comma;
    }

protected:
    uint64_t ts_sec_;
    uint64_t ts_usec_;
    uint64_t dlt_;
    uint64_t source_id_;
    std::string data_;
};

template<> struct json_adapter_v2::json_encode<kis_tracked_packet_v2> {
    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_packet_v2& e) {
        e.as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_packet_v2 *e) {
        e->as_json(os, opts);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_packet_v2& e,
            json_adapter_v2::field_group_map& fields) {
        e.filtered_as_json(os, opts, fields);
    }

    void operator()(std::ostream& os, json_adapter_v2::opts *opts, kis_tracked_packet_v2 *e,
            json_adapter_v2::field_group_map& fields) {
        e->filtered_as_json(os, opts, fields);
    }
};


#endif /* __PACKET_V2_H__ */
