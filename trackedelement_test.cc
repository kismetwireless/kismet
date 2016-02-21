#include <msgpack.hpp>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include "trackedelement.h"
#include <string>
#include <iostream>
#include <sstream>
#include <map>
#include <string>

std::map<int, std::string> namemap;

namespace msgpack {
MSGPACK_API_VERSION_NAMESPACE(MSGPACK_DEFAULT_API_NS) {
namespace adaptor {

template<>
    struct pack<mac_addr> {
        template <typename Stream>
            packer<Stream>& operator()(msgpack::packer<Stream>& o, 
                    mac_addr const& v) const {
                o.pack_array(2);
                o.pack(v.longmac);
                o.pack(v.longmask);
                return o;
            }
    };

template<>
    struct pack<TrackerElement *> {
        template <typename Stream>
            packer<Stream>& operator()(msgpack::packer<Stream>& o, 
                    TrackerElement * const& v) const {

                printf("packer\n");

                o.pack_array(2);

                o.pack((int) v->get_type());

                TrackerElement::tracked_map *tmap;
                TrackerElement::map_iterator map_iter;

                TrackerElement::tracked_mac_map *tmacmap;
                TrackerElement::mac_map_iterator mac_map_iter;

                switch (v->get_type()) {
                    case TrackerString:
                        o.pack(GetTrackerValue<string>(v));
                        break;
                    case TrackerInt8:
                        o.pack(GetTrackerValue<int8_t>(v));
                        break;
                    case TrackerUInt8:
                        o.pack(GetTrackerValue<uint8_t>(v));
                        break;
                    case TrackerInt16:
                        o.pack(GetTrackerValue<int16_t>(v));
                        break;
                    case TrackerUInt16:
                        o.pack(GetTrackerValue<uint16_t>(v));
                        break;
                    case TrackerInt32:
                        o.pack(GetTrackerValue<int32_t>(v));
                        break;
                    case TrackerUInt32:
                        o.pack(GetTrackerValue<uint32_t>(v));
                        break;
                    case TrackerInt64:
                        o.pack(GetTrackerValue<int64_t>(v));
                        break;
                    case TrackerUInt64:
                        o.pack(GetTrackerValue<uint64_t>(v));
                        break;
                    case TrackerFloat:
                        o.pack(GetTrackerValue<float>(v));
                        break;
                    case TrackerDouble:
                        o.pack(GetTrackerValue<double>(v));
                        break;
                    case TrackerMac:
                        o.pack(GetTrackerValue<mac_addr>(v));
                        break;
                    case TrackerUuid:
                        o.pack(GetTrackerValue<uuid>(v).UUID2String());
                        break;
                    case TrackerVector:
                        o.pack(*(v->get_vector()));
                        break;
                    case TrackerMap:
                        tmap = v->get_map();
                        o.pack_map(tmap->size());
                        for (map_iter = tmap->begin(); map_iter != tmap->end(); 
                                ++map_iter) {
                            o.pack(namemap[map_iter->first]);
                            o.pack(map_iter->second);

                        }
                        break;
                    case TrackerIntMap:
                        tmap = v->get_intmap();
                        o.pack_map(tmap->size());
                        for (map_iter = tmap->begin(); map_iter != tmap->end(); 
                                ++map_iter) {
                            o.pack(namemap[map_iter->first]);
                            o.pack(map_iter->second);

                        }
                        break;
                    case TrackerMacMap:
                        tmacmap = v->get_macmap();
                        o.pack_map(tmacmap->size());
                        for (mac_map_iter = tmacmap->begin(); 
                                mac_map_iter != tmacmap->end();
                                ++mac_map_iter) {
                            o.pack(mac_map_iter->first);
                            o.pack(mac_map_iter->second);
                        }

                    default:
                        break;
                }

                return o;
            }
    };

}
}
}

class MyFormatter : public TrackerElementFormatterBasic {
public:
    void vector_to_stream(TrackerElement *e, ostream& stream) {
        stream << "VECTOR";
    }
};

int main(void) {
    printf("sizeof element: %ul\n", sizeof(TrackerElement));
    TrackerElement *core = new TrackerElement(TrackerMap);
    TrackerElement *vec = new TrackerElement(TrackerVector);

    namemap[0] = "kis.field.zero";
    namemap[1] = "kis.field.one";
    namemap[2] = "kis.field.two";
    namemap[3] = "kis.field.three";
    namemap[4] = "kis.field.four";
    namemap[5] = "kis.field.five";
    namemap[6] = "kis.field.six";
    namemap[7] = "kis.field.seven";
    namemap[8] = "kis.field.eight";
    namemap[9] = "kis.field.nine";

    printf("Adding vec to core\n");
    core->add_map(0, vec);

    for (int i = 0; i < 10; i++) {
        printf("Adding %d to vec\n", i);
        TrackerElement *f = new TrackerElement(TrackerInt32);
        f->set(i);

        vec->add_vector(f);
    }

    TrackerElement *submap = new TrackerElement(TrackerMap);
    for (int i = 5; i < 10; i++) {
        printf("Adding %d to map as float\n", i);
        TrackerElement *f = new TrackerElement(TrackerFloat);
        f->set((float) i);

        submap->add_map(i, f);
    }

    core->add_map(1, submap);

    // MyFormatter f;
    TrackerElementFormatterBasic f;

    f.get_as_stream(core, cout);
    cout << "\n";


    // serialize the object into the buffer.
    // any classes that implements write(const char*,size_t) can be a buffer.
    std::stringstream buffer;
    // msgpack::pack(buffer, src);
    msgpack::pack(buffer, core);

    // send the buffer ...
    buffer.seekg(0);

    // deserialize the buffer into msgpack::object instance.
    std::string str(buffer.str());

    for (unsigned int x = 0; x < str.length(); x++) {
        printf("\\x%02x", str[x] & 0xFF);
    }
    printf("\n");

    FILE *serbin = fopen("serialized.bin", "w+");
    fwrite(buffer.str().c_str(), buffer.str().length(), 1, serbin);
    fclose(serbin);

    msgpack::unpacked result;

    msgpack::unpack(result, str.data(), str.size());

    // deserialized object is valid during the msgpack::unpacked instance alive.
    msgpack::object deserialized = result.get();

    // msgpack::object supports ostream.
    std::cout << deserialized << std::endl;


    return 0;

}

