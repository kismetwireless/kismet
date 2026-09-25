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

#ifndef __PROTOBUF_DECODER_H__
#define __PROTOBUF_DECODER_H__

#include <stdint.h>

#include <list>
#include <string_view>

// manually process protobuf streams & extract message content without
// the original proto files

namespace protobuf_decoder {

const unsigned int max_varint = (64+6) / 7;
const unsigned int max_lengthcode = (32 + 6) / 7;
const unsigned int fieldnum_scale = 8;

enum class tagtype {
    UNDEFINED = -1,
    VARINT = 0,
    FIXED64 = 1,
    LEN = 2,
    STARTGROUP = 3,
    ENDGROUP = 4,
    FIXED32 = 5,
};

class decoder {
public:
    decoder(const std::string_view& buf) : buf_{buf} {
        pos_ = 0;
        type_ = tagtype::UNDEFINED;
        id_ = 0;
    }

    int64_t next_field() {
        if (pos_ >= buf_.length()) {
            return -1;
        }

        auto tag = read_varint();

        if (tag > UINT32_MAX)
            throw std::runtime_error("protobuf field tag too large");

        id_ = uint32_t(tag / fieldnum_scale);
        type_ = static_cast<tagtype>(tag % fieldnum_scale);

        return id_;
    }

    constexpr tagtype get_type() const {
        return type_;
    }

    void ignore_field() {
        uint64_t len;
        std::list<uint32_t> stack;

        switch (type_) {
            case tagtype::VARINT:
                read_varint();
                break;
            case tagtype::FIXED32:
                pos_ += 4;
                break;
            case tagtype::FIXED64:
                pos_ += 8;
                break;
            case tagtype::LEN:
                len = read_varint();
                if (len > INT32_MAX)
                    throw std::runtime_error("protobuf byte array too long for int32");
                pos_ += len;
                break;
            case tagtype::STARTGROUP:
                while (!stack.empty()) {
                    auto nf = next_field();
                    if (nf < 0)
                        throw std::runtime_error("protobuf end of buffer in group");

                    if (type_ == tagtype::STARTGROUP) {
                        stack.push_front(nf);
                    } else if (type_ == tagtype::ENDGROUP) {
                        if (nf != *stack.begin()) {
                            throw std::runtime_error("protobuf mismatched group");
                        }

                        stack.pop_front();
                    } else {
                        ignore_field();
                    }
                }
                break;
            default:
                throw std::runtime_error("protobuf unsupported field type");
        }
    }

    std::string_view get_bytearray() {
        if (type_ != tagtype::LEN)
            throw std::runtime_error("protobuf field type mismatch, not len buffer");

        auto len = read_varint();
        if (len > INT32_MAX)
            throw std::runtime_error("protobuf byte array too long for in32");

        auto oldpos = pos_;

        pos_ += int32_t(len);

        return buf_.substr(oldpos, len);
    }

    uint64_t get_int() {
        switch (type_) {
            case tagtype::VARINT:
                return read_varint();
            case tagtype::FIXED64:
                return read_fixed_le<uint64_t>();
            case tagtype::FIXED32:
                return read_fixed_le<uint32_t>();
            default:
                throw std::runtime_error("protobuf field type mismatch");
        }
    }

    template<typename fp>
    fp get_float() {
        switch (type_) {
            case tagtype::FIXED64:
                return fp(read_fixed_le<double>());
            case tagtype::FIXED32:
                return fp(read_fixed_le<float>());
            default:
                throw std::runtime_error("protobuf field type mismatch");
        }
    }


protected:
    void advance_buf(size_t n) {
        if (pos_ + n >= buf_.size()) {
            throw std::runtime_error("protobuf too short for requested advance");
        }

        pos_ += n;
    }

    template <typename t>
    t read_fixed_le() {
        static_assert(sizeof(t) == 4 || sizeof(t) == 8, "can only extract 4 or 8 byte values");

        t ret = 0;
        const size_t sz = sizeof(t);
#ifdef WORDS_BIGENDIAN
        if (sz == 4) {
            ret =
                (t) (buf_.data() + pos_ + 3) << 24 |
                (t) (buf_.data() + pos_ + 2) << 16 |
                (t) (buf_.data() + pos_ + 1) << 8 |
                (t) (but_.data());
        } else if (sz == 8) {
            ret =
                (t) (buf_.data() + pos_ + 7) << 56 |
                (t) (buf_.data() + pos_ + 6) << 48 |
                (t) (buf_.data() + pos_ + 5) << 40 |
                (t) (buf_.data() + pos_ + 4) << 32 |
                (t) (buf_.data() + pos_ + 3) << 24 |
                (t) (buf_.data() + pos_ + 2) << 16 |
                (t) (buf_.data() + pos_ + 1) << 8 |
                (t) (but_.data());
        }
#else
        memcpy(&ret, buf_.data() + pos_, sz);
#endif

        pos_ += sz;

        return ret;
    }

    uint64_t read_varint() {
        uint64_t value = 0;
        uint64_t byte;
        int shift = 0;

        if (pos_ >= buf_.length())
            throw std::runtime_error("protobuf stream eof reading varint");

        // incremental read & check that things fit inside the buffer still
        if (buf_.length() - pos_ < 10) {
            do {
                if (pos_ >= buf_.length())
                    throw std::runtime_error("protobuf stream eof reading varint");
                if (shift >= 64)
                    throw std::runtime_error("protobuf varint too large");

                byte = (uint8_t) buf_.data()[pos_] & 0xFF;
                value |= ((byte & 127) << shift);

                shift += 7;
                pos_++;
            } while (byte & 128);

            return value;
        }

        // there's enough runway in the buffer to read a full-sized varint without
        // doing checking, so read it all

        byte = (uint8_t) buf_.data()[pos_];
        value |= (byte & 127);
        if (byte < 128) {
            pos_ += 1;
            return value;
        }

        byte = (uint8_t) buf_.data()[pos_ + 1];
        value |= (byte & 127) << 7;
        if (byte < 128) {
            pos_ += 2;
            return value;
        }

        byte = (uint8_t) buf_.data()[pos_ + 2];
        value |= (byte & 127) << (2 * 7);
        if (byte < 128) {
            pos_ += 3;
            return value;
        }

        byte = (uint8_t) buf_.data()[pos_ + 3];
        value |= (byte & 127) << (3 * 7);
        if (byte < 128) {
            pos_ += 4;
            return value;
        }

        byte = (uint8_t) buf_.data()[pos_ + 4];
        value |= (byte & 127) << (4 * 7);
        if (byte < 128) {
            pos_ += 5;
            return value;
        }

        byte = (uint8_t) buf_.data()[pos_ + 5];
        value |= (byte & 127) << (5 * 7);
        if (byte < 128) {
            pos_ += 6;
            return value;
        }

        byte = (uint8_t) buf_.data()[pos_ + 6];
        value |= (byte & 127) << (6 * 7);
        if (byte < 128) {
            pos_ += 7;
            return value;
        }

        byte = (uint8_t) buf_.data()[pos_ + 7];
        value |= (byte & 127) << (7 * 7);
        if (byte < 128) {
            pos_ += 8;
            return value;
        }

        byte = (uint8_t) buf_.data()[pos_ + 8];
        value |= (byte & 127) << (8 * 7);
        if (byte < 128) {
            pos_ += 9;
            return value;
        }

        byte = (uint8_t) buf_.data()[pos_ + 9];
        value |= (byte & 127) << (9 * 7);
        if (byte < 128) {
            pos_ += 10;
            return value;
        }

        throw std::runtime_error("protobuf varint too large");
    }

    int32_t read_zz32() {
        auto ret = uint32_t(read_varint());
        return int32_t((ret >> 1) ^ uint32_t(int32_t(ret & 1) * -1));
    }

    int64_t read_zz64() {
        auto ret = read_varint();
        return (ret >> 1) ^ (int64_t(ret & 1) * -1);
    }

    int32_t parse_zz32() {
        switch (type_) {
            case tagtype::VARINT:
                return read_zz32();
            case tagtype::FIXED64:
                return read_fixed_le<int64_t>();
            case tagtype::FIXED32:
                return read_fixed_le<int32_t>();
            default:
                throw std::runtime_error("protobuf field type mismatch, can't parse zz value");
        }
    }

    int64_t parse_zz64() {
        switch (type_) {
            case tagtype::VARINT:
                return read_zz64();
            case tagtype::FIXED64:
                return read_fixed_le<int64_t>();
            case tagtype::FIXED32:
                return read_fixed_le<int32_t>();
            default:
                throw std::runtime_error("protobuf field type mismatch, can't parse zz value");
        }
    }

    const std::string_view buf_;
    size_t pos_;

    tagtype type_;
    uint32_t id_;
};

}

#endif /* __PROTOBUF_DECODER_H__ */
