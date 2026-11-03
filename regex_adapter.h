/*
    this file is part of kismet

    kismet is free software; you can redistribute it and/or modify
    it under the terms of the gnu general public license as published by
    the free software foundation; either version 2 of the license, or
    (at your option) any later version.

    kismet is distributed in the hope that it will be useful,
    but without any warranty; without even the implied warranty of
    merchantability or fitness for a particular purpose.  see the
    gnu general public license for more details.

    you should have received a copy of the gnu general public license
    along with kismet; if not, write to the free software
    foundation, inc., 59 temple place, suite 330, boston, ma  02111-1307  usa
*/

#ifndef __REGEX_ADAPTER_H__
#define __REGEX_ADAPTER_H__

#include "config.h"

#include <string>
#include <string_view>

#ifdef HAVE_LIBPCRE1
#include <pcre.h>
#endif

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#include "boost/algorithm/string.hpp"

#include "fmt.h"

namespace kis_regex {

class regex {
public:
    regex(const std::string& regex) {
#if defined(HAVE_LIBPCRE1)
        const char *compile_error, *study_error;
        int err_offt;

        re = pcre_compile(regex.c_str(), 0, &compile_error, &err_offt, NULL);

        if (re == nullptr) {
            const auto e = fmt::format("Could not parse PCRE Regex: {} at {}",
                    compile_error, err_offt);
            throw std::runtime_error(e);
        }

        study = pcre_study(re, 0, &study_error);
        if (study_error != nullptr) {
            pcre_free(re);

            const auto e = fmt::format("Could not parse PCRE Regex, optimization failed: {}", study_error);
            throw std::runtime_error(e);
        }
#elif defined(HAVE_LIBPCRE2)
        PCRE2_SIZE erroroffset;
        int errornumber;

        re = NULL;
        match_data = NULL;

        re = pcre2_compile((PCRE2_SPTR8) regex.c_str(),
                PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);

        if (re == nullptr) {
            PCRE2_UCHAR buffer[256];
            pcre2_get_error_message(errornumber, buffer, sizeof(buffer));

            const auto e = fmt::format("Could not parse PCRE regex: {} at {}",
                    (int) erroroffset, (char *) buffer);
            throw std::runtime_error(e);
        }

        match_data = pcre2_match_data_create_from_pattern(re, NULL);
#else
        throw std::runtime_error("Kismet was not compiled with PCRE regex support");
#endif
    }

    regex(const regex&) = delete;

    regex(regex&& r) {
#if defined(HAVE_LIBPCRE1)
        re = r.re;
        r.re = nullptr;

        study = r.study;
        r.study = nullptr;
#elif defined(HAVE_LIBPCRE2)
        match_data = r.match_data;
        r.match_data = nullptr;

        re = r.re;
        r.re = nullptr;
#endif
    }

    ~regex() {
#if defined(HAVE_LIBPCRE1)
        if (re != NULL)
            pcre_free(re);
        if (study != NULL)
            pcre_free_study(study);
#elif defined(HAVE_LIBPCRE2)
        if (match_data != nullptr)
            pcre2_match_data_free(match_data);
        if (re != nullptr)
            pcre2_code_free(re);
#endif
    }

    bool match(const std::string_view& text) const {
        int rc = -1;

#if defined(HAVE_LIBPCRE1)
        int ovector[128];
        rc = pcre_exec(re, study, text.data(), text.length(), 0, 0, ovector, 128);

#elif defined(HAVE_LIBPCRE2)
        rc = pcre2_match(re, (PCRE2_SPTR8) text.data(), text.length(),
                0, 0, match_data, NULL);
#endif
        return rc >= 0;
    }

protected:
#if defined(HAVE_LIBPCRE1)
    pcre *re;
    pcre_extra *study;
#elif defined(HAVE_LIBPCRE2)
    pcre2_code *re;
    pcre2_match_data *match_data;
#endif
};

template<typename E> struct regex_match;

template<> struct regex_match<std::string> {
    bool operator()(const regex& re, const std::string& v) {
        return re.match(v);
    }
};

template<> struct regex_match<std::string_view> {
    bool operator()(const regex& re, const std::string_view v) {
        return re.match(v);
    }
};

// not strictly regex but no smarter place to put it really; also handle
// pure string matching here

template<typename E> struct string_match;

template<> struct string_match<std::string> {
    bool operator()(const std::string& match, const std::string& v,
            bool match_icase, bool match_full) {
        using match_range = const boost::iterator_range<std::string::const_iterator>;

        if (match_icase) {
            const auto mr = boost::ifind_first(
                    match_range(v.begin(), v.end()),
                    match_range(match.begin(), match.end()));

            if (mr) {
                if (match_full) {
                    if (mr.begin() == v.begin() && mr.end() == v.end()) {
                        return true;
                    } else {
                        return false;
                    }
                }

                return true;
            }
        } else {
            const auto mr = boost::find_first(
                    match_range(v.begin(), v.end()),
                    match_range(match.begin(), match.end()));

            if (mr) {
                if (match_full) {
                    if (mr.begin() == v.begin() && mr.end() == v.end()) {
                        return true;
                    } else {
                        return false;
                    }
                }

                return true;
            }
        }

        return false;
    }
};

template<> struct string_match<std::string_view> {
    bool operator()(const std::string& match, const std::string_view& v,
            bool match_icase, bool match_full) {
        using match_range = const boost::iterator_range<std::string_view::const_iterator>;
        const std::string_view match_v{match};

        if (match_icase) {
            const auto mr = boost::ifind_first(
                    match_range(v.begin(), v.end()),
                    match_range(match_v.begin(), match_v.end()));

            if (mr) {
                if (match_full) {
                    if (mr.begin() == v.begin() && mr.end() == v.end()) {
                        return true;
                    } else {
                        return false;
                    }
                }

                return true;
            }
        } else {
            const auto mr = boost::find_first(
                    match_range(v.begin(), v.end()),
                    match_range(match_v.begin(), match_v.end()));

            if (mr) {
                if (match_full) {
                    if (mr.begin() == v.begin() && mr.end() == v.end()) {
                        return true;
                    } else {
                        return false;
                    }
                }

                return true;
            }
        }

        return false;
    }
};

}

#endif /* __REGEX_ADAPTER_H__ */
