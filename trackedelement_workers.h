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

#ifndef __TRACKEDELEMENT_WORKERS__
#define __TRACKEDELEMENT_WORKERS__ 

#include "config.h"

#include <functional>

#include "kis_mutex.h"
#include "trackedelement.h"
#include "trackedcomponent.h"
#include "nlohmann/json.hpp"

#ifdef HAVE_LIBPCRE1
#include <pcre.h>
#endif

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

class tracker_element_worker {
public:
    tracker_element_worker() {
        mutex.set_name("tracker_element_worker");
        matched = std::make_shared<tracker_element_vector>();
    }
    virtual ~tracker_element_worker() { }

    // Match against a vector of elements; caller is responsible for ensuring this vector is protected
    // and stable.
    virtual std::shared_ptr<tracker_element_vector> do_work(std::shared_ptr<tracker_element_vector> v);

    virtual std::shared_ptr<tracker_element_vector> get_matched_elements() {
        return matched;
    }

protected:
    virtual bool match_element(std::shared_ptr<tracker_element> element) = 0;
    virtual void set_matched_elements(std::shared_ptr<tracker_element_vector> elements);

    kis_mutex mutex;
    std::shared_ptr<tracker_element_vector> matched;
};

class tracker_element_function_worker : public tracker_element_worker {
public:
    using filter_cb = std::function<bool (std::shared_ptr<tracker_element>)>;

    tracker_element_function_worker(filter_cb cb) :
        filter{cb} { }

    tracker_element_function_worker(const tracker_element_function_worker& w) {
        filter = w.filter;
        matched = w.matched;
    }

    virtual ~tracker_element_function_worker() { }

    virtual bool match_element(std::shared_ptr<tracker_element> element) override;

protected:
    filter_cb filter;
};

class tracker_element_regex_worker : public tracker_element_worker {
public:
    struct pcre_filter {
#if defined(HAVE_LIBPCRE1) || defined(HAVE_LIBPCRE2)
        pcre_filter(const std::string& target, const std::string& in_regex);
        ~pcre_filter();

        std::string target;

#if defined(HAVE_LIBPCRE1)
        pcre *re;
        pcre_extra *study;
#elif defined(HAVE_LIBPCRE2)
        pcre2_code *re;
        pcre2_match_data *match_data;
#endif

#endif
    };

    tracker_element_regex_worker(const std::vector<std::shared_ptr<tracker_element_regex_worker::pcre_filter>>& filter_vec); 
    tracker_element_regex_worker(nlohmann::json& json_pcre_vec);
    tracker_element_regex_worker(const std::vector<std::pair<std::string, std::string>>& str_pcre_vec);
    tracker_element_regex_worker(const tracker_element_regex_worker& w) {
        filter_vec = w.filter_vec;
        matched = w.matched;
    }

    virtual ~tracker_element_regex_worker() { }

    virtual bool match_element(std::shared_ptr<tracker_element> element) override;

protected:
    std::vector<std::shared_ptr<tracker_element_regex_worker::pcre_filter>> filter_vec;
};

class tracker_element_stringmatch_worker : public tracker_element_worker {
public:
    tracker_element_stringmatch_worker(const std::string& in_query,
            const std::vector<std::vector<int>>& in_paths);
    tracker_element_stringmatch_worker(const tracker_element_stringmatch_worker& w) {
        query = w.query;
        fieldpaths = w.fieldpaths;
        mac_query_term = w.mac_query_term;
        mac_query_term_len = w.mac_query_term_len;
        matched = w.matched;
    }

    virtual ~tracker_element_stringmatch_worker() { }

    virtual bool match_element(std::shared_ptr<tracker_element> element) override;

protected:
    std::string query;
    std::vector<std::vector<int>> fieldpaths;
    uint64_t mac_query_term;
    unsigned int mac_query_term_len;

};

class tracker_element_icasestringmatch_worker : public tracker_element_worker {
public:
    tracker_element_icasestringmatch_worker(const std::string& in_query,
            const std::vector<std::vector<int>>& in_paths);
    tracker_element_icasestringmatch_worker(const tracker_element_icasestringmatch_worker& w) {
        query = w.query;
        fieldpaths = w.fieldpaths;
        mac_query_term = w.mac_query_term;
        mac_query_term_len = w.mac_query_term_len;
        matched = w.matched;
    }

    virtual ~tracker_element_icasestringmatch_worker() { }

    virtual bool match_element(std::shared_ptr<tracker_element> element) override;

protected:
    std::string query;
    std::vector<std::vector<int>> fieldpaths;
    uint64_t mac_query_term;
    unsigned int mac_query_term_len;

};

#endif /* ifndef TRACKEDELEMENT_WORKERS */
