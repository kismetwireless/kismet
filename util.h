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

#ifndef __UTIL_H__
#define __UTIL_H__

#include "config.h"

#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <pwd.h>
#include <ctype.h>
#include <math.h>
#include <string.h>

#include <atomic>
#include <string>
#include <map>
#include <vector>
#include <list>
#include <sstream>
#include <iomanip>
#include <stdexcept>
#include <functional>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <chrono>
#include <sstream>
#include <future>
#include <exception>

#include <sys/time.h>

#include <pthread.h> 

#include "fmt.h"

#include "multi_constexpr.h"
#include "string_view.hpp"

#include "nlohmann/json.hpp"

// Forward-define formatters for a bunch of json features we use throughout kismet
// template <>struct fmt::formatter<nlohmann::json::array_t> : fmt::ostream_formatter {};
// template <>struct fmt::formatter<nlohmann::json::string_t> : fmt::ostream_formatter {};
// template <>struct fmt::formatter<nlohmann::json::number_float_t> : fmt::ostream_formatter {};
// template <>struct fmt::formatter<nlohmann::json::number_integer_t> : fmt::ostream_formatter {};
// template <>struct fmt::formatter<nlohmann::json::number_unsigned_t> : fmt::ostream_formatter {};

// Munge a string to printable - printable assumed to be either a UTF8 string, or 
// a pure ascii string if we can't confirm that it's UTF8
std::string munge_to_printable(const std::string& in_str) noexcept;
std::string munge_to_printable(const char *begin, size_t len) noexcept;

std::string str_lower(const std::string& in_str);
std::string str_upper(const std::string& in_str);
std::string str_strip(const std::string& in_str);

std::string multi_replace_all(const std::string& in, const std::string& match, const std::string& repl);

int hex_str_to_uint8(const std::string& in_str, uint8_t *in_buf, int in_buflen);
std::string uint8_to_hex_str(uint8_t *in_buf, int in_buflen);

template<class t> 
std::string n_to_string(t in_n, int in_precision = 0, int in_hex = 0) {
    std::ostringstream osstr;

    if (in_hex)
        osstr << std::hex;

    if (in_precision)
        osstr << std::setprecision(in_precision) << std::fixed;

    osstr << in_n;

    return osstr.str();
}

int subtract_timeval(struct timeval *in_tv1, struct timeval *in_tv2,
        struct timeval *out_tv);

// Generic options pair
struct opt_pair {
    std::string opt;
    std::string val;
	int quoted;
};

// Generic option handlers
std::string fetch_opt(const std::string& in_key, std::vector<opt_pair> *in_vec, 
        const std::string& d_value = "");

int fetch_opt_bool(const std::string& in_key, std::vector<opt_pair> *in_vec, int dvalue);
std::vector<std::string> fetch_opt_vec(const std::string& in_key, std::vector<opt_pair> *in_vec);

// Quick fetch of strings from a map of options
std::string fetch_opt(const std::string& in_key, const std::map<std::string, std::string>& in_map, 
        std::string dvalue = "");
int fetch_opt_bool(const std::string& in_key, const std::map<std::string, std::string>& in_map, 
        int dvalue = 0);

int string_to_opts(const std::string& in_line, const std::string& in_sep, std::vector<opt_pair> *in_vec);
void append_to_opts(const std::string& opt, const std::string& val, std::vector<opt_pair> *in_vec);
void replace_all_opts(const std::string& opt, const std::string& val, std::vector<opt_pair> *in_vec);

template<typename T>
T string_to_n(const std::string& s, std::ios_base&(*base)(std::ios_base &) = nullptr) {
    std::stringstream ss(s);
    T t;

    if (base != nullptr)
        ss >> base;

    ss >> t;

    if (ss.fail())
        throw std::runtime_error("unable to parse string value");

    return t;
}

template<typename T>
T string_to_n_dfl(const std::string& s, T dvalue) {
    try {
        return string_to_n<T>(s);
    } catch (const std::exception& e) {
        return dvalue;
    }
}

// String compare, 1 true 0 false -1 unknown, or default value as provided
int string_to_bool(const std::string& s, int dvalue = -1);

// String to integer.  Throws exception if not an integer!
int string_to_int(const std::string& s);
unsigned int string_to_uint(const std::string& s);

// Append to a string, with a delimiter if applicable
std::string string_append(const std::string& s, const std::string& a, const std::string& d = " ");

int x_to_i(char x);
int hex_to_uchar(unsigned char *in_hex, unsigned char *in_chr);

std::vector<std::string> str_tokenize(const std::string& in_str, const std::string& in_split, 
        int return_partial = 1);
std::string str_join(const std::vector<std::string>& in_content, const std::string& in_delim, 
        bool in_first = false);

// 'smart' tokenizeing with start/end positions
struct smart_word_token {
    std::string word;
    size_t begin;
    size_t end;

    smart_word_token& operator= (const smart_word_token& op) {
        word = op.word;
        begin = op.begin;
        end = op.end;
        return *this;
    }
};

std::vector<smart_word_token> base_str_tokenize(const std::string& in_str, 
        const std::string& in_split, const std::string& in_quote);

// Simplified quoted string tokenizer, expects " ' to start at the beginning
// of the token, no abc"def ghi"
std::vector<std::string> quote_str_tokenize(const std::string& in_str, const std::string& in_split);

int TokenNullJoin(std::string *ret_str, const char **in_list);

std::string in_line_wrap(const std::string& in_txt, unsigned int in_hdr_len, unsigned int in_max_len);
std::vector<std::string> line_wrap(const std::string& in_txt, unsigned int in_hdr_len, unsigned int in_maxlen);
std::vector<int> str_to_int_vector(const std::string& in_text);

void float_to_pair(float in_float, int16_t *primary, int64_t *mantissa);
float pair_to_float(int16_t primary, int64_t mantissa);

#ifdef SYS_LINUX
int fetch_sys_loadavg(uint8_t *in_avgmaj, uint8_t *in_avgmin);
#endif

// Adler-32 incremental checksum, performs a non-contiguous checksum over 
// multiple records.
// Caller must set s1 and s2 to 0 for the initial call and provide them for
// subsequent calls.
uint32_t adler32_append_checksum(const void *in_buf, size_t in_len, uint32_t cs);
uint32_t adler32_checksum(const void *in_buf, size_t in_len);
uint32_t adler32_checksum(const std::string& in_buf);

// 802.11 checksum functions, derived from the BBN USRP 802.11 code
#define IEEE_802_3_CRC32_POLY	0xEDB88320
unsigned int update_crc32_80211(unsigned int crc, const unsigned char *data,
								int len, unsigned int poly);
void crc32_init_table_80211(unsigned int *crc32_table);
unsigned int crc32_le_80211(unsigned int *crc32_table, const unsigned char *buf, 
							int len);


// Simple lexer for "advanced" filter stuff and other tools
#define _kis_lex_none			0
#define _kis_lex_string			1
#define _kis_lex_quotestring	2
#define _kis_lex_popen			3
#define _kis_lex_pclose			4
#define _kis_lex_negate			5
#define _kis_lex_delim			6

typedef struct {
	int type;
    std::string data;
} _kis_lex_rec;

std::list<_kis_lex_rec> LexString(std::string in_line, std::string& errstr);

#define LAT_CONVERSION_FACTOR 10000000
#define LON_CONVERSION_FACTOR 10000000
#define ALT_CONVERSION_FACTOR 1000

/* PPI-Geolocation tag conversion routines. (from lib_ppi_geotag)
 * Floating point numbers are stored on disk in a handful of fixed-point formats (fixedX_Y)
 * designed to preserve the appropriate amount of precision vs range. These functions convert
 * the fixedX_Y fixed point values into 'native' doubles for displaying.
 * Documentation on these formats can be found in the PPI-GEOLOCATION specification
 */
double fixed3_7_to_double(u_int32_t in);
double fixed3_6_to_double(u_int32_t in);
double fixed6_4_to_double(u_int32_t in);

u_int32_t double_to_fixed3_7(double in);
u_int32_t double_to_fixed3_6(double in);
u_int32_t double_to_fixed6_4(double in);

/*
 * Some values are encoded as 32-bit unsigned nano-second counters.
 * Usually we want to display these values as doubles.
 */
double    ns_to_double(u_int32_t in);
u_int32_t double_to_ns(double in);

// Utility class for doing conditional thread locking; allows one thread to wait
// indefinitely and another thread to easily unlock it
template<class t>
class conditional_locker {
public:
    conditional_locker() : 
        locked(false) { }

    conditional_locker(t in_data) :
        locked(false),
        data(in_data) { }

    ~conditional_locker() {
        unlock();
    }

    // Lock the conditional, does not block the caller
    void lock() {
        std::lock_guard<std::mutex> lk(m);
        locked = true;
    }

    // Block this thread until another thread calls us and unlocks us, return
    // whatever value we were unlocked with
    t block_until() {
        std::unique_lock<std::mutex> lk(m);
        cv.wait(lk, [this](){ return !locked; });
        return data;
    }

    // Block for a given number of milliseconds, returning false if it did not
    // successfully unlock
    bool block_for_ms(const std::chrono::milliseconds& rel_time) {
        std::unique_lock<std::mutex> lk(m);
        return cv.wait_for(lk, rel_time, [this](){ return !locked; });
    }

    // Unlock the conditional, unblocking whatever thread was blocked
    // waiting for us, and passing whatever data we'd like to pass
    void unlock(t in_data) {
        {
            std::lock_guard<std::mutex> lk(m);

            locked = false;
            data = in_data;
        }
        cv.notify_all();
    }

    void unlock() {
        {
            std::lock_guard<std::mutex> lk(m);

            locked = false;
        }

        cv.notify_all();
    }

    void unlock_one(t in_data) {
        {
            std::lock_guard<std::mutex> lk(m);

            locked = false;
            data = in_data;
        }
        cv.notify_one();
    }

    void unlock_one() {
        {
            std::lock_guard<std::mutex> lk(m);

            locked = false;
        }

        cv.notify_one();
    }

protected:
    std::mutex m;
    std::condition_variable cv;
    bool locked;
    t data;
};

// Basic override of a stream buf to allow us to operate purely from memory
struct membuf : public std::streambuf {
	membuf(const char *begin, const char *end) : begin(begin), end(end) {
		this->setg(const_cast<char *>(begin), const_cast<char *>(begin), const_cast<char *>(end));
	}

	virtual pos_type seekoff(off_type off, std::ios_base::seekdir dir, 
			std::ios_base::openmode which = std::ios_base::in) override {
		if (dir == std::ios_base::cur)
			gbump(off);
		else if (dir == std::ios_base::end)
			setg(const_cast<char *>(begin), const_cast<char *>(end+off), const_cast<char *>(end));
		else if (dir == std::ios_base::beg)
			setg(const_cast<char *>(begin), const_cast<char *>(begin+off), const_cast<char *>(end));

		return gptr() - eback();
	}

	virtual pos_type seekpos(std::streampos pos, std::ios_base::openmode mode) override {
		return seekoff(pos - pos_type(off_type(0)), std::ios_base::beg, mode);
	}

	const char *begin, *end;
};

// Local copy of strerror_r because glibc did such an amazingly poor job of it
std::string kis_strerror_r(int errnum);

double ts_to_double(struct timeval ts);
double ts_now_to_double();

// Flexible method to convert a hex string to a binary string; accepts
// both upper and lower case hex, and prepends '0' to the first byte if 
// an odd number of bytes in the original string
std::string hex_to_bytes(const std::string& in);

void thread_set_process_name(const std::string& name);

// Closure promise; executes a function as it leaves scope
class closure_promise {
public:
    closure_promise(std::function<void (void)> promise) :
        promise{promise} {}

    ~closure_promise() {
        promise();
    }
protected:
    std::function<void (void)> promise;
};

// Basic constant-time string compare for passwords and session keys
struct constant_time_string_compare_ne {
    bool operator()(const std::string& a, const std::string& b) const {
        bool r = true;

        if (a.length() != b.length())
            r = false;

        for (size_t x = 0; x < a.length() && x < b.length(); x++) {
            if (a[x] != b[x])
                r = false;
        }

        return r == false;
    }

    bool operator()(const nonstd::string_view& a, const nonstd::string_view& b) const {
        bool r = true;

        if (a.length() != b.length())
            r = false;

        for (size_t x = 0; x < a.length() && x < b.length(); x++) {
            if (a[x] != b[x])
                r = false;
        }

        return r == false;
    }

};

struct future_stringbuf_timeout : public std::exception {
    const char *what() const throw () {
        return "timed out";
    }
};

struct future_stringbuf : public std::stringbuf {
public:
    future_stringbuf(size_t chunk = 1024) :
        std::stringbuf{},
        chunk{chunk}, 
        blocking{false},
        done{true} { }

    bool is_complete() const { return done; }
    void complet() {
        done = true;
        sync();
    }

    void cancel() {
        done = true;
        sync();
    }

    size_t size() const { return str().size(); }

    void wait() {
        if (blocking)
            throw std::runtime_error("future_stream already blocking");

        if (done || str().size())
            return;

        blocking = true;
        
        data_available_pm = std::promise<bool>();

        auto ft = data_available_pm.get_future();

        ft.wait();

        blocking = false;
    }

    template<class Rep, class Period>
    void wait_for(const std::chrono::duration<Rep, Period>& timeout) {
        if (blocking)
            throw std::runtime_error("future_stream already blocking");

        if (done || str().size())
            return;

        blocking = true;
        
        data_available_pm = std::promise<bool>();

        auto ft = data_available_pm.get_future();

        auto r = ft.wait_for(timeout);
        if (r == std::future_status::timeout)
            throw future_stringbuf_timeout();
        else if (r == std::future_status::deferred)
            throw std::runtime_error("future_stream blocked with no future");

        blocking = false;
    }

    virtual std::streamsize xsputn(const char_type *s, std::streamsize n) override {
        auto r = std::stringbuf::xsputn(s, n);

        if (str().length() >= chunk)
            sync();

        return r;
    }

    virtual int_type overflow(int_type ch) override {
        auto r = std::stringbuf::overflow(ch);

        if (str().length() >= chunk)
            sync();

        return r;
    }

    virtual int sync() override {
        auto r = std::stringbuf::sync();

        if (blocking) {
            try {
                data_available_pm.set_value(true);
            } catch (const std::future_error& e) {
                ;
            }
        }

        return r;
    }


protected:
    size_t chunk;
    std::atomic<bool> blocking;
    std::atomic<bool> done;
    std::promise<bool> data_available_pm;
};

bool is_valid_utf8(const std::string& subject);

bool iequals(const std::string& a, const std::string& b);
uint64_t human_to_freq_khz(const std::string&);

template <class S, class D>
void string_vector_merge(S *source, D *destination,
        std::function<bool (const std::string& a, const std::string& b)> merge_fn) {
    bool dest_empty = destination->size() == 0;

    for (const auto& si : *source) {
        if (dest_empty) {
            destination->push_back(si);
            continue;
        } else {
            bool merge = true;
            for (const auto& sd : *destination) {
                merge = merge_fn(si, sd);

                if (!merge) {
                    break;
                }
            }

            if (merge) {
                destination->push_back(si);
            }
        }
    }
}

template <class S, class D>
void string_vector_merge(const S& source, D *destination,
        std::function<bool (const std::string& a, const std::string& b)> merge_fn) {
    bool dest_empty = destination->size() == 0;

    for (const auto& si : source) {
        if (dest_empty) {
            destination->push_back(si);
            continue;
        } else {
            bool merge = true;
            for (const auto& sd : *destination) {
                merge = merge_fn(si, sd);

                if (!merge) {
                    break;
                }
            }

            if (merge) {
                destination->push_back(si);
            }
        }
    }
}

template <class S, class D>
void string_vector_merge(S& source, D *destination,
        std::function<bool (const std::string& a, const std::string& b)> merge_fn) {
    return string_vector_merge<S, D>(&source, destination, merge_fn);
}

// highly inefficient inline filtering without recreating the object
template <class D, class S>
void string_vector_inline_filter(D *destination, S *filter,
        std::function<bool (const std::string& a, const std::string& b)> match_fn) {
    if (filter->size() == 0) {
        return;
    }

    for (const auto& fi : *filter) {
        for (size_t i = 0; i < destination->size(); i++) {
            if (match_fn(fi, *(destination->begin() + i))) {
                destination->erase(destination->begin() + i);
                break;
            }
        }
    }
}

template <class D, class S>
void string_vector_inline_filter(D *destination, const S& filter,
        std::function<bool (const std::string& a, const std::string& b)> match_fn) {

    if (filter.size() == 0) {
        return;
    }

    for (const auto& fi : filter) {
        for (size_t i = 0; i < destination->size(); i++) {
            if (match_fn(fi, *(destination->begin() + i))) {
                destination->erase(destination->begin() + i);
                break;
            }
        }
    }
}

template <class D, class S>
void string_vector_inline_filter(D& destination, S *filter,
        std::function<bool (const std::string& a, const std::string& b)> match_fn) {
    return string_vector_inline_filter<D, S>(&destination, filter, match_fn);
}

// an inefficient regex compare that has to compile the regex each time; only call from
// queries that aren't high load
bool regex_string_compare(const std::string& restr, const std::string& content);

#endif

