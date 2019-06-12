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

#include <sys/time.h>

#include <pthread.h> 

#include "multi_constexpr.h"

// Munge a string to characters safe for calling in a shell
std::string MungeToPrintable(const char *in_data, unsigned int max, int nullterm);
std::string MungeToPrintable(const std::string& in_str);

std::string StrLower(const std::string& in_str);
std::string StrUpper(const std::string& in_str);
std::string StrStrip(const std::string& in_str);

std::string MultiReplaceAll(const std::string& in, const std::string& match, const std::string& repl);

int HexStrToUint8(const std::string& in_str, uint8_t *in_buf, int in_buflen);
std::string HexStrFromUint8(uint8_t *in_buf, int in_buflen);

template<class t> class NtoString {
public:
	NtoString(t in_n, int in_precision = 0, int in_hex = 0) { 
        std::ostringstream osstr;

		if (in_hex)
			osstr << std::hex;

		if (in_precision)
			osstr << std::setprecision(in_precision) << std::fixed;

		osstr << in_n;

		s = osstr.str();
	}

    std::string Str() { return s; }

    std::string s;
};

#define IntToString(I)			NtoString<int>((I)).Str()
#define UIntToString(I)			NtoString<unsigned int>((I)).Str()
#define HexIntToString(I)		NtoString<unsigned int>((I), 0, 1).Str()
#define LongIntToString(L)		NtoString<long int>((L)).Str()
#define ULongToString(L)		NtoString<unsigned long int>((L)).Str()
#define FloatToString(F)		NtoString<float>((F)).Str()

void SubtractTimeval(struct timeval *in_tv1, struct timeval *in_tv2,
        struct timeval *out_tv);

// Generic options pair
struct opt_pair {
    std::string opt;
    std::string val;
	int quoted;
};

// Generic option handlers
std::string FetchOpt(const std::string& in_key, std::vector<opt_pair> *in_vec, 
        const std::string& d_value = "");

int FetchOptBoolean(const std::string& in_key, std::vector<opt_pair> *in_vec, int dvalue);
std::vector<std::string> FetchOptVec(const std::string& in_key, std::vector<opt_pair> *in_vec);

// Quick fetch of strings from a map of options
std::string FetchOpt(const std::string& in_key, const std::map<std::string, std::string>& in_map, 
        std::string dvalue = "");
int FetchOptBoolean(const std::string& in_key, const std::map<std::string, std::string>& in_map, 
        int dvalue = 0);

int StringToOpts(const std::string& in_line, const std::string& in_sep, std::vector<opt_pair> *in_vec);
void AddOptToOpts(const std::string& opt, const std::string& val, std::vector<opt_pair> *in_vec);
void ReplaceAllOpts(const std::string& opt, const std::string& val, std::vector<opt_pair> *in_vec);

template<typename T>
T StringTo(const std::string& s) {
    std::stringstream ss(s);
    T t;

    ss >> t;

    if (ss.fail())
        throw std::runtime_error("unable to parse string value");

    return t;
}

template<typename T>
T StringTo(const std::string& s, T dvalue) {
    try {
        return StringTo<T>(s);
    } catch (const std::exception& e) {
        return dvalue;
    }
}

// String compare, 1 true 0 false -1 unknown, or default value as provided
int StringToBool(const std::string& s, int dvalue = -1);

// String to integer.  Throws exception if not an integer!
int StringToInt(const std::string& s);
unsigned int StringToUInt(const std::string& s);

// Append to a string, with a delimiter if applicable
std::string StringAppend(const std::string& s, const std::string& a, const std::string& d = " ");

int XtoI(char x);
int Hex2UChar(unsigned char *in_hex, unsigned char *in_chr);

std::vector<std::string> StrTokenize(const std::string& in_str, const std::string& in_split, 
        int return_partial = 1);
std::string StrJoin(const std::vector<std::string>& in_content, const std::string& in_delim, 
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

std::vector<smart_word_token> BaseStrTokenize(const std::string& in_str, 
        const std::string& in_split, const std::string& in_quote);

// Simplified quoted string tokenizer, expects " ' to start at the beginning
// of the token, no abc"def ghi"
std::vector<std::string> QuoteStrTokenize(const std::string& in_str, const std::string& in_split);

int TokenNullJoin(std::string *ret_str, const char **in_list);

std::string InLineWrap(const std::string& in_txt, unsigned int in_hdr_len, unsigned int in_max_len);
std::vector<std::string> LineWrap(const std::string& in_txt, unsigned int in_hdr_len, unsigned int in_maxlen);
std::vector<int> Str2IntVec(const std::string& in_text);

void Float2Pair(float in_float, int16_t *primary, int64_t *mantissa);
float Pair2Float(int16_t primary, int64_t mantissa);

#ifdef SYS_LINUX
int FetchSysLoadAvg(uint8_t *in_avgmaj, uint8_t *in_avgmin);
#endif

// Adler-32 checksum, derived from rsync, adler-32
uint32_t Adler32Checksum(const char *buf1, size_t len);

// C++ shortcut
uint32_t Adler32Checksum(const std::string& buf1);

// Adler-32 incremental checksum, performs a non-contiguous checksum over 
// multiple records.
// Caller must set s1 and s2 to 0 for the initial call and provide them for
// subsequent calls.
uint32_t Adler32IncrementalChecksum(const char *buf1, size_t len, 
        uint32_t *s1, uint32_t *s2);

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

protected:
    std::mutex m;
    std::condition_variable cv;
    bool locked;
    t data;
};

// Basic override of a stream buf to allow us to operate purely from memory
struct membuf : std::streambuf {
	membuf(char *begin, char *end) : begin(begin), end(end) {
		this->setg(begin, begin, end);
	}

	virtual pos_type seekoff(off_type off, std::ios_base::seekdir dir, 
			std::ios_base::openmode which = std::ios_base::in) override {
        if (dir == std::ios_base::cur)
            gbump(off);
		else if (dir == std::ios_base::end)
			setg(begin, end+off, end);
		else if (dir == std::ios_base::beg)
			setg(begin, begin+off, end);

		return gptr() - eback();
	}

	virtual pos_type seekpos(std::streampos pos, std::ios_base::openmode mode) override {
        return seekoff(pos - pos_type(off_type(0)), std::ios_base::beg, mode);
	}

	char *begin, *end;
};

// Local copy of strerror_r because glibc did such an amazingly poor job of it
std::string kis_strerror_r(int errnum);

double ts_to_double(struct timeval ts);
double ts_now_to_double();

std::string hexstr_to_binstr(const char *hs);

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

};

#endif

