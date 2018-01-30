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

#include <sys/time.h>

#include <pthread.h> 

// ieee float struct for a 64bit float for serialization
typedef struct {
	uint64_t mantissa:52 __attribute__ ((packed));
	uint64_t exponent:11 __attribute__ ((packed));
	uint64_t sign:1 __attribute__ ((packed));
} ieee_64_float_t;

typedef struct {
	unsigned int mantissal:32;
	unsigned int mantissah:20;
	unsigned int exponent:11;
	unsigned int sign:1;
} ieee_double_t;

typedef struct {
	unsigned int mantissal:32;
	unsigned int mantissah:32;
	unsigned int exponent:15;
	unsigned int sign:1;
	unsigned int empty:16;
} ieee_long_double_t;

// Munge a string to characters safe for calling in a shell
std::string MungeToPrintable(const char *in_data, unsigned int max, int nullterm);
std::string MungeToPrintable(std::string in_str);

std::string StrLower(std::string in_str);
std::string StrUpper(std::string in_str);
std::string StrStrip(std::string in_str);
std::string StrPrintable(std::string in_str);
std::string AlignString(std::string in_txt, char in_spacer, int in_align, int in_width);

std::string MultiReplaceAll(std::string in, std::string match, std::string repl);

int HexStrToUint8(std::string in_str, uint8_t *in_buf, int in_buflen);
std::string HexStrFromUint8(uint8_t *in_buf, int in_buflen);

template<class t> class NtoString {
public:
	NtoString(t in_n, int in_precision = 0, int in_hex = 0) { 
		ostringstream osstr;

		if (in_hex)
			osstr << hex;

		if (in_precision)
			osstr << setprecision(in_precision) << fixed;

		osstr << in_n;

		s = osstr.str();
	}

	string Str() { return s; }

	string s;
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
	string opt;
	string val;
	int quoted;
};

// Generic option handlers
std::string FetchOpt(std::string in_key, std::vector<opt_pair> *in_vec);
int FetchOptBoolean(std::string in_key, std::vector<opt_pair> *in_vec, int dvalue);
std::vector<string> FetchOptVec(std::string in_key, std::vector<opt_pair> *in_vec);

// Quick fetch of strings from a map of options
std::string FetchOpt(std::string in_key, std::map<string, std::string> in_map, 
        std::string dvalue = "");
int FetchOptBoolean(std::string in_key, std::map<string, std::string> in_map, int dvalue = 0);

int StringToOpts(std::string in_line, std::string in_sep, std::vector<opt_pair> *in_vec);
void AddOptToOpts(std::string opt, std::string val, std::vector<opt_pair> *in_vec);
void ReplaceAllOpts(std::string opt, std::string val, std::vector<opt_pair> *in_vec);

// String compare, 1 true 0 false -1 unknown, or default value as provided
int StringToBool(std::string s, int dvalue = -1);

// String to integer.  Throws exception if not an integer!
int StringToInt(std::string s);
unsigned int StringToUInt(std::string s);

// Append to a string, with a delimiter if applicable
std::string StringAppend(std::string s, std::string a, std::string d = " ");

int XtoI(char x);
int Hex2UChar(unsigned char *in_hex, unsigned char *in_chr);

std::vector<std::string> StrTokenize(std::string in_str, std::string in_split, 
        int return_partial = 1);
std::string StrJoin(std::vector<string> in_content, std::string in_delim, 
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

vector<smart_word_token> BaseStrTokenize(std::string in_str, 
										 string in_split, std::string in_quote);
vector<smart_word_token> NetStrTokenize(std::string in_str, std::string in_split, 
										int return_partial = 1);

// Simplified quoted string tokenizer, expects " ' to start at the beginning
// of the token, no abc"def ghi"
vector<string> QuoteStrTokenize(std::string in_str, std::string in_split);

int TokenNullJoin(std::string *ret_str, const char **in_list);

std::string InLineWrap(std::string in_txt, unsigned int in_hdr_len,
				  unsigned int in_max_len);
vector<string> LineWrap(std::string in_txt, unsigned int in_hdr_len, 
						unsigned int in_maxlen);
vector<int> Str2IntVec(std::string in_text);

int IsBlank(const char *s);

// Clean up XML and CSV data for output
std::string SanitizeXML(std::string);
std::string SanitizeCSV(std::string);

void Float2Pair(float in_float, int16_t *primary, int64_t *mantissa);
float Pair2Float(int16_t primary, int64_t mantissa);

#ifdef SYS_LINUX
int FetchSysLoadAvg(uint8_t *in_avgmaj, uint8_t *in_avgmin);
#endif

// Adler-32 checksum, derived from rsync, adler-32
uint32_t Adler32Checksum(const char *buf1, size_t len);

// C++ shortcut
uint32_t Adler32Checksum(std::string buf1);

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
	string data;
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

class kis_datachunk;
int GetLengthTagOffsets(unsigned int init_offset, 
        kis_datachunk *in_chunk,
        std::map<int, std::vector<int> > *tag_cache_map);

// Utility class for doing conditional thread locking; allows one thread to wait
// indefinitely and another thread to easily unlock it
template<class t>
class conditional_locker {
public:
    conditional_locker() {
        locked = false;
    }

    conditional_locker(t in_data) {
        locked = false;
        data = in_data;
    }

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

        // Return false if waiting is to be continued, so the inverse of the
        // lock state
        cv.wait(lk, [this](){ return !locked; });

        return data;
    }

    // Unlock the conditional, unblocking whatever thread was blocked
    // waiting for us, and passing whatever data we'd like to pass
    void unlock(t in_data) {
        std::unique_lock<std::mutex> lk(m);
        locked = false;
        data = in_data;
        lk.unlock();
        cv.notify_one();
    }

    void unlock() {
        std::unique_lock<std::mutex> lk(m);
        locked = false;
        lk.unlock();
        cv.notify_one();
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

	virtual pos_type seekpos(streampos pos, std::ios_base::openmode mode) override {
        return seekoff(pos - pos_type(off_type(0)), std::ios_base::beg, mode);
	}

	char *begin, *end;
};

// Local copy of strerror_r because glibc did such an amazingly poor job of it
std::string kis_strerror_r(int errnum);

double ts_to_double(struct timeval ts);
double ts_now_to_double();

std::string hexstr_to_binstr(const char *hs);

#ifdef MISSING_STD_TO_STRING
namespace std {
    template<typename T>
    std::string to_string(const T &n) {
        std::ostringstream s;
        s << n;
        return s.str();
    }
}
#endif

#endif

