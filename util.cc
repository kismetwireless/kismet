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

#include "config.h"

#include "util.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <fcntl.h>
#include <stdarg.h>
#include <math.h>
#include <string.h>

#include <algorithm>
#include <cctype>
#include <string>

#ifdef HAVE_LIBPCRE1
#include <pcre.h>
#endif

#ifdef HAVE_LIBPCRE2
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>
#endif

#ifdef HAVE_LIBUTIL_H
# include <libutil.h>
#endif /* HAVE_LIBUTIL_H */

#if PF_ARGV_TYPE == PF_ARGV_PSTAT
#error "pstat?"
#endif

#if PF_ARGV_TYPE == PF_ARGV_PSTAT
# ifdef HAVE_SYS_PSTAT_H
#  include <sys/pstat.h>
# else
#  undef PF_ARGV_TYPE
#  define PF_ARGV_TYPE PF_ARGV_WRITEABLE
# endif /* HAVE_SYS_PSTAT_H */
#endif /* PF_ARGV_PSTAT */

#if PF_ARGV_TYPE == PF_ARGV_PSSTRINGS
# ifndef HAVE_SYS_EXEC_H
#  undef PF_ARGV_TYPE
#  define PF_ARGV_TYPE PF_ARGV_WRITEABLE
# else
#  include <machine/vmparam.h>
#  include <sys/exec.h>
# endif /* HAVE_SYS_EXEC_H */
#endif /* PF_ARGV_PSSTRINGS */

// We need this to make uclibc happy since they don't even have rintf...
#ifndef rintf
#define rintf(x) (float) rint((double) (x))
#endif

#include <sstream>
#include <iomanip>
#include <stdexcept>

#include "packet.h"

#include <pthread.h>

uint32_t adler32_append_checksum(const void *in_buf, size_t in_len, uint32_t cs) {
    size_t i{0};
    uint32_t ls1 = cs & 0xFFFF;
    uint32_t ls2 = (cs >> 16) & 0xffff;
    const uint32_t *buf = (const uint32_t *) in_buf;
	const uint8_t *sub_buf = nullptr;

    if (in_len < 4)
        return 0;

    for (i = 0; i < (in_len - 4); i += 4, buf++) {
        ls2 += (4 * (ls1 + ((*buf) & 0xFF))) + 
            (3 * ((*buf >> 8) & 0xFF)) +
            (2 * ((*buf >> 16) & 0xFF)) + 
            ((*buf >> 24) & 0xFF);

        ls1 += ((*buf >> 24) & 0xFF) +
            ((*buf >> 16) & 0xFF) +
            ((*buf >> 8) & 0xFF) +
            ((*buf) & 0xFF);
    }

    switch (in_len - i) {
        case 4:
            ls1 += ((*buf) & 0xFF);
            ls2 += ls1;
            ls1 += ((*buf >> 8) & 0xFF);
            ls2 += ls1;
            ls1 += ((*buf >> 16) & 0xFF);
            ls2 += ls1;
            ls1 += ((*buf >> 24) & 0xFF);
            ls2 += ls1;
            break;
        case 3:
			sub_buf = (uint8_t *) buf;
            // ls1 += ((*buf) & 0xFF);
			ls1 += sub_buf[0];
            ls2 += ls1;
            // ls1 += ((*buf >> 8) & 0xFF);
			ls1 += sub_buf[1];
            ls2 += ls1;
            // ls1 += ((*buf >> 16) & 0xFF);
			ls1 += sub_buf[2];
            ls2 += ls1;
            break;
        case 2:
			sub_buf = (uint8_t *) buf;
            // ls1 += ((*buf) & 0xFF);
			ls1 += sub_buf[0];
            ls2 += ls1;
            // ls1 += ((*buf >> 8) & 0xFF);
			ls1 += sub_buf[1];
            ls2 += ls1;
            break;
        case 1:
			sub_buf = (uint8_t *) buf;
            // ls1 += ((*buf) & 0xFF);
			ls1 += sub_buf[0];
            ls2 += ls1;
            break;
    }

	return (ls1 & 0xffff) + (ls2 << 16);
}

uint32_t adler32_checksum(const void *in_buf, size_t in_len) {
    return adler32_append_checksum(in_buf, in_len, 0);
}

uint32_t adler32_checksum(const std::string& in_buf) {
    return adler32_checksum(in_buf.data(), in_buf.length());
}

#if 0 

// Old munge-to-print code

// Convert a byte to an octal escape
std::string d2oa(uint8_t n) {
    std::string oa = "\\000";

	// make sure n is in the correct range
	// (currently redundant, since n is declared a uint8, but
	// protects against future changes)
	n &= 0377;

    int i = 3;
    while (n > 0) {
        oa[i--] =  '0' + (n & 07);
        n >>= 3;
    }

    return oa;
}

// Munge text down to printable characters only.  Simpler, cleaner munger than
// before (and more blatant when munging)
std::string munge_to_printable(const char *in_data, unsigned int max, int nullterm) {
    std::stringstream ret;
	unsigned int i;

	for (i = 0; i < max; i++) {
		if ((unsigned char) in_data[i] == 0 && nullterm == 1)
			return ret.str();

		if (in_data[i] == '\\') {
			// replace any input backslash by two backslashes,
			// to distinguish it from a backslash created by
			// the "octalize" process.
			ret << "\\\\";
		} else if ((unsigned char) in_data[i] >= 32 && (unsigned char) in_data[i] <= 126) {
            ret << in_data[i];
		} else {
			// "octalize" (convert to a printed octal representation)
			// any characters outside the printable range
            ret << d2oa(in_data[i]);
		}
	}

	return ret.str();
}

#endif

bool is_valid_utf8(const char *subject, size_t length) {
    int i, ix, nb, j;

    for (i = 0, ix = length; i < ix; i++) {
        auto c = (unsigned char) subject[i];

        if (0x00 <= c && c <= 0x7f) {
            nb = 0;
        } else if ((c & 0xE0) == 0xC0) {
            nb = 1;
        } else if ( c==0xed && i < (ix - 1) && 
                ((unsigned char) subject[i+1] & 0xa0) == 0xa0) {
            return false; 
        } else if ((c & 0xF0) == 0xE0) {
            nb = 2;
        } else if ((c & 0xF8) == 0xF0) {
            nb = 3; 
        } else {
            return false;
        }

        for (j = 0; j < nb && i < ix; j++) { 
            if ((++i == ix) || (((unsigned char) subject[i] & 0xC0) != 0x80)) {
                return false;
            }
        }
    }

    return true;
}

bool is_valid_utf8(const std::string& subject) {
	return is_valid_utf8(subject.data(), subject.size());
}


/* sanitize_extra_space and sanitize_string taken from nlohmann's jsonhpp library,
   Copyright 2013-2015 Niels Lohmann. and under the MIT license */
std::size_t munge_extra_space(const char *s, size_t len, bool utf8) noexcept {
    std::size_t result = 0;

    for (size_t i = 0; i < len; i++) {
        u_char c = s[i];

        switch (c & 0xFF) {
            case '"':
            case '\\':
            case '\b':
            case '\f':
            case '\n':
            case '\r':
            case '\t':
                {
                    // from c (1 byte) to \x (2 bytes)
                    result += 1;
                    break;
                }

            default:
                if (!utf8) {
                    if (c >= 32 && c <= 126) {
                        result += 1;
                    } else {
                        result += 3;
                    }
                } else {
                    if (c >= 0x00 and c <= 0x1f) {
                        // from c (1 byte) to \uxxxx (6 bytes)
                        result += 5;
                    }
                }


                break;
        }
    }

    return result;
}

std::size_t munge_extra_space(const std::string& s, bool utf8) noexcept {
	return munge_extra_space(s.data(), s.size(), utf8);
}

std::string munge_to_printable(const char *s, size_t len) noexcept {
	if (len == 0) {
		return "";
	}

    const auto utf8 = is_valid_utf8(s, len);
    const auto space = munge_extra_space(s, utf8);

    if (space == 0) {
        return s;
    }

    // create a result string of necessary size
    std::string result(len + space, '\\');
    std::size_t pos = 0;

    for (size_t i = 0; i < len; i++) {
        u_char c = s[i];

        switch (c) {
            // quotation mark (0x22)
            case '"':
                {
                    result[pos + 1] = '"';
                    pos += 2;
                    break;
                }

                // reverse solidus (0x5c)
            case '\\':
                {
                    // nothing to change
                    pos += 2;
                    break;
                }

                // backspace (0x08)
            case '\b':
                {
                    result[pos + 1] = 'b';
                    pos += 2;
                    break;
                }

                // formfeed (0x0c)
            case '\f':
                {
                    result[pos + 1] = 'f';
                    pos += 2;
                    break;
                }

                // newline (0x0a)
            case '\n':
                {
                    result[pos + 1] = 'n';
                    pos += 2;
                    break;
                }

                // carriage return (0x0d)
            case '\r':
                {
                    result[pos + 1] = 'r';
                    pos += 2;
                    break;
                }

                // horizontal tab (0x09)
            case '\t':
                {
                    result[pos + 1] = 't';
                    pos += 2;
                    break;
                }

            default:
                if (!utf8) {
                    if (c >= 32 && c <= 126) {
                        result[pos++] = c;
                    } else {
                        sprintf(&result[pos], "x%02X", c);
                        pos += 4;
                    }
                } else {

                    if (c >= 0x00 and c <= 0x1f) {
                        // print character c as \uxxxx
                        sprintf(&result[pos + 1], "u%04x", int(c));
                        pos += 6;
                        // overwrite trailing null character
                        result[pos] = '\\';
                    } else {
                        // all other characters are added as-is
                        result[pos++] = c;
                    }
                }

                break;
        }
    }

    return result;
}

std::string munge_to_printable(const std::string& s) noexcept {
	return munge_to_printable(s.data(), s.length());
}


std::string str_lower(const std::string& in_str) {
    std::string retstr(in_str);
    std::transform(retstr.begin(), retstr.end(), retstr.begin(), (int(*)(int)) std::tolower);
    return retstr;
}

std::string str_upper(const std::string& in_str) {
    std::string retstr(in_str);
    std::transform(retstr.begin(), retstr.end(), retstr.begin(), (int(*)(int)) std::toupper);
    return retstr;
}

std::string str_strip(const std::string& in_str) {
    std::string temp;
    unsigned int start, end;

    start = 0;
    end = in_str.length();

    if (in_str[0] == '\n')
        return "";

    for (unsigned int x = 0; x < in_str.length(); x++) {
        if (in_str[x] != ' ' && in_str[x] != '\t') {
            start = x;
            break;
        }
    }
    for (unsigned int x = in_str.length(); x > 1; ) {
		x--;
        if (in_str[x] != ' ' && in_str[x] != '\t' && in_str[x] != '\n') {
            end = x;
            break;
        }
    }

    return in_str.substr(start, end-start+1);
}

int hex_str_to_uint8(const std::string& in_str, uint8_t *in_buf, int in_buflen) {
	int decode_pos = 0;
	int str_pos = 0;

	while ((unsigned int) str_pos < in_str.length() && decode_pos < in_buflen) {
		short int tmp;

		if (in_str[str_pos] == ' ') {
			str_pos++;
			continue;
		}

		if (sscanf(in_str.substr(str_pos, 2).c_str(), "%2hx", &tmp) != 1) {
			return -1;
		}

		in_buf[decode_pos++] = tmp;
		str_pos += 2;
	}

	return decode_pos;
}

std::string uint8_to_hex_str(uint8_t *in_buf, int in_buflen) {
    std::string rs;

    rs.reserve(in_buflen * 2);

    for (int i = 0; i < in_buflen; i++) {
        char c = in_buf[i];

        auto n = (c >> 4) & 0x0F;
        if (n <= 9)
            rs += '0' + n;
        else
            rs += 'A' + n - 10;

        auto n2 = c & 0x0F;
        if (n2 <= 9)
            rs += '0' + n2;
        else
            rs += 'A' + n2 - 10;
    }

    return rs;

}

int x_to_i(char x) {
    if (isxdigit(x)) {
        if (x <= '9')
            return x - '0';
        return toupper(x) - 'A' + 10;
    }

    return -1;
}

int hex_to_uchar(unsigned char *in_hex, unsigned char *in_chr) {
    memset(in_chr, 0, sizeof(unsigned char) * WEPKEY_MAX);
    int chrpos = 0;

    for (unsigned int strpos = 0; strpos < WEPKEYSTR_MAX && chrpos < WEPKEY_MAX; strpos++) {
        if (in_hex[strpos] == 0)
            break;

        if (in_hex[strpos] == ':')
            strpos++;

        // Assume we're going to eat the pair here
        if (isxdigit(in_hex[strpos])) {
            if (strpos > (WEPKEYSTR_MAX - 2))
                return 0;

            int d1, d2;
            if ((d1 = x_to_i(in_hex[strpos++])) == -1)
                return 0;
            if ((d2 = x_to_i(in_hex[strpos])) == -1)
                return 0;

            in_chr[chrpos++] = (d1 * 16) + d2;
        }

    }

    return(chrpos);
}

// Complex string tokenizer which understands nested delimiters, such as 
// "foo","bar","baz,foo",something
// and network protocols like
// foo bar \001baz foo\001
std::vector<smart_word_token> base_str_tokenize(const std::string& in_str, 
        const std::string& in_split, const std::string& in_quote) {
	size_t begin = 0;
	size_t end = 0;
    std::vector<smart_word_token> ret;
    smart_word_token stok;
	int special = 0;
    std::string val;
	
	if (in_str.length() == 0)
		return ret;

	for (unsigned int x = 0; x < in_str.length(); x++) {
		if (in_str.find(in_quote, x) == x) {
			if (special == 0) {
				// reset beginning on string if we're in a special block
				begin = x;
				special = 1;
			} else {
				special = 0;
			}

			continue;
		}

		if (special == 0 && in_str.find(in_split, x) == x) {
			stok.begin = begin;
			stok.end = end;
			stok.word = val;

			ret.push_back(stok);

			val = "";
			x += in_split.length() - 1;

			begin = x;

			continue;
		}

		val += in_str[x];
		end = x;
	}

	stok.begin = begin;
	stok.end = end;
	stok.word = val;
	ret.push_back(stok);

	return ret;
}

// No-frills tokenize with no intelligence about nested delimiters
std::vector<std::string> str_tokenize(const std::string& in_str, const std::string& in_split, 
        int return_partial) {
    size_t begin = 0;
    size_t end = in_str.find(in_split);
    std::vector<std::string> ret;

    if (in_str.length() == 0)
        return ret;
    
    while (end != std::string::npos) {
        std::string sub = in_str.substr(begin, end-begin);
        begin = end+1;
        end = in_str.find(in_split, begin);
        ret.push_back(sub);
    }

    if (return_partial && begin != in_str.size())
        ret.push_back(in_str.substr(begin, in_str.size() - begin));

    return ret;
}

std::string str_join(const std::vector<std::string>& in_content, const std::string& in_delim, bool in_first) {
    std::ostringstream ostr;

    bool d = false;

    for (auto x = in_content.begin(); x != in_content.end(); ++x) {
        if (d || in_first)
            ostr << in_delim;

        if (!d)
            d = true;

        ostr << (*x);
    }

    return ostr.str();
}

// Collapse into basic tokenizer rewrite
std::vector<std::string> quote_str_tokenize(const std::string& in_str, const std::string& in_split) {
    std::vector<std::string> ret;
    std::vector<smart_word_token> bret;

	bret = base_str_tokenize(in_str, in_split, "\"");

	for (unsigned int b = 0; b < bret.size(); b++) {
		ret.push_back(bret[b].word);
	}

	return ret;
}

int TokenNullJoin(std::string *ret_str, const char **in_list) {
	int ret = 0;
    std::stringstream ss;

    while (in_list[ret] != NULL) {
        ss << in_list[ret];

        if (in_list[ret + 1] != NULL)
            ss << ",";
        (*ret_str) += ",";

        ret++;
    }

    *ret_str = ss.str();

    return ret;
}

// Quick fetch of strings from a map of options
std::string fetch_opt(const std::string& in_key, std::vector<opt_pair> *in_vec,
        const std::string& dvalue) {
    if (in_vec == nullptr)
        return dvalue;

    for (auto x : *in_vec) {
        if (x.opt == in_key)
            return x.val;
    }

    return dvalue;
}

std::string fetch_opt(const std::string& in_key, const std::map<std::string, std::string>& in_map, 
        std::string dvalue) {

    auto i = in_map.find(in_key);
    
    if (i == in_map.end())
        return dvalue;

    return i->second;
}

int fetch_opt_bool(const std::string& in_key, std::vector<opt_pair> *in_vec, int dvalue) {
    std::string s = fetch_opt(in_key, in_vec);

	return string_to_bool(s, dvalue);
}


int fetch_opt_bool(const std::string& in_key, const std::map<std::string, std::string>& in_map, int dvalue) {
    auto i = in_map.find(in_key);

    if (i == in_map.end())
        return dvalue;

    return string_to_bool(i->second, dvalue);
}

std::vector<std::string> fetch_opt_vec(const std::string& in_key, std::vector<opt_pair> *in_vec) {
    std::string lkey = str_lower(in_key);
    std::vector<std::string> ret;

    if (in_vec == NULL)
        return ret;

    for (auto x : *in_vec) {
        if (x.opt == lkey)
            ret.push_back(x.val);
    }

    return ret;
}

int string_to_opts(const std::string& in_line, const std::string& in_sep, std::vector<opt_pair> *in_vec) {
    std::vector<std::string> optv;
    opt_pair optp;

    int in_tag = 1, in_quote = 0;

    optp.quoted = 0;

    for (unsigned int x = 0; x < in_line.length(); x++) {
        if (in_tag && in_line[x] != '=') {
            optp.opt += in_line[x];
            continue;
        }

        if (in_tag && in_line[x] == '=') {
            in_tag = 0;
            continue;
        }

        if (in_line[x] == '"') {
            if (in_quote == 0) {
                in_quote = 1;
                optp.quoted = 1;
            } else {
                in_quote = 0;
            }

            continue;
        }

        if (in_quote == 0 && in_line[x] == in_sep[0]) {
            in_vec->push_back(optp);
            optp.quoted = 0;
            optp.opt = "";
            optp.val = "";
            in_tag = 1;
            continue;
        }

        optp.val += in_line[x];
    }

    if (optp.opt.length() > 0 && optp.val.length() > 0)
        in_vec->push_back(optp);

    return 1;
}

void append_to_opts(const std::string& opt, const std::string& val, std::vector<opt_pair> *in_vec) {
	opt_pair optp;

	optp.opt = str_lower(opt);
	optp.val = val;

	in_vec->push_back(optp);
}

void replace_all_opts(const std::string& opt, const std::string& val, std::vector<opt_pair> *in_vec) {
	opt_pair optp;

	optp.opt = str_lower(opt);
	optp.val = val;

	for (unsigned int x = 0; x < in_vec->size(); x++) {
		if ((*in_vec)[x].val == optp.val) {
			in_vec->erase(in_vec->begin() + x);
			x--;
			continue;
		}
	}

	in_vec->push_back(optp);
}

std::vector<std::string> line_wrap(const std::string& in_txt, unsigned int in_hdr_len,
        unsigned int in_maxlen) {
    std::vector<std::string> ret;

	size_t pos, prev_pos, start, hdroffset;
	start = hdroffset = 0;

	for (pos = prev_pos = in_txt.find(' ', in_hdr_len); pos != std::string::npos; 
		 pos = in_txt.find(' ', pos + 1)) {
		if ((hdroffset + pos) - start >= in_maxlen) {
			if (pos - prev_pos > (in_maxlen / 4)) {
				pos = prev_pos = start + (in_maxlen - hdroffset);
			}

            std::string str(hdroffset, ' ');
			hdroffset = in_hdr_len;
			str += in_txt.substr(start, prev_pos - start);
			ret.push_back(str);
			
			start = prev_pos;
		}

		prev_pos = pos + 1;
	}

	while (in_txt.length() - start > (in_maxlen - hdroffset)) {
        std::string str(hdroffset, ' ');
		hdroffset = in_hdr_len;

		str += in_txt.substr(start, (prev_pos - start));
		ret.push_back(str);

		start = prev_pos;

		prev_pos+= (in_maxlen - hdroffset);
	}

    std::string str(hdroffset, ' ');
	str += in_txt.substr(start, in_txt.length() - start);
	ret.push_back(str);

	return ret;
}

std::string in_line_wrap(const std::string& in_txt, unsigned int in_hdr_len, 
				  unsigned int in_maxlen) {
    std::vector<std::string> raw = line_wrap(in_txt, in_hdr_len, in_maxlen);
    std::stringstream ss;

	for (unsigned int x = 0; x < raw.size(); x++) {
        ss << raw[x] << "\n";
	}

	return ss.str();
}

void float_to_pair(float in_float, int16_t *primary, int64_t *mantissa) {
    *primary = (int) in_float;
    *mantissa = (long) (1000000 * ((in_float) - *primary));
}

float pair_to_float(int16_t primary, int64_t mantissa) {
    return (double) primary + ((double) mantissa / 1000000);
}

std::vector<int> str_to_int_vector(const std::string& in_text) {
    std::vector<std::string> optlist = str_tokenize(in_text, ",");
    std::vector<int> ret;
    int ch;

    for (unsigned int x = 0; x < optlist.size(); x++) {
        if (sscanf(optlist[x].c_str(), "%d", &ch) != 1) {
            ret.clear();
            break;
        }

        ret.push_back(ch);
    }

    return ret;
}

#ifdef SYS_LINUX
int fetch_sys_loadavg(uint8_t *in_avgmaj, uint8_t *in_avgmin) {
    FILE *lf;
    short unsigned int tmaj, tmin;

    if ((lf = fopen("/proc/loadavg", "r")) == NULL) {
        return -1;
    }

    if (fscanf(lf, "%hu.%hu", &tmaj, &tmin) != 2) {
        fclose(lf);
        return -1;
    }

    (*in_avgmaj) = tmaj;
    (*in_avgmin) = tmin;

    fclose(lf);

    return 1;
}
#endif

std::list<_kis_lex_rec> LexString(std::string in_line, std::string& errstr) {
    std::list<_kis_lex_rec> ret;
	int curstate = _kis_lex_none;
	_kis_lex_rec cpr;
    std::string tempstr;
	char lastc = 0;
	char c = 0;

	cpr.type = _kis_lex_none;
	cpr.data = "";
	ret.push_back(cpr);

	for (size_t pos = 0; pos < in_line.length(); pos++) {
		lastc = c;
		c = in_line[pos];

		cpr.data = "";

		if (curstate == _kis_lex_none) {
			// Open paren
			if (c == '(') {
				cpr.type = _kis_lex_popen;
				ret.push_back(cpr);
				continue;
			}

			// close paren
			if (c == ')') {
				cpr.type = _kis_lex_pclose;
				ret.push_back(cpr);
				continue;
			}

			// Negation
			if (c == '!') {
				cpr.type = _kis_lex_negate;
				ret.push_back(cpr);
				continue;
			}

			// delimiter
			if (c == ',') {
				cpr.type = _kis_lex_delim;
				ret.push_back(cpr);
				continue;
			}

			// start a quoted string
			if (c == '"') {
				curstate = _kis_lex_quotestring;
				tempstr = "";
				continue;
			}
		
			curstate = _kis_lex_string;
			tempstr = c;
			continue;
		}

		if (curstate == _kis_lex_quotestring) {
			// We don't close on an escaped \"
			if (c == '"' && lastc != '\\') {
				// Drop out of the string and make the lex stack element
				curstate = _kis_lex_none;
				cpr.type = _kis_lex_quotestring;
				cpr.data = tempstr;
				ret.push_back(cpr);

				tempstr = "";

				continue;
			}

			// Add it to the quoted temp strnig
			tempstr += c;
		}

		if (curstate == _kis_lex_string) {
			// If we're a special character break out and add the lex stack element
			// otherwise increase our unquoted string
			if (c == '(' || c == ')' || c == '!' || c == '"' || c == ',') {
				cpr.type = _kis_lex_string;
				cpr.data = tempstr;
				ret.push_back(cpr);
				tempstr = "";
				curstate = _kis_lex_none;
				pos--;
				continue;
			}

			tempstr += c;
			continue;
		}
	}

	if (curstate == _kis_lex_quotestring) {
		errstr = "Unfinished quoted string in line '" + in_line + "'";
		ret.clear();
	}

	return ret;
}

// Taken from the BBN USRP 802.11 encoding code
unsigned int update_crc32_80211(unsigned int crc, const unsigned char *data,
								int len, unsigned int poly) {
	int i, j;
	unsigned short ch;

	for ( i = 0; i < len; ++i) {
		ch = data[i];
		for (j = 0; j < 8; ++j) {
			if ((crc ^ ch) & 0x0001) {
				crc = (crc >> 1) ^ poly;
			} else {
				crc = (crc >> 1);
			}
			ch >>= 1;
		}
	}
	return crc;
}

void crc32_init_table_80211(unsigned int *crc32_table) {
	int i;
	unsigned char c;

	for (i = 0; i < 256; ++i) {
		c = (unsigned char) i;
		crc32_table[i] = update_crc32_80211(0, &c, 1, IEEE_802_3_CRC32_POLY);
	}
}

unsigned int crc32_le_80211(unsigned int *crc32_table, const unsigned char *buf, 
							int len) {
	int i;
	unsigned int crc = 0xFFFFFFFF;

	for (i = 0; i < len; ++i) {
		crc = (crc >> 8) ^ crc32_table[(crc ^ buf[i]) & 0xFF];
	}

	crc ^= 0xFFFFFFFF;

	return crc;
}

int subtract_timeval(struct timeval *in_tv1, struct timeval *in_tv2,
					 struct timeval *out_tv) {
    if (in_tv1->tv_usec < in_tv2->tv_usec) {
        int nsec = (in_tv2->tv_usec - in_tv2->tv_usec) / 1000000 + 1;
        in_tv2->tv_usec -= 1000000 * nsec;
        in_tv2->tv_sec += nsec;
    }

    if (in_tv1->tv_usec - in_tv2->tv_usec > 1000000) {
        int nsec = (in_tv1->tv_usec - in_tv2->tv_usec) / 1000000;
        in_tv2->tv_usec += 1000000 * nsec;
        in_tv2->tv_sec -= nsec;
    }

    out_tv->tv_sec = in_tv1->tv_sec - in_tv2->tv_sec;
    out_tv->tv_usec = in_tv1->tv_usec - in_tv2->tv_usec;

    return in_tv1->tv_sec < in_tv2->tv_sec;
}

/* Airware PPI gps conversion code from Johnny Csh */

/*
 * input: a unsigned 32-bit (native endian) value between 0 and 3600000000 (inclusive)
 * output: a signed floating point value between -180.0000000 and + 180.0000000, inclusive)
 */
double fixed3_7_to_double(u_int32_t in) {
    int32_t remapped_in = in - (180 * 10000000);
    double ret = (double) ((double) remapped_in / 10000000);
    return ret;
}
/*
 * input: a native 32 bit unsigned value between 0 and 999999999
 * output: a positive floating point value between 000.0000000 and 999.9999999
 */
double fixed3_6_to_double(u_int32_t in) {
    double ret = (double) in  / 1000000.0;
    return ret;
}
/*
 * input: a native 32 bit unsigned value between 0 and 999.999999
 * output: a signed floating point value between -180000.0000 and +180000.0000
 */
double fixed6_4_to_double(u_int32_t in) {
    int32_t remapped_in = in - (180000 * 10000);
    double ret = (double) ((double) remapped_in / 10000);
    return ret;
}
/*
 * input: a native 32 bit nano-second counter
 * output: a signed floating point second counter
 */
double ns_to_double(u_int32_t in) {
    double ret;
    ret = (double) in / 1000000000;
    return ret;
}

/*
 * input: a signed floating point value between -180.0000000 and + 180.0000000, inclusive)
 * output: a unsigned 32-bit (native endian) value between 0 and 3600000000 (inclusive)
 */
u_int32_t double_to_fixed3_7(double in) 
{
    if (in < -180 || in >= 180) 
        return 0;
    //This may be positive or negative.
    int32_t scaled_in =  (int32_t) ((in) * (double) 10000000); 
    //If the input conditions are met, this will now always be positive.
    u_int32_t  ret = (u_int32_t) (scaled_in +  ((int32_t) 180 * 10000000)); 
    return ret;
}
/*
 * input: a signed floating point value between -180000.0000 and + 180000.0000, inclusive)
 * output: a unsigned 32-bit (native endian) value between 0 and 3600000000 (inclusive)
 */
u_int32_t double_to_fixed6_4(double in) 
{
    if (in < -180000.0001 || in >= 180000.0001) 
        return 0;
    //This may be positive or negative.
    int32_t scaled_in =  (int32_t) ((in) * (double) 10000); 
    //If the input conditions are met, this will now always be positive.
    u_int32_t  ret = (u_int32_t) (scaled_in +  ((int32_t) 180000 * 10000)); 
    return ret;
}
/*
 * input: a positive floating point value between 000.0000000 and 999.9999999
 * output: a native 32 bit unsigned value between 0 and 999999999
 */
u_int32_t double_to_fixed3_6(double in) {
    u_int32_t ret = (u_int32_t) (in  * (double) 1000000.0);
    return ret;
}

/*
 * input: a signed floating point second counter
 * output: a native 32 bit nano-second counter
 */
u_int32_t double_to_ns(double in) {
    u_int32_t ret;
    ret =  in * (double) 1000000000;
    return ret;
}

int string_to_bool(const std::string& s, int dvalue) {
    std::string ls = str_lower(s);

	if (ls == "true" || ls == "t") {
		return 1;
	} else if (ls == "false" || ls == "f") {
		return 0;
	}

	return dvalue;
}

int string_to_int(const std::string& s) {
    int r;

    if (sscanf(s.c_str(), "%d", &r) != 1)
        throw(std::runtime_error("not an integer"));

    return r;
}

unsigned int string_to_uint(const std::string& s) {
    unsigned int r;

    if (sscanf(s.c_str(), "%u", &r) != 1)
        throw(std::runtime_error("not an unsigned integer"));

    return r;
}

std::string string_append(const std::string& s, const std::string& a, const std::string& d) {
    std::stringstream ss;

	if (s.length() == 0)
		return a;

	if (s.length() > d.length() && s.substr(s.length() - d.length(), d.length()) == d) {
        ss << s << a;
        return ss.str();
    }

    ss << s << d << a;
    return ss.str();
}

std::string multi_replace_all(const std::string& in, const std::string& match, const std::string& repl) {
    std::string work = in;

    for (size_t pos = 0; (pos = in.find(match, pos)) != std::string::npos;
            pos += repl.length()) {
        work.replace(pos, match.length(), repl);
    }

    return work;
}

static const char *strerror_result(int, const char *s) { 
    return s;
}

static const char *strerror_result(const char *s, const char *) {
    return s;
}

std::string kis_strerror_r(int errnum) {
    char d_errstr[1024];

    using namespace std;
    auto r = std::string(strerror_result(strerror_r(errnum, d_errstr, sizeof(d_errstr)), d_errstr));

    if (r.length() == 0)
        return fmt::format("Unknown error: {}", errnum);

    return r;
}

double ts_to_double(struct timeval ts) {
    return (double) ts.tv_sec + (double) ((double) ts.tv_usec / (double) 1000000);
}

double ts_now_to_double() {
    struct timeval ts;
    gettimeofday(&ts, NULL);
    return (double) ts.tv_sec + (double) ((double) ts.tv_usec / (double) 1000000);
}

std::string hex_to_bytes(const std::string& in) {
    if (in.length() == 0)
        return "";

    std::string ret;
    ret.reserve((in.length() / 2) + 1);
    size_t p = 0;

    // Prefix with a 0 if we're an odd length
    if ((in.length() % 2) != 0) {
        if (in[0] >= '0' && in[0] <= '9')
            ret += in[0] - '0';
        else if (in[0] >= 'a' && in[0] <= 'f')
            ret += in[0] - 'a' + 0xA;
        else if (in[0] >= 'A' && in[0] <= 'F')
            ret += in[0] - 'A' + 0xA;
        else
            return "";

        p = 1;
    }

    // Start either at the base element or one above if we're
    // forcing a prefix of 0
    for (size_t x = p; x + 1 < in.length(); x += 2) {
        auto b1 = '0';
        auto b2 = '0';

        if (in[x] >= '0' && in[x] <= '9')
            b1 = in[x] - '0';
        else if (in[x] >= 'a' && in[x] <= 'f')
            b1 = in[x] - 'a' + 0xA;
        else if (in[x] >= 'A' && in[x] <= 'F')
            b1 = in[x] - 'A' + 0xA;
        else
            return "";

        if (in[x + 1] >= '0' && in[x + 1] <= '9')
            b2 = in[x + 1] - '0';
        else if (in[x + 1] >= 'a' && in[x + 1] <= 'f')
            b2 = in[x + 1] - 'a' + 0xA;
        else if (in[x + 1] >= 'A' && in[x + 1] <= 'F')
            b2 = in[x + 1] - 'A' + 0xA;
        else
            return "";

        ret += (((b1 & 0xF) << 4) + (b2 & 0xF));
    }

    return ret;
}


#if defined(SYS_LINUX)
void thread_set_process_name(const std::string& name) { 
    pthread_setname_np(pthread_self(), name.c_str());
}
#else
void thread_set_process_name(const std::string& name) { }
#endif

bool iequals(const std::string& a, const std::string& b) {
    return std::equal(a.begin(), a.end(),
		b.begin(), b.end(),
		[](char a, char b) { return ::tolower(a) == ::tolower(b); });
}

uint64_t human_to_freq_khz(const std::string &s) {
	auto ds = s;
	int scale = 1;

	try {
		auto unit = s.substr(s.length() - 3, 3);

		if (iequals(unit, "khz")) {
			ds = s.substr(0, s.length() - 3);
			scale = 1000;
		} else if (iequals(unit, "mhz")) {
			ds = s.substr(0, s.length() - 3);
			scale = 1000*1000;
		} else if (iequals(unit, "ghz")) {
			ds = s.substr(0, s.length() - 3);
			scale = 1000*1000*1000;
		} else if (iequals(unit.substr(1, 2), "hz")) {
			ds = s.substr(0, s.length() - 2);
			scale = 1;
		}
	} catch (...) { }

	auto v = string_to_n<uint64_t>(ds);

	return v * scale;
}

bool regex_string_compare(const std::string& restr, const std::string& content) {
#if defined(HAVE_LIBPCRE1) || defined(HAVE_LIBPCRE2)

    int rc;
#if defined(HAVE_LIBPCRE1)
    const char *compile_error, *study_error;
    int erroroffset;
    std::ostringstream errordesc;

    pcre *re = NULL;
    pcre_extra *study = NULL;

    re = pcre_compile(restr.c_str(), 0, &compile_error, &erroroffset, NULL);

    if (re == NULL) {
        const auto e = fmt::format("could not parse PCRE regex: {} at {}",
                compile_error, erroroffset);
        throw std::runtime_error(e);
    }

    study = pcre_study(re, 0, &study_error);

    if (study_error != NULL) {
        const auto e =
            fmt::format("could not parse PCRE regex, optimization failure: {}", study_error);

        pcre_free(re);

        throw std::runtime_error(e);
    }

    int ovector[128];
    rc = pcre_exec(re, study, contente.c_str(), content.length(), 0, 0, ovector, 128);

    pcre_free(re);
    pcre_free(study);

#elif defined(HAVE_LIBPCRE2)
    PCRE2_SIZE erroroffset;
    int errornumber;

    pcre2_code *re = NULL;
    pcre2_match_data *match_data = NULL;

    re = pcre2_compile((PCRE2_SPTR8) restr.c_str(),
       PCRE2_ZERO_TERMINATED, 0, &errornumber, &erroroffset, NULL);

    if (re == nullptr) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
        pcre2_code_free(re);
        const auto e = fmt::format("could not parse PCRE regex: {} at {}",
                (int) erroroffset, (char *) buffer);
        throw std::runtime_error(e);
    }

	match_data = pcre2_match_data_create_from_pattern(re, NULL);
    rc = pcre2_match(re, (PCRE2_SPTR8) content.c_str(), content.length(),
            0, 0, match_data, NULL);

    pcre2_match_data_free(match_data);
    pcre2_code_free(re);
#endif

    if (rc > 0) {
        return true;
    }

#endif

    return false;

}
