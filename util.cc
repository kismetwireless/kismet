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

#include "packet.h"

// Munge input to shell-safe
void MungeToShell(char *in_data, unsigned int max) {
    unsigned int i, j;

    for (i = 0, j = 0; i < max && j < max; i++) {
        if (in_data[i] == '\0')
            break;

        if (isalnum(in_data[i]) || isspace(in_data[i]) ||
            in_data[i] == '=' || in_data[i] == '-' || in_data[i] == '_' ||
            in_data[i] == '.' || in_data[i] == ',') {

            if (j == i) {
                j++;
            } else {
                in_data[j++] = in_data[i];
            }
        }
    }

    in_data[j] = '\0';

}

// Quick wrapper to save us time in other code
string MungeToShell(string in_data) {
    char *data = new char[in_data.length() + 1];
    string ret;

    snprintf(data, in_data.length() + 1, "%s", in_data.c_str());

    MungeToShell(data, in_data.length() + 1);

    ret = data;
    delete[] data;
    return ret;
}

// Munge text down to printable characters only.  Simpler, cleaner munger than
// before (and more blatant when munging)
string MungeToPrintable(const char *in_data, unsigned int max, int nullterm) {
	string ret;
	unsigned int i;

	for (i = 0; i < max; i++) {
		if ((unsigned char) in_data[i] == 0 && nullterm == 1)
			return ret;

		if ((unsigned char) in_data[i] >= 32 && (unsigned char) in_data[i] <= 126) {
			ret += in_data[i];
		} else {
			ret += '\\';
			ret += ((in_data[i] >> 6) & 0x03) + '0';
			ret += ((in_data[i] >> 3) & 0x07) + '0';
			ret += ((in_data[i] >> 0) & 0x07) + '0';
		}
	}

	return ret;
}

string MungeToPrintable(string in_str) {
	return MungeToPrintable(in_str.c_str(), in_str.length(), 1);
}

string StrLower(string in_str) {
    string thestr = in_str;
    for (unsigned int i = 0; i < thestr.length(); i++)
        thestr[i] = tolower(thestr[i]);

    return thestr;
}

string StrUpper(string in_str) {
    string thestr = in_str;

    for (unsigned int i = 0; i < thestr.length(); i++)
        thestr[i] = toupper(thestr[i]);

    return thestr;
}

string StrStrip(string in_str) {
    string temp;
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

string StrPrintable(string in_str) {
    string thestr;

    for (unsigned int i = 0; i < in_str.length(); i++) {
		if (isprint(in_str[i])) {
			thestr += in_str[i];
		}
	}

    return thestr;
}

int IsBlank(const char *s) {
    int len, i;

    if (NULL == s) { 
		return 1; 
	}

    if (0 == (len = strlen(s))) { 
		return 1; 
	}

    for (i = 0; i < len; ++i) {
        if (' ' != s[i]) { 
			return 0; 
		}
    }

    return 1;
}

string AlignString(string in_txt, char in_spacer, int in_align, int in_width) {
	if (in_align == 1) {
		// Center -- half, text, chop to fit
		int sp = (in_width / 2) - (in_txt.length() / 2);
		string ts = "";

		if (sp > 0) {
			ts = string(sp, in_spacer);
		}

		ts += in_txt.substr(0, in_width);

		return ts;
	} else if (in_align == 2) {
		// Right -- width - len, chop to fit
		int sp = (in_width - in_txt.length());
		string ts = "";

		if (sp > 0) {
			ts = string(sp, in_spacer);
		}

		ts += in_txt.substr(0, in_width);

		return ts;
	}

	// Left align -- make sure it's not too long
	return in_txt.substr(0, in_width);
}

int HexStrToUint8(string in_str, uint8_t *in_buf, int in_buflen) {
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

int XtoI(char x) {
    if (isxdigit(x)) {
        if (x <= '9')
            return x - '0';
        return toupper(x) - 'A' + 10;
    }

    return -1;
}

int Hex2UChar(unsigned char *in_hex, unsigned char *in_chr) {
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
            if ((d1 = XtoI(in_hex[strpos++])) == -1)
                return 0;
            if ((d2 = XtoI(in_hex[strpos])) == -1)
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
vector<smart_word_token> BaseStrTokenize(string in_str, 
										 string in_split, string in_quote) {
	size_t begin = 0;
	size_t end = 0;
	vector<smart_word_token> ret;
    smart_word_token stok;
	int special = 0;
	string val;
	
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
vector<string> StrTokenize(string in_str, string in_split, int return_partial) {
    size_t begin = 0;
    size_t end = in_str.find(in_split);
    vector<string> ret;

    if (in_str.length() == 0)
        return ret;
    
    while (end != string::npos) {
        string sub = in_str.substr(begin, end-begin);
        begin = end+1;
        end = in_str.find(in_split, begin);
        ret.push_back(sub);
    }

    if (return_partial && begin != in_str.size())
        ret.push_back(in_str.substr(begin, in_str.size() - begin));

    return ret;
}

// Collapse into basic tokenizer
vector<smart_word_token> NetStrTokenize(string in_str, string in_split, 
										int return_partial) {
	return BaseStrTokenize(in_str, in_split, "\001");
}

// Collapse into basic tokenizer rewrite
vector<string> QuoteStrTokenize(string in_str, string in_split) {
	vector<string> ret;
	vector<smart_word_token> bret;

	bret = BaseStrTokenize(in_str, in_split, "\"");

	for (unsigned int b = 0; b < bret.size(); b++) {
		ret.push_back(bret[b].word);
	}

	return ret;
}

int TokenNullJoin(string *ret_str, const char **in_list) {
	int ret = 0;

	while (in_list[ret] != NULL) {
		(*ret_str) += in_list[ret];

		if (in_list[ret + 1] != NULL)
			(*ret_str) += ",";

		ret++;
	}

	return ret;
}

// Find an option - just like config files
string FetchOpt(string in_key, vector<opt_pair> *in_vec) {
	string lkey = StrLower(in_key);

	if (in_vec == NULL)
		return "";

	for (unsigned int x = 0; x < in_vec->size(); x++) {
		if ((*in_vec)[x].opt == lkey)
			return (*in_vec)[x].val;
	}

	return "";
}

int FetchOptBoolean(string in_key, vector<opt_pair> *in_vec, int dvalue) {
	string s = FetchOpt(in_key, in_vec);

	return StringToBool(s, dvalue);
}

vector<string> FetchOptVec(string in_key, vector<opt_pair> *in_vec) {
	string lkey = StrLower(in_key);
	vector<string> ret;

	if (in_vec == NULL)
		return ret;

	for (unsigned int x = 0; x < in_vec->size(); x++) {
		if ((*in_vec)[x].opt == lkey)
			ret.push_back((*in_vec)[x].val);
	}

	return ret;
}

int StringToOpts(string in_line, string in_sep, vector<opt_pair> *in_vec) {
	vector<string> optv;
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

	in_vec->push_back(optp);

	return 1;
}

void AddOptToOpts(string opt, string val, vector<opt_pair> *in_vec) {
	opt_pair optp;

	optp.opt = StrLower(opt);
	optp.val = val;

	in_vec->push_back(optp);
}

void ReplaceAllOpts(string opt, string val, vector<opt_pair> *in_vec) {
	opt_pair optp;

	optp.opt = StrLower(opt);
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

vector<string> LineWrap(string in_txt, unsigned int in_hdr_len, 
						unsigned int in_maxlen) {
	vector<string> ret;

	size_t pos, prev_pos, start, hdroffset;
	start = hdroffset = 0;

	for (pos = prev_pos = in_txt.find(' ', in_hdr_len); pos != string::npos; 
		 pos = in_txt.find(' ', pos + 1)) {
		if ((hdroffset + pos) - start >= in_maxlen) {
			if (pos - prev_pos > (in_maxlen / 4)) {
				pos = prev_pos = start + (in_maxlen - hdroffset);
			}

			string str(hdroffset, ' ');
			hdroffset = in_hdr_len;
			str += in_txt.substr(start, prev_pos - start);
			ret.push_back(str);
			
			start = prev_pos;
		}

		prev_pos = pos + 1;
	}

	while (in_txt.length() - start > (in_maxlen - hdroffset)) {
		string str(hdroffset, ' ');
		hdroffset = in_hdr_len;

		str += in_txt.substr(start, (prev_pos - start));
		ret.push_back(str);

		start = prev_pos;

		prev_pos+= (in_maxlen - hdroffset);
	}

	string str(hdroffset, ' ');
	str += in_txt.substr(start, in_txt.length() - start);
	ret.push_back(str);

	return ret;
}

string InLineWrap(string in_txt, unsigned int in_hdr_len, 
				  unsigned int in_maxlen) {
	vector<string> raw = LineWrap(in_txt, in_hdr_len, in_maxlen);
	string ret;

	for (unsigned int x = 0; x < raw.size(); x++) {
		ret += raw[x] + "\n";
	}

	return ret;
}

string SanitizeXML(string in_str) {
	// Ghetto-fied XML sanitizer.  Add more stuff later if we need to.
	string ret;
	for (unsigned int x = 0; x < in_str.length(); x++) {
		if (in_str[x] == '&')
			ret += "&amp;";
		else if (in_str[x] == '<')
			ret += "&lt;";
		else if (in_str[x] == '>')
			ret += "&gt;";
		else
			ret += in_str[x];
	}

	return ret;
}

string SanitizeCSV(string in_str) {
	string ret;
	for (unsigned int x = 0; x < in_str.length(); x++) {
		if (in_str[x] == ';')
			ret += " ";
		else
			ret += in_str[x];
	}

	return ret;
}

void Float2Pair(float in_float, int16_t *primary, int64_t *mantissa) {
    *primary = (int) in_float;
    *mantissa = (long) (1000000 * ((in_float) - *primary));
}

float Pair2Float(int16_t primary, int64_t mantissa) {
    return (double) primary + ((double) mantissa / 1000000);
}

vector<int> Str2IntVec(string in_text) {
    vector<string> optlist = StrTokenize(in_text, ",");
    vector<int> ret;
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

int RunSysCmd(char *in_cmd) {
    return system(in_cmd);
}

pid_t ExecSysCmd(char *in_cmd) {
    // Slice it into an array to pass to exec
    vector<string> cmdvec = StrTokenize(in_cmd, " ");
    char **cmdarg = new char *[cmdvec.size() + 1];
    pid_t retpid;
    unsigned int x;

    // Convert it to a pointer array
    for (x = 0; x < cmdvec.size(); x++) 
        cmdarg[x] = (char *) cmdvec[x].c_str();
    cmdarg[x] = NULL;

    if ((retpid = fork()) == 0) {
        // Nuke the file descriptors so that they don't blat on
        // input or output
        for (unsigned int x = 0; x < 256; x++)
            close(x);

        execve(cmdarg[0], cmdarg, NULL);
        exit(0);
    }

    delete[] cmdarg;
    return retpid;
}

#ifdef SYS_LINUX
int FetchSysLoadAvg(uint8_t *in_avgmaj, uint8_t *in_avgmin) {
    FILE *lf;
    short unsigned int tmaj, tmin;

    if ((lf = fopen("/proc/loadavg", "r")) == NULL) {
        fclose(lf);
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

// Convert the beacon interval to # of packets per second
unsigned int Ieee80211Interval2NSecs(int in_interval) {
	double interval_per_sec;

	interval_per_sec = (double) in_interval * 1024 / 1000000;
	
	return (unsigned int) ceil(1.0f / interval_per_sec);
}

uint32_t Adler32Checksum(const char *buf1, int len) {
	int i;
	uint32_t s1, s2;
	char *buf = (char *)buf1;
	int CHAR_OFFSET = 0;

	s1 = s2 = 0;
	for (i = 0; i < (len-4); i+=4) {
		s2 += 4*(s1 + buf[i]) + 3*buf[i+1] + 2*buf[i+2] + buf[i+3] + 
			10*CHAR_OFFSET;
		s1 += (buf[i+0] + buf[i+1] + buf[i+2] + buf[i+3] + 4*CHAR_OFFSET); 
	}

	for (; i < len; i++) {
		s1 += (buf[i]+CHAR_OFFSET); s2 += s1;
	}

	return (s1 & 0xffff) + (s2 << 16);
}

int IEEE80211Freq[][2] = {
	{1, 2412},
	{2, 2417},
	{3, 2422},
	{4, 2427},
	{5, 2432},
	{6, 2437},
	{7, 2442},
	{8, 2447},
	{9, 2452},
	{10, 2457},
	{11, 2462},
	{12, 2467},
	{13, 2472},
	{14, 2484},
	// We could do the math here, but what about 4ghz nonsense?
	// We'll do table lookups for now.
	{36, 5180},
	{37, 5185},
	{38, 5190},
	{39, 5195},
	{40, 5200},
	{41, 5205},
	{42, 5210},
	{43, 5215},
	{44, 5220},
	{45, 5225},
	{46, 5230},
	{47, 5235},
	{48, 5240},
	{52, 5260},
	{53, 5265},
	{54, 5270},
	{55, 5275},
	{56, 5280},
	{57, 5285},
	{58, 5290},
	{59, 5295},
	{60, 5300},
	{64, 5320},
	{149, 5745},
	{150, 5750},
	{152, 5760},
	{153, 5765},
	{157, 5785},
	{160, 5800},
	{161, 5805},
	{165, 5825},
	{0, 0}
};

int ChanToFreq(int in_chan) {
    int x = 0;
    // 80211b frequencies to channels

    while (IEEE80211Freq[x][0] != 0) {
        if (IEEE80211Freq[x][0] == in_chan) {
            return IEEE80211Freq[x][1];
        }
        x++;
    }

    return in_chan;
}

int FreqToChan(int in_freq) {
    int x = 0;
    // 80211b frequencies to channels

    while (IEEE80211Freq[x][1] != 0) {
        if (IEEE80211Freq[x][1] == in_freq) {
            return IEEE80211Freq[x][0];
        }
        x++;
    }

    return in_freq;
}

// Multiplatform method of setting a process title.  Lifted from proftpd main.c
// * ProFTPD - FTP server daemon
// * Copyright (c) 1997, 1998 Public Flood Software
// * Copyright (c) 1999, 2000 MacGyver aka Habeeb J. Dihu <macgyver@tos.net>
// * Copyright (c) 2001, 2002, 2003 The ProFTPD Project team
//
// Process title munging is ugly!

// Externs to glibc
#ifdef HAVE___PROGNAME
extern char *__progname, *__progname_full;
#endif /* HAVE___PROGNAME */
extern char **environ;

// This is not good at all.  i should probably rewrite this, but...
static char **Argv = NULL;
static char *LastArgv = NULL;

void init_proc_title(int argc, char *argv[], char *envp[]) {
	register int i, envpsize;
	char **p;

	/* Move the environment so setproctitle can use the space. */
	for (i = envpsize = 0; envp[i] != NULL; i++)
		envpsize += strlen(envp[i]) + 1;

	if ((p = (char **)malloc((i + 1) * sizeof(char *))) != NULL) {
		environ = p;

		// Stupid strncpy because it makes the linker not whine
		for (i = 0; envp[i] != NULL; i++)
			if ((environ[i] = (char *) malloc(strlen(envp[i]) + 1)) != NULL)
				strncpy(environ[i], envp[i], strlen(envp[i]) + 1);

		environ[i] = NULL;
	}

	Argv = argv;

	for (i = 0; i < argc; i++)
		if (!i || (LastArgv + 1 == argv[i]))
			LastArgv = argv[i] + strlen(argv[i]);

	for (i = 0; envp[i] != NULL; i++)
		if ((LastArgv + 1) == envp[i])
			LastArgv = envp[i] + strlen(envp[i]);

#ifdef HAVE___PROGNAME
	/* Set the __progname and __progname_full variables so glibc and company
	 * don't go nuts.
	 */
	__progname = strdup("kismet");
	__progname_full = strdup(argv[0]);
#endif /* HAVE___PROGNAME */
}

void set_proc_title(const char *fmt, ...) {
	va_list msg;
	static char statbuf[BUFSIZ];

#ifndef HAVE_SETPROCTITLE
#if PF_ARGV_TYPE == PF_ARGV_PSTAT
	union pstun pst;
#endif /* PF_ARGV_PSTAT */
	char *p;
	int i,maxlen = (LastArgv - Argv[0]) - 2;
#endif /* HAVE_SETPROCTITLE */

	va_start(msg,fmt);

	memset(statbuf, 0, sizeof(statbuf));

#ifdef HAVE_SETPROCTITLE
# if __FreeBSD__ >= 4 && !defined(FREEBSD4_0) && !defined(FREEBSD4_1)
	/* FreeBSD's setproctitle() automatically prepends the process name. */
	vsnprintf(statbuf, sizeof(statbuf), fmt, msg);

# else /* FREEBSD4 */
	/* Manually append the process name for non-FreeBSD platforms. */
	snprintf(statbuf, sizeof(statbuf), "%s: ", Argv[0]);
	vsnprintf(statbuf + strlen(statbuf), sizeof(statbuf) - strlen(statbuf),
			  fmt, msg);

# endif /* FREEBSD4 */
	setproctitle("%s", statbuf);

#else /* HAVE_SETPROCTITLE */
	/* Manually append the process name for non-setproctitle() platforms. */
	snprintf(statbuf, sizeof(statbuf), "%s: ", Argv[0]);
	vsnprintf(statbuf + strlen(statbuf), sizeof(statbuf) - strlen(statbuf),
			  fmt, msg);

#endif /* HAVE_SETPROCTITLE */

	va_end(msg);

#ifdef HAVE_SETPROCTITLE
	return;
#else
	i = strlen(statbuf);

#if PF_ARGV_TYPE == PF_ARGV_NEW
	/* We can just replace argv[] arguments.  Nice and easy.
	*/
	Argv[0] = statbuf;
	Argv[1] = NULL;
#endif /* PF_ARGV_NEW */

#if PF_ARGV_TYPE == PF_ARGV_WRITEABLE
	/* We can overwrite individual argv[] arguments.  Semi-nice.
	*/
	snprintf(Argv[0], maxlen, "%s", statbuf);
	p = &Argv[0][i];

	while(p < LastArgv)
		*p++ = '\0';
	Argv[1] = NULL;
#endif /* PF_ARGV_WRITEABLE */

#if PF_ARGV_TYPE == PF_ARGV_PSTAT
	pst.pst_command = statbuf;
	pstat(PSTAT_SETCMD, pst, i, 0, 0);
#endif /* PF_ARGV_PSTAT */

#if PF_ARGV_TYPE == PF_ARGV_PSSTRINGS
	PS_STRINGS->ps_nargvstr = 1;
	PS_STRINGS->ps_argvstr = statbuf;
#endif /* PF_ARGV_PSSTRINGS */

#endif /* HAVE_SETPROCTITLE */
}

list<_kis_lex_rec> LexString(string in_line, string& errstr) {
	list<_kis_lex_rec> ret;
	int curstate = _kis_lex_none;
	_kis_lex_rec cpr;
	string tempstr;
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

			// Close paren
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

void SubtractTimeval(struct timeval *in_tv1, struct timeval *in_tv2,
					 struct timeval *out_tv) {
	if (in_tv1->tv_sec < in_tv2->tv_sec ||
		(in_tv1->tv_sec == in_tv2->tv_sec && in_tv1->tv_usec < in_tv2->tv_usec) ||
		in_tv1->tv_sec == 0 || in_tv2->tv_sec == 0) {
		out_tv->tv_sec = 0;
		out_tv->tv_usec = 0;
		return;
	}

	if (in_tv2->tv_usec > in_tv1->tv_usec) {
		out_tv->tv_usec = 1000000 + in_tv1->tv_usec - in_tv2->tv_usec;
		out_tv->tv_sec = in_tv1->tv_sec - in_tv2->tv_sec - 1;
	} else {
		out_tv->tv_usec = in_tv1->tv_usec - in_tv2->tv_usec;
		out_tv->tv_sec = in_tv1->tv_sec - in_tv2->tv_sec;
	}
}

/* Airware PPI gps conversion code from Johnny Csh */

/*
 * input: a unsigned 32-bit (native endian) value between 0 and 3600000000 (inclusive)
 * output: a signed floating point value betwen -180.0000000 and + 180.0000000, inclusive)
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
 * input: a signed floating point value betwen -180.0000000 and + 180.0000000, inclusive)
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
 * input: a signed floating point value betwen -180000.0000 and + 180000.0000, inclusive)
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

int StringToBool(string s, int dvalue) {
	string ls = StrLower(s);

	if (ls == "true" || ls == "t") {
		return 1;
	} else if (ls == "false" || ls == "f") {
		return 0;
	}

	return dvalue;
}

string StringAppend(string s, string a, string d) {
	if (s.length() == 0)
		return a;

	if (s.length() > d.length() &&
		s.substr(s.length() - d.length(), d.length()) == d)
		return s + a;

	return s + d + a;
}

int GetLengthTagOffsets(unsigned int init_offset, 
						kis_datachunk *in_chunk,
						map<int, vector<int> > *tag_cache_map) {
    int cur_tag = 0;
    // Initial offset is 36, that's the first tag
    unsigned int cur_offset = (unsigned int) init_offset;
    uint8_t len;

    // Bail on invalid incoming offsets
    if (init_offset >= in_chunk->length) {
        return -1;
	}
    
    // If we haven't parsed the tags for this frame before, parse them all now.
    // Return an error code if one of them is malformed.
    if (tag_cache_map->size() == 0) {
        while (1) {
            // Are we over the packet length?
            if (cur_offset + 2 >= in_chunk->length) {
                break;
            }

            // Read the tag we're on and bail out if we're done
            cur_tag = (int) in_chunk->data[cur_offset];

            // Move ahead one byte and read the length.
            len = (in_chunk->data[cur_offset+1] & 0xFF);

            // If this is longer than we have...
            if ((cur_offset + len + 2) > in_chunk->length) {
                return -1;
            }

            // (*tag_cache_map)[cur_tag] = cur_offset + 1;
			
            (*tag_cache_map)[cur_tag].push_back(cur_offset + 1);

            // Jump the length+length byte, this should put us at the next tag
            // number.
            cur_offset += len+2;
        }
    }
    
    return 0;
}

