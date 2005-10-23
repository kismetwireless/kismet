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
#include <fcntl.h>
#include <stdarg.h>

#ifdef HAVE_LIBUTIL_H
# include <libutil.h>
#endif /* HAVE_LIBUTIL_H */

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

// Munge input to shell-safe
void MungeToShell(char *in_data, int max) {
    int i, j;

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
string MungeToPrintable(const char *in_data, int max, int nullterm) {
	string ret;
	int i;

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
    for (unsigned int x = in_str.length() - 1; x > 0; x--) {
        if (in_str[x] != ' ' && in_str[x] != '\t' && in_str[x] != '\n') {
            end = x;
            break;
        }
    }

    return in_str.substr(start, end-start+1);

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

vector<smart_word_token> SmartStrTokenize(string in_str, string in_split, int return_partial) {
    size_t begin = 0;
    size_t end = in_str.find(in_split);
    vector<smart_word_token> ret;
    smart_word_token stok;

    if (in_str.length() == 0)
        return ret;
    
    while (end != string::npos) {
        stok.word = in_str.substr(begin, end-begin);
        stok.begin = begin;
        stok.end = end;

        begin = end+1;
        end = in_str.find(in_split, begin);
        ret.push_back(stok);
    }

    if (return_partial && begin != in_str.size()) {
        stok.word = in_str.substr(begin, in_str.size() - begin);
        stok.begin = begin;
        stok.end = in_str.size();
        ret.push_back(stok);
    }

    return ret;
}

vector<string> LineWrap(string in_txt, unsigned int in_hdr_len, 
						unsigned int in_maxlen) {
	vector<string> ret;

	size_t pos, prev_pos, start, hdroffset;
	start = hdroffset = 0;

	for (pos = prev_pos = in_txt.find(' ', in_hdr_len); pos != string::npos; 
		 pos = in_txt.find(' ', pos + 1)) {
		if ((hdroffset + pos) - start >= in_maxlen) {
			if (pos - prev_pos > (in_maxlen / 5)) {
				prev_pos = start + (in_maxlen - hdroffset);
			}

			string str(hdroffset, ' ');
			hdroffset = in_hdr_len;
			str += in_txt.substr(start, prev_pos - start);
			ret.push_back(str);
			
			start = prev_pos;
		}

		prev_pos = pos + 1;
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
    system(in_cmd);
    
    return 0;
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
