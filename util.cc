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

string StrLower(string in_str) {
    string thestr = in_str;
    for (unsigned int i = 0; i < thestr.length(); i++)
        thestr[i] = tolower(thestr[i]);

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

vector<string> LineWrap(string in_txt, unsigned int in_hdr_len, unsigned int in_maxlen) {
	vector<string> ret;

	size_t pos, prev_pos, start, hdroffset;
	start = hdroffset = 0;

	for (pos = prev_pos = in_txt.find(' ', in_hdr_len); pos != string::npos; pos = in_txt.find(' ', pos + 1)) {
		if ((hdroffset + pos) - start > in_maxlen) {
			if (pos - prev_pos > 8) {
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


