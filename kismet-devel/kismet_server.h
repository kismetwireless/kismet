#ifndef __KISMET_SERVER_H__
#define __KISMET_SERVER_H__

#include "config.h"

#include <map>
#include <string>

#define MAJOR 2
#define MINOR 5

string ExpandLogPath(string path, string logname, string type);
void CatchShutdown(int sig);
int Usage(char *argv);
void NetWriteInfo();
void PlaySound(string player, string sound, map<string, string> soundmap);
void SayText(string player, string text);
void NetWriteStatus(char *in_status);

#endif
