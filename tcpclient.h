#ifndef __TCPCLIENT_H__
#define __TCPCLIENT_H__

#include "config.h"

#include <stdio.h>
#include <string>
#include <vector>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netdb.h>
#include <fcntl.h>
#include <errno.h>

#include "packetracker.h"

#define TCP_SELECT_TIMEOUT 100

#ifndef MAXHOSTNAMELEN
#define MAXHOSTNAMELEN 64
#endif

#define LINKQ_MAX 100
#define LEVEL_MAX 255
#define NOISE_MAX 255

// TCP Client.  Simple nonblocking client to extract network info exported by the
// Kismet TCP server component and parse it.  Frontends should include this.

class TcpClient {
public:
    TcpClient();
    ~TcpClient();

    int Valid() { return sv_valid; };

    int Connect(short int in_port, char *in_host);

    int FetchDescriptor() { return client_fd; }

    int Poll();

    int Send(const char *in_data);

    // Fetch the location
    int FetchLoc(float *in_lat, float *in_lon, float *in_alt, float *in_spd, int *in_mode);
    // Fetch the mode
    int FetchMode() { return mode; }

    // Fetch the time reported by the server
    time_t FetchServTime();
    // Fetch a vector of all the BSSID's reported to us
    vector<wireless_network *> FetchNetworkList();
    // Get the most recently touched n-th networks
    vector<wireless_network *> FetchNthRecent(unsigned int n);

    char *FetchError() { return errstr; }
    int FetchNumNetworks() { return num_networks; }
    int FetchNumPackets() { return num_packets; }
    int FetchNumCrypt() { return num_crypt; }
    int FetchNumInteresting() { return num_interesting; }
    int FetchNumNoise() { return num_noise; }
    int FetchNumDropped() { return num_dropped; }

    int FetchMajor() { return major; }
    int FetchMinor() { return minor; }
    time_t FetchStart() { return start_time; }
    time_t FetchTime() { return serv_time; }

    char *FetchStatus() { return status; }

    int FetchPower() { return power; }
    int FetchQuality() { return quality; }
    int FetchNoise() { return noise; }

    int FetchChannelPower(int in_channel);

    int GetMaxStrings() { return maxstrings; }
    void SetMaxStrings(int in_max) {
        maxstrings = in_max;
        if (strings.size() > maxstrings)
            strings.erase(strings.begin(), strings.begin() + (strings.size() - maxstrings));
    }
    vector<string> FetchStrings() { return strings; }
    void ClearStrings() { strings.clear(); }

    int GetMaxPackInfos() { return maxpackinfos; }
    void SetMaxPackInfos(int in_max) {
        maxpackinfos = in_max;
        if (packinfos.size() > maxpackinfos)
            packinfos.erase(packinfos.begin(), packinfos.begin() + (packinfos.size() - maxpackinfos));
    }
    vector<packet_info> FetchPackInfos() { return packinfos; }
    void ClearPackInfos() { packinfos.clear(); }

    void RemoveNetwork(string in_bssid);

protected:
    char errstr[1024];
    char status[STATUS_MAX];

    int ParseData(char *in_data);

    // Active server
    int sv_valid;

    // Server info
    short int port;
    char hostname[MAXHOSTNAMELEN];

    int client_fd;
    FILE *clientf;

    struct sockaddr_in client_sock, local_sock;
    struct hostent *client_host;

    // Data sent to us
    // GPS
    float lat, lon, alt, spd;
    int mode;
    // Timestampt
    time_t serv_time;

    map<string, wireless_network> net_map;

    int num_networks, num_packets, num_crypt,
        num_interesting, num_noise, num_dropped;

    int major, minor;
    time_t start_time;

    int power, quality, noise;

    unsigned int maxstrings, maxpackinfos;

    vector<string> strings;
    vector<packet_info> packinfos;

    channel_power channel_graph[CHANNEL_MAX];

    string writebuf;

};

#endif
