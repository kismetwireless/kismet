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

#ifndef __KISNETCLIENT_H__
#define __KISNETCLIENT_H__

#include "config.h"

#include "clinetframework.h"
#include "tcpclient.h"
#include "tracktypes.h"

#define LINKQ_MAX 100
#define LEVEL_MIN -255
#define LEVEL_MAX 255
#define NOISE_MIN -255
#define NOISE_MAX 255
#define SNR_MAX   50

#define CLIENT_NOTIFY  2
#define CLIENT_ALERT   4

class KismetClient : public ClientFramework {
public:
    KismetClient();
    KismetClient(GlobalRegistry *in_globalreg);
    virtual ~KismetClient();

    // Hooks so we can override straight to the TCP core
    virtual unsigned int MergeSet(fd_set in_rset, fd_set in_wset, 
                                  unsigned int in_max_fd,
                                  fd_set *out_rset, fd_set *out_wset) {
        return netclient->MergeSet(in_rset, in_wset, in_max_fd,
                                   out_rset, out_wset);
    }

    virtual int Poll(fd_set& in_rset, fd_set& in_wset) {
        return netclient->Poll(in_rset, in_wset);
    }
    
    virtual int ParseData();
    virtual int KillConnection();
    
    virtual int Shutdown();

    typedef struct alert_info {
        timeval alert_ts;
        string alert_text;
    };

    // Sort alerts by alert time
    class SortAlerts {
    public:
        inline bool operator() (const TcpClient::alert_info x, const TcpClient::alert_info y) const {
            if ((x.alert_ts.tv_sec > y.alert_ts.tv_sec) ||
                ((x.alert_ts.tv_sec== y.alert_ts.tv_sec) && (x.alert_ts.tv_usec > y.alert_ts.tv_usec)))
                return 1;
            return 0;
        }
    };

    typedef struct string_info {
        mac_addr bssid;
        mac_addr source;
        timeval string_ts;
        string text;
    };

    // Sort strings by alert time
    class SortStrings {
    public:
        inline bool operator() (const TcpClient::string_info x, const TcpClient::string_info y) const {
            if ((x.string_ts.tv_sec > y.string_ts.tv_sec) ||
                ((x.string_ts.tv_sec== y.string_ts.tv_sec) && (x.string_ts.tv_usec > y.string_ts.tv_usec)))
                return 1;
            return 0;
        }
    };

    typedef struct card_info {
        string interface;
        string type;
        string username;
        int channel;
        int id;
        int packets;
        int hopping;
    };

    // Enable a protocol - this lets clients based off our code pick what protocols they
    // support.
    void EnableProtocol(string in_protocol);
    // Disable a protocol
    void RemoveProtocol(string in_protocol);

    // Fetch the location
    int FetchLoc(float *in_lat, float *in_lon, float *in_alt, float *in_spd, float *in_hed, int *in_mode);
    // Fetch the mode
    int FetchMode() { return mode; }

    // Fetch the time reported by the server
    time_t FetchServTime();
    // Fetch a vector of all the BSSID's reported to us
    vector<wireless_network *> FetchNetworkList();
    // Get the most recently touched n-th networks
    vector<wireless_network *> FetchNthRecent(unsigned int n);

    // List of cards
    vector<card_info *> FetchCardList();

    short int FetchPort() { return port; }
    char *FetchHost() { return hostname; }

    char *FetchError() { return errstr; }

    string FetchServername() { return servername; }

    int FetchHopping() { return channel_hop; }

    int FetchNumNetworks() { return num_networks; }
    int FetchNumPackets() { return num_packets; }
    int FetchNumCrypt() { return num_crypt; }
    int FetchNumInteresting() { return num_interesting; }
    int FetchNumNoise() { return num_noise; }
    int FetchNumDropped() { return num_dropped; }

    int FetchDeltaNumNetworks() { return num_networks - old_num_networks; }
    int FetchDeltaNumPackets() { return num_packets - old_num_packets; }
    int FetchDeltaNumCrypt() { return num_crypt - old_num_crypt; }
    int FetchDeltaNumInteresting() { return num_interesting - old_num_interesting; }
    int FetchDeltaNumNoise() { return num_noise - old_num_noise; }
    int FetchDeltaNumDropped() { return num_dropped - old_num_dropped; }

    int FetchPacketRate() { return packet_rate; }

    char *FetchMajor() { return major; }
    char *FetchMinor() { return minor; }
    char *FetchTiny() { return tiny; }
    char *FetchBuild() { return build; }
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
    vector<string_info> FetchStrings() { return strings; }
    void ClearStrings() { strings.clear(); }

    int GetMaxPackInfos() { return maxpackinfos; }
    void SetMaxPackInfos(int in_max) {
        maxpackinfos = in_max;
        if (packinfos.size() > maxpackinfos)
            packinfos.erase(packinfos.begin(), packinfos.begin() + (packinfos.size() - maxpackinfos));
    }
    vector<packet_info> FetchPackInfos() { return packinfos; }
    void ClearPackInfos() { packinfos.clear(); }

    int GetMaxAlerts() { return maxalerts; }
    void SetMaxAlerts(int in_max) {
        maxalerts = in_max;
        if (alerts.size() > maxalerts)
            alerts.erase(alerts.begin(), alerts.begin() + (alerts.size() - maxalerts));
    }
    vector <alert_info> FetchAlerts() { return alerts; }
    void ClearAlarms() { alerts.clear(); }

    void RemoveNetwork(mac_addr in_bssid);

    wireless_network *FetchLastNewNetwork() { return last_new_network; }

    void SendRaw(const char *in_cmd);

    int FetchNetworkDirty();
protected:
    TcpClient *tcpcli;

    int cmdid;
    
    char host[MAXHOSTNAMELEN];
    int port;
    int reconnect_attempt;
    time_t last_disconnect;

    // Reconnect local trigger
    int Reconnect();
    int InjectCommand(string in_cmd);

    // Has the server identified itself w/ a valid KISMET line?
    int server_identified;
    
    // Data sent to us
    // GPS
    float lat, lon, alt, spd, heading;
    int mode;
    // Timestampt
    time_t serv_time;

    map<mac_addr, wireless_network *> net_map;
    vector<wireless_network *> net_map_vec;
    wireless_network *last_new_network;

    map<string, card_info *> card_map;
    vector<card_info *> card_map_vec;

    int num_networks, num_packets, num_crypt,
        num_interesting, num_noise, num_dropped, packet_rate;

    int old_num_networks, old_num_packets, old_num_crypt,
        old_num_interesting, old_num_noise, old_num_dropped, old_packet_rate;

    char major[24], minor[24], tiny[24];
    char build[24];
    time_t start_time;

    int power, quality, noise;

    unsigned int maxstrings, maxpackinfos, maxalerts;

    vector<string_info> strings;
    vector<packet_info> packinfos;
    vector<alert_info> alerts;

    channel_power channel_graph[CHANNEL_MAX];
   
    // Protocols we have enabled so that we can replay them on a reconnect
    map<string, int> protocol_map;

    // Fields we enable (what we know how to parse)
    map<string, string> protocol_default_map;

    int network_dirty;

    int channel_hop;

};

#endif

#endif

