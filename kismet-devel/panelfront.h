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

#ifndef __PANELFRONT_H__
#define __PANELFRONT_H__

#include "config.h"

#if (defined(HAVE_LIBNCURSES) && defined(HAVE_LIBPANEL) && defined(BUILD_PANEL))

#ifdef HAVE_LIBCURSES
#include <curses.h>
#include <panel.h>
#else
#include <ncurses.h>
#include <panel.h>
#endif
#undef erase
#undef clear
#undef move

#include <stdio.h>
#include <time.h>
#include <list>
#include <map>
#include <string>
#include <vector>

#include "packet.h"
#include "frontend.h"
#include "cursesfront.h"
#include "networksort.h"

#define COLOR_DEFAULT -1

// Handle curses implementations that don't define this
#ifndef ACS_HLINE
#define ACS_HLINE '-'
#endif

#ifndef ACS_VLINE
#define ACS_VLINE '|'
#endif

extern char *KismetHelpText[];
extern char *KismetHelpTextNarrow[];
extern char *KismetHelpDetails[];
extern char *KismetSortText[];
extern char *KismetSortTextNarrow[];
#define SORT_SIZE 10
extern char *KismetHelpPower[];
extern char *KismetHelpRate[];
extern char *KismetHelpGps[];
extern char *KismetHelpStats[];
extern char *KismetHelpDump[];
extern char *KismetHelpPack[];
extern char *KismetHelpAlert[];
extern char *KismetHelpServer[];

extern char *KismetClientHelpText[];
extern char *KismetClientHelpDetails[];
extern char *KismetClientSortText[];
extern char *KismetClientSortTextNarrow[];
#define CLIENT_SORT_SIZE 8

// These are in the kismet_curses.cc main code
extern int sound;
extern int speech;
extern unsigned int metric;

class PanelFront : public Frontend {
public:
    PanelFront();
    virtual ~PanelFront();

    void AddPrefs(map<string, string> in_prefs);

    void AddClient(TcpClient *in_client);

    void FetchClients(vector<TcpClient *> *in_vec);
    TcpClient *FetchPrimaryClient();

    int ParseArgs(int argc, char *argv[]) { return 0; }

    int Tick();

    int Poll();

    int InitDisplay(int in_decay, time_t in_start);

    // Draw the screen
    int DrawDisplay();

    // End
    int EndDisplay();

    int WriteStatus(string status);

protected:
    // Curses color pair
    typedef struct color_pair {
        color_pair() { index = -1; pair = 0; bold = 0; }

        int index;
        int bold;
        int pair;

    };

    // Tracking for our subwindows so we can spawn more than one at once.
    // Having to cast this all the time is annoying, but...
    typedef int (PanelFront::*panel_printer)(void *);
    typedef int (PanelFront::*key_handler)(void *, int);

    // This can be filled in by the generic panel spawner or by a special
    // spawner, like help is.
    typedef struct {
        // Window and panel
        WINDOW *win;
        PANEL *pan;
        // Function pointer to the function that handles our printing
        panel_printer printer;
        // Keyboard event handler
        key_handler input;
        // Title of window
        string title;

        // Not everything will use all of these but they're available
        // Start of sliding window over the data
        int start;
        // End of sliding window over the data
        int end;
        // Selected item
        int selected;
        // Printable lines for scrolling window
        int max_display;
        // Width of printable area
        int print_width;
        // Paused
        int paused;
        // Are we scrollable?
        int scrollable;

        // Some toggles for various windows to use if they need them
        int toggle0;
        int toggle1;
        int toggle2;

        // Text, if we store it seperately
        vector<string> text;
    } kis_window;

    // All the windows
    list<kis_window *> window_list;

    // Server context records for multiple servers
    typedef struct server_context {
        server_context() {
            client = NULL;
            quality = power = noise = 0;

            /*
            details_network = NULL;
            details_client = NULL;
            last_draw_size = last_client_draw_size = 0;
            */

            lat = lon = spd = alt = last_lat = last_lon = last_spd = last_alt = 0;
            fix = last_fix = 0;

            max_packet_rate = 0;

            num_networks = num_packets = num_crypt = num_interesting =
                num_noise = num_dropped = packet_rate = 0;

            server_time = 0;

            tagged = 0;
            primary = 0;
        }

        TcpClient *client;

        int quality, power, noise;

        /*
        display_network *details_network;
        wireless_client *details_client;
        vector<display_network *> last_displayed;
        vector<wireless_client *> last_client_displayed;

        // Size of the group vec the last time we drew it
        int last_draw_size;
        int last_client_draw_size;
        */

        vector<int> packet_history;

        float lat, lon, spd, alt;
        int fix;
        float last_lat, last_lon, last_spd, last_alt;
        int last_fix;

        // Statistics
        int max_packet_rate;

        int num_networks, num_packets, num_crypt, num_interesting,
            num_noise, num_dropped, packet_rate;

        time_t server_time;

        // Is this tagged for display?
        int tagged;
        // Is this the primary network?  (where we get GPS and quality info from)
        int primary;
    };

    // Update a context on the tick function
    void UpdateContexts();

    // Printers for our main 3 panels... This pulls MOST of this out of class globals,
    // but not quite all.
    int MainNetworkPrinter(void *in_window);
    int MainInfoPrinter(void *in_window);
    int MainStatusPrinter(void *in_window);

    // Just print the stored text
    int TextPrinter(void *in_window);
    // Various popups that generate stuff dynamically
    int SortPrinter(void *in_window);
    int PowerPrinter(void *in_window);
    int DetailsPrinter(void *in_window);
    int DumpPrinter(void *in_window);
    int GroupNamePrinter(void *in_window);
    int RatePrinter(void *in_window);
    int StatsPrinter(void *in_window);
    int PackPrinter(void *in_window);
    int GpsPrinter(void *in_window);
    int AlertPrinter(void *in_window);

    int MainClientPrinter(void *in_window);
    int SortClientPrinter(void *in_window);
    int DetailsClientPrinter(void *in_window);

    // List of servers we're connected to
    int ServersPrinter(void *in_window);
    int ServerJoinPrinter(void *in_window);

    // Keyboard handlers
    int MainInput(void *in_window, int in_chr);
    int SortInput(void *in_window, int in_chr);
    int PowerInput(void *in_window, int in_chr);
    int DetailsInput(void *in_window, int in_chr);
    int DumpInput(void *in_window, int in_chr);
    // Group titler skips all of this
    int RateInput(void *in_window, int in_chr);
    int StatsInput(void *in_window, int in_chr);
    int PackInput(void *in_window, int in_chr);
    // Help has a generic handler
    int TextInput(void *in_window, int in_chr);
    int GpsInput(void *in_window, int in_chr);
    int AlertInput(void *in_window, int in_chr);

    int MainClientInput(void *in_window, int in_chr);
    int SortClientInput(void *in_window, int in_chr);
    int DetailsClientInput(void *in_window, int in_chr);

    int ServersInput(void *in_window, int in_chr);

    // Spawn a generic popup
    void SpawnWindow(string in_title, panel_printer in_print, key_handler in_input,
                    int in_x = -1, int in_y = -1);

    // Spawn a help popup
    void SpawnHelp(char **in_helptext);

    // Kill a window
    void DestroyWindow(kis_window *in_window);

    void RescaleDisplay();

    void ZoomNetworks();

    void Details2Vector(wireless_network *in_net);

    void NetLine(string *in_str, wireless_network *net, const char *name, int sub,
                 int group, int expanded, int tagged);
    void ClientLine(string *in_str, wireless_client *wclient, int print_width);

    enum main_columns {
        mcol_unknown = -1,
        mcol_decay, mcol_name, mcol_shortname, mcol_ssid, mcol_shortssid, mcol_type,
        mcol_wep, mcol_channel, mcol_data, mcol_llc, mcol_crypt, mcol_weak, mcol_bssid,
        mcol_flags, mcol_ip, /* mcol_mask, mcol_gateway, */ mcol_packets, mcol_info, mcol_maxrate,
        mcol_manuf, mcol_signal, mcol_quality, mcol_noise, mcol_clients
    };

    enum client_columns {
        ccol_unknown = -1,
        ccol_decay, ccol_type, ccol_mac, ccol_manuf, ccol_data, ccol_crypt, ccol_weak,
        ccol_maxrate, ccol_ip, ccol_signal, ccol_quality, ccol_noise
    };

    main_columns Token2MainColumn(string in_token);
    client_columns Token2ClientColumn(string in_token);
    void SetMainColumns(string in_columns);
    void SetClientColumns(string in_columns);

    void MuteToggle();

    color_pair ColorParse(string in_color);

    int color;

    int clear_dump;

    sort_type sortby;
    client_sort_type client_sortby;

    vector<main_columns> column_vec;
    vector<client_columns> client_column_vec;

    int quality, power, noise;

    int zoomed;

    time_t server_time;

    display_network *details_network;
    wireless_client *details_client;
    vector<display_network *> last_displayed;
    vector<wireless_client *> last_client_displayed;

    int num_networks, num_packets, num_crypt, num_interesting, num_noise, num_dropped,
        packet_rate;

    int hsize, vsize;

    int old_sound;
    int old_speech;
    int muted;

    vector<int> packet_history;

    float lat, lon, spd, alt;
    int fix;
    float last_lat, last_lon, last_spd, last_alt;
    int last_fix;

    // Size of the group vec the last time we drew it
    int last_draw_size;
    int last_client_draw_size;

    // Battery monitoring states
    unsigned int monitor_bat;
    unsigned int bat_percentage;
    unsigned int bat_time;
    unsigned int bat_available;
    unsigned int bat_ac;
    unsigned int bat_charging;
    unsigned int bat_full_capacity[3];  // I doubt a machine has more than 3 batteries...

    // Statistics
    int max_packet_rate;

    // Keep these three here so we can refer to them easily - they're non-transient
    kis_window *net_win;
    kis_window *info_win;
    kis_window *stat_win;

    // This one is transient but we need to cheat
    kis_window *client_win;

    // Current one
    kis_window *cur_window;

    map<string, color_pair> color_map;

    // Current context so we can update multiple servers at once
    server_context *context;
    vector<server_context *> context_list;
    // Secondary vector of clients so we can quickly return clients
    vector<TcpClient *> client_list;

};

#endif

#endif
