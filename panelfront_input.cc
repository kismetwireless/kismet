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

#include <math.h>

#include "panelfront.h"
#include "displaynetworksort.h"

#if (defined(HAVE_LIBNCURSES) && defined(HAVE_LIBPANEL) && defined(BUILD_PANEL))

int PanelFront::MainInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;

    switch (in_chr) {
    case 'Q':
        return FE_QUIT;
        break;
    case 'q':
        WriteStatus("Use capital-Q to quit Kismet.");
        break;
    case KEY_UP:
        if (sortby != sort_auto) {
            if (kwin->selected == 0 && kwin->start != 0) {
                kwin->start--;
            } else if (kwin->selected > 0) {
                kwin->selected--;
            }
        } else {
            WriteStatus("Cannot scroll in autofit sort mode.");
        }

        break;
    case KEY_DOWN:
        if (sortby != sort_auto) {
            if (kwin->start + kwin->selected < last_draw_size - 1) {
                if ((kwin->start + kwin->selected >= kwin->end) &&
                    (kwin->start + kwin->selected + 1 < last_draw_size))
                    kwin->start++;
                else
                    kwin->selected++;
            }

        } else {
            WriteStatus("Cannot scroll in autofit sort mode.");
        }
        break;
    case KEY_PPAGE:
        if (sortby != sort_auto) {
            kwin->selected = -1; // We want to start a page in reverse
        } else {
            WriteStatus("Cannot scroll in autofit sort mode.");
        }

        break;
    case KEY_NPAGE:
        if (sortby != sort_auto) {
            kwin->selected = -2; // We want to start a page forward
        } else {
            WriteStatus("Cannot scroll in autofit sort mode.");
        }
        break;
    case KEY_RIGHT:
    case '+':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            if (last_displayed[kwin->selected]->type == group_bundle)
                last_displayed[kwin->selected]->expanded = 1;
        } else {
            WriteStatus("Cannot expand groups in autofit sort mode.");
        }
        break;
    case KEY_LEFT:
    case '-':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            if (last_displayed[kwin->selected]->type == group_bundle)
                last_displayed[kwin->selected]->expanded = 0;
        } else {
            WriteStatus("Cannot collapse groups in autofit sort mode.");
        }
        break;
    case 'i':
    case 'I':
    case KEY_ENTER:
        if (sortby != sort_auto &&  last_displayed.size() > 0) {
            details_network = last_displayed[kwin->selected];
            SpawnWindow("Network Details",
                        &PanelFront::DetailsPrinter, &PanelFront::DetailsInput);
        } else {
            WriteStatus("Cannot view details in autofit sort mode.");
        }
        break;
    case 't':
    case 'T':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            if (last_displayed[kwin->selected]->tagged)
                last_displayed[kwin->selected]->tagged = 0;
            else
                last_displayed[kwin->selected]->tagged = 1;
        } else {
            WriteStatus("Cannot tag networks in autofit sort mode.");
        }
        break;
    case 'n':
    case 'N':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            details_network = last_displayed[kwin->selected];
            SpawnWindow("Group Name", &PanelFront::GroupNamePrinter, NULL, 3, 30);
        } else {
            WriteStatus("Cannot name groups in autofit sort mode.");
        }
        break;
    case 'g':
    case 'G':
        if (sortby != sort_auto &&  last_displayed.size() > 0) {
            details_network = GroupTagged();
            if (details_network != NULL)
                SpawnWindow("Group Name", &PanelFront::GroupNamePrinter, NULL, 3, 30);
        } else {
            WriteStatus("Cannot create groups in autofit sort mode.");
        }
        break;
    case 'u':
    case 'U':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            if (last_displayed[kwin->selected] != NULL)
                if (last_displayed[kwin->selected]->type == group_bundle)
                    DestroyGroup(last_displayed[kwin->selected]);
        } else {
            WriteStatus("Cannot ungroup in autofit sort mode.");
        }
        break;
    case 'c':
    case 'C':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            details_network = last_displayed[kwin->selected];
            SpawnWindow("Client List", &PanelFront::MainClientPrinter, &PanelFront::MainClientInput);
        } else {
            WriteStatus("Cannot view clients in autofit sort mode.");
        }
        break;
    case 'h':
    case 'H':
        if (kwin->win->_maxx < 64)
            SpawnHelp(KismetHelpTextNarrow);
        else
            SpawnHelp(KismetHelpText);
        break;
    case 'z':
    case 'Z':
        ZoomNetworks();
        break;
    case 's':
    case 'S':
        SpawnWindow("Sort Network", &PanelFront::SortPrinter, &PanelFront::SortInput, SORT_SIZE);
        break;
    case 'l':
    case 'L':
        SpawnWindow("Wireless Card Power", &PanelFront::PowerPrinter, &PanelFront::PowerInput, 3);
        break;
    case 'd':
    case 'D':
        client->EnableProtocol("STRING");
        WriteStatus("Requesting strings from the server");

        SpawnWindow("Data Strings Dump", &PanelFront::DumpPrinter, &PanelFront::DumpInput);
        break;
    case 'r':
    case 'R':
        SpawnWindow("Packet Rate", &PanelFront::RatePrinter, &PanelFront::RateInput);
        break;
    case 'w':
    case 'W':
        SpawnWindow("Alerts", &PanelFront::AlertPrinter, &PanelFront::AlertInput);
        break;
    case 'a':
    case 'A':
        SpawnWindow("Statistics", &PanelFront::StatsPrinter, &PanelFront::StatsInput, 19, 65);
        break;
    case 'p':
    case 'P':
        client->EnableProtocol("PACKET");
        WriteStatus("Requesting packet types from the server");

        SpawnWindow("Packet Types", &PanelFront::PackPrinter, &PanelFront::PackInput);
        break;
    case 'f':
    case 'F':
        if (sortby != sort_auto && last_displayed.size() > 0) {
            details_network = last_displayed[kwin->selected];
            SpawnWindow("Network Location", &PanelFront::GpsPrinter, &PanelFront::GpsInput, 8, 34);
        } else {
            WriteStatus("Cannot view network GPS info in autofit sort mode.");
        }
        break;
    case 'm':
    case 'M':
        MuteToggle();
        break;
    case 'e':
    case 'E':
        SpawnWindow("Kismet Servers", &PanelFront::ServersPrinter, &PanelFront::ServersInput, 10, 62);
        break;
    }


    return 1;
}

int PanelFront::SortInput(void *in_window, int in_chr) {
    switch (in_chr) {
    case 'a':
    case 'A':
        sortby = sort_auto;
        WriteStatus("Autofitting network display");
        break;
    case 'c':
    case 'C':
        sortby = sort_channel;
        WriteStatus("Sorting by channel");
        break;
    case 'f':
        sortby = sort_first;
        WriteStatus("Sorting by time first detected");
        break;
    case 'F':
        sortby = sort_first_dec;
        WriteStatus("Sorting by time first detected (descending)");
        break;
    case 'l':
        sortby = sort_last;
        WriteStatus("Sorting by time most recently active");
        break;
    case 'L':
        sortby = sort_last_dec;
        WriteStatus("Sorting by time most recently active (descending)");
        break;
    case 'b':
        sortby = sort_bssid;
        WriteStatus("Sorting by BSSID");
        break;
    case 'B':
        sortby = sort_bssid_dec;
        WriteStatus("Sorting by BSSID (descending)");
        break;
    case 's':
        sortby = sort_ssid;
        WriteStatus("Sorting by SSID");
        break;
    case 'S':
        sortby = sort_ssid_dec;
        WriteStatus("Sorting by SSID (descending)");
        break;
    case 'w':
    case 'W':
        sortby = sort_wep;
        WriteStatus("Sorting by WEP");
        break;
    case 'p':
        sortby = sort_packets;
        WriteStatus("Sorting by packet counts.");
        break;
    case 'P':
        sortby = sort_packets_dec;
        WriteStatus("Sorting by packet counts (descending)");
        break;
    case 'q':
        sortby = sort_quality;
        WriteStatus("Sorting by signal quality");
        break;
    case 'Q':
        sortby = sort_signal;
        WriteStatus("Sorting by signal strength");
        break;
    case 'x':
    case 'X':
        break;
    default:
        beep();
        return 1;
        break;
    }

    // We don't have anything that doesn't kill the window for the key event
    return 0;
}

int PanelFront::PackInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;

    switch(in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpPack);
        break;

    case 'p':
    case 'P':
        if (kwin->paused)
            kwin->paused = 0;
        else
            kwin->paused = 1;
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        client->RemoveProtocol("PACKET");
        return 0;
        break;
    default:
        break;
    }

    return 1;

}

int PanelFront::DumpInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;

    switch(in_chr) {
    case 'm':
    case 'M':
        MuteToggle();
        break;
    case 'p':
    case 'P':
        // Ignore if we're pending a clear
        if (clear_dump == 1)
            break;

        if (kwin->paused)
            kwin->paused = 0;
        else
            kwin->paused = 1;
        break;
    case 't':
    case 'T':
        if (kwin->toggle0 == 0)
            kwin->toggle0 = 1;
        else
            kwin->toggle0 = 0;
        break;
    case 'c':
    case 'C':
        if (!kwin->paused)
            clear_dump = 1;
        break;
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpDump);
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        client->RemoveProtocol("STRING");
        return 0;
        break;
    default:
        break;
    }

    return 1;
}

// We don't do anything special here except spawn a help and pass it on to the
// text input handler.  Details is just a slightly special text window.
int PanelFront::DetailsInput(void *in_window, int in_chr) {
    int ret;
    switch (in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpDetails);
        break;
    case 'n':
        // Nasty hack but it works
        ret = (this->*net_win->input)(net_win, KEY_DOWN);
        details_network = last_displayed[net_win->selected];
        return ret;
        break;
    case 'p':
        ret = (this->*net_win->input)(net_win, KEY_UP);
        details_network = last_displayed[net_win->selected];
        return ret;
        break;
    case 'c':
    case 'C':
        SpawnWindow("Client List", &PanelFront::MainClientPrinter, &PanelFront::MainClientInput);
        break;
    default:
        return TextInput(in_window, in_chr);
        break;
    }

    return 1;
}

int PanelFront::PowerInput(void *in_window, int in_chr) {
    switch (in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpPower);
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        return 0;
        break;
    }

    return 1;
}

int PanelFront::GpsInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;

    switch (in_chr) {
    case 's':
    case 'S':
        kwin->selected = 1;
        break;
    case 'c':
    case 'C':
        kwin->selected = 0;
        break;
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpGps);
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        return 0;
        break;
    }

    return 1;
}

int PanelFront::RateInput(void *in_window, int in_chr) {
    switch (in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpRate);
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        return 0;
        break;
    }

    return 1;
}

int PanelFront::StatsInput(void *in_window, int in_chr) {
    switch (in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpStats);
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        return 0;
        break;
    }

    return 1;
}

int PanelFront::TextInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;

    switch (in_chr) {
    case KEY_PPAGE:
        if (kwin->start != 0)
            kwin->start = max(0, kwin->start - kwin->max_display);
        break;
    case KEY_NPAGE:
        if (kwin->end < (int) kwin->text.size() - 1 && kwin->end != 0)
            kwin->start = min((int)kwin->text.size() - kwin->max_display, kwin->start + kwin->max_display);
        break;
    case KEY_UP:
    case '-':
        if (kwin->start != 0) {
            kwin->start--;
        }
        break;
    case KEY_DOWN:
    case '+':
        if (kwin->end < (int) kwin->text.size() - 1 && kwin->end != 0) {
            kwin->start++;
        }
        break;
    case 'x':
    case 'X':
    case 'q':
    case 'Q':
        return 0;
        break;
    default:
        return 1;
        break;
    }

    return 1;
}

void PanelFront::MuteToggle() {
    if (muted) {
        speech = old_speech;
        sound = old_sound;
        muted = 0;
        WriteStatus("Restoring sound");
    } else if (sound != 0 || speech != 0) {
        old_speech = speech;
        old_sound = sound;
        sound = 0;
        speech = 0;
        muted = 1;
        WriteStatus("Muting sound");
    } else if (sound == 0 && speech == 0) {
        WriteStatus("Sound not enabled.");
    }
}

int PanelFront::AlertInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;

    switch (in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpAlert);
        break;
    case 't':
    case 'T':
        if (kwin->toggle0 == 0)
            kwin->toggle0 = 1;
        else
            kwin->toggle0 = 0;
        break;
    default:
        return TextInput(in_window, in_chr);
        break;
    }

    return 1;
}

int PanelFront::MainClientInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;
    int ret;

    switch (in_chr) {
    case 'Q':
    case 'q':
    case 'x':
    case 'X':
        return 0;
        break;
    case KEY_UP:
        if (client_sortby != client_sort_auto) {
            if (kwin->selected == 0 && kwin->start != 0) {
                kwin->start--;
            } else if (kwin->selected > 0) {
                kwin->selected--;
            }
        } else {
            WriteStatus("Cannot scroll clients in autofit sort mode.");
        }

        break;
    case KEY_DOWN:
        if (client_sortby != client_sort_auto) {
            if (kwin->start + kwin->selected < last_client_draw_size) {
                if (kwin->start + kwin->selected + 1 == last_client_draw_size) {
                    break;
                } else if ((kwin->start + kwin->selected + 1 > kwin->end) &&
                           (kwin->start + kwin->selected + 1 < last_client_draw_size)) {
                    kwin->start++;
                } else {
                    kwin->selected++;
                }
            }

        } else {
            WriteStatus("Cannot scroll clients in autofit sort mode.");
        }
        break;
    case KEY_PPAGE:
        if (client_sortby != client_sort_auto) {
            if (kwin->selected == 0 && kwin->start != 0) {
                kwin->start -= kwin->max_display;
                kwin->start = max(kwin->start,0);
            } else if (kwin->selected > 0) {
                kwin->selected -= kwin->max_display;
                kwin->selected = max(kwin->selected,0);
            }
        } else {
            WriteStatus("Cannot scroll clients in autofit sort mode.");
        }

        break;
    case KEY_NPAGE:
        if (client_sortby != client_sort_auto) {
            if (kwin->start + kwin->selected + kwin->max_display < last_client_draw_size)
                kwin->start += kwin->max_display - 1;
            else
                kwin->selected = kwin->end - kwin->start;
        } else {
            WriteStatus("Cannot scroll clients in autofit sort mode.");
        }
        break;
    case 's':
    case 'S':
        SpawnWindow("Sort Clients", &PanelFront::SortClientPrinter,
                    &PanelFront::SortClientInput, CLIENT_SORT_SIZE);
        break;
    case 'i':
    case 'I':
    case KEY_ENTER:
        if (client_sortby != client_sort_auto && last_client_displayed.size() > 0) {
            details_client = last_client_displayed[kwin->selected];
            SpawnWindow("Client Details",
                        &PanelFront::DetailsClientPrinter, &PanelFront::DetailsClientInput);
        } else {
            WriteStatus("Cannot view details in autofit sort mode.");
        }
        break;
    case 'n':
        // Nasty hack but it works
        ret = (this->*net_win->input)(net_win, KEY_DOWN);
        details_network = last_displayed[net_win->selected];
        return ret;
        break;
    case 'p':
        ret = (this->*net_win->input)(net_win, KEY_UP);
        details_network = last_displayed[net_win->selected];
        return ret;
        break;
    case 'h':
    case 'H':
        SpawnHelp(KismetClientHelpText);
        break;
    default:
        return 1;
        break;
    }

    return 1;
}

int PanelFront::SortClientInput(void *in_window, int in_chr) {
    switch (in_chr) {
    case 'a':
    case 'A':
        client_sortby = client_sort_auto;
        WriteStatus("Autofitting client display");
        break;
    case 'c':
    case 'C':
        client_sortby = client_sort_channel;
        WriteStatus("Sorting client display by channel");
        break;
    case 'f':
        client_sortby = client_sort_first;
        WriteStatus("Sorting client display by time first detected");
        break;
    case 'F':
        client_sortby = client_sort_first_dec;
        WriteStatus("Sorting client display by time first detected (descending)");
        break;
    case 'l':
        client_sortby = client_sort_last;
        WriteStatus("Sorting client display by time last detected");
        break;
    case 'L':
        client_sortby = client_sort_last_dec;
        WriteStatus("Sorting client display by time last detected (descending)");
        break;
    case 'm':
        client_sortby = client_sort_mac;
        WriteStatus("Sorting client display by MAC");
        break;
    case 'M':
        client_sortby = client_sort_mac_dec;
        WriteStatus("Sorting client display by MAC (descending)");
        break;
    case 'p':
        client_sortby = client_sort_packets;
        WriteStatus("Sorting client display by packets");
        break;
    case 'P':
        client_sortby = client_sort_packets_dec;
        WriteStatus("Sorting client display by packets (descending)");
        break;
    case 'w':
        client_sortby = client_sort_wep;
        WriteStatus("Sorting client display by WEP");
        break;
    case 'q':
        client_sortby = client_sort_quality;
        WriteStatus("Sorting client display by signal quality");
        break;
    case 'Q':
        client_sortby = client_sort_signal;
        WriteStatus("Sorting client display by signal power");
        break;
    case 'x':
    case 'X':
        break;
    default:
        beep();
        return 1;
        break;
    }

    // We don't have anything that doesn't kill the window for the key event
    return 0;
}

int PanelFront::DetailsClientInput(void *in_window, int in_chr) {
    int ret;
    switch (in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetClientHelpDetails);
        break;
    case 'n':
        // Nasty hack but it works
        ret = (this->*client_win->input)(client_win, KEY_DOWN);
        details_client = last_client_displayed[client_win->selected];
        return ret;
        break;
    case 'p':
        ret = (this->*client_win->input)(client_win, KEY_UP);
        details_client = last_client_displayed[client_win->selected];
        return ret;
        break;
    default:
        return TextInput(in_window, in_chr);
        break;
    }

    return 1;
}

int PanelFront::ServersInput(void *in_window, int in_chr) {
    kis_window *kwin = (kis_window *) in_window;
    char msg[1024];

    switch (in_chr) {
    case 'h':
    case 'H':
        SpawnHelp(KismetHelpServer);
        break;
    case KEY_UP:
        if (kwin->selected > 0) 
            kwin->selected--;
        else if (kwin->selected == 0 && kwin->start > 0)
            kwin->start--;
        break;
    case KEY_DOWN:
        if ((kwin->selected + kwin->start) < kwin->end)
            kwin->selected++;
        else if (kwin->end < ((int) context_list.size() - 1))
            kwin->start++;
        break;
    case 'c':
    case 'C':
        SpawnWindow("New Server", &PanelFront::ServerJoinPrinter, NULL, 3, 40);
        break;
    case 'd':
    case 'D':
        if ((kwin->start + kwin->selected) < (int) context_list.size()) {
            server_context *con = context_list[kwin->start + kwin->selected];
            if (con->client != NULL) {
                snprintf(msg, 1024, "Disconnecting from %s:%d",
                         con->client->FetchHost(), con->client->FetchPort());
                WriteStatus(msg);
                con->client->Disconnect();
            }
        }
        break;
    case 'r':
    case 'R':
        if ((kwin->start + kwin->selected) < (int) context_list.size()) {
            server_context *con = context_list[kwin->start + kwin->selected];
            if (con->client != NULL) {
                snprintf(msg, 1024, "Reconnecting to %s:%d",
                         con->client->FetchHost(), con->client->FetchPort());
                WriteStatus(msg);
                con->client->Connect(con->client->FetchPort(), con->client->FetchHost());
            }
        }
        break;
    case 't':
    case 'T':
        if ((kwin->start + kwin->selected) < (int) context_list.size()) {
            server_context *con = context_list[kwin->start + kwin->selected];

            if (con->primary)
                return 1;

            if (con->tagged) {
                con->tagged = 0;

                // Flush the rate graph
                packet_history.clear();
                for (unsigned int x = 0; x < (60 * 5); x++)
                    packet_history.push_back(0);
                // Flush all the group mappings so we can repopulate with just the
                // groups we have tagged now
                PurgeGroups();
            } else {
                con->tagged = 1;
            }
        }
        break;
    case 'p':
    case 'P':
        if ((kwin->start + kwin->selected) < (int) context_list.size()) {
            server_context *con = context_list[kwin->start + kwin->selected];

            if (con->primary)
                return 1;

            for (unsigned int x = 0; x < context_list.size(); x++)
                if (context_list[x]->primary)
                    context_list[x]->primary = 0;

            con->primary = 1;
            con->tagged = 1;
            context = con;
        }
        break;
    case 'q':
    case 'Q':
    case 'x':
    case 'X':
        return 0;
        break;
    }

    return 1;
}

#endif
