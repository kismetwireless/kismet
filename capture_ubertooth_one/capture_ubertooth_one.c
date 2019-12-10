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

#define _GNU_SOURCE

#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>

#include <sched.h>

#include <string.h>

/* According to POSIX.1-2001, POSIX.1-2008 */
#include <sys/select.h>

/* According to earlier standards */
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>

#include <unistd.h>
#include <errno.h>

#include <net/if.h>
#include <arpa/inet.h>

#include <ifaddrs.h>

#include <stdbool.h>

#include <time.h>

#include "../config.h"

#include "../capture_framework.h"

#include <ubertooth/ubertooth.h>

#define MAX_PACKET_LEN  8192

/* State tracking, put in userdata */
typedef struct {
    ubertooth_t *ut;

    char *interface;
    char *name;

} local_ubertooth_t;

unsigned int u1_chan_to_freq(unsigned int in_chan) {
    if (in_chan == 37)
        return 2402;
    else if (in_chan == 38)
        return 2426;
    else if (in_chan == 39)
        return 2480;

    if (in_chan <= 10)
        return 2404 + (in_chan * 2);

    if (in_chan <= 36)
        return 2428 + ((in_chan - 11) * 2);

    return 0;
}

unsigned int u1_freq_to_chan(unsigned int in_freq) {
    if (in_freq % 2)
        return 0;

    if (in_freq == 2402)
        return 37;

    if (in_freq == 2426)
        return 38;

    if (in_freq == 2480)
        return 39;

    if (in_freq >= 2404 && in_freq < 2426) 
        return (in_freq - 2404) / 2;

    if (in_freq >= 2428 && in_freq < 2480)
        return ((in_freq - 2428) / 2) + 11;

    return 0;
}

/* Convert a string into a local interpretation (which is just frequency)
 */
void *chantranslate_callback(kis_capture_handler_t *caph, char *chanstr) {
    local_ubertooth_t *local_ubertooth = (local_ubertooth_t *) caph->userdata;

    unsigned int *ret_localchan;
    unsigned int parsechan;
    int r;
    char errstr[STATUS_MAX];

    if ((r = sscanf(chanstr, "%u", &parsechan)) != 1) {
        snprintf(errstr, STATUS_MAX, "%s expected a numeric channel or frequency in MHz",
                local_ubertooth->name);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    if ((parsechan > 39 && parsechan < 2402) || parsechan > 2480 || parsechan % 2) {
        snprintf(errstr, STATUS_MAX, "%s expected a numeric channel (0-39) or frequency in "
                "MHz (2402-2480)", local_ubertooth->name);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
        return NULL;
    }

    ret_localchan = (unsigned int *) malloc(sizeof(unsigned int));
    *ret_localchan = 0;

    if (parsechan <= 39)
        *ret_localchan = u1_chan_to_freq(parsechan);
    else
        *ret_localchan = parsechan;

    return ret_localchan;
}

int populate_chanlist(kis_capture_handler_t *caph, char *interface, char *msg, 
        char ***chanlist, size_t *chanlist_sz) {

    /* For now we allow 37, 38, and 39 */
    *chanlist = (char **) malloc(sizeof(char *) * 3);

    (*chanlist)[0] = strdup("37");
    (*chanlist)[1] = strdup("38");
    (*chanlist)[2] = strdup("39");

    *chanlist_sz = 3;

    return 1;
}

int chancontrol_callback(kis_capture_handler_t *caph, uint32_t seqno, void *privchan, char *msg) {
    local_ubertooth_t *local_ubertooth = (local_ubertooth_t *) caph->userdata;

    if (privchan == NULL) {
        return 0;
    }

    unsigned int *channel = (unsigned int *) privchan;

    cmd_set_channel(local_ubertooth->ut->devh, *channel);
   
    return 1;
}


int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {

    char *placeholder = NULL;
    int placeholder_len;
    char *interface;
    int ret;
    char errstr[STATUS_MAX];

    *ret_spectrum = NULL;
    *ret_interface = cf_params_interface_new();

    unsigned int u1_num = 0;
    unsigned int parse_num = 0;

    if (u1_num == 0) {
        return 0;
    }


    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    u1_num = ubertooth_count();

    /* is it an ubertooth? */
    if (strcmp("ubertooth", interface) == 0) {
        parse_num = 0;
    } else if ((ret = sscanf(interface, "ubertooth%u", &parse_num)) != 1) {
        free(interface);
        return 0;
    }

    if (parse_num > u1_num) {
        free(interface);
        return 0;
    }

    populate_chanlist(caph, interface, errstr, 
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));

    (*ret_interface)->hardware = strdup("ubertooth");

    free(interface);

    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strdup(placeholder);
    } else {
        /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
         * and the mac address of the device */
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%12X",
                adler32_csum((unsigned char *) "kismet_cap_linux_wifi", 
                    strlen("kismet_cap_linux_wifi")) & 0xFFFFFFFF,
                parse_num);
        *uuid = strdup(errstr);
    }

    return 1;
}


int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, KismetExternal__Command *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    /* Try to open an interface for monitoring
     * 
     * - Confirm it's an interface, and that it's wireless, by doing a basic 
     *   siocgiwchan channel fetch to see if wireless icotls work on it
     * - Get the current mode - is it already in monitor mode?  If so, we're done
     *   and the world is good
     * - Check and warn about reg domain
     * - Check for rfkill
     * - It's not in monitor mode.  Try to make a VIF via mac80211 for it; this is
     *   by far the most likely to succeed on modern systems.
     * - Figure out if we can name the vif something sane under new interface
     *   naming rules; preferably interfaceXmon
     * - Extract channels
     * - Generate UUID
     * - Initiate pcap
     */

    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;

    char *placeholder = NULL;
    int placeholder_len;
    
    uint8_t hwaddr[6];

    char errstr[STATUS_MAX];
    char errstr2[STATUS_MAX];
    char pcap_errstr[PCAP_ERRBUF_SIZE] = "";

    char ifnam[IFNAMSIZ];

    unsigned int default_ht_20 = 0;
    unsigned int expand_ht_20 = 0;

    *uuid = NULL;
    *dlt = 0;

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    int mode;

    int ret;

    /* char regdom[5]; */

    char driver[32] = "";

    char *localchanstr = NULL;
    local_channel_t *localchan = NULL;

    int filter_locals = 0;
    char *ignore_filter = NULL;
    struct bpf_program bpf;

#ifdef HAVE_LIBNM
    NMClient *nmclient = NULL;
    NMDevice *nmdevice = NULL;
    const GPtrArray *nmdevices;
    GError *nmerror = NULL;
    int i;
#endif

    /* Clean up any existing local state on open; we can get re-opened if we're a 
     * remote source */
    if (local_wifi->interface) {
        free(local_wifi->interface);
        local_wifi->interface = NULL;
    }

    if (local_wifi->cap_interface) {
        free(local_wifi->cap_interface);
        local_wifi->cap_interface = NULL;
    }

    if (local_wifi->name) {
        free(local_wifi->name);
        local_wifi->name = NULL;
    }

    if (local_wifi->mac80211_socket) {
        mac80211_disconnect(local_wifi->mac80211_socket);
        local_wifi->mac80211_socket = NULL;
    }

    if (local_wifi->pd != NULL) {
        pcap_close(local_wifi->pd);
        local_wifi->pd = NULL;
    }

    /* Start processing the open */

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return -1;
    }

    local_wifi->interface = strndup(placeholder, placeholder_len);

    if ((placeholder_len = 
                cf_find_flag(&placeholder, "name", definition)) > 0) {
        local_wifi->name = strndup(placeholder, placeholder_len);
    } else {
        local_wifi->name = strdup(local_wifi->interface);
    }

    /* Do we use verbose diagnostics? */
    if ((placeholder_len = 
                cf_find_flag(&placeholder, "verbose", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->verbose_diagnostics = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->verbose_diagnostics = 1;
        }
    }

    /* Do we use extremely verbose statistics? */
    if ((placeholder_len = 
                cf_find_flag(&placeholder, "statistics", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->verbose_statistics = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->verbose_statistics = 1;
        }
    }

    /* Do we ignore any other interfaces on this device? */
    if ((placeholder_len = 
                cf_find_flag(&placeholder, "filter_locals", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            filter_locals = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            filter_locals = 1;
        }
    }

    /* get the mac address; this should be standard for anything */
    if (ifconfig_get_hwaddr(local_wifi->interface, errstr, hwaddr) < 0) {
        snprintf(msg, STATUS_MAX, "Could not fetch interface address from '%s': %s",
                local_wifi->interface, errstr);
        return -1;
    }

    /* get the driver */
    linux_getsysdrv(local_wifi->interface, driver);

    /* if we're hard rfkilled we can't do anything */
    if (linux_sys_get_rfkill(local_wifi->interface, LINUX_RFKILL_TYPE_HARD) == 1) {
        snprintf(msg, STATUS_MAX, "Interface '%s' is set to hard rfkill; check your "
                "wireless switch if you have one.", local_wifi->interface);
        return -1;
    }

    /* if we're soft rfkilled, unkill us */
    if (linux_sys_get_rfkill(local_wifi->interface, LINUX_RFKILL_TYPE_SOFT) == 1) {
        if (linux_sys_clear_rfkill(local_wifi->interface) < 0) {
            snprintf(msg, STATUS_MAX, "%s unable to activate interface '%s' set to "
                    "soft rfkill", 
                    local_wifi->name, local_wifi->interface);
            return -1;
        }
        snprintf(errstr, STATUS_MAX, "%s removed soft-rfkill and enabled interface '%s'", 
                local_wifi->name, local_wifi->interface);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the mac address of the device */
    if ((placeholder_len = cf_find_flag(&placeholder, "uuid", definition)) > 0) {
        *uuid = strdup(placeholder);
    } else {
        snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
                adler32_csum((unsigned char *) "kismet_cap_linux_wifi", 
                    strlen("kismet_cap_linux_wifi")) & 0xFFFFFFFF,
                hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
                hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
        *uuid = strdup(errstr);
    }

    /* Look up the driver and set any special attributes */
    if (strcmp(driver, "8812au") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the 8812au driver, "
                "which has problems using mac80211 VIF mode.  Disabling mac80211 VIF "
                "creation but retaining mac80211 channel controls.", 
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);

        local_wifi->use_mac80211_vif = 0;
    } else if (strcmp(driver, "8814au") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the 8814au driver, "
                "which has problems using mac80211 VIF mode.  Disabling mac80211 VIF "
                "creation but retaining mac80211 channel controls.", 
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);

        local_wifi->use_mac80211_vif = 0;
    } else if (strcmp(driver, "rtl88xxau") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the rtl88xxau driver, "
                "which has problems using mac80211 VIF mode.  Disabling mac80211 VIF "
                "creation but retaining mac80211 channel controls.",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);
        local_wifi->use_mac80211_vif = 0;
    } else if (strcmp(driver, "rtl8812au") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the rtl8812au driver, "
                "these drivers have been very unreliable and typically will not properly "
                "configure monitor mode.  We'll continue to try, but expect an error "
                "when configuring monitor mode in the next step.  You may have better "
                "luck with the drivers from https://github.com/aircrack-ng/rtl8812au",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);

        local_wifi->use_mac80211_vif = 0;
    } else if (strcmp(driver, "rtl8814au") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the rtl8814au driver, "
                "these drivers have been very unreliable and typically will not properly "
                "configure monitor mode.  We'll continue to try, but expect an error "
                "when configuring monitor mode in the next step.  You may have better "
                "luck with the drivers from https://github.com/aircrack-ng/rtl8812au",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);

        local_wifi->use_mac80211_vif = 0;
    } else if (strcmp(driver, "rtl88x2bu") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the rtl88x2bu driver, "
                "these drivers may have reliability problems, and do not work with VIFs."
                "We'll continue, but there may be errors.", 
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);
        local_wifi->use_mac80211_vif = 0;
        local_wifi->use_mac80211_channels = 0;
    } else if (strcmp(driver, "ath10k_pci") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks to use the ath10k_pci "
                "driver, which is known to report large numbers of invalid packets. "
                "Kismet will attempt to filter these but it is not possible to "
                "cleanly filter all of them; you may see large quantities of spurious "
                "networks.", 
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);
    } else if (strcmp(driver, "brcmfmac") == 0 ||
            strcmp(driver, "brcmfmac_sdio") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks like it is a Broadcom "
                "binary driver found in the Raspberry Pi and some Android devices; "
                "this will ONLY work with the nexmon patches",
                local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);
    } else if (strcmp(driver, "iwlwifi") == 0) {
        snprintf(errstr, STATUS_MAX, "%s interface '%s' looks like an Intel iwlwifi device; under "
                "some driver and firmware versions these have shown significant problems tuning to "
                "HT and VHT channels, with firmware and driver crashes.  Newer kernels seem to solve "
                "this problem; if you're on an older version, set htchannels=false,vhtchannels=false "
                "in your source definition.", local_wifi->name, local_wifi->interface);
        cf_send_warning(caph, errstr);
    }

    /* Try to get it into monitor mode if it isn't already; even mac80211 drivers
     * respond to SIOCGIWMODE */
    if (iwconfig_get_mode(local_wifi->interface, errstr, &mode) < 0) {
        snprintf(msg, STATUS_MAX, "%s unable to get current wireless mode of "
                "interface '%s': %s", local_wifi->name, local_wifi->interface, errstr);
        return -1;
    }

    /* We think we can do something with this interface; if we have support,
     * connect to network manager.  Because it looks like nm keeps trying
     * to deliver reports to us as long as we're connected, DISCONNECT 
     * when we're done! */
#ifdef HAVE_LIBNM
    nmclient = nm_client_new(NULL, &nmerror);

    if (nmclient == NULL) {
        if (nmerror != NULL) {
            snprintf(errstr, STATUS_MAX, "%s could not connect to NetworkManager, "
                    "cannot automatically prevent interface '%s' from being "
                    "modified if NetworkManager is running: %s",
                    local_wifi->name, local_wifi->interface, nmerror->message);
        } else {
            snprintf(errstr, STATUS_MAX, "%s could not connect to NetworkManager, "
                    "cannot automatically prevent interface '%s' from being "
                    "modified if NetworkManager is running.",
                    local_wifi->name, local_wifi->interface);
        }

        cf_send_message(caph, errstr, MSGFLAG_INFO);
    } else if (nm_client_get_nm_running(nmclient)) {
        nmdevices = nm_client_get_devices(nmclient);

        if (nmdevices != NULL) {
            for (i = 0; i < nmdevices->len; i++) {
                const NMDevice *d = g_ptr_array_index(nmdevices, i);

                if (strcmp(nm_device_get_iface((NMDevice *) d), 
                            local_wifi->interface) == 0) {
                    nmdevice = (NMDevice *) d;
                    break;
                }
            }
        }
    }

    if (nmdevice != NULL) {
        local_wifi->reset_nm_management = nm_device_get_managed(nmdevice);

        if (local_wifi->reset_nm_management) {
            snprintf(errstr, STATUS_MAX, "%s telling NetworkManager not to control "
                    "interface '%s': you may need to re-initialize this interface "
                    "later or tell NetworkManager to control it again via 'nmcli'",
                    local_wifi->name, local_wifi->interface);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
            nm_device_set_managed(nmdevice, 0);
        }
    }

    /* We MUST make sure to release the networkmanager object later or we'll leak
     * memory continually as NM queues events for us */

#endif

    if (mode != LINUX_WLEXT_MONITOR) {
        int existing_ifnum;

        /* If we don't use vifs at all, per a priori knowledge of the driver */
        if (local_wifi->use_mac80211_vif == 0) {
            local_wifi->cap_interface = strdup(local_wifi->interface);
        } else {
            /* Look to see if there's a vif= flag specified on the source line; this
             * takes precedence over everything */
            if ((placeholder_len = cf_find_flag(&placeholder, "vif", definition)) > 0) {
                local_wifi->cap_interface = strndup(placeholder, placeholder_len);
            } else {
                /* Look for an existing monitor mode interface */
                existing_ifnum = 
                    find_interface_mode_by_parent(local_wifi->interface, 
                            LINUX_WLEXT_MONITOR);

                if (existing_ifnum >= 0) {
                    if (if_indextoname((unsigned int) existing_ifnum, ifnam) != NULL) {
                        local_wifi->cap_interface = strdup(ifnam);
                        snprintf(errstr, STATUS_MAX, "%s found existing monitor interface "
                                "'%s' for source interface '%s'",
                                local_wifi->name, local_wifi->cap_interface, local_wifi->interface);
                        cf_send_message(caph, errstr, MSGFLAG_INFO);
                    }
                }
            }
        }
            
        /* Otherwise try to come up with a monitor name */
        if (local_wifi->cap_interface == NULL) {
            /* First we'd like to make a monitor vif if we can; can we fit that
             * in our interface name?  */
            if (strlen(local_wifi->interface) + 3 >= IFNAMSIZ) {
                /* Can't fit our name in, we have to make an unrelated name, 
                 * we'll call it 'kismonX'; find the next kismonX interface */
                int ifnum = find_next_ifnum("kismon");

                if (ifnum < 0) {
                    snprintf(msg, STATUS_MAX, "%s could not append 'mon' extension to "
                            "existing interface (%s) and could not find a kismonX "
                            "within 100 tries", local_wifi->name, local_wifi->interface);
                    return -1;
                }

                /* We know we're ok here; we got this by figuring out nothing
                 * matched and then enumerating our own */
                snprintf(ifnam, IFNAMSIZ, "kismon%d", ifnum);
            } else {
                snprintf(ifnam, IFNAMSIZ, "%smon", local_wifi->interface);

                /* We need to check the mode here to make sure we're not in a weird
                 * state where NM retyped our interface or something */
                if (iwconfig_get_mode(ifnam, errstr, &mode) >= 0) {
                    if (mode != LINUX_WLEXT_MONITOR) {
                        snprintf(msg, STATUS_MAX, "%s a monitor vif already exists "
                                "for interface '%s' (%s) but isn't in monitor mode, "
                                "check that NetworkManager isn't hijacking the "
                                "interface, delete the false monitor vif, and try "
                                "again.", local_wifi->name, local_wifi->interface, ifnam);
                        return -1;
                    }
                }
            }

            /* Dup our monitor interface name */
            local_wifi->cap_interface = strdup(ifnam);
        }

    } else {
        /* Otherwise the capinterface equals the interface because it's 
         * already in monitor mode, either because the user specified a monitor
         * vif or the interface is using legacy controls */
        local_wifi->cap_interface = strdup(local_wifi->interface);
    }

    /* We think we know what we're going to capture from now; see if it already 
     * exists and is in monitor mode; we may be doing multiple mode fetches
     * but it doesn't really matter much; it's a simple ioctl and it only
     * happens during open; we tolerate a failure here since the interface
     * might not exist! */

    if (iwconfig_get_mode(local_wifi->interface, errstr, &mode) < 0) 
        mode = -1;

    /* We're going to start interacting with devices - connect to mac80211 if
     * we can; an error here is tolerable because we'll fail properly later
     * on */
    local_wifi->mac80211_socket = NULL;

    if (mac80211_connect(local_wifi->interface, &(local_wifi->mac80211_socket),
                &(local_wifi->mac80211_id), &(local_wifi->mac80211_ifidx),
                errstr) < 0) {

        /* If we didn't get a mac80211 handle we can't use mac80211, period, fall back
         * to trying to use the legacy ioctls */
        local_wifi->use_mac80211_vif = 0;
        local_wifi->use_mac80211_channels = 0;
    } else {
        /* We know we can talk to mac80211; disconnect until we know our capinterface */
        mac80211_disconnect(local_wifi->mac80211_socket);
    }

    /* The interface we want to use isn't in monitor mode - and presumably
     * doesn't exist - so try to make a monitor vif via mac80211; this will 
     * work with all modern drivers and we'd definitely rather do this.
     */
    if (mode != LINUX_WLEXT_MONITOR && local_wifi->use_mac80211_vif &&
            strcmp(local_wifi->interface, local_wifi->cap_interface) != 0) {
        /* First, look for some nl80211 flags in the arguments. */
        unsigned int num_flags = 2;
        unsigned int fi;
        unsigned int *flags = NULL;

        bool fcs = false;
        bool plcp = false;

        if ((placeholder_len = cf_find_flag(&placeholder, "fcsfail", definition)) > 0) {
            if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
                snprintf(errstr, STATUS_MAX,
                        "%s source '%s' configuring monitor interface to pass packets "
                        "which fail FCS checksum", 
                        local_wifi->name, local_wifi->interface);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                num_flags++;
                fcs = true;
            }
        }

        if ((placeholder_len = cf_find_flag(&placeholder, "plcpfail", 
                        definition)) > 0) {
            if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
                snprintf(errstr, STATUS_MAX,
                        "%s source '%s' configuring monitor interface to pass packets "
                        "which fail PLCP checksum", local_wifi->name, local_wifi->interface);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                num_flags++;
                plcp = true;
            }
        }

        /* Allocate the flag list */
        flags = (unsigned int *) malloc(sizeof(unsigned int) * num_flags);

        /* We always set these */
        fi = 0;
        flags[fi++] = NL80211_MNTR_FLAG_CONTROL;
        flags[fi++] = NL80211_MNTR_FLAG_OTHER_BSS;

        if (fcs)
            flags[fi++] = NL80211_MNTR_FLAG_FCSFAIL;

        if (plcp)
            flags[fi++] = NL80211_MNTR_FLAG_PLCPFAIL;

        /* Try to make the monitor vif */
        if (mac80211_create_monitor_vif(local_wifi->interface,
                    local_wifi->cap_interface, flags, num_flags, errstr) < 0) {
            /* Send an error message */
            snprintf(errstr2, STATUS_MAX, "%s failed to create monitor vif interface '%s' "
                    "for interface '%s': %s", 
                    local_wifi->name, local_wifi->cap_interface,
                    local_wifi->interface, errstr);
            cf_send_message(caph, errstr2, MSGFLAG_ERROR);

            /* Forget the cap_iface and set it to the standard iface for the rest of our
             * attempts */
            if (local_wifi->cap_interface != NULL) {
                free(local_wifi->cap_interface);
                local_wifi->cap_interface = strdup(local_wifi->interface);
            }

            /* Try to switch the mode of this interface to monitor; maybe we're a
             * wlext or nexmon device after all.  Do we look like nexmon? */
            if (strcmp(driver, "brcmfmac") == 0 || strcmp(driver, "brcmfmac_sdio") == 0) {
                local_wifi->use_mac80211_vif = 0;

                local_wifi->nexmon = init_nexmon(local_wifi->interface);

                if (local_wifi->nexmon == NULL) {
                    snprintf(msg, STATUS_MAX, "%s interface '%s' looks like a Broadcom "
                            "embedded device but could not be initialized:  You MUST install "
                            "the nexmon patched drivers to use this device with Kismet",
                            local_wifi->name, local_wifi->interface);
                    return -1;
                }

                /* Nexmon needs the interface UP to place it into monitor mode properly.  Weird! */
                if (ifconfig_interface_up(local_wifi->cap_interface, errstr) != 0) {
                    snprintf(msg, STATUS_MAX, "%s could not bring up capture interface '%s', "
                            "check 'dmesg' for possible errors while loading firmware: %s",
                            local_wifi->name, local_wifi->cap_interface, errstr);
                    return -1;
                }

                if (nexmon_monitor(local_wifi->nexmon) < 0) {
                    snprintf(msg, STATUS_MAX, "%s could not place interface '%s' into monitor mode "
                            "via nexmon drivers; you MUST install the patched nexmon drivers to "
                            "use embedded broadcom interfaces with Kismet", local_wifi->name, local_wifi->interface);
                    return -1;
                }

            } else {
                /* Otherwise do we look like wext? */
                if (ifconfig_interface_down(local_wifi->interface, errstr) != 0) {
                    snprintf(msg, STATUS_MAX, "%s could not bring down interface "
                            "'%s' to set monitor mode: %s", 
                            local_wifi->name, local_wifi->interface, errstr);
                    free(flags);
                    return -1;
                }

                if (iwconfig_set_mode(local_wifi->interface, errstr, 
                            LINUX_WLEXT_MONITOR) < 0) {
                    snprintf(errstr2, STATUS_MAX, "%s failed to put interface '%s' in monitor mode: %s", 
                            local_wifi->name, local_wifi->interface, errstr);
                    cf_send_message(caph, errstr2, MSGFLAG_ERROR);

                    /* We've failed at everything */
                    snprintf(msg, STATUS_MAX, "%s failed to create a monitor vif and could "
                            "not set mode of existing interface, unable to put "
                            "'%s' into monitor mode.", local_wifi->name, local_wifi->interface);

                    free(flags);

                    return -1;
                } else {
                    snprintf(errstr2, STATUS_MAX, "%s configured '%s' as monitor mode "
                            "interface instead of using a monitor vif; will continue using "
                            "this interface as the capture source.", 
                            local_wifi->name, local_wifi->interface);
                    cf_send_message(caph, errstr2, MSGFLAG_INFO);

                    local_wifi->use_mac80211_vif = 0;
                }
            }
        } else {
            snprintf(errstr2, STATUS_MAX, "%s successfully created monitor interface "
                    "'%s' for interface '%s'", local_wifi->name, local_wifi->cap_interface,
                    local_wifi->interface);
        }

        free(flags);
    } else if (mode != LINUX_WLEXT_MONITOR) {
        /* Otherwise we want monitor mode but we don't have nl / found the same vif */

        /* fprintf(stderr, "debug - bringing down cap interface %s to set mode\n", local_wifi->cap_interface); */
        if (ifconfig_interface_down(local_wifi->interface, errstr) != 0) {
            snprintf(msg, STATUS_MAX, "%s could not bring down interface "
                    "'%s' to set monitor mode: %s", 
                    local_wifi->name, local_wifi->interface, errstr);
            return -1;
        }

        if (strcmp(driver, "brcmfmac") == 0 || strcmp(driver, "brcmfmac_sdio") == 0) {
            /* Do we look like a nexmon brcm that is too old to handle vifs? */
            local_wifi->use_mac80211_vif = 0;

            local_wifi->nexmon = init_nexmon(local_wifi->interface);

            if (local_wifi->nexmon == NULL) {
                snprintf(msg, STATUS_MAX, "%s interface '%s' looks like a Broadcom "
                        "embedded device but could not be initialized:  You MUST install "
                        "the nexmon patched drivers to use this device with Kismet",
                        local_wifi->name, local_wifi->interface);
                return -1;
            }

            /* Nexmon needs the interface UP to place it into monitor mode properly.  Weird! */
            if (ifconfig_interface_up(local_wifi->cap_interface, errstr) != 0) {
                snprintf(msg, STATUS_MAX, "%s could not bring up capture interface '%s', "
                        "check 'dmesg' for possible errors while loading firmware: %s",
                        local_wifi->name, local_wifi->cap_interface, errstr);
                return -1;
            }

            if (nexmon_monitor(local_wifi->nexmon) < 0) {
                snprintf(msg, STATUS_MAX, "%s could not place interface '%s' into monitor mode "
                        "via nexmon drivers; you MUST install the patched nexmon drivers to "
                        "use embedded broadcom interfaces with Kismet", 
                        local_wifi->name, local_wifi->interface);
                return -1;
            }
        } else if (iwconfig_set_mode(local_wifi->interface, errstr, LINUX_WLEXT_MONITOR) < 0) {
            /* Otherwise we're some sort of non-vif wext? */
            snprintf(errstr2, STATUS_MAX, "%s %s failed to put interface '%s' in monitor mode: %s", 
                    local_wifi->name, local_wifi->cap_interface, local_wifi->interface, errstr);
            cf_send_message(caph, errstr2, MSGFLAG_ERROR);

            /* We've failed at everything */
            snprintf(msg, STATUS_MAX, "%s could not not set mode of existing interface, "
                    "unable to put '%s' into monitor mode.", local_wifi->name, local_wifi->interface);
            return -1;
        } else {
            snprintf(errstr2, STATUS_MAX, "%s %s configured '%s' as monitor mode "
                    "interface instead of using a monitor vif",
                    local_wifi->name, local_wifi->cap_interface, local_wifi->interface);
            cf_send_message(caph, errstr2, MSGFLAG_INFO);
        }
    } else {
        if (strcmp(local_wifi->interface, local_wifi->cap_interface) == 0) {
            snprintf(errstr, STATUS_MAX, "%s interface '%s' is already in monitor mode",
                    local_wifi->name, local_wifi->interface);
        } else {
            snprintf(errstr, STATUS_MAX, "%s monitor interface '%s' already exists for "
                    "capture interface '%s', we'll use that.",
                    local_wifi->name, local_wifi->interface, local_wifi->cap_interface);
        }

        cf_send_message(caph, errstr, MSGFLAG_INFO);
    }

    if (iwconfig_get_mode(local_wifi->cap_interface, errstr, &mode) < 0 ||
            mode != LINUX_WLEXT_MONITOR) {
        snprintf(msg, STATUS_MAX, "%s capture interface '%s' did not enter monitor "
                "mode, something is wrong.", local_wifi->name, local_wifi->cap_interface);
        return -1;
    }


    /* If we're using a vif we need to bring down the parent and bring up the vif;
     * if we're not using a vif we just need to bring up the interface */
    if (strcmp(local_wifi->interface, local_wifi->cap_interface) != 0) {
        int ign_primary = 0;
        if ((placeholder_len = cf_find_flag(&placeholder, "ignoreprimary", 
                        definition)) > 0) {
            if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
                snprintf(errstr, STATUS_MAX,
                        "%s %s/%s ignoring state of primary interface and "
                        "leaving it in an 'up' state; this may cause problems "
                        "with channel hopping.", 
                        local_wifi->name, local_wifi->interface, local_wifi->cap_interface);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                ign_primary = 1;
            }
        }

        if (!ign_primary) {
            snprintf(errstr2, STATUS_MAX, "%s bringing down parent interface '%s'",
                    local_wifi->name, local_wifi->interface);
            cf_send_message(caph, errstr2, MSGFLAG_INFO);

            if (ifconfig_interface_down(local_wifi->interface, errstr) != 0) {
                snprintf(msg, STATUS_MAX, "%s could not bring down parent interface "
                        "'%s' to capture using '%s': %s", 
                        local_wifi->name, local_wifi->interface, local_wifi->cap_interface, errstr);
                return -1;
            }
        }
    }

#ifdef HAVE_LIBNM
    /* Now, if we have a reference to networkmanager, try to tell it to ignore
     * the monitor mode interface, too, in case it gets any ideas */

    if (nmclient != NULL && nm_client_get_nm_running(nmclient)) {
        nmdevices = nm_client_get_devices(nmclient);

        if (nmdevices != NULL) {
            for (i = 0; i < nmdevices->len; i++) {
                const NMDevice *d = g_ptr_array_index(nmdevices, i);

                if (strcmp(nm_device_get_iface((NMDevice *) d), 
                            local_wifi->cap_interface) == 0) {
                    nmdevice = (NMDevice *) d;
                    break;
                }
            }
        }
    }

    if (nmdevice != NULL) {
        local_wifi->reset_nm_management = nm_device_get_managed(nmdevice);

        if (local_wifi->reset_nm_management) {
            snprintf(errstr, STATUS_MAX, "%s telling NetworkManager not to control "
                    "interface '%s': you may need to re-initialize this interface "
                    "later or tell NetworkManager to control it again via 'nmcli'",
                    local_wifi->name, local_wifi->interface);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
            nm_device_set_managed(nmdevice, 0);
        }
    }

    /* We HAVE to unref the nmclient and disconnect here or it keeps trying
     * to deliver messages to us, filling up hundreds of megs of ram */
    if (nmclient != NULL)
        g_object_unref(nmclient);
#endif


    /* fprintf(stderr, "debug - bringing up cap interface %s to capture\n", local_wifi->cap_interface); */

    /* Bring up the cap interface no matter what */
    if (ifconfig_interface_up(local_wifi->cap_interface, errstr) != 0) {
        snprintf(msg, STATUS_MAX, "%s could not bring up capture interface '%s', "
                "check 'dmesg' for possible errors while loading firmware: %s",
                local_wifi->name, local_wifi->cap_interface, errstr);
        return -1;
    }

    /* Do we exclude HT or VHT channels?  Equally, do we force them to be turned on? */
    if ((placeholder_len = 
                cf_find_flag(&placeholder, "ht_channels", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->use_ht_channels = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->use_ht_channels = 1;
        }
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "vht_channels", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            local_wifi->use_vht_channels = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            local_wifi->use_vht_channels = 1;
        } 
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "default_ht20", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            default_ht_20 = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            default_ht_20 = 1;
        }
    }

    if ((placeholder_len =
                cf_find_flag(&placeholder, "expand_ht20", definition)) > 0) {
        if (strncasecmp(placeholder, "false", placeholder_len) == 0) {
            expand_ht_20 = 0;
        } else if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
            expand_ht_20 = 1;
        }
    }

    ret = populate_chanlist(caph, local_wifi->cap_interface, errstr, default_ht_20, expand_ht_20,
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));
    if (ret < 0) {
        snprintf(msg, STATUS_MAX, "%s could not get list of channels from capture "
                "interface '%s' on '%s': %s", local_wifi->name, local_wifi->cap_interface,
                local_wifi->interface, errstr);
        return -1;
    }

    (*ret_interface)->hardware = strdup(driver);

#if 0
    /* Get the iw regdom and see if it makes sense */
    if (linux_sys_get_regdom(regdom) == 0) {
        if (strcmp(regdom, "00") == 0) {
            snprintf(errstr, STATUS_MAX, "%s system-wide wireless regulatory domain "
                    "is set to '00'; this can cause problems setting channels.  If "
                    "you encounter problems, set the regdom with a command like "
                    "'sudo iw reg set US' or whatever country is appropriate for "
                    "your location.", local_wifi->name);
            cf_send_warning(caph, errstr);
        }
    }
#endif

    /* Open the pcap */
    local_wifi->pd = pcap_open_live(local_wifi->cap_interface, 
            MAX_PACKET_LEN, 1, 1000, pcap_errstr);

    if (local_wifi->pd == NULL || strlen(pcap_errstr) != 0) {
        snprintf(msg, STATUS_MAX, "%s could not open capture interface '%s' on '%s' "
                "as a pcap capture: %s", local_wifi->name, local_wifi->cap_interface, 
                local_wifi->interface, pcap_errstr);
        return -1;
    }

    if (filter_locals) {
        if ((ret = build_localdev_filter(&ignore_filter)) > 0) {
            if (ret > 8) {
                snprintf(errstr, STATUS_MAX, "%s found more than 8 local interfaces (%d), limiting "
                        "the exclusion filter to the first 8 because of limited kernel filter memory.",
                        local_wifi->name, ret);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
            }

            if (pcap_compile(local_wifi->pd, &bpf, ignore_filter, 0, 0) < 0) {
                snprintf(errstr, STATUS_MAX, "%s unable to compile filter to exclude other "
                        "local interfaces: %s",
                        local_wifi->name, pcap_geterr(local_wifi->pd));
                cf_send_message(caph, errstr, MSGFLAG_INFO);
            } else {
                if (pcap_setfilter(local_wifi->pd, &bpf) < 0) {
                    snprintf(errstr, STATUS_MAX, "%s unable to assign filter to exclude other "
                            "local interfaces: %s",
                            local_wifi->name, pcap_geterr(local_wifi->pd));
                    cf_send_message(caph, errstr, MSGFLAG_INFO);
                }
            }

            free(ignore_filter);
        }
    }

    local_wifi->datalink_type = pcap_datalink(local_wifi->pd);
    *dlt = local_wifi->datalink_type;

    if (strcmp(local_wifi->interface, local_wifi->cap_interface) != 0) {
        snprintf(msg, STATUS_MAX, "%s Linux Wi-Fi capturing from monitor vif '%s' on "
                "interface '%s'", local_wifi->name, local_wifi->cap_interface, local_wifi->interface);
    } else {
        snprintf(msg, STATUS_MAX, "%s Linux Wi-Fi capturing from interface '%s'",
                local_wifi->name, local_wifi->interface);
    }

    (*ret_interface)->capif = strdup(local_wifi->cap_interface);

    if (local_wifi->use_mac80211_channels) {
        if (mac80211_connect(local_wifi->cap_interface, &(local_wifi->mac80211_socket),
                    &(local_wifi->mac80211_id), &(local_wifi->mac80211_ifidx),
                    errstr) < 0) {
            local_wifi->use_mac80211_channels = 0;
        }
    }

    if ((placeholder_len = 
                cf_find_flag(&placeholder, "channel", definition)) > 0) {
        localchanstr = strndup(placeholder, placeholder_len);

        localchan = 
            (local_channel_t *) chantranslate_callback(caph, localchanstr);

        free(localchanstr);

        if (localchan == NULL) {
            snprintf(msg, STATUS_MAX, 
                    "%s %s/%s could not parse channel= option provided in source "
                    "definition", local_wifi->name, local_wifi->interface, local_wifi->cap_interface);
            return -1;
        }

        local_channel_to_str(localchan, errstr);
        (*ret_interface)->chanset = strdup(errstr);

        snprintf(errstr, STATUS_MAX, "%s setting initial channel to %s", 
                local_wifi->name, (*ret_interface)->chanset);
        cf_send_message(caph, errstr, MSGFLAG_INFO);

        if (chancontrol_callback(caph, 0, localchan, msg) < 0) {
            free(localchan);
            return -1;
        }
    }

    if (localchan != NULL)
        free(localchan);

    return 1;
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, cf_params_list_interface_t ***interfaces) {
    DIR *devdir;
    struct dirent *devfile;
    char errstr[STATUS_MAX];

    /* Basic list of devices */
    typedef struct wifi_list {
        char *device;
        char *flags;
        char *driver;
        struct wifi_list *next;
    } wifi_list_t; 

    wifi_list_t *devs = NULL;
    size_t num_devs = 0;

    unsigned int i;

    char driver[32] = "";

    if ((devdir = opendir("/sys/class/net/")) == NULL) {
        /* fprintf(stderr, "debug - no /sys/class/net dir?\n"); */

        /* Not an error, just nothing to do */
        *interfaces = NULL;
        return 0;
    }

    /* Look at the files in the sys dir and see if they're wi-fi */
    while ((devfile = readdir(devdir)) != NULL) {
        /* if we can get the current channel with simple iwconfig ioctls
         * it's definitely a wifi device; even mac80211 devices respond 
         * to it */
        int mode;
        if (iwconfig_get_mode(devfile->d_name, errstr, &mode) >= 0) {
            wifi_list_t *d = (wifi_list_t *) malloc(sizeof(wifi_list_t));
            num_devs++;
            d->device = strdup(devfile->d_name);
            d->flags = NULL;

            linux_getsysdrv(devfile->d_name, driver);
            d->driver = strdup(driver);

            d->next = devs;
            devs = d;
        }
    }

    closedir(devdir);

    if (num_devs == 0) {
        *interfaces = NULL;
        return 0;
    }

    *interfaces = 
        (cf_params_list_interface_t **) malloc(sizeof(cf_params_list_interface_t *) * num_devs);

    i = 0;

    while (devs != NULL) {
        wifi_list_t *td = devs->next;

        /* Allocate an interface */
        (*interfaces)[i] = (cf_params_list_interface_t *) malloc(sizeof(cf_params_list_interface_t));
        memset((*interfaces)[i], 0, sizeof(cf_params_list_interface_t));

        /* All these strings were strdup'd already so we assign the pointers and let the
         * cleanup of the interface list free them */
        (*interfaces)[i]->interface = devs->device;
        (*interfaces)[i]->flags = devs->flags;
        (*interfaces)[i]->hardware = devs->driver;

        free(devs);
        devs = td;

        i++;
    }

    return num_devs;
}

void pcap_dispatch_cb(u_char *user, const struct pcap_pkthdr *header,
        const u_char *data)  {
    kis_capture_handler_t *caph = (kis_capture_handler_t *) user;
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    int ret;

    /* fprintf(stderr, "debug - pcap_dispatch - got packet %u\n", header->caplen); */

    /* Try repeatedly to send the packet; go into a thread wait state if
     * the write buffer is full & we'll be woken up as soon as it flushes
     * data out in the main select() loop */
    while (1) {
        if ((ret = cf_send_data(caph, 
                        NULL, NULL, NULL,
                        header->ts, 
                        local_wifi->datalink_type,
                        header->caplen, (uint8_t *) data)) < 0) {
            pcap_breakloop(local_wifi->pd);
            cf_send_error(caph, 0, "unable to send DATA frame");
            cf_handler_spindown(caph);
        } else if (ret == 0) {
            /* Go into a wait for the write buffer to get flushed */
            cf_handler_wait_ringbuffer(caph);
            continue;
        } else {
            break;
        }
    }
}

void capture_thread(kis_capture_handler_t *caph) {
    local_wifi_t *local_wifi = (local_wifi_t *) caph->userdata;
    char errstr[PCAP_ERRBUF_SIZE];
    char *pcap_errstr;
    char iferrstr[STATUS_MAX];
    int ifflags = 0, ifret;

    /* Simple capture thread: since we don't care about blocking and 
     * channel control is managed by the channel hopping thread, all we have
     * to do is enter a blocking pcap loop */

    pcap_loop(local_wifi->pd, -1, pcap_dispatch_cb, (u_char *) caph);

    pcap_errstr = pcap_geterr(local_wifi->pd);

    snprintf(errstr, PCAP_ERRBUF_SIZE, "%s interface '%s' closed: %s", 
            local_wifi->name, local_wifi->cap_interface, 
            strlen(pcap_errstr) == 0 ? "interface closed" : pcap_errstr );

    cf_send_error(caph, 0, errstr);

    ifret = ifconfig_get_flags(local_wifi->cap_interface, iferrstr, &ifflags);

    if (ifret < 0 || !(ifflags & IFF_UP)) {
        snprintf(errstr, PCAP_ERRBUF_SIZE, "%s interface '%s' no longer appears to be up; "
                "This can happen when it is unplugged, or another service like DHCP or "
                "NetworKManager has taken over and shut it down on us.", 
                local_wifi->name, local_wifi->cap_interface);
        cf_send_error(caph, 0, errstr);
    }

    cf_handler_spindown(caph);
}

int main(int argc, char *argv[]) {
    local_wifi_t local_wifi = {
        .pd = NULL,
        .interface = NULL,
        .cap_interface = NULL,
        .name = NULL,
        .datalink_type = -1,
        .override_dlt = -1,
        .use_mac80211_vif = 1,
        .use_mac80211_channels = 1,
        .mac80211_socket = NULL,
        .use_ht_channels = 1,
        .use_vht_channels = 1,
        .seq_channel_failure = 0,
        .reset_nm_management = 0,
        .nexmon = NULL,
        .verbose_diagnostics = 0,
        .verbose_statistics = 0,
        .channel_set_ns_avg = 0,
        .channel_set_ns_count = 0,
    };

#ifdef HAVE_LIBNM
    NMClient *nmclient = NULL;
    const GPtrArray *nmdevices;
    GError *nmerror = NULL;
    int i;
#endif

#if 0
    /* Remap stderr so we can log debugging to a file */
    FILE *sterr;
    sterr = fopen("/tmp/capture_linux_wifi.stderr", "a");
    dup2(fileno(sterr), STDERR_FILENO);
    dup2(fileno(sterr), STDOUT_FILENO);
#endif

    /* fprintf(stderr, "CAPTURE_LINUX_WIFI launched on pid %d\n", getpid()); */

    kis_capture_handler_t *caph = cf_handler_init("linuxwifi");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local_wifi);

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    cf_handler_set_listdevices_cb(caph, list_callback);

    /* Set the translation cb */
    cf_handler_set_chantranslate_cb(caph, chantranslate_callback);

    /* Set the control cb */
    cf_handler_set_chancontrol_cb(caph, chancontrol_callback);

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

    /* Set a channel hop spacing of 4 to get the most out of 2.4 overlap;
     * it does nothing and hurts nothing on 5ghz */
    cf_handler_set_hop_shuffle_spacing(caph, 4);

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    /* Support remote capture by launching the remote loop */
    cf_handler_remote_capture(caph);

    /* Jail our ns */
    cf_jail_filesystem(caph);

    /* Strip our privs */
    cf_drop_most_caps(caph);

    cf_handler_loop(caph);

    /* We're done - try to reset the networkmanager awareness of the interface */

#ifdef HAVE_LIBNM
    if (local_wifi.reset_nm_management) {
        nmclient = nm_client_new(NULL, &nmerror);

        if (nmclient != NULL) {
            if (nm_client_get_nm_running(nmclient)) {
                nmdevices = nm_client_get_devices(nmclient);

                if (nmdevices != NULL) {
                    for (i = 0; i < nmdevices->len; i++) {
                        const NMDevice *d = g_ptr_array_index(nmdevices, i);

                        if (strcmp(nm_device_get_iface((NMDevice *) d), 
                                    local_wifi.interface) == 0) {
                            nm_device_set_managed((NMDevice *) d, 1);
                            break;
                        }
                    }
                }
            }

            g_object_unref(nmclient);
        }
    }
#endif

    cf_handler_free(caph);

    return 1;
}

