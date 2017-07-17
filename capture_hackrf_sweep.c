/*
    This file is part of Kismet and of HackRF
   
    HackRF sweep components based on hackrf_sweep.c from the HackRF
    project, 

    Copyright 2016 Dominic Spill <dominicgs@gmail.com>
    Copyright 2016 Mike Walters <mike@flomp.net>
    Copyright 2017 Michael Ossmann <mike@ossmann.com>

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

/* capture_hackrf_sweep
 *
 * Capture binary which interfaces to the HackRF radio to gather spectrum
 * measurement which is then reported to Kismet via the SPECTRUM kv pairs.
 *
 * This binary only needs to run as root if the hackrf device is not writeable
 * by the user (as configured in udev); user access is assumed.
 *
 */

#include <getopt.h>
#include <pthread.h>
#include <fcntl.h>

#include <sched.h>

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

#include "config.h"

#include "simple_datasource_proto.h"
#include "capture_framework.h"


#ifndef BUILD_HACKRF_SWEEP

/* If the required libraries (hackrf and fftw3) are not available, build the 
 * capture binary, but only return errors.
 */


int open_callback(kis_capture_handler_t *, uint32_t, char *,
        char *msg, uint32_t *, char **, simple_cap_proto_frame_t *,
        cf_params_interface_t **, cf_params_spectrum_t **) {

    snprintf(msg, STATUS_MAX, "Kismet was not compiled with the hackrf libraries, "
            "cannot use hackrf_sweep; check the results of ./configure or consult "
            "your distribution documentation"); 
    return -1;
}

int probe_callback(kis_capture_handler_t *, uint32_t, char *,
        char *msg, char **, simple_cap_proto_frame_t *,
        cf_params_interface_t **, cf_params_spectrum_t **) {

    snprintf(msg, STATUS_MAX, "Kismet was not compiled with the hackrf libraries, "
            "cannot use hackrf_sweep; check the results of ./configure or consult "
            "your distribution documentation"); 
    return -1;
}

int list_callback(kis_capture_handler_t *, uint32_t,
        char *, char ***interfaces, char ***flags) {

    *interfaces = NULL;
    *flags = NULL;
    return 0;
}

void capture_thread(kis_capture_handler_t *) {
    return;
}

#else

#include <libhackrf/hackrf.h>
#include <fftw3.h>
#include <inttypes.h>

int probe_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, char **uuid, simple_cap_proto_frame_t *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
    char *placeholder = NULL;
    int placeholder_len;
    char *interface = NULL;
    char *serial = NULL;
    char errstr[STATUS_MAX];
    hackrf_device_list_t *list;
    int x;

    *ret_spectrum = cf_params_spectrum_new();
    *ret_interface = NULL;

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return 0;
    }

    interface = strndup(placeholder, placeholder_len);

    // All hackrfsweeps use 'hackrf' as the interface
    if (strcmp(interface, "hackrf") != 0) {
        snprintf(msg, STATUS_MAX, "Doesn't look like a hackrf");
        return 0;
    }


    if (hackrf_init() != HACKRF_SUCCESS) {
        snprintf(msg, STATUS_MAX, "hackrf_sweep could not initialize libhackrf");
        return 0;
    }

    list = hackrf_device_list();

    if (list == NULL) {
        return 0;
    }

    if (list->devicecount == 0)
        return 0;


    // Figure out if we have a serial #
    if ((placeholder_len = cf_find_flag(&placeholder, "serial", definition)) > 0) {
        serial = strndup(placeholder, placeholder_len);
    } 

    if (serial == NULL && list->devicecount != 1) {
        snprintf(msg, STATUS_MAX, "multiple hackrf devices found, specify serial number");
        hackrf_device_list_free(list);
        hackrf_exit();
        return 0;
    }

    for (x = 0; x < list->devicecount; x++) {
        if (strcmp(serial, list->serial_numbers[x]) == 0) {
            unsigned long s;
            if (sscanf(serial, "%lx", &s) == 1) {
                /* Make a spoofed, but consistent, UUID based on the adler32 of the 
                 * capture name and the serial of the device */
                snprintf(errstr, STATUS_MAX, "%08X-0000-0000-%04lX-%12lX",
                        adler32_csum((unsigned char *) "kismet_cap_hackrf_sweep", 
                            strlen("kismet_cap_hackrf_sweep")) & 0xFFFFFFFF,
                        (s >> 48) & 0xFFFF, s & 0xFFFFFFFFFFFF);
                *uuid = strdup(errstr);

                hackrf_device_list_free(list);
                hackrf_exit();

                return 1;
            }

        }

    }

    hackrf_device_list_free(list);
    hackrf_exit();

    return 0;
}

int open_callback(kis_capture_handler_t *caph, uint32_t seqno, char *definition,
        char *msg, uint32_t *dlt, char **uuid, simple_cap_proto_frame_t *frame,
        cf_params_interface_t **ret_interface,
        cf_params_spectrum_t **ret_spectrum) {
#if 0
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

    *uuid = NULL;
    *dlt = 0;

    *ret_interface = cf_params_interface_new();
    *ret_spectrum = NULL;

    int mode;

    int ret;

    char regdom[4];

    char driver[32] = "";

    char *localchanstr = NULL;
    local_channel_t *localchan = NULL;

#ifdef HAVE_LIBNM
    NMClient *nmclient = NULL;
    NMDevice *nmdevice = NULL;
    const GPtrArray *nmdevices;
    GError *nmerror = NULL;
    int i;
#endif

    if ((placeholder_len = cf_parse_interface(&placeholder, definition)) <= 0) {
        snprintf(msg, STATUS_MAX, "Unable to find interface in definition"); 
        return -1;
    }

    local_wifi->interface = strndup(placeholder, placeholder_len);

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
            snprintf(msg, STATUS_MAX, "Unable to activate interface '%s' set to "
                    "soft rfkill", local_wifi->interface);
            return -1;
        }
        snprintf(errstr, STATUS_MAX, "Removed soft-rfkill and enabled interface '%s'", 
                local_wifi->interface);
        cf_send_message(caph, errstr, MSGFLAG_INFO);
    }

    /* Make a spoofed, but consistent, UUID based on the adler32 of the interface name 
     * and the mac address of the device */
    snprintf(errstr, STATUS_MAX, "%08X-0000-0000-0000-%02X%02X%02X%02X%02X%02X",
            adler32_csum((unsigned char *) "kismet_cap_linux_wifi", 
                strlen("kismet_cap_linux_wifi")) & 0xFFFFFFFF,
            hwaddr[0] & 0xFF, hwaddr[1] & 0xFF, hwaddr[2] & 0xFF,
            hwaddr[3] & 0xFF, hwaddr[4] & 0xFF, hwaddr[5] & 0xFF);
    *uuid = strdup(errstr);

    /* Look up the driver and set any special attributes */
    if (strcmp(driver, "8812au") == 0) {
        snprintf(errstr, STATUS_MAX, "Interface '%s' looks to use the 8812au driver, "
                "which has problems using mac80211 VIF mode.  Disabling mac80211 VIF "
                "creation but retaining mac80211 channel controls.", 
                local_wifi->interface);
        cf_send_warning(caph, errstr, MSGFLAG_INFO, errstr);

        local_wifi->use_mac80211_vif = 0;
    } else if (strcmp(driver, "ath10k_pci") == 0) {
        snprintf(errstr, STATUS_MAX, "Interface '%s' looks to use the ath10k_pci "
                "driver, which is known to report large numbers of invalid packets. "
                "Kismet will attempt to filter these but it is not possible to "
                "cleanly filter all of them; you may see large quantities of spurious "
                "networks.", local_wifi->interface);
        cf_send_warning(caph, errstr, MSGFLAG_INFO, errstr);
    } else if (strcmp(driver, "iwlwifi") == 0) {
        snprintf(errstr, STATUS_MAX, "Interface '%s' looks to use the Intel iwlwifi "
                "driver.  Some Intel Wi-Fi cards encounter problems setting some "
                "channels which can cause the interface to fully reset.",
                local_wifi->interface);
        cf_send_warning(caph, errstr, MSGFLAG_INFO, errstr);
    }

    /* Try to get it into monitor mode if it isn't already; even mac80211 drivers
     * respond to SIOCGIWMODE */
    if (iwconfig_get_mode(local_wifi->interface, errstr, &mode) < 0) {
        snprintf(msg, STATUS_MAX, "Unable to get current wireless mode of "
                "interface '%s': %s", local_wifi->interface, errstr);
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
            snprintf(errstr, STATUS_MAX, "Could not connect to NetworkManager, "
                    "cannot automatically prevent interface '%s' from being "
                    "modified if NetworkManager is running: %s",
                    local_wifi->interface, nmerror->message);
        } else {
            snprintf(errstr, STATUS_MAX, "Could not connect to NetworkManager, "
                    "cannot automatically prevent interface '%s' from being "
                    "modified if NetworkManager is running.",
                    local_wifi->interface);
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
            snprintf(errstr, STATUS_MAX, "Telling NetworkManager not to control "
                    "interface '%s': you may need to re-initialize this interface "
                    "later or tell NetworkManager to control it again via 'nmcli'",
                    local_wifi->interface);
            cf_send_message(caph, errstr, MSGFLAG_INFO);
            nm_device_set_managed(nmdevice, 0);
        }
    }

    /* We HAVE to unref the nmclient and disconnect here or it keeps trying
     * to deliver messages to us, filling up hundreds of megs of ram */
    if (nmclient != NULL)
        g_object_unref(nmclient);

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
                        snprintf(errstr, STATUS_MAX, "Found existing monitor interface "
                                "'%s' for source interface '%s'",
                                local_wifi->cap_interface, local_wifi->interface);
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
                    snprintf(msg, STATUS_MAX, "Could not append 'mon' extension to "
                            "existing interface (%s) and could not find a kismonX "
                            "within 100 tries", local_wifi->interface);
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
                        snprintf(msg, STATUS_MAX, "A monitor vif already exists "
                                "for interface '%s' (%s) but isn't in monitor mode, "
                                "check that NetworkManager isn't hijacking the "
                                "interface, delete the false monitor vif, and try "
                                "again.", local_wifi->interface, ifnam);
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
    local_wifi->mac80211_handle = NULL;
    local_wifi->mac80211_cache = NULL;
    local_wifi->mac80211_family = NULL;

    if (mac80211_connect(local_wifi->interface, &(local_wifi->mac80211_handle),
                &(local_wifi->mac80211_cache), &(local_wifi->mac80211_family),
                errstr) < 0) {
        local_wifi->mac80211_handle = NULL;
        local_wifi->mac80211_cache = NULL;
        local_wifi->mac80211_family = NULL;
    }

    /* If we didn't get a mac80211 handle we can't use mac80211, period, fall back
     * to trying to use the legacy ioctls */
    if (local_wifi->mac80211_handle == NULL) {
        local_wifi->use_mac80211_vif = 0;
        local_wifi->use_mac80211_channels = 0;
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
                        "Source '%s' configuring monitor interface to pass packets "
                        "which fail FCS checksum", local_wifi->interface);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                num_flags++;
                fcs = true;
            }
        }

        if ((placeholder_len = cf_find_flag(&placeholder, "plcpfail", 
                        definition)) > 0) {
            if (strncasecmp(placeholder, "true", placeholder_len) == 0) {
                snprintf(errstr, STATUS_MAX,
                        "Source '%s' configuring monitor interface to pass packets "
                        "which fail PLCP checksum", local_wifi->interface);
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
            snprintf(errstr2, STATUS_MAX, "Failed to create monitor vif interface '%s' "
                    "for interface '%s': %s", local_wifi->cap_interface,
                    local_wifi->interface, errstr);
            cf_send_message(caph, errstr2, MSGFLAG_ERROR);

            /* Try to switch the mode of this interface to monitor; maybe we're a
             * wlext device after all.  It has to be down, first */

            if (ifconfig_interface_down(local_wifi->interface, errstr) != 0) {
                snprintf(msg, STATUS_MAX, "Could not bring down interface "
                        "'%s' to set monitor mode: %s", local_wifi->interface, errstr);
                return -1;
            }

            if (iwconfig_set_mode(local_wifi->interface, errstr, 
                        LINUX_WLEXT_MONITOR) < 0) {
                snprintf(errstr2, STATUS_MAX, "Failed to put interface '%s' in monitor "
                        "mode: %s", local_wifi->interface, errstr);
                cf_send_message(caph, errstr2, MSGFLAG_ERROR);

                /* We've failed at everything */
                snprintf(msg, STATUS_MAX, "Failed to create a monitor vif and could "
                        "not set mode of existing interface, unable to put "
                        "'%s' into monitor mode.", local_wifi->interface);

                free(flags);

                return -1;
            } else {
                snprintf(errstr2, STATUS_MAX, "Configured '%s' as monitor mode "
                        "interface instead of using a monitor vif; will continue using "
                        "this interface as the capture source.", local_wifi->interface);
                cf_send_message(caph, errstr2, MSGFLAG_INFO);

                local_wifi->use_mac80211_vif = 0;
            }
        } else {
            snprintf(errstr2, STATUS_MAX, "Successfully created monitor interface "
                    "'%s' for interface '%s'", local_wifi->cap_interface,
                    local_wifi->interface);
        }

        free(flags);
    } else if (mode != LINUX_WLEXT_MONITOR) {
        /* Otherwise we want monitor mode but we don't have nl / found the same vif */

        /* fprintf(stderr, "debug - bringing down cap interface %s to set mode\n", local_wifi->cap_interface); */
        if (ifconfig_interface_down(local_wifi->interface, errstr) != 0) {
            snprintf(msg, STATUS_MAX, "Could not bring down interface "
                    "'%s' to set monitor mode: %s", local_wifi->interface, errstr);
            return -1;
        }

        if (iwconfig_set_mode(local_wifi->interface, errstr, LINUX_WLEXT_MONITOR) < 0) {
            snprintf(errstr2, STATUS_MAX, "Failed to put interface '%s' in monitor "
                    "mode: %s", local_wifi->interface, errstr);
            cf_send_message(caph, errstr2, MSGFLAG_ERROR);

            /* We've failed at everything */
            snprintf(msg, STATUS_MAX, "Could not not set mode of existing interface, "
                    "unable to put '%s' into monitor mode.", local_wifi->interface);
            return -1;
        } else {
            snprintf(errstr2, STATUS_MAX, "Configured '%s' as monitor mode "
                    "interface instead of using a monitor vif",
                    local_wifi->interface);
            cf_send_message(caph, errstr2, MSGFLAG_INFO);
        }
    } else {
        if (strcmp(local_wifi->interface, local_wifi->cap_interface) == 0) {
            snprintf(errstr, STATUS_MAX, "Interface '%s' is already in monitor mode",
                    local_wifi->interface);
        } else {
            snprintf(errstr, STATUS_MAX, "Monitor interface '%s' already exists for "
                    "capture interface '%s', we'll use that.",
                    local_wifi->interface, local_wifi->cap_interface);
        }

        cf_send_message(caph, errstr, MSGFLAG_INFO);
    }

    if (iwconfig_get_mode(local_wifi->cap_interface, errstr, &mode) < 0 ||
            mode != LINUX_WLEXT_MONITOR) {
        snprintf(msg, STATUS_MAX, "Capture interface '%s' did not enter monitor "
                "mode, something is wrong.", local_wifi->cap_interface);
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
                        "Source '%s' ignoring state of primary interface and "
                        "leaving it in an 'up' state; this may cause problems "
                        "with channel hopping.", local_wifi->interface);
                cf_send_message(caph, errstr, MSGFLAG_INFO);
                ign_primary = 1;
            }
        }

        if (!ign_primary) {
            snprintf(errstr2, STATUS_MAX, "Bringing down parent interface '%s'",
                    local_wifi->interface);
            cf_send_message(caph, errstr2, MSGFLAG_INFO);

            if (ifconfig_interface_down(local_wifi->interface, errstr) != 0) {
                snprintf(msg, STATUS_MAX, "Could not bring down parent interface "
                        "'%s' to capture using '%s': %s", local_wifi->interface,
                        local_wifi->cap_interface, errstr);
                return -1;
            }
        }
    }

    /* fprintf(stderr, "debug - bringing up cap interface %s to capture\n", local_wifi->cap_interface); */

    /* Bring up the cap interface no matter what */
    if (ifconfig_interface_up(local_wifi->cap_interface, errstr) != 0) {
        snprintf(msg, STATUS_MAX, "Could not bring up capture interface '%s', "
                "check 'dmesg' for possible errors while loading firmware: %s",
                local_wifi->cap_interface, errstr);
        return -1;
    }

    ret = populate_chanlist(local_wifi->cap_interface, errstr, 
            &((*ret_interface)->channels), &((*ret_interface)->channels_len));
    if (ret < 0) {
        snprintf(msg, STATUS_MAX, "Could not get list of channels from capture "
                "interface '%s' on '%s': %s", local_wifi->cap_interface,
                local_wifi->interface, errstr);
        return -1;
    }

    /* Get the iw regdom and see if it makes sense */
    if (linux_sys_get_regdom(regdom) == 0) {
        if (strcmp(regdom, "00") == 0) {
            snprintf(errstr, STATUS_MAX, "System-wide wireless regulatory domain "
                    "is set to '00'; this can cause problems setting channels.  If "
                    "you encounter problems, set the regdom with a command like "
                    "'sudo iw reg set US' or whatever country is appropriate for "
                    "your location.");
            cf_send_warning(caph, errstr, MSGFLAG_INFO, errstr);
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
                    "Could not parse channel= option provided in source "
                    "definition");
            return -1;
        }

        local_channel_to_str(localchan, errstr);
        (*ret_interface)->chanset = strdup(errstr);

        snprintf(errstr, STATUS_MAX, "Setting initial channel to %s", 
                (*ret_interface)->chanset);
        cf_send_message(caph, errstr, MSGFLAG_INFO);

        if (chancontrol_callback(caph, 0, localchan, msg) < 0) {
            return -1;
        }
    }

    /* Open the pcap */
    local_wifi->pd = pcap_open_live(local_wifi->cap_interface, 
            MAX_PACKET_LEN, 1, 1000, pcap_errstr);

    if (local_wifi->pd == NULL || strlen(pcap_errstr) != 0) {
        snprintf(msg, STATUS_MAX, "Could not open capture interface '%s' on '%s' "
                "as a pcap capture: %s", local_wifi->cap_interface, 
                local_wifi->interface, pcap_errstr);
        return -1;
    }

    local_wifi->datalink_type = pcap_datalink(local_wifi->pd);
    *dlt = local_wifi->datalink_type;

    if (strcmp(local_wifi->interface, local_wifi->cap_interface) != 0) {
        snprintf(msg, STATUS_MAX, "Linux Wi-Fi capturing from monitor vif '%s' on "
                "interface '%s'", local_wifi->cap_interface, local_wifi->interface);
    } else {
        snprintf(msg, STATUS_MAX, "Linux Wi-Fi capturing from interface '%s'",
                local_wifi->interface);
    }

    (*ret_interface)->capif = strdup(local_wifi->cap_interface);

    return 1;
#endif
}

int list_callback(kis_capture_handler_t *caph, uint32_t seqno,
        char *msg, char ***interfaces, char ***flags) {

    char errstr[STATUS_MAX];
    hackrf_device_list_t *list;

    *interfaces = NULL;
    *flags = NULL;

    int x = 0;

    if (hackrf_init() != HACKRF_SUCCESS) {
        snprintf(msg, STATUS_MAX, "hackrf_sweep could not initialize libhackrf");
        return 0;
    }

    list = hackrf_device_list();

    if (list == NULL) {
        return 0;
    }

    if (list->devicecount == 0)
        return 0;

    *interfaces = (char **) malloc(sizeof(char *) * list->devicecount);
    *flags = (char **) malloc(sizeof(char *) * list->devicecount);

    for (x = 0; x < list->devicecount; x++) {
        *interfaces[x] = strdup("hackrf");

        snprintf(errstr, STATUS_MAX, "serial=%s", list->serial_numbers[x]);
        *flags[x] = strdup(errstr);
    }

    x = list->devicecount;

    hackrf_device_list_free(list);

    hackrf_exit();

    return x;
}

void capture_thread(kis_capture_handler_t *caph) {
#if 0
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

    snprintf(errstr, PCAP_ERRBUF_SIZE, "Interface '%s' closed: %s", 
            local_wifi->cap_interface, 
            strlen(pcap_errstr) == 0 ? "interface closed" : pcap_errstr );

    cf_send_error(caph, errstr);

    ifret = ifconfig_get_flags(local_wifi->cap_interface, iferrstr, &ifflags);

    if (ifret < 0 || !(ifflags & IFF_UP)) {
        snprintf(errstr, PCAP_ERRBUF_SIZE, "Interface '%s' no longer appears to be up; "
                "This can happen when it is unplugged, or another service like DHCP or "
                "NetworKManager has taken over and shut it down on us.", 
                local_wifi->cap_interface);
        cf_send_error(caph, errstr);
    }

    cf_handler_spindown(caph);
#endif
}

#endif


int main(int argc, char *argv[]) {
#if 0
    local_wifi_t local_wifi = {
        .pd = NULL,
        .interface = NULL,
        .cap_interface = NULL,
        .datalink_type = -1,
        .override_dlt = -1,
        .use_mac80211_vif = 1,
        .use_mac80211_channels = 1,
        .mac80211_cache = NULL,
        .mac80211_handle = NULL,
        .mac80211_family = NULL,
        .seq_channel_failure = 0,
        .reset_nm_management = 0,
    };
#endif

    kis_capture_handler_t *caph = cf_handler_init("hackrfsweep");

    if (caph == NULL) {
        fprintf(stderr, "FATAL: Could not allocate basic handler data, your system "
                "is very low on RAM or something is wrong.\n");
        return -1;
    }

#if 0
    /* Set the local data ptr */
    cf_handler_set_userdata(caph, &local_wifi);
#endif

    /* Set the callback for opening  */
    cf_handler_set_open_cb(caph, open_callback);

    /* Set the callback for probing an interface */
    cf_handler_set_probe_cb(caph, probe_callback);

    /* Set the list callback */
    cf_handler_set_listdevices_cb(caph, list_callback);

    /* Set the capture thread */
    cf_handler_set_capture_cb(caph, capture_thread);

    if (cf_handler_parse_opts(caph, argc, argv) < 1) {
        cf_print_help(caph, argv[0]);
        return -1;
    }

    cf_handler_loop(caph);

    cf_handler_free(caph);

    return 1;
}

