/*
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 LLC
 *
 */

#include "wifi_coconut/wifi_coconut.h"
#include "userspace/userspace.h"

struct wifi_coconut_context *init_coconut_context() {
    struct wifi_coconut_context *ctx =
        (struct wifi_coconut_context *) malloc(sizeof(struct wifi_coconut_context));

    if (ctx == NULL)
        return NULL;

    memset(ctx, 0, sizeof(struct wifi_coconut_context));

    pthread_mutex_init(&ctx->diagnostics.mutex, NULL);

    return ctx;
}


/*
 * Map the bus positions to device numbers so we can open
 * them in order.
 */
const int device_number_map[7][4] = {
    { 0, 1, 2, 3 },
    { 4, 5, 6, 7 },
    { 8, 9, 0, 0 },
    { 10, 0, 0, 0 },
    { 13, 0, 0, 0 },
    { 12, 0, 0, 0 },
    { 11, 0, 0, 0 },
};

int find_coconuts_cluster(struct wifi_coconut_context *coconut_context,
        struct userspace_wifi_probe_dev *devicelist,
        struct wifi_coconut **coconut) {

    /*
     * Potential coconuts we've found so far
     */
    struct wifi_coconut *potential_coconuts = NULL;
    struct wifi_coconut *coconut_iter = NULL;
    struct wifi_coconut *matched_coconuts = NULL;
    int root_number = 0;
    int index_offt = 0;
    struct userspace_wifi_probe_dev *device;
    bool continue_descent = true;
    int device_pos_num;
    bool found_partial = false;

    /*
     * Fallback enumeration of just 14 rt2800 radios without looking at the bus path
     */
    int num_raw_devices = 0;
    struct userspace_wifi_probe_dev *raw_devices[14];

    int i;

    for (num_raw_devices = 0; num_raw_devices < 14; num_raw_devices++)
        raw_devices[num_raw_devices] = NULL;
    num_raw_devices = 0;

    while (continue_descent) {
        device = devicelist;

        continue_descent = false;

        while (device) {
            device_pos_num = -1;

#ifdef FIND_DEBUG
            printf("device %x %x bus len %d ", device->device_id_match->idVendor, device->device_id_match->idProduct, device->usb_bus_path_len);
            for (int x = 0; x < device->usb_bus_path_len; x++)
                printf("/%d", device->usb_bus_path[x]);
            printf("\n");
#endif

            /*
             * Immediately exclude anything that isn't homed on a nested hub
             * or doesn't have the right pid/vid;  We don't need to check the
             * driver string because of the vid/pid matching.
             */
            if (device->usb_bus_path_len + index_offt < 2 ||
                    device->device_id_match->idVendor != 0x148f ||
                    device->device_id_match->idProduct != 0x5370) {
#ifdef FIND_DEBUG
                printf("invalid device, bus len too short %d offt %d\n", device->usb_bus_path_len, index_offt);
#endif
                device = device->next;
                continue;
            }

            /*
             * If we have any device which has enough of a path to continue
             * past this cycle, flag to keep going when we're done.
             */
            if (device->usb_bus_path_len - index_offt > 3) {
                continue_descent = true;
                device = device->next;
                continue;
            }

            root_number = device->usb_bus_path[index_offt];

            /* Look for a potential coconut that already matches root */
            coconut_iter = potential_coconuts;
            while (coconut_iter != NULL) {
                if (coconut_iter->coconut_number == root_number)
                    break;

                coconut_iter = coconut_iter->next;
            }

            /* Make a new potential record to populate if this is the first
             * device of this root tree
             */
            if (coconut_iter == NULL) {
                /* Allocate a coconut if it doesn't exist */
                coconut_iter = (struct wifi_coconut *) malloc(sizeof(*coconut_iter));
                if (coconut_iter == NULL) {
                    goto failure;
                }
                memset(coconut_iter, 0, sizeof(*coconut_iter));

#ifdef FIND_DEBUG
                printf("setting up coconut %d\n", root_number);
#endif

                /*
                 * Set up the coconut
                 */
                coconut_iter->coconut_context = coconut_context;
                coconut_iter->coconut_number = root_number;
                coconut_iter->valid = true;
                coconut_iter->bus_count[0] = 4;
                coconut_iter->bus_count[1] = 4;
                coconut_iter->bus_count[2] = 4;
                coconut_iter->bus_count[3] = 2;

                coconut_iter->next = potential_coconuts;
                potential_coconuts = coconut_iter;

                found_partial = true;
            }

            /* Is the coconut already in error? */
            if (!coconut_iter->valid) {
                device = device->next;
                continue;
            }

            /* Is there room in this coconut? */
            if (coconut_iter->device_num >= 14) {
                coconut_iter->valid = false;
                device = device->next;
                continue;
            }

            /* Validate bus layout */
            if (device->usb_bus_path_len - index_offt == 3) {
                if (device->usb_bus_path[index_offt + 1] < 1 ||
                        device->usb_bus_path[index_offt + 1] > 3 ||
                        device->usb_bus_path[index_offt + 2] < 1 ||
                        device->usb_bus_path[index_offt + 2] > 4) {
                    device = device->next;
                    continue;
                }

                if (--coconut_iter->bus_count[device->usb_bus_path[index_offt + 1]] < 0) {
#ifdef FIND_DEBUG
                    printf("coconut no longer valid bus count [%d] negative\n", index_offt + 1);
#endif
                    coconut_iter->valid = false;
                    device = device->next;
                    continue;
                }

                device_pos_num = device_number_map[device->usb_bus_path[index_offt + 1] - 1][device->usb_bus_path[index_offt + 2] - 1];

            } else if (device->usb_bus_path_len - index_offt == 2) {
                if (device->usb_bus_path[index_offt + 1] < 4 ||
                    device->usb_bus_path[index_offt + 1] > 7) {
#ifdef FIND_DEBUG
                    printf("coconut no longer valid, path 2/4-7 violated\n");
#endif
                    coconut_iter->valid = false;
                    device = device->next;
                    continue;
                }

                if (--coconut_iter->bus_count[0] < 0) {
#ifdef FIND_DEBUG
                    printf("coconut no longer valid, bus count [0] negative\n");
#endif
                    coconut_iter->valid = false;
                    device = device->next;
                    continue;
                }

                device_pos_num = device_number_map[device->usb_bus_path[index_offt + 1] - 1][0];
            }

            if (device_pos_num < 0 || device_pos_num >= 14) {
#ifdef FIND_DEBUG
                printf("Got invalid number %d\n", device_pos_num);
#endif
            } else {
                coconut_iter->probed_devices[device_pos_num] = device;
                coconut_iter->device_num++;
            }

            device = device->next;
        }

        /* Merge any coconuts that were valid */
        coconut_iter = potential_coconuts;
        while (coconut_iter != NULL) {
            struct wifi_coconut *tmp;
            tmp = coconut_iter->next;

            if (coconut_iter->valid && coconut_iter->device_num == 14) {
                coconut_iter->next = matched_coconuts;
                matched_coconuts = coconut_iter;

                for (i = 0; i < 14; i++) {
                    if (coconut_iter->probed_devices[i] != NULL) {
                        memcpy(coconut_iter->first_usb_serial, coconut_iter->probed_devices[i]->usb_serial, 64);
                        break;
                    }
                }
            } else {
#ifdef FIND_DEBUG
                printf("Invalid coconut, valid %u device num %u\n", coconut_iter->valid, coconut_iter->device_num);
#endif
                free(coconut_iter);
            }

            coconut_iter = tmp;
        }

        /* Reset the potential list and increment down the path */
        potential_coconuts = NULL;
        index_offt++;
    }

    *coconut = matched_coconuts;

    /* If we didn't find any coconuts on a nested bus, look for just 14 radios.  some platforms
     * like catalina are having real trouble exposing the bus tree through libusb right now.
     */
    if (*coconut == NULL) {
        device = devicelist;
        while (device && num_raw_devices < 14) {
            if (device->device_id_match->idVendor != 0x148f ||
                    device->device_id_match->idProduct != 0x5370) {
                device = device->next;
                continue;
            }

            raw_devices[num_raw_devices] = device;
            num_raw_devices++;
            device = device->next;
        }

        /* If we found at least 14 raw compatible devices, just make a coconut out of them
         * and call it good enough */
        if (num_raw_devices == 14) {
            coconut_iter = (struct wifi_coconut *) malloc(sizeof(*coconut_iter));
            if (coconut_iter == NULL) {
                goto failure;
            }

#ifdef FIND_DEBUG
            printf("Creating catch-all coconut-0 for 14 devices not in the right order\n");
#endif

            memset(coconut_iter, 0, sizeof(*coconut_iter));

            /*
             * Set up the coconut
             */
            coconut_iter->coconut_context = coconut_context;
            coconut_iter->coconut_number = 0;
            coconut_iter->valid = true;

            /*
             * Copy the raw list of devices
             */
            coconut_iter->device_num = 0;
            for (coconut_iter->device_num = 0; coconut_iter->device_num < 14; coconut_iter->device_num++)
                coconut_iter->probed_devices[coconut_iter->device_num] = raw_devices[coconut_iter->device_num];

            coconut_iter->next = NULL;

            *coconut = coconut_iter;

            for (i = 0; i < 14; i++) {
                if (coconut_iter->probed_devices[i] != NULL) {
                    memcpy(coconut_iter->first_usb_serial, coconut_iter->probed_devices[i]->usb_serial, 64);
                    break;
                }
            }
        }
    }

    if (*coconut == NULL) {
        if (found_partial)
            return WIFI_COCONUT_FIND_CLUSTER_PARTIAL;
        return WIFI_COCONUT_FIND_CLUSTER_NONE;
    }

    return WIFI_COCONUT_FIND_CLUSTER_OK;

failure:
#ifdef FIND_DEBUG
    printf("coconut find fell into failure\n");
#endif

    coconut_iter = potential_coconuts;
    while (coconut_iter != NULL) {
        struct wifi_coconut *tmp;

        tmp = coconut_iter;
        coconut_iter = coconut_iter->next;
        free(tmp);
    }

    coconut_iter = matched_coconuts;
    while (coconut_iter != NULL) {
        struct wifi_coconut *tmp;

        tmp = coconut_iter;
        coconut_iter = coconut_iter->next;
        free(tmp);
    }

    return -ENOMEM;
}

void free_coconuts(struct wifi_coconut *coconuts) {
    struct wifi_coconut *next;

    while (coconuts) {
        next = coconuts->next;
        free(coconuts);
        coconuts = next;
    }
}

void print_wifi_coconuts(struct wifi_coconut *coconuts) {
    struct wifi_coconut *iter = coconuts;

    while (iter != NULL) {
        fprintf(stderr, "I've got a lovely bunch of coconuts!  coconut-%d\n", iter->coconut_number);
        iter = iter->next;
    }
}

int coconut_search_and_open(struct wifi_coconut_context *coconut_context,
        bool wait_for_coconut, int coconut_number,
        int (*status_callback)(struct wifi_coconut_context *, void *, int, int, struct wifi_coconut *),
        void *cb_aux) {
    struct userspace_wifi_probe_dev *probed;
    int probed_count;
    struct wifi_coconut *coconuts = NULL, *ci = NULL;
    int r, d, htch;

    while (1) {
        probed_count = userspace_wifi_probe(coconut_context->context, &probed);

        if (probed_count == 0) {
            if (status_callback != NULL) {
                r = (*status_callback)(coconut_context, cb_aux, WIFI_COCONUT_SEARCH_STATE_NO_RADIOS, -1, NULL);

                /* Override waiting for a coconut if the callback returns a 'do not
                 * continue'; such as running as non-root */
                if (r < 0)
                    return WIFI_COCONUT_SEARCH_STATE_NO_RADIOS;
            }

            if (!wait_for_coconut)
                return WIFI_COCONUT_SEARCH_STATE_NO_RADIOS;

            sleep(1);
            continue;
        }

        r = find_coconuts_cluster(coconut_context, probed, &coconuts);

        if (coconuts == NULL) {
            userspace_wifi_free_probe(probed);
            probed = NULL;

            /*
             * We actually ignore the cluster return value here; we'd only
             * have gotten this far if we found SOME usb radios, just not what
             * we need.
             */

            if (status_callback != NULL) {
                r = (*status_callback)(coconut_context, cb_aux, WIFI_COCONUT_SEARCH_STATE_NO_COCONUT, -1, NULL);

                /* Allow the callback to reject a continued wait */
                if (r < 0)
                    return WIFI_COCONUT_SEARCH_STATE_NO_COCONUT;
            }

            if (!wait_for_coconut)
                return WIFI_COCONUT_SEARCH_STATE_NO_COCONUT;

            sleep(1);
            continue;
        }

        if (status_callback != NULL) {
            r = (*status_callback)(coconut_context, cb_aux, WIFI_COCONUT_SEARCH_STATE_LIST, -1, coconuts);

            if (r < 0)
                return WIFI_COCONUT_SEARCH_STATE_ERROR;
        }

        if (coconut_number >= 0) {
            ci = coconuts;

            while (ci != NULL) {
                if (ci->coconut_number == coconut_number) {
                    coconut_context->coconut = ci;
                    coconut_context->coconut_number = coconut_number;
                    coconut_context->coconuts = coconuts;
                    break;
                }

                ci = ci->next;
            }
        } else {
            coconut_context->coconut = coconuts;
            coconut_context->coconuts = coconuts;
            coconut_context->coconut_number = coconuts->coconut_number;
        }

        if (coconut_context->coconut == NULL) {
            free_coconuts(coconuts);
            userspace_wifi_free_probe(probed);

            if (status_callback != NULL) {
                r = (*status_callback)(coconut_context, cb_aux, WIFI_COCONUT_SEARCH_STATE_MISMATCH, -1, NULL);

                if (r < 0)
                    return WIFI_COCONUT_SEARCH_STATE_MISMATCH;

            }

            if (!wait_for_coconut)
                return WIFI_COCONUT_SEARCH_STATE_MISMATCH;

            sleep(1);
            continue;
        }

        /* Otherwise we've got a coconut assigned, drop out of the spinloop
         * and move to opening */
        break;
    }

    if (status_callback != NULL)
        (*status_callback)(coconut_context, cb_aux, WIFI_COCONUT_SEARCH_STATE_FOUND, -1, NULL);

    /* We might need to handle partial devices */
    for (d = 0; d < 14; d++) {
        if (coconut_context->coconut->probed_devices[d] == NULL) {
            if (status_callback != NULL)
                (*status_callback)(coconut_context, cb_aux, WIFI_COCONUT_SEARCH_STATE_NO_DEV, d, NULL);
            continue;
        }

        /* TODO how do we handle channel mapping w partial devices? */

        r = userspace_wifi_device_open(coconut_context->context,
                coconut_context->coconut->probed_devices[d],
                &coconut_context->coconut->active_devices[d]);

        /*
         * If we failed to open, and have a callback, call it and use that to
         * decide if we abort opening entirely; otherwise, abort opening the
         * rest of the coconut and fail out
         */
        if (r < 0) {
            if (status_callback != NULL) {
                if ((*status_callback)(coconut_context, cb_aux, WIFI_COCONUT_SEARCH_STATE_DEV_ERROR, d, NULL) < 0) {
                    coconut_context->coconut = NULL;
                    free_coconuts(coconuts);
                    userspace_wifi_free_probe(probed);
                    return WIFI_COCONUT_SEARCH_STATE_ERROR;
                }

                continue;
            } else {
                coconut_context->coconut = NULL;
                free_coconuts(coconuts);
                userspace_wifi_free_probe(probed);
                return WIFI_COCONUT_SEARCH_STATE_ERROR;
            }
        }

        userspace_wifi_device_set_id(coconut_context->context,
                coconut_context->coconut->active_devices[d], d);

        if (!coconut_context->ht40 || d < 12) {
            userspace_wifi_device_set_channel(coconut_context->context,
                    coconut_context->coconut->active_devices[d],
                    d + 1,
                    NL80211_CHAN_WIDTH_20);
        } else {
            if (d == 12)
                htch = 1;
            if (d == 13)
                htch = 11;

            userspace_wifi_device_set_channel(coconut_context->context,
                    coconut_context->coconut->active_devices[d],
                    htch,
                    NL80211_CHAN_WIDTH_40);
        }

        if (coconut_context->disable_leds)
            userspace_wifi_device_set_led(coconut_context->context,
                    coconut_context->coconut->active_devices[d], false);
        else
            userspace_wifi_device_set_led(coconut_context->context,
                    coconut_context->coconut->active_devices[d], true);

        if (!coconut_context->disable_blink)
            userspace_wifi_device_enable_led_control(coconut_context->context,
                    coconut_context->coconut->active_devices[d]);

        if (status_callback != NULL)
            (*status_callback)(coconut_context, cb_aux, WIFI_COCONUT_SEARCH_STATE_DEV_OPENED, d, NULL);
    }

   if (status_callback != NULL)
       (*status_callback)(coconut_context, cb_aux, WIFI_COCONUT_SEARCH_STATE_DONE, -1, NULL);

   return WIFI_COCONUT_SEARCH_STATE_DONE;
}

/*
 * Open all the devices in a wifi coconut, setting each one to a channel
 */
int open_wifi_coconut(struct wifi_coconut_context *coconut_context, struct wifi_coconut *coconut) {
    int d;
    int r;
    int htch;

    coconut_context->coconut = coconut;

    if (!coconut_context->quiet)
        printf("Opening coconut with %d devices\n", coconut->device_num);

    for (d = 0; d < 14; d++) {
        if (coconut_context->coconut->probed_devices[d] == NULL) {
            if (!coconut_context->quiet)
                printf("Device %d null!\n", d);
            continue;
        }

        if (!coconut_context->quiet) {
            if (!coconut_context->quiet) {
                fprintf(stderr, "Opening Coconut-%d #%d... ", coconut->coconut_number, d + 1);
                fflush(stderr);
            }
        }

        r = userspace_wifi_device_open(coconut->coconut_context->context,
                coconut->probed_devices[d], &coconut->active_devices[d]);

        if (r != 0) {
            if (!coconut_context->quiet)
                printf("Failed to open device %d: %d %s\n", d, r, strerror(r));
            return -1;
        }

        userspace_wifi_device_set_id(coconut->coconut_context->context,
                coconut->active_devices[d], d);

        if (!coconut_context->ht40 || d < 12) {
            userspace_wifi_device_set_channel(coconut->coconut_context->context,
                    coconut->active_devices[d],
                    d + 1,
                    NL80211_CHAN_WIDTH_20);
        } else {
            if (d == 12)
                htch = 1;
            if (d == 13)
                htch = 11;

            userspace_wifi_device_set_channel(coconut->coconut_context->context,
                    coconut->active_devices[d],
                    htch,
                    NL80211_CHAN_WIDTH_40);
        }

        if (coconut_context->disable_leds)
            userspace_wifi_device_set_led(coconut->coconut_context->context,
                    coconut->active_devices[d], false);
        else
            userspace_wifi_device_set_led(coconut->coconut_context->context,
                    coconut->active_devices[d], true);

        if (!coconut_context->disable_blink)
            userspace_wifi_device_enable_led_control(coconut->coconut_context->context,
                    coconut->active_devices[d]);

        if (!coconut_context->quiet) {
            fprintf(stderr, "OK!\n");
            fflush(stderr);
        }

    }

    return 0;
}

/*
 * Activate all the devices in a wifi coconut
 */
int start_wifi_coconut_capture(struct wifi_coconut_context *coconut_context) {
    int d;

    for (d = 0; d < 14; d++) {
        if (coconut_context->coconut->active_devices[d] == NULL) {
            fprintf(stderr, "debug - missing active device %d\n", d);
            continue;
        }

        /*
         * If LEDs are inverted, turn off LEDs once we've enumerated all the radios.
         */
        if (coconut_context->invert_leds)
            userspace_wifi_device_set_led(coconut_context->context,
                    coconut_context->coconut->active_devices[d], false);

        userspace_wifi_device_start_capture(coconut_context->context,
                coconut_context->coconut->active_devices[d]);
    }

    return 0;
}

