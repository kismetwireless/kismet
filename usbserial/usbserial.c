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

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "usbserial.h"

/* Quectel's usual layout for its Qualcomm modules; interface 4 is QMI / RmNet and
 * isn't a serial port */
static const usbserial_role_t quectel_roles[] = {
    { 0, "diag" },
    { 1, "nmea" },
    { 2, "at" },
    { 3, "modem" },
    { 0, NULL },
};

static const usbserial_model_t models[] = {
    { 0x2c7c, 0x0121, "Quectel EC21", quectel_roles },
    { 0x2c7c, 0x0125, "Quectel EC25 / EG25-G", quectel_roles },
    { 0x2c7c, 0x0191, "Quectel EG91", quectel_roles },
    { 0x2c7c, 0x0195, "Quectel EG95", quectel_roles },
    { 0x2c7c, 0x0296, "Quectel BG96", quectel_roles },
    { 0x2c7c, 0x0306, "Quectel EP06 / EG06 / EM06", quectel_roles },
    { 0x2c7c, 0x0512, "Quectel EG12 / EM12 / EG18", quectel_roles },
    { 0x2c7c, 0x0800, "Quectel RM500Q / RM502Q", quectel_roles },
    { 0x2c7c, 0x0801, "Quectel RM520N", quectel_roles },
};

#define CDC_SET_CONTROL_LINE_STATE  0x22
#define CDC_LINE_DTR                0x01
#define CDC_LINE_RTS                0x02

struct usbserial_port {
    usbserial_dev_t *dev;

    uint8_t ifnum;
    const char *role;

    uint8_t ep_in;
    uint8_t ep_out;
    uint8_t ep_intr;
    uint16_t out_maxpkt;
    uint16_t intr_maxpkt;

    /* CDC style port which takes the line state request */
    int acm;
    int claimed;
    /* Qualcomm DIAG: one HDLC frame per transfer; the modem drops the rest of a
     * transfer after its first frame */
    int one_frame;

    struct libusb_transfer *rx[USBSERIAL_RX_XFERS];
    struct libusb_transfer *intr;
    struct libusb_transfer *tx;

    /* Send queue; a ring, protected by the device lock */
    uint8_t *txq;
    size_t txq_head;
    size_t txq_len;

    int tx_busy;
    /* The transfer in flight is a zero length packet ending the last one */
    int tx_zlp;
};

struct usbserial_dev {
    libusb_context *ctx;
    libusb_device_handle *handle;
    const usbserial_model_t *model;

    usbserial_port_t ports[USBSERIAL_MAX_PORTS];
    size_t num_ports;

    pthread_mutex_t lock;
    pthread_t event_thread;
    int thread_running;

    /* Transfers submitted and not yet completed */
    int inflight;
    int stopping;
    int failed;
    int cancelled;

    /* Why it failed; a generic transfer error is checked against the device being
     * unplugged before it's reported, since macOS reports an unplug that way */
    char fail_reason[128];
    int fail_unknown;

    usbserial_rx_cb_t rx_cb;
    usbserial_err_cb_t err_cb;
    void *aux;
};

const usbserial_model_t *usbserial_find_model(uint16_t vid, uint16_t pid) {
    size_t i;

    for (i = 0; i < sizeof(models) / sizeof(models[0]); i++) {
        if (models[i].vid == vid && models[i].pid == pid)
            return &models[i];
    }

    return NULL;
}

static const char *model_role(const usbserial_model_t *model, uint8_t ifnum) {
    const usbserial_role_t *r;

    for (r = model->roles; r->role != NULL; r++) {
        if (r->ifnum == ifnum)
            return r->role;
    }

    return NULL;
}

int usbserial_list(FILE *out) {
    libusb_context *ctx = NULL;
    libusb_device **list = NULL;
    ssize_t n, i;
    int found = 0;

    if (libusb_init(&ctx) != 0)
        return -1;

    n = libusb_get_device_list(ctx, &list);

    for (i = 0; i < n; i++) {
        struct libusb_device_descriptor dd;
        const usbserial_model_t *model;

        if (libusb_get_device_descriptor(list[i], &dd) != 0)
            continue;

        if ((model = usbserial_find_model(dd.idVendor, dd.idProduct)) == NULL)
            continue;

        fprintf(out, "%04x:%04x bus %u addr %u  %s\n", dd.idVendor, dd.idProduct,
                libusb_get_bus_number(list[i]), libusb_get_device_address(list[i]),
                model->name);
        found++;
    }

    if (n >= 0)
        libusb_free_device_list(list, 1);
    libusb_exit(ctx);

    return found;
}

/* Whether a host driver has an interface; macOS can't say, and there a claim
 * simply fails when one does */
static int iface_driver(libusb_device_handle *h, uint8_t ifnum) {
    int r;

    if (h == NULL)
        return -1;

    r = libusb_kernel_driver_active(h, ifnum);

#ifdef __APPLE__
    /* macOS also reports an interface another program has claimed as driver
     * active, and these interfaces have no host driver there; the claim tells */
    if (r == 1 || r == LIBUSB_ERROR_NOT_SUPPORTED)
        return 0;
#endif
    if (r == 0 || r == 1)
        return r;
    return -1;
}

int usbserial_enum(usbserial_enum_cb_t cb, void *aux) {
    libusb_context *ctx = NULL;
    libusb_device **list = NULL;
    ssize_t n, i;
    int found = 0;

    if (libusb_init(&ctx) != 0)
        return -1;

    if ((n = libusb_get_device_list(ctx, &list)) < 0) {
        libusb_exit(ctx);
        return -1;
    }

    for (i = 0; i < n; i++) {
        struct libusb_device_descriptor dd;
        struct libusb_config_descriptor *cd = NULL;
        libusb_device_handle *h = NULL;
        const usbserial_model_t *model;
        int f;

        if (libusb_get_device_descriptor(list[i], &dd) != 0)
            continue;

        if ((model = usbserial_find_model(dd.idVendor, dd.idProduct)) == NULL)
            continue;

        if (libusb_get_active_config_descriptor(list[i], &cd) != 0)
            continue;

        /* Only to ask about host drivers; opening doesn't disturb them */
        if (libusb_open(list[i], &h) != 0)
            h = NULL;

        for (f = 0; f < cd->bNumInterfaces; f++) {
            const struct libusb_interface_descriptor *id;
            usbserial_portinfo_t info;
            const char *role;

            if (cd->interface[f].num_altsetting < 1)
                continue;

            id = &cd->interface[f].altsetting[0];

            if ((role = model_role(model, id->bInterfaceNumber)) == NULL)
                continue;

            memset(&info, 0, sizeof(info));
            info.vid = dd.idVendor;
            info.pid = dd.idProduct;
            info.bus = libusb_get_bus_number(list[i]);
            info.addr = libusb_get_device_address(list[i]);
            info.model = model->name;
            info.ifnum = id->bInterfaceNumber;
            info.role = role;
            info.cls = id->bInterfaceClass;
            info.sub = id->bInterfaceSubClass;
            info.prot = id->bInterfaceProtocol;
            info.driver = iface_driver(h, id->bInterfaceNumber);

            if (cb != NULL)
                cb(&info, aux);
            found++;
        }

        if (h != NULL)
            libusb_close(h);
        libusb_free_config_descriptor(cd);
    }

    libusb_free_device_list(list, 1);
    libusb_exit(ctx);

    return found;
}

/* Find the bulk pair, and the interrupt endpoint if there is one */
static int port_endpoints(usbserial_port_t *port,
        const struct libusb_interface_descriptor *id) {
    int e;

    for (e = 0; e < id->bNumEndpoints; e++) {
        const struct libusb_endpoint_descriptor *ed = &id->endpoint[e];
        int type = ed->bmAttributes & LIBUSB_TRANSFER_TYPE_MASK;
        int in = (ed->bEndpointAddress & LIBUSB_ENDPOINT_DIR_MASK) == LIBUSB_ENDPOINT_IN;

        if (type == LIBUSB_TRANSFER_TYPE_BULK && in && port->ep_in == 0) {
            port->ep_in = ed->bEndpointAddress;
        } else if (type == LIBUSB_TRANSFER_TYPE_BULK && !in && port->ep_out == 0) {
            port->ep_out = ed->bEndpointAddress;
            port->out_maxpkt = ed->wMaxPacketSize & 0x7ff;
        } else if (type == LIBUSB_TRANSFER_TYPE_INTERRUPT && in && port->ep_intr == 0) {
            port->ep_intr = ed->bEndpointAddress;
            port->intr_maxpkt = ed->wMaxPacketSize & 0x7ff;
        }
    }

    if (port->ep_in == 0 || port->ep_out == 0 || port->out_maxpkt == 0)
        return -1;

    /* CDC class-specific descriptors (type 0x24) mark a port that understands the
     * line state request */
    {
        const unsigned char *x = id->extra;
        int left = id->extra_length;

        while (left >= 2 && x[0] >= 2 && x[0] <= left) {
            if (x[1] == 0x24)
                port->acm = 1;
            left -= x[0];
            x += x[0];
        }
    }

    return 0;
}

static int errno_of(int r) {
    switch (r) {
        case LIBUSB_ERROR_ACCESS:
            return EACCES;
        case LIBUSB_ERROR_NO_DEVICE:
        case LIBUSB_ERROR_NOT_FOUND:
            return ENODEV;
        case LIBUSB_ERROR_BUSY:
            return EBUSY;
        case LIBUSB_ERROR_NO_MEM:
            return ENOMEM;
        default:
            return EIO;
    }
}

static void free_dev(usbserial_dev_t *dev) {
    size_t i;
    int x;

    for (i = 0; i < dev->num_ports; i++) {
        usbserial_port_t *port = &dev->ports[i];

        for (x = 0; x < USBSERIAL_RX_XFERS; x++) {
            if (port->rx[x] != NULL) {
                free(port->rx[x]->buffer);
                libusb_free_transfer(port->rx[x]);
            }
        }

        if (port->intr != NULL) {
            free(port->intr->buffer);
            libusb_free_transfer(port->intr);
        }

        if (port->tx != NULL) {
            free(port->tx->buffer);
            libusb_free_transfer(port->tx);
        }

        free(port->txq);

        if (port->claimed)
            libusb_release_interface(dev->handle, port->ifnum);
    }

    if (dev->handle != NULL)
        libusb_close(dev->handle);
    if (dev->ctx != NULL)
        libusb_exit(dev->ctx);

    pthread_mutex_destroy(&dev->lock);
    free(dev);
}

static struct libusb_transfer *alloc_transfer(size_t len) {
    struct libusb_transfer *t = libusb_alloc_transfer(0);

    if (t == NULL)
        return NULL;

    if ((t->buffer = (unsigned char *) malloc(len)) == NULL) {
        libusb_free_transfer(t);
        return NULL;
    }

    t->length = (int) len;
    return t;
}

usbserial_dev_t *usbserial_open(uint16_t vid, uint16_t pid, int bus, int addr,
        char *err, size_t errlen) {
    return usbserial_open_ports(vid, pid, bus, addr, 0, USBSERIAL_DETACH, err, errlen);
}

usbserial_dev_t *usbserial_open_ports(uint16_t vid, uint16_t pid, int bus, int addr,
        uint32_t ifmask, int flags, char *err, size_t errlen) {
    usbserial_dev_t *dev;
    libusb_device **list = NULL;
    libusb_device *match = NULL;
    struct libusb_config_descriptor *cd = NULL;
    ssize_t n, i;
    int r, f, x;

    if ((dev = (usbserial_dev_t *) calloc(1, sizeof(*dev))) == NULL) {
        snprintf(err, errlen, "out of memory");
        errno = ENOMEM;
        return NULL;
    }

    pthread_mutex_init(&dev->lock, NULL);

    if ((r = libusb_init(&dev->ctx)) != 0) {
        snprintf(err, errlen, "libusb init failed: %s", libusb_strerror(r));
        dev->ctx = NULL;
        free_dev(dev);
        errno = EIO;
        return NULL;
    }

    if ((n = libusb_get_device_list(dev->ctx, &list)) < 0) {
        snprintf(err, errlen, "could not list USB devices: %s", libusb_strerror((int) n));
        free_dev(dev);
        errno = EIO;
        return NULL;
    }

    for (i = 0; i < n && match == NULL; i++) {
        struct libusb_device_descriptor dd;
        const usbserial_model_t *model;

        if (libusb_get_device_descriptor(list[i], &dd) != 0)
            continue;

        if (vid != 0 && (dd.idVendor != vid || dd.idProduct != pid))
            continue;

        if (bus >= 0 && libusb_get_bus_number(list[i]) != bus)
            continue;

        if (addr >= 0 && libusb_get_device_address(list[i]) != addr)
            continue;

        if ((model = usbserial_find_model(dd.idVendor, dd.idProduct)) == NULL)
            continue;

        dev->model = model;
        match = list[i];
    }

    if (match == NULL) {
        snprintf(err, errlen, "no supported USB serial device found");
        libusb_free_device_list(list, 1);
        free_dev(dev);
        errno = ENODEV;
        return NULL;
    }

    r = libusb_open(match, &dev->handle);

    if (r == 0)
        r = libusb_get_active_config_descriptor(match, &cd);

    libusb_free_device_list(list, 1);

    if (r != 0) {
        snprintf(err, errlen, "could not open %s: %s", dev->model->name, libusb_strerror(r));
        free_dev(dev);
        errno = errno_of(r);
        return NULL;
    }

    /* On Linux the option driver owns these interfaces; take them back from it while
     * we hold them */
    if (flags & USBSERIAL_DETACH)
        libusb_set_auto_detach_kernel_driver(dev->handle, 1);

    for (f = 0; f < cd->bNumInterfaces && dev->num_ports < USBSERIAL_MAX_PORTS; f++) {
        const struct libusb_interface_descriptor *id;
        usbserial_port_t *port;
        const char *role;

        if (cd->interface[f].num_altsetting < 1)
            continue;

        id = &cd->interface[f].altsetting[0];

        if ((role = model_role(dev->model, id->bInterfaceNumber)) == NULL)
            continue;

        if (ifmask != 0 && (id->bInterfaceNumber >= 32 ||
                    !(ifmask & (1u << id->bInterfaceNumber))))
            continue;

        port = &dev->ports[dev->num_ports];
        memset(port, 0, sizeof(*port));
        port->dev = dev;
        port->ifnum = id->bInterfaceNumber;
        port->role = role;
        port->one_frame = strcmp(role, "diag") == 0;

        if (port_endpoints(port, id) < 0)
            continue;

        dev->num_ports++;
    }

    libusb_free_config_descriptor(cd);

    if (dev->num_ports == 0) {
        snprintf(err, errlen, "%s has none of its expected serial interfaces",
                dev->model->name);
        free_dev(dev);
        errno = ENODEV;
        return NULL;
    }

    for (i = 0; i < (ssize_t) dev->num_ports; i++) {
        usbserial_port_t *port = &dev->ports[i];

        if (!(flags & USBSERIAL_DETACH) && iface_driver(dev->handle, port->ifnum) == 1) {
            snprintf(err, errlen, "interface %u (%s) of %s has a host driver",
                    port->ifnum, port->role, dev->model->name);
            free_dev(dev);
            errno = EBUSY;
            return NULL;
        }

        if ((r = libusb_claim_interface(dev->handle, port->ifnum)) != 0) {
            snprintf(err, errlen, "could not claim interface %u (%s) of %s: %s%s",
                    port->ifnum, port->role, dev->model->name, libusb_strerror(r),
                    r == LIBUSB_ERROR_ACCESS || r == LIBUSB_ERROR_BUSY ?
                    "; is another program using the device?" : "");
            free_dev(dev);
            errno = r == LIBUSB_ERROR_BUSY ? EAGAIN : errno_of(r);
#ifdef __APPLE__
            /* macOS refuses an interface another program holds as ACCESS */
            if (r == LIBUSB_ERROR_ACCESS)
                errno = EAGAIN;
#endif
            return NULL;
        }

        port->claimed = 1;

        for (x = 0; x < USBSERIAL_RX_XFERS; x++) {
            if ((port->rx[x] = alloc_transfer(USBSERIAL_RX_XFER_SIZE)) == NULL)
                break;
        }

        port->tx = alloc_transfer(USBSERIAL_TX_XFER_SIZE);
        port->txq = (uint8_t *) malloc(USBSERIAL_TXQ_SIZE);

        if (port->ep_intr != 0 && port->intr_maxpkt != 0)
            port->intr = alloc_transfer(port->intr_maxpkt);

        if (x < USBSERIAL_RX_XFERS || port->tx == NULL || port->txq == NULL ||
                (port->ep_intr != 0 && port->intr_maxpkt != 0 && port->intr == NULL)) {
            snprintf(err, errlen, "out of memory");
            free_dev(dev);
            errno = ENOMEM;
            return NULL;
        }
    }

    return dev;
}

/* Lock held; the event thread reports it once the transfers are back */
static void fail_locked(usbserial_dev_t *dev, const char *reason, int unknown) {
    if (dev->failed)
        return;

    dev->failed = 1;
    dev->fail_unknown = unknown;
    snprintf(dev->fail_reason, sizeof(dev->fail_reason), "%s", reason);
}

/* Lock held */
static int submit_locked(usbserial_dev_t *dev, struct libusb_transfer *t) {
    int r;

    if (dev->stopping || dev->failed)
        return -1;

    if ((r = libusb_submit_transfer(t)) != 0) {
        if (r == LIBUSB_ERROR_NO_DEVICE)
            fail_locked(dev, "device was removed", 0);
        else
            fail_locked(dev, libusb_strerror(r), 1);
        return -1;
    }

    dev->inflight++;
    return 0;
}

/* Lock held; start the next send if there's queued data and nothing in flight */
static void tx_next_locked(usbserial_port_t *port) {
    size_t len, first;

    if (port->tx_busy || port->txq_len == 0)
        return;

    len = port->txq_len;
    if (len > USBSERIAL_TX_XFER_SIZE)
        len = USBSERIAL_TX_XFER_SIZE;

    /* End the transfer at the first frame's closing flag; a leading lone flag
     * goes with the frame after it */
    if (port->one_frame) {
        size_t i;

        for (i = 1; i < len; i++) {
            if (port->txq[(port->txq_head + i) % USBSERIAL_TXQ_SIZE] == 0x7e) {
                len = i + 1;
                break;
            }
        }
    }

    first = USBSERIAL_TXQ_SIZE - port->txq_head;
    if (first > len)
        first = len;

    memcpy(port->tx->buffer, port->txq + port->txq_head, first);
    memcpy(port->tx->buffer + first, port->txq, len - first);

    port->tx->length = (int) len;
    port->tx_zlp = 0;

    if (submit_locked(port->dev, port->tx) == 0)
        port->tx_busy = 1;
}

static int transfer_status_ok(usbserial_dev_t *dev, struct libusb_transfer *t) {
    switch (t->status) {
        case LIBUSB_TRANSFER_COMPLETED:
        case LIBUSB_TRANSFER_TIMED_OUT:
            return 1;
        case LIBUSB_TRANSFER_CANCELLED:
            return 0;
        case LIBUSB_TRANSFER_NO_DEVICE:
            fail_locked(dev, "device was removed", 0);
            return 0;
        case LIBUSB_TRANSFER_STALL:
            fail_locked(dev, "endpoint stalled", 1);
            return 0;
        default:
            fail_locked(dev, "transfer failed", 1);
            return 0;
    }
}

static void LIBUSB_CALL rx_complete(struct libusb_transfer *t) {
    usbserial_port_t *port = (usbserial_port_t *) t->user_data;
    usbserial_dev_t *dev = port->dev;
    int ok;

    pthread_mutex_lock(&dev->lock);
    dev->inflight--;
    ok = transfer_status_ok(dev, t) && !dev->stopping;
    pthread_mutex_unlock(&dev->lock);

    if (!ok)
        return;

    /* Deliver without the lock, so the callback can queue writes */
    if (t->actual_length > 0 && dev->rx_cb != NULL)
        dev->rx_cb(port, t->buffer, (size_t) t->actual_length, dev->aux);

    pthread_mutex_lock(&dev->lock);
    submit_locked(dev, t);
    pthread_mutex_unlock(&dev->lock);
}

/* CDC serial state notifications; nothing here needs them, but the endpoint is kept
 * drained like a host driver would */
static void LIBUSB_CALL intr_complete(struct libusb_transfer *t) {
    usbserial_port_t *port = (usbserial_port_t *) t->user_data;
    usbserial_dev_t *dev = port->dev;

    pthread_mutex_lock(&dev->lock);
    dev->inflight--;
    if (transfer_status_ok(dev, t))
        submit_locked(dev, t);
    pthread_mutex_unlock(&dev->lock);
}

static void LIBUSB_CALL tx_complete(struct libusb_transfer *t) {
    usbserial_port_t *port = (usbserial_port_t *) t->user_data;
    usbserial_dev_t *dev = port->dev;
    size_t sent;

    pthread_mutex_lock(&dev->lock);
    dev->inflight--;
    port->tx_busy = 0;

    if (!transfer_status_ok(dev, t)) {
        pthread_mutex_unlock(&dev->lock);
        return;
    }

    if (port->tx_zlp) {
        port->tx_zlp = 0;
        tx_next_locked(port);
        pthread_mutex_unlock(&dev->lock);
        return;
    }

    sent = t->actual_length > 0 ? (size_t) t->actual_length : 0;
    if (sent > port->txq_len)
        sent = port->txq_len;

    port->txq_head = (port->txq_head + sent) % USBSERIAL_TXQ_SIZE;
    port->txq_len -= sent;

    /* A send that fills its last packet exactly needs a zero length packet to end it */
    if (sent > 0 && sent == (size_t) t->length && sent % port->out_maxpkt == 0) {
        t->length = 0;
        port->tx_zlp = 1;
        if (submit_locked(dev, t) == 0)
            port->tx_busy = 1;
        pthread_mutex_unlock(&dev->lock);
        return;
    }

    tx_next_locked(port);
    pthread_mutex_unlock(&dev->lock);
}

/* Lock held; cancelling a transfer that isn't in flight is harmless */
static void cancel_all_locked(usbserial_dev_t *dev) {
    size_t i;
    int x;

    if (dev->cancelled)
        return;

    dev->cancelled = 1;

    for (i = 0; i < dev->num_ports; i++) {
        usbserial_port_t *port = &dev->ports[i];

        for (x = 0; x < USBSERIAL_RX_XFERS; x++)
            libusb_cancel_transfer(port->rx[x]);
        if (port->intr != NULL)
            libusb_cancel_transfer(port->intr);
        if (port->tx_busy)
            libusb_cancel_transfer(port->tx);
    }
}

/* Whether the device has been unplugged; only from the event thread with no
 * transfers in flight, since it makes a synchronous request */
static int device_gone(usbserial_dev_t *dev) {
    libusb_device *self = libusb_get_device(dev->handle);
    libusb_device **list = NULL;
    unsigned char status[2];
    ssize_t n, i;
    int r, found = 0;

    r = libusb_control_transfer(dev->handle,
            LIBUSB_ENDPOINT_IN | LIBUSB_REQUEST_TYPE_STANDARD | LIBUSB_RECIPIENT_DEVICE,
            LIBUSB_REQUEST_GET_STATUS, 0, 0, status, sizeof(status), 500);

    if (r == LIBUSB_ERROR_NO_DEVICE)
        return 1;
    if (r >= 0)
        return 0;

    /* Some backends fail the request without saying why; fall back to whether the
     * device is still on the bus */
    if ((n = libusb_get_device_list(dev->ctx, &list)) < 0)
        return 0;

    for (i = 0; i < n; i++) {
        if (list[i] == self) {
            found = 1;
            break;
        }
    }

    libusb_free_device_list(list, 1);

    return !found;
}

static void *event_thread(void *arg) {
    usbserial_dev_t *dev = (usbserial_dev_t *) arg;
    int report = 0;

    while (1) {
        struct timeval tv = { 0, 100000 };
        int done;

        pthread_mutex_lock(&dev->lock);

        /* One failed transfer stops the device; bring the rest back */
        if (dev->failed)
            cancel_all_locked(dev);

        done = (dev->stopping || dev->failed) && dev->inflight == 0;
        report = dev->failed && !dev->stopping;

        pthread_mutex_unlock(&dev->lock);

        if (done)
            break;

        libusb_handle_events_timeout_completed(dev->ctx, &tv, NULL);
    }

    if (report && dev->err_cb != NULL) {
        if (dev->fail_unknown && device_gone(dev))
            snprintf(dev->fail_reason, sizeof(dev->fail_reason), "device was removed");

        dev->err_cb(dev, dev->fail_reason, dev->aux);
    }

    return NULL;
}

int usbserial_start(usbserial_dev_t *dev, usbserial_rx_cb_t rx_cb,
        usbserial_err_cb_t err_cb, void *aux, char *err, size_t errlen) {
    size_t i;
    int x, r;

    dev->rx_cb = rx_cb;
    dev->err_cb = err_cb;
    dev->aux = aux;

    for (i = 0; i < dev->num_ports; i++) {
        usbserial_port_t *port = &dev->ports[i];

        if (!port->acm)
            continue;

        /* Raise DTR / RTS as a host serial driver does on open; some firmware won't
         * answer on the AT ports until it sees DTR */
        r = libusb_control_transfer(dev->handle,
                LIBUSB_REQUEST_TYPE_CLASS | LIBUSB_RECIPIENT_INTERFACE | LIBUSB_ENDPOINT_OUT,
                CDC_SET_CONTROL_LINE_STATE, CDC_LINE_DTR | CDC_LINE_RTS, port->ifnum,
                NULL, 0, 1000);

        if (r < 0 && r != LIBUSB_ERROR_PIPE) {
            snprintf(err, errlen, "could not set the line state on interface %u: %s",
                    port->ifnum, libusb_strerror(r));
            return -1;
        }
    }

    pthread_mutex_lock(&dev->lock);

    for (i = 0; i < dev->num_ports; i++) {
        usbserial_port_t *port = &dev->ports[i];

        for (x = 0; x < USBSERIAL_RX_XFERS; x++) {
            libusb_fill_bulk_transfer(port->rx[x], dev->handle, port->ep_in,
                    port->rx[x]->buffer, USBSERIAL_RX_XFER_SIZE, rx_complete, port, 0);
            submit_locked(dev, port->rx[x]);
        }

        libusb_fill_bulk_transfer(port->tx, dev->handle, port->ep_out, port->tx->buffer,
                0, tx_complete, port, 5000);

        if (port->intr != NULL) {
            libusb_fill_interrupt_transfer(port->intr, dev->handle, port->ep_intr,
                    port->intr->buffer, port->intr_maxpkt, intr_complete, port, 0);
            submit_locked(dev, port->intr);
        }
    }

    if (dev->failed) {
        pthread_mutex_unlock(&dev->lock);
        snprintf(err, errlen, "could not start reading from the device");
        return -1;
    }

    pthread_mutex_unlock(&dev->lock);

    if (pthread_create(&dev->event_thread, NULL, event_thread, dev) != 0) {
        snprintf(err, errlen, "could not start the USB event thread: %s", strerror(errno));
        return -1;
    }

    dev->thread_running = 1;
    return 0;
}

void usbserial_close(usbserial_dev_t *dev) {
    if (dev == NULL)
        return;

    pthread_mutex_lock(&dev->lock);
    dev->stopping = 1;
    cancel_all_locked(dev);
    pthread_mutex_unlock(&dev->lock);

    /* The event thread runs until every cancelled transfer has come back */
    if (dev->thread_running) {
        pthread_join(dev->event_thread, NULL);
    } else {
        while (1) {
            struct timeval tv = { 0, 100000 };
            int left;

            pthread_mutex_lock(&dev->lock);
            left = dev->inflight;
            pthread_mutex_unlock(&dev->lock);

            if (left == 0)
                break;

            libusb_handle_events_timeout_completed(dev->ctx, &tv, NULL);
        }
    }

    free_dev(dev);
}

size_t usbserial_num_ports(usbserial_dev_t *dev) {
    return dev->num_ports;
}

usbserial_port_t *usbserial_get_port(usbserial_dev_t *dev, size_t n) {
    if (n >= dev->num_ports)
        return NULL;
    return &dev->ports[n];
}

const char *usbserial_model_name(usbserial_dev_t *dev) {
    return dev->model->name;
}

const char *usbserial_port_role(usbserial_port_t *port) {
    return port->role;
}

uint8_t usbserial_port_ifnum(usbserial_port_t *port) {
    return port->ifnum;
}

ssize_t usbserial_write(usbserial_port_t *port, const uint8_t *data, size_t len) {
    usbserial_dev_t *dev = port->dev;
    size_t space, tail, first;

    pthread_mutex_lock(&dev->lock);

    if (dev->failed || dev->stopping) {
        pthread_mutex_unlock(&dev->lock);
        return -1;
    }

    space = USBSERIAL_TXQ_SIZE - port->txq_len;
    if (len > space)
        len = space;

    tail = (port->txq_head + port->txq_len) % USBSERIAL_TXQ_SIZE;
    first = USBSERIAL_TXQ_SIZE - tail;
    if (first > len)
        first = len;

    memcpy(port->txq + tail, data, first);
    memcpy(port->txq, data + first, len - first);
    port->txq_len += len;

    tx_next_locked(port);

    pthread_mutex_unlock(&dev->lock);

    return (ssize_t) len;
}

size_t usbserial_tx_space(usbserial_port_t *port) {
    size_t space;

    pthread_mutex_lock(&port->dev->lock);
    space = USBSERIAL_TXQ_SIZE - port->txq_len;
    pthread_mutex_unlock(&port->dev->lock);

    return space;
}
