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

/* Linux USB core API on libusb */

#include <libusb.h>

#include <kcompat/kcompat.h>
#include <kcompat/host.h>

static libusb_context *kc_usb_ctx;
static pthread_t kc_usb_thread;
static volatile bool kc_usb_running;
static struct usb_driver *kc_usb_drivers;

static void kc_usb_mark_gone(struct usb_device *dev) {
    dev->kc_gone = true;
    dev->state = USB_STATE_NOTATTACHED;
}

static int kc_usb_errno(int r) {
    switch (r) {
        case LIBUSB_ERROR_TIMEOUT:
            return -ETIMEDOUT;
        case LIBUSB_ERROR_NO_DEVICE:
            return -ENODEV;
        case LIBUSB_ERROR_NOT_FOUND:
            return -ENOENT;
        case LIBUSB_ERROR_NO_MEM:
            return -ENOMEM;
        case LIBUSB_ERROR_BUSY:
            return -EBUSY;
        case LIBUSB_ERROR_ACCESS:
            return -EACCES;
        case LIBUSB_ERROR_PIPE:
            return -EPIPE;
        case LIBUSB_ERROR_OVERFLOW:
            return -EOVERFLOW;
        case LIBUSB_ERROR_INVALID_PARAM:
            return -EINVAL;
        case LIBUSB_ERROR_NOT_SUPPORTED:
            return -EOPNOTSUPP;
        default:
            return -EPROTO;
    }
}

void kc_usb_register_driver(struct usb_driver *drv) {
    drv->kc_next = kc_usb_drivers;
    kc_usb_drivers = drv;
}

/* Completions run here, standing in for interrupt context */
static void *kc_usb_event_thread(void *arg) {
    (void) arg;

    kc_current();
    snprintf(current->comm, sizeof(current->comm), "usb-events");

    while (kc_usb_running) {
        struct timeval tv = { 0, 100000 };
        libusb_handle_events_timeout_completed(kc_usb_ctx, &tv, NULL);
    }

    return NULL;
}

int kc_usb_init(void) {
    int r;

    if (kc_usb_ctx != NULL)
        return 0;

    if ((r = kc_runtime_init()) < 0)
        return r;

    if ((r = libusb_init(&kc_usb_ctx)) < 0)
        return kc_usb_errno(r);

    kc_usb_running = true;
    if (pthread_create(&kc_usb_thread, NULL, kc_usb_event_thread, NULL) != 0) {
        libusb_exit(kc_usb_ctx);
        kc_usb_ctx = NULL;
        return -EAGAIN;
    }

    return 0;
}

void kc_usb_exit(void) {
    if (kc_usb_ctx == NULL)
        return;

    kc_usb_running = false;
    libusb_interrupt_event_handler(kc_usb_ctx);
    pthread_join(kc_usb_thread, NULL);
    libusb_exit(kc_usb_ctx);
    kc_usb_ctx = NULL;
}

static bool kc_usb_id_match(const struct usb_device_id *id, const struct libusb_device_descriptor *d,
        const struct libusb_interface_descriptor *intf) {
    if ((id->match_flags & USB_DEVICE_ID_MATCH_VENDOR) && id->idVendor != d->idVendor)
        return false;
    if ((id->match_flags & USB_DEVICE_ID_MATCH_PRODUCT) && id->idProduct != d->idProduct)
        return false;
    if ((id->match_flags & USB_DEVICE_ID_MATCH_INT_CLASS) &&
            (intf == NULL || id->bInterfaceClass != intf->bInterfaceClass))
        return false;
    if ((id->match_flags & USB_DEVICE_ID_MATCH_INT_SUBCLASS) &&
            (intf == NULL || id->bInterfaceSubClass != intf->bInterfaceSubClass))
        return false;
    if ((id->match_flags & USB_DEVICE_ID_MATCH_INT_PROTOCOL) &&
            (intf == NULL || id->bInterfaceProtocol != intf->bInterfaceProtocol))
        return false;
    return true;
}

static enum usb_device_speed kc_usb_speed(int s) {
    switch (s) {
        case LIBUSB_SPEED_LOW:
            return USB_SPEED_LOW;
        case LIBUSB_SPEED_FULL:
            return USB_SPEED_FULL;
        case LIBUSB_SPEED_HIGH:
            return USB_SPEED_HIGH;
        case LIBUSB_SPEED_SUPER:
            return USB_SPEED_SUPER;
        case LIBUSB_SPEED_SUPER_PLUS:
            return USB_SPEED_SUPER_PLUS;
        default:
            return USB_SPEED_UNKNOWN;
    }
}

/* The first registered driver with an ID matching the device and interface */
static const struct usb_device_id *kc_usb_match_driver(const struct libusb_device_descriptor *d,
        const struct libusb_interface_descriptor *intf, const struct usb_driver **drvp) {
    for (const struct usb_driver *drv = kc_usb_drivers; drv != NULL; drv = drv->kc_next) {
        for (const struct usb_device_id *id = drv->id_table; id->match_flags != 0; id++) {
            if (kc_usb_id_match(id, d, intf)) {
                *drvp = drv;
                return id;
            }
        }
    }

    return NULL;
}

int kc_usb_find_devices(struct kc_usb_probe_entry **list) {
    libusb_device **devs;
    ssize_t n;
    int found = 0;

    *list = NULL;

    if (kc_usb_ctx == NULL)
        return -ENODEV;

    if ((n = libusb_get_device_list(kc_usb_ctx, &devs)) < 0)
        return kc_usb_errno((int) n);

    for (ssize_t i = 0; i < n; i++) {
        struct libusb_device_descriptor d;
        struct libusb_config_descriptor *cfg = NULL;
        const struct usb_driver *drv = NULL;
        const struct usb_device_id *id = NULL;
        int nintf = 0, k = 0;

        if (libusb_get_device_descriptor(devs[i], &d) < 0)
            continue;

        if (libusb_get_active_config_descriptor(devs[i], &cfg) == 0)
            nintf = cfg->bNumInterfaces;

        /* Like the kernel, match each interface, so a Wi-Fi interface after Bluetooth ones is
         * found; the first match claims the device.  Without a config, match the device IDs. */
        if (nintf == 0) {
            id = kc_usb_match_driver(&d, NULL, &drv);
        } else {
            for (k = 0; k < nintf && id == NULL; k++)
                if (cfg->interface[k].num_altsetting > 0)
                    id = kc_usb_match_driver(&d, &cfg->interface[k].altsetting[0], &drv);
            k--;
        }

        if (cfg)
            libusb_free_config_descriptor(cfg);

        if (id == NULL)
            continue;

        struct kc_usb_probe_entry *e = calloc(1, sizeof(*e));
        if (e == NULL)
            break;

        uint8_t ports[8];
        int np = libusb_get_port_numbers(devs[i], ports, sizeof(ports));
        int off = snprintf(e->path, sizeof(e->path), "%d", libusb_get_bus_number(devs[i]));
        for (int p = 0; p < np && off < (int) sizeof(e->path); p++)
            off += snprintf(e->path + off, sizeof(e->path) - (size_t) off, "%s%d", p ? "." : "-", ports[p]);

        e->dev = libusb_ref_device(devs[i]);
        e->driver = drv;
        e->id = id;
        e->intf_index = k;
        e->vid = d.idVendor;
        e->pid = d.idProduct;
        e->bus = libusb_get_bus_number(devs[i]);
        e->address = libusb_get_device_address(devs[i]);
        e->speed = kc_usb_speed(libusb_get_device_speed(devs[i]));
        e->next = *list;
        *list = e;
        found++;
    }

    libusb_free_device_list(devs, 1);
    return found;
}

void kc_usb_free_probe(struct kc_usb_probe_entry *list) {
    while (list) {
        struct kc_usb_probe_entry *next = list->next;
        libusb_unref_device(list->dev);
        free(list);
        list = next;
    }
}

static void kc_usb_reset_work(struct work_struct *w) {
    struct usb_device *udev = container_of(w, struct usb_device, kc_reset_work);
    usb_reset_device(udev);
}

static void kc_usb_free_device(struct usb_device *udev) {
    struct usb_interface *intf = udev->kc_intf;

    if (intf) {
        kc_device_release(&intf->dev);
        if (intf->altsetting)
            free(intf->altsetting->endpoint);
        free(intf->altsetting);
        free(intf);
    }

    if (udev->kc_handle)
        libusb_close(udev->kc_handle);
    if (udev->kc_dev)
        libusb_unref_device(udev->kc_dev);

    kc_device_release(&udev->dev);
    free(udev->product);
    free(udev->manufacturer);
    free(udev->serial);
    free(udev);
}

static char *kc_usb_get_string(libusb_device_handle *h, uint8_t idx) {
    unsigned char buf[128];

    if (idx == 0 || libusb_get_string_descriptor_ascii(h, idx, buf, sizeof(buf)) <= 0)
        return NULL;

    return strdup((const char *) buf);
}

/* On Linux the kernel's own driver may be bound to the interface.  libusb's auto-detach
 * detaches it on claim and reattaches it on release; where that's unavailable, detach by
 * hand and reattach in kc_usb_reattach_kernel. */
static int kc_usb_detach_kernel(struct usb_device *udev, int ifnum) {
    int r = libusb_kernel_driver_active(udev->kc_handle, ifnum);

    /* Not supported on this platform, or nothing bound */
    if (r <= 0)
        return 0;

    dev_info(&udev->dev, "detaching kernel driver from interface %d\n", ifnum);

    if (libusb_set_auto_detach_kernel_driver(udev->kc_handle, 1) == LIBUSB_SUCCESS)
        return 0;

    if ((r = libusb_detach_kernel_driver(udev->kc_handle, ifnum)) < 0 && r != LIBUSB_ERROR_NOT_FOUND) {
        dev_err(&udev->dev, "could not detach kernel driver from interface %d: %s\n", ifnum,
                libusb_strerror(r));
        return kc_usb_errno(r);
    }

    udev->kc_reattach = (r == LIBUSB_SUCCESS);
    return 0;
}

static void kc_usb_reattach_kernel(struct usb_device *udev, int ifnum) {
    if (!udev->kc_reattach)
        return;

    udev->kc_reattach = false;
    if (!udev->kc_gone)
        libusb_attach_kernel_driver(udev->kc_handle, ifnum);
}

int kc_usb_probe_device(const struct kc_usb_probe_entry *entry, struct usb_interface **intfp) {
    struct libusb_device_descriptor d;
    struct libusb_config_descriptor *cfg = NULL;
    struct usb_device *udev;
    struct usb_interface *intf;
    int r;

    *intfp = NULL;

    if ((udev = calloc(1, sizeof(*udev))) == NULL)
        return -ENOMEM;

    udev->kc_dev = libusb_ref_device(entry->dev);
    udev->devnum = entry->address;
    udev->speed = (enum usb_device_speed) entry->speed;
    udev->state = USB_STATE_CONFIGURED;
    snprintf(udev->devpath, sizeof(udev->devpath), "%s", entry->path);
    udev->bus = &udev->kc_bus;
    /* No scatter-gather; drivers use linear buffers */
    udev->kc_bus.sg_tablesize = 0;
    kc_device_init(&udev->dev, NULL, entry->path);
    INIT_WORK(&udev->kc_reset_work, kc_usb_reset_work);

    if ((r = libusb_get_device_descriptor(entry->dev, &d)) < 0 ||
            (r = libusb_get_active_config_descriptor(entry->dev, &cfg)) < 0) {
        r = kc_usb_errno(r);
        goto fail;
    }

    udev->descriptor.bLength = d.bLength;
    udev->descriptor.bDescriptorType = d.bDescriptorType;
    udev->descriptor.bcdUSB = cpu_to_le16(d.bcdUSB);
    udev->descriptor.bDeviceClass = d.bDeviceClass;
    udev->descriptor.bMaxPacketSize0 = d.bMaxPacketSize0;
    udev->descriptor.idVendor = cpu_to_le16(d.idVendor);
    udev->descriptor.idProduct = cpu_to_le16(d.idProduct);
    udev->descriptor.bcdDevice = cpu_to_le16(d.bcdDevice);
    udev->descriptor.bNumConfigurations = d.bNumConfigurations;

    /* SuperSpeed encodes ep0's max packet as a power of two */
    udev->ep0.desc.wMaxPacketSize = cpu_to_le16(udev->speed >= USB_SPEED_SUPER ?
            (1u << d.bMaxPacketSize0) : d.bMaxPacketSize0);

    /* The config may have changed since the device was listed */
    if (entry->intf_index < 0 || entry->intf_index >= cfg->bNumInterfaces ||
            cfg->interface[entry->intf_index].num_altsetting < 1 ||
            !kc_usb_id_match(entry->id, &d, &cfg->interface[entry->intf_index].altsetting[0])) {
        r = -ENODEV;
        goto fail;
    }

    const struct libusb_interface_descriptor *lid = &cfg->interface[entry->intf_index].altsetting[0];

    if ((intf = calloc(1, sizeof(*intf))) == NULL ||
            (intf->altsetting = calloc(1, sizeof(*intf->altsetting))) == NULL ||
            (intf->altsetting->endpoint = calloc(lid->bNumEndpoints ? lid->bNumEndpoints : 1,
                                                 sizeof(struct usb_host_endpoint))) == NULL) {
        if (intf) {
            free(intf->altsetting);
            free(intf);
        }
        r = -ENOMEM;
        goto fail;
    }

    udev->kc_intf = intf;
    intf->kc_udev = udev;
    intf->kc_driver = entry->driver;
    intf->cur_altsetting = intf->altsetting;
    intf->num_altsetting = 1;

    char iname[64];
    snprintf(iname, sizeof(iname), "%s:1.%d", entry->path, lid->bInterfaceNumber);
    kc_device_init(&intf->dev, &udev->dev, iname);

    struct usb_interface_descriptor *id = &intf->altsetting->desc;
    id->bLength = lid->bLength;
    id->bDescriptorType = lid->bDescriptorType;
    id->bInterfaceNumber = lid->bInterfaceNumber;
    id->bAlternateSetting = lid->bAlternateSetting;
    id->bNumEndpoints = lid->bNumEndpoints;
    id->bInterfaceClass = lid->bInterfaceClass;
    id->bInterfaceSubClass = lid->bInterfaceSubClass;
    id->bInterfaceProtocol = lid->bInterfaceProtocol;

    for (int i = 0; i < lid->bNumEndpoints; i++) {
        struct usb_host_endpoint *ep = &intf->altsetting->endpoint[i];
        const struct libusb_endpoint_descriptor *le = &lid->endpoint[i];

        ep->desc.bLength = le->bLength;
        ep->desc.bDescriptorType = le->bDescriptorType;
        ep->desc.bEndpointAddress = le->bEndpointAddress;
        ep->desc.bmAttributes = le->bmAttributes;
        ep->desc.wMaxPacketSize = cpu_to_le16(le->wMaxPacketSize);
        ep->desc.bInterval = le->bInterval;

        if (le->bEndpointAddress & USB_DIR_IN)
            udev->ep_in[le->bEndpointAddress & 0xf] = ep;
        else
            udev->ep_out[le->bEndpointAddress & 0xf] = ep;
    }

    libusb_free_config_descriptor(cfg);
    cfg = NULL;

    if ((r = libusb_open(entry->dev, &udev->kc_handle)) < 0) {
        if (r == LIBUSB_ERROR_ACCESS)
            dev_err(&udev->dev, "no permission to open the USB device; run as root or "
                    "grant access with a udev rule\n");
        r = kc_usb_errno(r);
        goto fail;
    }

    udev->product = kc_usb_get_string(udev->kc_handle, d.iProduct);
    udev->manufacturer = kc_usb_get_string(udev->kc_handle, d.iManufacturer);
    udev->serial = kc_usb_get_string(udev->kc_handle, d.iSerialNumber);

    if ((r = kc_usb_detach_kernel(udev, id->bInterfaceNumber)) < 0)
        goto fail;

    if ((r = libusb_claim_interface(udev->kc_handle, id->bInterfaceNumber)) < 0) {
        dev_err(&udev->dev, "could not claim interface %d: %s%s\n", id->bInterfaceNumber,
                libusb_strerror(r), r == LIBUSB_ERROR_BUSY ? " (in use by another program)" : "");
        r = kc_usb_errno(r);
        kc_usb_reattach_kernel(udev, id->bInterfaceNumber);
        goto fail;
    }

    if ((r = entry->driver->probe(intf, entry->id)) < 0) {
        libusb_release_interface(udev->kc_handle, id->bInterfaceNumber);
        kc_usb_reattach_kernel(udev, id->bInterfaceNumber);
        goto fail;
    }

    *intfp = intf;
    return 0;

fail:
    if (cfg)
        libusb_free_config_descriptor(cfg);
    kc_usb_free_device(udev);
    return r;
}

void kc_usb_disconnect(struct usb_interface *intf) {
    struct usb_device *udev = intf->kc_udev;

    if (intf->kc_driver && intf->kc_driver->disconnect)
        intf->kc_driver->disconnect(intf);

    cancel_work_sync(&udev->kc_reset_work);
    libusb_release_interface(udev->kc_handle, intf->altsetting->desc.bInterfaceNumber);
    kc_usb_reattach_kernel(udev, intf->altsetting->desc.bInterfaceNumber);
    kc_usb_free_device(udev);
}

int usb_maxpacket(struct usb_device *udev, unsigned int pipe) {
    unsigned int ep = usb_pipeendpoint(pipe);
    struct usb_host_endpoint *e;

    if (ep == 0)
        return le16_to_cpu(udev->ep0.desc.wMaxPacketSize);

    e = usb_pipein(pipe) ? udev->ep_in[ep] : udev->ep_out[ep];
    return e ? usb_endpoint_maxp(&e->desc) : 0;
}

int usb_control_msg(struct usb_device *dev, unsigned int pipe, u8 request, u8 requesttype,
        u16 value, u16 index, void *data, u16 size, int timeout) {
    int r;
    (void) pipe;

    if (dev->kc_gone)
        return -ENODEV;

    r = libusb_control_transfer(dev->kc_handle, requesttype, request, value, index, data, size,
            (unsigned int) timeout);

    if (r == LIBUSB_ERROR_NO_DEVICE)
        kc_usb_mark_gone(dev);

    return r < 0 ? kc_usb_errno(r) : r;
}

static unsigned char kc_pipe_ep(unsigned int pipe) {
    return (unsigned char) (usb_pipeendpoint(pipe) | (usb_pipein(pipe) ? LIBUSB_ENDPOINT_IN : 0));
}

int usb_bulk_msg(struct usb_device *dev, unsigned int pipe, void *data, int len, int *actual,
        int timeout) {
    int got = 0, r;

    if (dev->kc_gone)
        return -ENODEV;

    r = libusb_bulk_transfer(dev->kc_handle, kc_pipe_ep(pipe), data, len, &got, (unsigned int) timeout);

    if (actual)
        *actual = got;

    if (r == LIBUSB_ERROR_NO_DEVICE)
        kc_usb_mark_gone(dev);

    return r < 0 ? kc_usb_errno(r) : 0;
}

/* Resets the device; a device which re-enumerates is treated as gone */
int usb_reset_device(struct usb_device *dev) {
    int r;

    if (dev->kc_gone)
        return -ENODEV;

    r = libusb_reset_device(dev->kc_handle);

    if (r == LIBUSB_ERROR_NOT_FOUND || r == LIBUSB_ERROR_NO_DEVICE) {
        dev_err(&dev->dev, "device re-enumerated after reset");
        kc_usb_mark_gone(dev);
        return -ENODEV;
    }

    if (r < 0)
        return kc_usb_errno(r);

    /* A reset drops the claim on some platforms, and a kernel driver may rebind meanwhile */
    if (dev->kc_intf) {
        int ifnum = dev->kc_intf->altsetting->desc.bInterfaceNumber;

        if ((r = kc_usb_detach_kernel(dev, ifnum)) < 0)
            return r;

        r = libusb_claim_interface(dev->kc_handle, ifnum);
        if (r < 0) {
            dev_err(&dev->dev, "could not reclaim interface %d after reset: %s\n", ifnum,
                    libusb_strerror(r));
            return kc_usb_errno(r);
        }
    }

    return 0;
}

void usb_queue_reset_device(struct usb_interface *intf) {
    schedule_work(&intf->kc_udev->kc_reset_work);
}

int usb_string(struct usb_device *dev, int index, char *buf, size_t size) {
    int r = libusb_get_string_descriptor_ascii(dev->kc_handle, (uint8_t) index, (unsigned char *) buf,
            (int) size);
    return r < 0 ? kc_usb_errno(r) : r;
}

/* URBs */
void usb_init_urb(struct urb *urb) {
    memset(urb, 0, sizeof(*urb));
    pthread_mutex_init(&urb->kc_lock, NULL);
    pthread_cond_init(&urb->kc_cond, NULL);
    urb->kc_refs = 1;
}

struct urb *usb_alloc_urb(int iso_packets, gfp_t flags) {
    struct urb *urb;
    (void) iso_packets;
    (void) flags;

    if ((urb = malloc(sizeof(*urb))) == NULL)
        return NULL;

    usb_init_urb(urb);
    urb->kc_allocated = true;
    return urb;
}

static void kc_urb_release(struct urb *urb) {
    if (urb->kc_xfer)
        libusb_free_transfer(urb->kc_xfer);

    if (urb->transfer_flags & URB_FREE_BUFFER)
        free(urb->transfer_buffer);

    if (urb->kc_allocated) {
        pthread_mutex_destroy(&urb->kc_lock);
        pthread_cond_destroy(&urb->kc_cond);
        free(urb);
    }
}

/* Drops a reference with kc_lock held; true when it was the last */
static bool kc_urb_put_locked(struct urb *urb) {
    if (WARN_ON(urb->kc_refs <= 0))
        return false;
    return --urb->kc_refs == 0;
}

struct urb *usb_get_urb(struct urb *urb) {
    if (urb) {
        pthread_mutex_lock(&urb->kc_lock);
        urb->kc_refs++;
        pthread_mutex_unlock(&urb->kc_lock);
    }
    return urb;
}

/* As in the kernel, a submitted URB holds its own reference, so freeing it doesn't cancel
 * the transfer; it's released after its completion handler runs.  Drivers kill or poison
 * URBs whose buffers they're about to free. */
void usb_free_urb(struct urb *urb) {
    bool last;

    if (urb == NULL)
        return;

    pthread_mutex_lock(&urb->kc_lock);
    last = kc_urb_put_locked(urb);
    pthread_mutex_unlock(&urb->kc_lock);

    if (last)
        kc_urb_release(urb);
}

static int kc_urb_status(const struct libusb_transfer *x, const struct urb *urb) {
    switch (x->status) {
        case LIBUSB_TRANSFER_COMPLETED:
            if ((urb->transfer_flags & URB_SHORT_NOT_OK) && x->actual_length < x->length)
                return -EREMOTEIO;
            return 0;
        case LIBUSB_TRANSFER_CANCELLED:
            return -ENOENT;
        case LIBUSB_TRANSFER_NO_DEVICE:
            return -ESHUTDOWN;
        case LIBUSB_TRANSFER_TIMED_OUT:
            return -ETIMEDOUT;
        case LIBUSB_TRANSFER_STALL:
            return -EPIPE;
        case LIBUSB_TRANSFER_OVERFLOW:
            return -EOVERFLOW;
        default:
            return -EPROTO;
    }
}

static void LIBUSB_CALL kc_urb_complete(struct libusb_transfer *x) {
    struct urb *urb = x->user_data;

    urb->actual_length = (u32) x->actual_length;
    urb->status = kc_urb_status(x, urb);

    if (x->status == LIBUSB_TRANSFER_NO_DEVICE)
        kc_usb_mark_gone(urb->dev);

    pthread_mutex_lock(&urb->kc_lock);
    urb->kc_active = false;
    urb->kc_in_cb = true;
    pthread_mutex_unlock(&urb->kc_lock);

    if (urb->complete)
        urb->complete(urb);

    /* The handler may have freed the URB or submitted it again; the reference taken when
     * this submission started keeps it valid until here */
    pthread_mutex_lock(&urb->kc_lock);
    urb->kc_in_cb = false;
    pthread_cond_broadcast(&urb->kc_cond);
    bool last = kc_urb_put_locked(urb);
    pthread_mutex_unlock(&urb->kc_lock);

    if (last)
        kc_urb_release(urb);
}

int usb_submit_urb(struct urb *urb, gfp_t flags) {
    struct usb_device *dev = urb->dev;
    int r;
    (void) flags;

    if (dev == NULL || urb->complete == NULL)
        return -EINVAL;

    if (dev->kc_gone)
        return -ENODEV;

    /* Scatter-gather isn't offered */
    if (urb->num_sgs)
        return -EINVAL;

    if (urb->kc_xfer == NULL && (urb->kc_xfer = libusb_alloc_transfer(0)) == NULL)
        return -ENOMEM;

    pthread_mutex_lock(&urb->kc_lock);

    if (urb->kc_reject) {
        pthread_mutex_unlock(&urb->kc_lock);
        return -EPERM;
    }

    if (urb->kc_active) {
        pthread_mutex_unlock(&urb->kc_lock);
        return -EBUSY;
    }

    if (usb_pipetype(urb->pipe) == PIPE_INTERRUPT)
        libusb_fill_interrupt_transfer(urb->kc_xfer, dev->kc_handle, kc_pipe_ep(urb->pipe),
                urb->transfer_buffer, (int) urb->transfer_buffer_length, kc_urb_complete, urb, 0);
    else
        libusb_fill_bulk_transfer(urb->kc_xfer, dev->kc_handle, kc_pipe_ep(urb->pipe),
                urb->transfer_buffer, (int) urb->transfer_buffer_length, kc_urb_complete, urb, 0);

    urb->kc_xfer->flags = (urb->transfer_flags & URB_ZERO_PACKET) ? LIBUSB_TRANSFER_ADD_ZERO_PACKET : 0;
    urb->status = -EINPROGRESS;
    urb->actual_length = 0;

    if ((r = libusb_submit_transfer(urb->kc_xfer)) < 0) {
        pthread_mutex_unlock(&urb->kc_lock);
        if (r == LIBUSB_ERROR_NO_DEVICE)
            kc_usb_mark_gone(dev);
        return kc_usb_errno(r);
    }

    urb->kc_active = true;
    urb->kc_refs++;
    pthread_mutex_unlock(&urb->kc_lock);

    return 0;
}

int usb_unlink_urb(struct urb *urb) {
    int r = -EBUSY;

    pthread_mutex_lock(&urb->kc_lock);
    if (urb->kc_active && urb->kc_xfer)
        r = libusb_cancel_transfer(urb->kc_xfer) == 0 ? -EINPROGRESS : -EBUSY;
    pthread_mutex_unlock(&urb->kc_lock);

    return r;
}

/* Cancels and waits for the completion handler; must not run on the USB event thread */
static void kc_urb_cancel_wait(struct urb *urb) {
    if (pthread_equal(pthread_self(), kc_usb_thread)) {
        WARN_ON(1);
        return;
    }

    if (urb->kc_active && urb->kc_xfer)
        libusb_cancel_transfer(urb->kc_xfer);

    while (urb->kc_active || urb->kc_in_cb)
        pthread_cond_wait(&urb->kc_cond, &urb->kc_lock);
}

void usb_kill_urb(struct urb *urb) {
    if (urb == NULL)
        return;

    pthread_mutex_lock(&urb->kc_lock);
    urb->kc_reject++;
    kc_urb_cancel_wait(urb);
    urb->kc_reject--;
    pthread_mutex_unlock(&urb->kc_lock);
}

void usb_poison_urb(struct urb *urb) {
    if (urb == NULL)
        return;

    pthread_mutex_lock(&urb->kc_lock);
    urb->kc_reject++;
    kc_urb_cancel_wait(urb);
    pthread_mutex_unlock(&urb->kc_lock);
}

void usb_unpoison_urb(struct urb *urb) {
    if (urb == NULL)
        return;

    pthread_mutex_lock(&urb->kc_lock);
    if (urb->kc_reject > 0)
        urb->kc_reject--;
    pthread_mutex_unlock(&urb->kc_lock);
}
