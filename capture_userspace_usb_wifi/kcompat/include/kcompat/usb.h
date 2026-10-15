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

#ifndef __KCOMPAT_USB_H__
#define __KCOMPAT_USB_H__

/* Linux USB core API on libusb.
 *
 * Synchronous control and bulk messages map to libusb synchronous transfers; URBs map to
 * asynchronous libusb transfers whose completions run on the kcompat USB event thread,
 * where the kernel would run them in interrupt context.  Drivers register with
 * module_usb_driver() and are probed by kc_usb_probe_device(). */

#include "skb.h"

struct libusb_device_handle;
struct libusb_device;
struct libusb_transfer;

#define USB_DIR_OUT 0
#define USB_DIR_IN 0x80
#define USB_TYPE_MASK (0x03 << 5)
#define USB_TYPE_STANDARD (0x00 << 5)
#define USB_TYPE_CLASS (0x01 << 5)
#define USB_TYPE_VENDOR (0x02 << 5)
#define USB_RECIP_DEVICE 0x00
#define USB_RECIP_INTERFACE 0x01
#define USB_RECIP_ENDPOINT 0x02
#define USB_RECIP_OTHER 0x03

#define USB_ENDPOINT_NUMBER_MASK 0x0f
#define USB_ENDPOINT_DIR_MASK 0x80
#define USB_ENDPOINT_XFERTYPE_MASK 0x03
#define USB_ENDPOINT_XFER_CONTROL 0
#define USB_ENDPOINT_XFER_ISOC 1
#define USB_ENDPOINT_XFER_BULK 2
#define USB_ENDPOINT_XFER_INT 3
#define USB_CLASS_VENDOR_SPEC 0xff

#define URB_SHORT_NOT_OK 0x0001
#define URB_ZERO_PACKET 0x0040
#define URB_NO_TRANSFER_DMA_MAP 0x0004
#define URB_FREE_BUFFER 0x0100

enum usb_device_speed {
    USB_SPEED_UNKNOWN = 0,
    USB_SPEED_LOW,
    USB_SPEED_FULL,
    USB_SPEED_HIGH,
    USB_SPEED_WIRELESS,
    USB_SPEED_SUPER,
    USB_SPEED_SUPER_PLUS,
};

struct usb_device_descriptor {
    u8 bLength;
    u8 bDescriptorType;
    __le16 bcdUSB;
    u8 bDeviceClass;
    u8 bDeviceSubClass;
    u8 bDeviceProtocol;
    u8 bMaxPacketSize0;
    __le16 idVendor;
    __le16 idProduct;
    __le16 bcdDevice;
    u8 iManufacturer;
    u8 iProduct;
    u8 iSerialNumber;
    u8 bNumConfigurations;
};

struct usb_endpoint_descriptor {
    u8 bLength;
    u8 bDescriptorType;
    u8 bEndpointAddress;
    u8 bmAttributes;
    __le16 wMaxPacketSize;
    u8 bInterval;
};

struct usb_interface_descriptor {
    u8 bLength;
    u8 bDescriptorType;
    u8 bInterfaceNumber;
    u8 bAlternateSetting;
    u8 bNumEndpoints;
    u8 bInterfaceClass;
    u8 bInterfaceSubClass;
    u8 bInterfaceProtocol;
    u8 iInterface;
};

struct usb_host_endpoint {
    struct usb_endpoint_descriptor desc;
};

struct usb_host_interface {
    struct usb_interface_descriptor desc;
    struct usb_host_endpoint *endpoint;
};

struct usb_interface {
    struct usb_host_interface *altsetting;
    struct usb_host_interface *cur_altsetting;
    unsigned int num_altsetting;
    int minor;
    struct device dev;
    /* kcompat */
    struct usb_device *kc_udev;
    const struct usb_driver *kc_driver;
};

struct usb_bus {
    unsigned int sg_tablesize;
    bool no_sg_constraint;
};

struct usb_device {
    int devnum;
    char devpath[16];
    enum usb_device_speed speed;
    struct usb_bus *bus;
    struct device dev;
    struct usb_device_descriptor descriptor;
    struct usb_host_endpoint ep0;
    struct usb_host_endpoint *ep_in[16];
    struct usb_host_endpoint *ep_out[16];
    char *product;
    char *manufacturer;
    char *serial;
    /* kcompat */
    struct libusb_device *kc_dev;
    struct libusb_device_handle *kc_handle;
    struct usb_bus kc_bus;
    struct usb_interface *kc_intf;
    struct work_struct kc_reset_work;
    bool kc_gone;
};

struct urb;
typedef void (*usb_complete_t)(struct urb *);

struct urb {
    struct usb_device *dev;
    unsigned int pipe;
    unsigned int transfer_flags;
    void *transfer_buffer;
    dma_addr_t transfer_dma;
    u32 transfer_buffer_length;
    u32 actual_length;
    int status;
    struct scatterlist *sg;
    int num_sgs;
    unsigned char *setup_packet;
    int interval;
    void *context;
    usb_complete_t complete;
    /* kcompat */
    struct libusb_transfer *kc_xfer;
    pthread_mutex_t kc_lock;
    pthread_cond_t kc_cond;
    /* A libusb transfer is outstanding */
    bool kc_active;
    /* The completion handler is running */
    bool kc_in_cb;
    /* Submissions fail while non-zero (kill or poison in progress) */
    int kc_reject;
    bool kc_allocated;
};

struct usb_device_id {
    u16 match_flags;
    u16 idVendor;
    u16 idProduct;
    u16 bcdDevice_lo;
    u16 bcdDevice_hi;
    u8 bDeviceClass;
    u8 bDeviceSubClass;
    u8 bDeviceProtocol;
    u8 bInterfaceClass;
    u8 bInterfaceSubClass;
    u8 bInterfaceProtocol;
    u8 bInterfaceNumber;
    kernel_ulong_t driver_info;
};

#define USB_DEVICE_ID_MATCH_VENDOR 0x0001
#define USB_DEVICE_ID_MATCH_PRODUCT 0x0002
#define USB_DEVICE_ID_MATCH_INT_CLASS 0x0080
#define USB_DEVICE_ID_MATCH_INT_SUBCLASS 0x0100
#define USB_DEVICE_ID_MATCH_INT_PROTOCOL 0x0200
#define USB_DEVICE_ID_MATCH_DEVICE (USB_DEVICE_ID_MATCH_VENDOR | USB_DEVICE_ID_MATCH_PRODUCT)
#define USB_DEVICE(vend, prod) \
    .match_flags = USB_DEVICE_ID_MATCH_DEVICE, .idVendor = (vend), .idProduct = (prod)
#define USB_DEVICE_AND_INTERFACE_INFO(vend, prod, cl, sc, pr) \
    .match_flags = USB_DEVICE_ID_MATCH_DEVICE | USB_DEVICE_ID_MATCH_INT_CLASS | \
        USB_DEVICE_ID_MATCH_INT_SUBCLASS | USB_DEVICE_ID_MATCH_INT_PROTOCOL, \
    .idVendor = (vend), .idProduct = (prod), .bInterfaceClass = (cl), \
    .bInterfaceSubClass = (sc), .bInterfaceProtocol = (pr)

struct usb_driver {
    const char *name;
    int (*probe)(struct usb_interface *intf, const struct usb_device_id *id);
    void (*disconnect)(struct usb_interface *intf);
    int (*suspend)(struct usb_interface *intf, int message);
    int (*resume)(struct usb_interface *intf);
    int (*reset_resume)(struct usb_interface *intf);
    int (*pre_reset)(struct usb_interface *intf);
    int (*post_reset)(struct usb_interface *intf);
    const struct usb_device_id *id_table;
    unsigned int supports_autosuspend:1;
    unsigned int disable_hub_initiated_lpm:1;
    unsigned int soft_unbind:1;
    struct device_driver driver;
    /* kcompat registry */
    const struct usb_driver *kc_next;
};
typedef struct {
    int event;
} pm_message_t;

void kc_usb_register_driver(struct usb_driver *drv);
#define usb_register(drv) (kc_usb_register_driver(drv), 0)
#define usb_deregister(drv) do { (void) (drv); } while (0)
#define module_usb_driver(drv) \
    static void __attribute__((constructor)) __kc_register_##drv(void) { kc_usb_register_driver(&drv); }

/* Pipes, encoded as in the kernel */
#define PIPE_ISOCHRONOUS 0
#define PIPE_INTERRUPT 1
#define PIPE_CONTROL 2
#define PIPE_BULK 3
static inline unsigned int __create_pipe(struct usb_device *dev, unsigned int endpoint) {
    return ((unsigned int) dev->devnum << 8) | (endpoint << 15);
}
#define usb_sndctrlpipe(dev, ep) ((PIPE_CONTROL << 30) | __create_pipe(dev, ep))
#define usb_rcvctrlpipe(dev, ep) ((PIPE_CONTROL << 30) | __create_pipe(dev, ep) | USB_DIR_IN)
#define usb_sndbulkpipe(dev, ep) ((PIPE_BULK << 30) | __create_pipe(dev, ep))
#define usb_rcvbulkpipe(dev, ep) ((PIPE_BULK << 30) | __create_pipe(dev, ep) | USB_DIR_IN)
#define usb_sndintpipe(dev, ep) ((PIPE_INTERRUPT << 30) | __create_pipe(dev, ep))
#define usb_rcvintpipe(dev, ep) ((PIPE_INTERRUPT << 30) | __create_pipe(dev, ep) | USB_DIR_IN)
#define usb_pipein(pipe) ((pipe) & USB_DIR_IN)
#define usb_pipeout(pipe) (!usb_pipein(pipe))
#define usb_pipeendpoint(pipe) (((pipe) >> 15) & 0xf)
#define usb_pipetype(pipe) (((pipe) >> 30) & 3)
#define usb_pipebulk(pipe) (usb_pipetype(pipe) == PIPE_BULK)

static inline int usb_endpoint_num(const struct usb_endpoint_descriptor *e) {
    return e->bEndpointAddress & USB_ENDPOINT_NUMBER_MASK;
}
static inline int usb_endpoint_type(const struct usb_endpoint_descriptor *e) {
    return e->bmAttributes & USB_ENDPOINT_XFERTYPE_MASK;
}
static inline bool usb_endpoint_dir_in(const struct usb_endpoint_descriptor *e) {
    return (e->bEndpointAddress & USB_ENDPOINT_DIR_MASK) == USB_DIR_IN;
}
static inline bool usb_endpoint_dir_out(const struct usb_endpoint_descriptor *e) { return !usb_endpoint_dir_in(e); }
static inline bool usb_endpoint_xfer_bulk(const struct usb_endpoint_descriptor *e) {
    return usb_endpoint_type(e) == USB_ENDPOINT_XFER_BULK;
}
static inline bool usb_endpoint_xfer_int(const struct usb_endpoint_descriptor *e) {
    return usb_endpoint_type(e) == USB_ENDPOINT_XFER_INT;
}
static inline bool usb_endpoint_is_bulk_in(const struct usb_endpoint_descriptor *e) {
    return usb_endpoint_xfer_bulk(e) && usb_endpoint_dir_in(e);
}
static inline bool usb_endpoint_is_bulk_out(const struct usb_endpoint_descriptor *e) {
    return usb_endpoint_xfer_bulk(e) && usb_endpoint_dir_out(e);
}
static inline bool usb_endpoint_is_int_in(const struct usb_endpoint_descriptor *e) {
    return usb_endpoint_xfer_int(e) && usb_endpoint_dir_in(e);
}
static inline int usb_endpoint_maxp(const struct usb_endpoint_descriptor *e) {
    return le16_to_cpu(e->wMaxPacketSize) & 0x7ff;
}
int usb_maxpacket(struct usb_device *udev, unsigned int pipe);

static inline struct usb_device *interface_to_usbdev(struct usb_interface *intf) { return intf->kc_udev; }
#define to_usb_interface(d) container_of(d, struct usb_interface, dev)
#define to_usb_device(d) container_of(d, struct usb_device, dev)
static inline void *usb_get_intfdata(struct usb_interface *intf) { return dev_get_drvdata(&intf->dev); }
static inline void usb_set_intfdata(struct usb_interface *intf, void *data) { dev_set_drvdata(&intf->dev, data); }
#define usb_get_dev(d) (d)
#define usb_put_dev(d) do { (void) (d); } while (0)
#define usb_enable_autosuspend(d) do { (void) (d); } while (0)
#define usb_disable_autosuspend(d) do { (void) (d); } while (0)
#define usb_autopm_get_interface(i) 0
#define usb_autopm_put_interface(i) do { (void) (i); } while (0)

int usb_control_msg(struct usb_device *dev, unsigned int pipe, u8 request, u8 requesttype,
        u16 value, u16 index, void *data, u16 size, int timeout);
int usb_bulk_msg(struct usb_device *dev, unsigned int pipe, void *data, int len, int *actual,
        int timeout);
#define usb_interrupt_msg usb_bulk_msg
int usb_reset_device(struct usb_device *dev);
void usb_queue_reset_device(struct usb_interface *intf);
int usb_string(struct usb_device *dev, int index, char *buf, size_t size);

struct urb *usb_alloc_urb(int iso_packets, gfp_t flags);
void usb_init_urb(struct urb *urb);
void usb_free_urb(struct urb *urb);
int usb_submit_urb(struct urb *urb, gfp_t flags);
int usb_unlink_urb(struct urb *urb);
void usb_kill_urb(struct urb *urb);
void usb_poison_urb(struct urb *urb);
void usb_unpoison_urb(struct urb *urb);
static inline void usb_fill_bulk_urb(struct urb *urb, struct usb_device *dev, unsigned int pipe,
        void *buf, int len, usb_complete_t complete, void *context) {
    urb->dev = dev; urb->pipe = pipe; urb->transfer_buffer = buf;
    urb->transfer_buffer_length = (u32) len; urb->complete = complete; urb->context = context;
}
#define usb_fill_int_urb(urb, dev, pipe, buf, len, complete, context, interval) \
    do { usb_fill_bulk_urb(urb, dev, pipe, buf, len, complete, context); (urb)->interval = (interval); } while (0)

/* Host side, used by the tool and capture code */
struct kc_usb_probe_entry {
    struct libusb_device *dev;
    const struct usb_driver *driver;
    const struct usb_device_id *id;
    u16 vid;
    u16 pid;
    int bus;
    int address;
    int speed;
    char path[32];
    struct kc_usb_probe_entry *next;
};
int kc_usb_init(void);
void kc_usb_exit(void);
/* Lists devices matching any registered driver; free with kc_usb_free_probe() */
int kc_usb_find_devices(struct kc_usb_probe_entry **list);
void kc_usb_free_probe(struct kc_usb_probe_entry *list);
/* Opens the device and calls the driver's probe */
int kc_usb_probe_device(const struct kc_usb_probe_entry *entry, struct usb_interface **intf);
/* Calls the driver's disconnect and releases the device */
void kc_usb_disconnect(struct usb_interface *intf);

#endif
