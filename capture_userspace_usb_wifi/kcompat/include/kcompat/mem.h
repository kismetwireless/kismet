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

#ifndef __KCOMPAT_MEM_H__
#define __KCOMPAT_MEM_H__

/* Allocation, struct device with managed (devm_) resources, and device logging */

#include "sync.h"

#define GFP_KERNEL 0x01u
#define GFP_ATOMIC 0x02u
#define GFP_NOWAIT 0x04u
#define GFP_DMA32 0x08u
#define GFP_NOIO 0x10u
#define __GFP_ZERO 0x100u
#define __GFP_NOWARN 0x200u
#define __GFP_RETRY_MAYFAIL 0x400u
#define __GFP_COMP 0x800u
#define GFP_USER GFP_KERNEL

void *kc_alloc(size_t size, gfp_t flags);
void kc_free(const void *p);
#define kmalloc(s, f) kc_alloc(s, f)
#define kzalloc(s, f) kc_alloc(s, (f) | __GFP_ZERO)
#define kmalloc_array(n, s, f) kc_alloc(size_mul(n, s), f)
#define kcalloc(n, s, f) kc_alloc(size_mul(n, s), (f) | __GFP_ZERO)
#define kvmalloc(s, f) kmalloc(s, f)
#define kvzalloc(s, f) kzalloc(s, f)
#define kvcalloc(n, s, f) kcalloc(n, s, f)
#define kvmalloc_array(n, s, f) kmalloc_array(n, s, f)
#define vmalloc(s) kmalloc(s, GFP_KERNEL)
#define vzalloc(s) kzalloc(s, GFP_KERNEL)
#define kfree(p) kc_free(p)
#define kvfree(p) kc_free(p)
#define vfree(p) kc_free(p)
#define kfree_sensitive(p) kc_free(p)
/* The first argument is the object, as in "kzalloc_flex(*ptr, member, n)" */
#define kzalloc_flex(obj, member, count, ...) \
    kzalloc(struct_size_t(typeof(obj), member, count), GFP_KERNEL)
#define kzalloc_obj(obj, ...) kzalloc(sizeof(obj), GFP_KERNEL)
#define NUMA_NO_NODE (-1)
void *krealloc(const void *p, size_t size, gfp_t flags);
void *kmemdup(const void *src, size_t len, gfp_t flags);
char *kstrdup(const char *s, gfp_t flags);
char *kasprintf(gfp_t flags, const char *fmt, ...) __printf(2, 3);
char *kvasprintf(gfp_t flags, const char *fmt, va_list ap);
#define kfree_const(p) kfree(p)
#define kstrdup_const(s, f) kstrdup(s, f)

/* Record fifos, as linux/kfifo.h: a power-of-two ring of fixed-size elements, with the
 * size rounded down as kfifo_alloc() does */
struct __kfifo {
    unsigned int in;
    unsigned int out;
    unsigned int mask;
    unsigned int esize;
    void *data;
};
#define DECLARE_KFIFO_PTR(fifo, type) struct { struct __kfifo kfifo; type *ptr; } fifo
#define kfifo_alloc(fifo, size, gfp) ({ \
    typeof(fifo) __f = (fifo); \
    unsigned int __n = (size), __s = 1; \
    while (__s <= __n / 2) \
        __s <<= 1; \
    __f->kfifo.in = __f->kfifo.out = 0; \
    __f->kfifo.esize = sizeof(*__f->ptr); \
    __f->kfifo.data = __n < 2 ? NULL : kmalloc_array(__s, __f->kfifo.esize, gfp); \
    __f->kfifo.mask = __f->kfifo.data ? __s - 1 : 0; \
    __n < 2 ? -EINVAL : (__f->kfifo.data ? 0 : -ENOMEM); \
})
#define kfifo_free(fifo) do { \
    kfree((fifo)->kfifo.data); \
    (fifo)->kfifo.data = NULL; \
    (fifo)->kfifo.in = (fifo)->kfifo.out = (fifo)->kfifo.mask = 0; \
} while (0)
#define kfifo_reset(fifo) do { (fifo)->kfifo.in = (fifo)->kfifo.out = 0; } while (0)
#define kfifo_len(fifo) ((fifo)->kfifo.in - (fifo)->kfifo.out)
#define kfifo_is_empty(fifo) ((fifo)->kfifo.in == (fifo)->kfifo.out)
#define kfifo_is_full(fifo) (kfifo_len(fifo) > (fifo)->kfifo.mask)
#define kfifo_put(fifo, val) ({ \
    typeof(fifo) __f = (fifo); \
    typeof(*__f->ptr) __v = (val); \
    unsigned int __ok = !kfifo_is_full(__f); \
    if (__ok) { \
        ((typeof(__f->ptr)) __f->kfifo.data)[__f->kfifo.in & __f->kfifo.mask] = __v; \
        __f->kfifo.in++; \
    } \
    __ok; \
})
#define kfifo_get(fifo, valp) ({ \
    typeof(fifo) __f = (fifo); \
    unsigned int __ok = !kfifo_is_empty(__f); \
    if (__ok) { \
        *(valp) = ((typeof(__f->ptr)) __f->kfifo.data)[__f->kfifo.out & __f->kfifo.mask]; \
        __f->kfifo.out++; \
    } \
    __ok; \
})

/* Devices */
struct device_driver {
    const char *name;
};
struct device_node;
struct fwnode_handle;
struct device {
    struct device *parent;
    char name[64];
    void *driver_data;
    void *platform_data;
    struct device_driver *driver;
    struct device_node *of_node;
    struct fwnode_handle *fwnode;
    /* Managed allocations, released with the device */
    pthread_mutex_t devres_lock;
    struct kc_devres *devres;
};
void kc_device_init(struct device *dev, struct device *parent, const char *name);
void kc_device_release(struct device *dev);
static inline const char *dev_name(const struct device *dev) { return dev ? dev->name : "(null)"; }
static inline void *dev_get_drvdata(const struct device *dev) { return dev->driver_data; }
static inline void dev_set_drvdata(struct device *dev, void *data) { dev->driver_data = data; }
#define get_device(d) (d)
#define put_device(d) do { (void) (d); } while (0)
static inline struct device_node *dev_of_node(struct device *dev) { return dev->of_node; }
#define dev_to_node(d) (-1)
#define device_set_wakeup_enable(d, e) do { (void) (d); } while (0)
#define device_can_wakeup(d) 0
#define device_init_wakeup(d, e) 0

void *devm_kmalloc(struct device *dev, size_t size, gfp_t flags);
#define devm_kzalloc(d, s, f) devm_kmalloc(d, s, (f) | __GFP_ZERO)
#define devm_kcalloc(d, n, s, f) devm_kmalloc(d, size_mul(n, s), (f) | __GFP_ZERO)
#define devm_kmalloc_array(d, n, s, f) devm_kmalloc(d, size_mul(n, s), f)
void *devm_kmemdup(struct device *dev, const void *src, size_t len, gfp_t flags);
char *devm_kstrdup(struct device *dev, const char *s, gfp_t flags);
char *devm_kasprintf(struct device *dev, gfp_t flags, const char *fmt, ...) __printf(3, 4);
void devm_kfree(struct device *dev, const void *p);

void kc_dev_printk(const char *level, const struct device *dev, const char *fmt, ...) __printf(3, 4);
#define dev_printk(level, dev, fmt, ...) kc_dev_printk(level, dev, fmt, ##__VA_ARGS__)
#define dev_emerg(dev, fmt, ...) kc_dev_printk(KERN_EMERG, dev, fmt, ##__VA_ARGS__)
#define dev_crit(dev, fmt, ...) kc_dev_printk(KERN_CRIT, dev, fmt, ##__VA_ARGS__)
#define dev_err(dev, fmt, ...) kc_dev_printk(KERN_ERR, dev, fmt, ##__VA_ARGS__)
#define dev_warn(dev, fmt, ...) kc_dev_printk(KERN_WARNING, dev, fmt, ##__VA_ARGS__)
#define dev_notice(dev, fmt, ...) kc_dev_printk(KERN_NOTICE, dev, fmt, ##__VA_ARGS__)
#define dev_info(dev, fmt, ...) kc_dev_printk(KERN_INFO, dev, fmt, ##__VA_ARGS__)
#define dev_dbg(dev, fmt, ...) kc_dev_printk(KERN_DEBUG, dev, fmt, ##__VA_ARGS__)
#define dev_err_ratelimited dev_err
#define dev_warn_ratelimited dev_warn
#define dev_info_ratelimited dev_info
#define dev_dbg_ratelimited dev_dbg
#define dev_err_once dev_err
#define dev_warn_once dev_warn
#define dev_info_once dev_info
#define dev_err_probe(dev, err, fmt, ...) ({ dev_err(dev, fmt, ##__VA_ARGS__); (err); })
#define dev_WARN_ONCE(dev, cond, fmt, ...) WARN(cond, fmt, ##__VA_ARGS__)

#endif
