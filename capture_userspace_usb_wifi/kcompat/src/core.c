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

/* Logging, allocation, managed device resources, idr, firmware loading and randomness */

#define _GNU_SOURCE

#include <fcntl.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <unistd.h>

#include <kcompat/kcompat.h>
#include "../../../firmware_file.h"
#include <kcompat/host.h>

/* Logging */
static kc_log_cb_t kc_log_cb;
static void *kc_log_ctx;
static int kc_log_level = 4;

void kc_set_log_cb(kc_log_cb_t cb, void *ctx, int max_level) {
    kc_log_cb = cb;
    kc_log_ctx = ctx;
    kc_log_level = max_level;
}

static void kc_vlog(const char *fmt, va_list ap) {
    char buf[1024];
    int level = 4;

    vsnprintf(buf, sizeof(buf), fmt, ap);

    /* Strip the KERN_ level prefix */
    const char *msg = buf;
    if (msg[0] == '<' && msg[1] >= '0' && msg[1] <= '7' && msg[2] == '>') {
        level = msg[1] - '0';
        msg += 3;
    }

    if (level > kc_log_level)
        return;

    if (kc_log_cb != NULL) {
        kc_log_cb(kc_log_ctx, level, msg);
        return;
    }

    size_t len = strlen(msg);
    fprintf(stderr, "%s%s", msg, (len && msg[len - 1] == '\n') ? "" : "\n");
}

void kc_printk(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    kc_vlog(fmt, ap);
    va_end(ap);
}

void kc_dev_printk(const char *level, const struct device *dev, const char *fmt, ...) {
    char buf[1024];
    va_list ap;

    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    kc_printk("%s%s: %s", level, dev_name(dev), buf);
}

/* Bytes only; groupsize is ignored */
void print_hex_dump(const char *level, const char *prefix_str, int prefix_type, int rowsize,
        int groupsize, const void *buf, size_t len, bool ascii) {
    const u8 *p = buf;
    (void) groupsize;

    if (rowsize != 16 && rowsize != 32)
        rowsize = 16;

    for (size_t off = 0; off < len; off += (size_t) rowsize) {
        size_t n = len - off < (size_t) rowsize ? len - off : (size_t) rowsize;
        char line[32 * 4 + 8];
        size_t l = 0;

        for (size_t i = 0; i < n; i++)
            l += (size_t) snprintf(line + l, sizeof(line) - l, "%02x ", p[off + i]);
        if (ascii) {
            line[l++] = ' ';
            for (size_t i = 0; i < n; i++)
                line[l++] = (p[off + i] >= 0x20 && p[off + i] < 0x7f) ? (char) p[off + i] : '.';
        }
        line[l] = '\0';

        if (prefix_type == DUMP_PREFIX_OFFSET)
            kc_printk("%s%s%.8zx: %s", level, prefix_str, off, line);
        else if (prefix_type == DUMP_PREFIX_ADDRESS)
            kc_printk("%s%s%p: %s", level, prefix_str, (const void *) (p + off), line);
        else
            kc_printk("%s%s%s", level, prefix_str, line);
    }
}

int kc_scnprintf(char *buf, size_t size, const char *fmt, ...) {
    va_list ap;
    int r;

    if (size == 0)
        return 0;

    va_start(ap, fmt);
    r = vsnprintf(buf, size, fmt, ap);
    va_end(ap);

    if (r < 0)
        return 0;
    return (size_t) r >= size ? (int) size - 1 : r;
}

/* Allocation */
void *kc_alloc(size_t size, gfp_t flags) {
    /* size_mul() saturates on overflow */
    if (size == (size_t) -1)
        return NULL;

    if (flags & __GFP_ZERO)
        return calloc(1, size ? size : 1);

    return malloc(size ? size : 1);
}

void kc_free(const void *p) {
    free((void *) p);
}

void *krealloc(const void *p, size_t size, gfp_t flags) {
    (void) flags;
    return realloc((void *) p, size);
}

void *kmemdup(const void *src, size_t len, gfp_t flags) {
    void *p = kc_alloc(len, flags);
    if (p)
        memcpy(p, src, len);
    return p;
}

char *kstrdup(const char *s, gfp_t flags) {
    (void) flags;
    return s ? strdup(s) : NULL;
}

char *kvasprintf(gfp_t flags, const char *fmt, va_list ap) {
    char *s = NULL;
    (void) flags;
    if (vasprintf(&s, fmt, ap) < 0)
        return NULL;
    return s;
}

char *kasprintf(gfp_t flags, const char *fmt, ...) {
    va_list ap;
    char *s;
    va_start(ap, fmt);
    s = kvasprintf(flags, fmt, ap);
    va_end(ap);
    return s;
}

/* Managed resources; freed by kc_device_release() */
struct kc_devres {
    struct kc_devres *next;
    void *ptr;
};

void kc_device_init(struct device *dev, struct device *parent, const char *name) {
    memset(dev, 0, sizeof(*dev));
    dev->parent = parent;
    snprintf(dev->name, sizeof(dev->name), "%s", name);
    pthread_mutex_init(&dev->devres_lock, NULL);
}

void kc_device_release(struct device *dev) {
    struct kc_devres *r, *next;

    pthread_mutex_lock(&dev->devres_lock);
    for (r = dev->devres; r != NULL; r = next) {
        next = r->next;
        free(r->ptr);
        free(r);
    }
    dev->devres = NULL;
    pthread_mutex_unlock(&dev->devres_lock);
}

static void *kc_devres_add(struct device *dev, void *p) {
    struct kc_devres *r;

    if (p == NULL)
        return NULL;

    if ((r = malloc(sizeof(*r))) == NULL) {
        free(p);
        return NULL;
    }

    r->ptr = p;
    pthread_mutex_lock(&dev->devres_lock);
    r->next = dev->devres;
    dev->devres = r;
    pthread_mutex_unlock(&dev->devres_lock);

    return p;
}

void *devm_kmalloc(struct device *dev, size_t size, gfp_t flags) {
    return kc_devres_add(dev, kc_alloc(size, flags));
}

void *devm_kmemdup(struct device *dev, const void *src, size_t len, gfp_t flags) {
    return kc_devres_add(dev, kmemdup(src, len, flags));
}

char *devm_kstrdup(struct device *dev, const char *s, gfp_t flags) {
    return kc_devres_add(dev, kstrdup(s, flags));
}

char *devm_kasprintf(struct device *dev, gfp_t flags, const char *fmt, ...) {
    va_list ap;
    char *s;
    va_start(ap, fmt);
    s = kvasprintf(flags, fmt, ap);
    va_end(ap);
    return kc_devres_add(dev, s);
}

void devm_kfree(struct device *dev, const void *p) {
    struct kc_devres **rp;

    pthread_mutex_lock(&dev->devres_lock);
    for (rp = &dev->devres; *rp != NULL; rp = &(*rp)->next) {
        if ((*rp)->ptr == p) {
            struct kc_devres *r = *rp;
            *rp = r->next;
            free(r->ptr);
            free(r);
            break;
        }
    }
    pthread_mutex_unlock(&dev->devres_lock);
}

/* idr; ids index a growable pointer array */
int idr_alloc(struct idr *idr, void *ptr, int start, int end, gfp_t gfp) {
    (void) gfp;

    if (end <= 0)
        end = INT_MAX;

    for (int id = start; id < end; id++) {
        if (id >= idr->size) {
            int nsize = idr->size ? idr->size * 2 : 64;
            void **n;

            while (nsize <= id)
                nsize *= 2;

            if ((n = realloc(idr->ptrs, sizeof(void *) * (size_t) nsize)) == NULL)
                return -ENOMEM;

            memset(n + idr->size, 0, sizeof(void *) * (size_t) (nsize - idr->size));
            idr->ptrs = n;
            idr->size = nsize;
        }

        if (idr->ptrs[id] == NULL) {
            idr->ptrs[id] = ptr;
            return id;
        }
    }

    return -ENOSPC;
}

void *idr_find(const struct idr *idr, unsigned long id) {
    return id < (unsigned long) idr->size ? idr->ptrs[id] : NULL;
}

void *idr_remove(struct idr *idr, unsigned long id) {
    void *p = idr_find(idr, id);
    if (p)
        idr->ptrs[id] = NULL;
    return p;
}

void *idr_replace(struct idr *idr, void *ptr, unsigned long id) {
    void *p = idr_find(idr, id);
    if (p == NULL)
        return ERR_PTR(-ENOENT);
    idr->ptrs[id] = ptr;
    return p;
}

void idr_destroy(struct idr *idr) {
    free(idr->ptrs);
    idr->ptrs = NULL;
    idr->size = 0;
}

bool idr_is_empty(const struct idr *idr) {
    for (int i = 0; i < idr->size; i++)
        if (idr->ptrs[i])
            return false;
    return true;
}

void *idr_get_next(const struct idr *idr, int *nextid) {
    for (int i = *nextid; i >= 0 && i < idr->size; i++) {
        if (idr->ptrs[i]) {
            *nextid = i;
            return idr->ptrs[i];
        }
    }
    return NULL;
}

/* Firmware: name is a relative path such as "mediatek/WIFI_RAM_CODE_MT7961_1.bin" */
#define KC_FW_MAX_PATHS 16
#define KC_FW_MAX_SIZE (16 * 1024 * 1024)
static char *kc_fw_paths[KC_FW_MAX_PATHS];
static size_t kc_fw_npaths;

void kc_firmware_set_paths(const char *const *paths, size_t n) {
    for (size_t i = 0; i < kc_fw_npaths; i++)
        free(kc_fw_paths[i]);
    kc_fw_npaths = 0;

    for (size_t i = 0; i < n && kc_fw_npaths < KC_FW_MAX_PATHS; i++)
        if (paths[i] != NULL && (kc_fw_paths[kc_fw_npaths] = strdup(paths[i])) != NULL)
            kc_fw_npaths++;
}

/* Each directory in turn, as named and then in each compressed form */
int request_firmware(const struct firmware **fwp, const char *name, struct device *dev) {
    const char *suffixes[FW_FILE_MAX_SUFFIXES];
    size_t num_suffixes = fw_file_suffixes(suffixes);
    struct firmware *fw;
    char path[1024];

    *fwp = NULL;

    /* No absolute paths or parent references from drivers */
    if (name == NULL || name[0] == '/' || strstr(name, "..") != NULL)
        return -EINVAL;

    if ((fw = calloc(1, sizeof(*fw))) == NULL)
        return -ENOMEM;

    for (size_t i = 0; i < kc_fw_npaths; i++) {
        for (size_t s = 0; s < num_suffixes; s++) {
            uint8_t *data;
            size_t len;
            int n, r;

            n = snprintf(path, sizeof(path), "%s/%s%s", kc_fw_paths[i], name, suffixes[s]);
            if (n < 0 || (size_t) n >= sizeof(path))
                continue;

            if ((r = fw_file_read(path, KC_FW_MAX_SIZE, &data, &len)) == 0) {
                fw->data = data;
                fw->size = len;
                dev_dbg(dev, "loaded firmware %s (%zu bytes)", path, fw->size);
                *fwp = fw;
                return 0;
            }

            if (r != -ENOENT)
                dev_err(dev, "could not load firmware %s: %s", path, strerror(-r));
        }
    }

    dev_err(dev, "firmware %s not found", name);
    free(fw);
    return -ENOENT;
}

int request_firmware_nowait(struct module *module, bool uevent, const char *name, struct device *dev,
        gfp_t gfp, void *context, void (*cont)(const struct firmware *fw, void *context)) {
    const struct firmware *fw = NULL;
    (void) module;
    (void) uevent;
    (void) gfp;

    /* A missing file is reported to cont as a NULL firmware, as the kernel does */
    if (request_firmware(&fw, name, dev) < 0)
        fw = NULL;

    cont(fw, context);
    return 0;
}

void release_firmware(const struct firmware *fw) {
    if (fw == NULL)
        return;
    free((void *) fw->data);
    free((void *) fw);
}

/* Randomness */
void kc_get_random_bytes(void *buf, size_t len) {
    u8 *p = buf;

    /* getentropy() is limited to 256 bytes per call */
    while (len > 0) {
        size_t n = len > 256 ? 256 : len;
        if (getentropy(p, n) != 0)
            abort();
        p += n;
        len -= n;
    }
}

void eth_random_addr(u8 *addr) {
    kc_get_random_bytes(addr, ETH_ALEN);
    addr[0] &= 0xfe;
    addr[0] |= 0x02;
}
