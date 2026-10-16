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

/* sk_buff, pages, page_pool and net_device */

#include <execinfo.h>

#include <kcompat/kcompat.h>

/* Pages: a page-aligned struct page followed by PAGE_SIZE of data */
struct page *alloc_pages(gfp_t gfp, unsigned int order) {
    struct page *p;

    /* Only single pages; drivers here don't use higher orders */
    if (order != 0)
        return NULL;

    if (posix_memalign((void **) &p, PAGE_SIZE, 2 * PAGE_SIZE) != 0)
        return NULL;

    memset(p, 0, sizeof(*p));
    atomic_set(&p->refcount, 1);
    if (gfp & __GFP_ZERO)
        memset(page_address(p), 0, PAGE_SIZE);

    return p;
}

void __free_pages(struct page *p, unsigned int order) {
    (void) order;
    put_page(p);
}

void put_page(struct page *p) {
    if (p != NULL && atomic_dec_and_test(&p->refcount))
        free(p);
}

/* page_pool: whole pages, no recycling */
struct page_pool *page_pool_create(const struct page_pool_params *params) {
    struct page_pool *pool = calloc(1, sizeof(*pool));

    if (pool == NULL)
        return ERR_PTR(-ENOMEM);

    pool->p = *params;
    return pool;
}

void page_pool_destroy(struct page_pool *pool) {
    free(pool);
}

struct page *page_pool_alloc_frag(struct page_pool *pool, unsigned int *offset, unsigned int size,
        gfp_t gfp) {
    struct page *p;

    if (size > PAGE_SIZE)
        return NULL;

    if ((p = alloc_pages(gfp, 0)) == NULL)
        return NULL;

    p->nmdesc.pp = pool;
    *offset = 0;
    return p;
}

struct page *page_pool_dev_alloc_pages(struct page_pool *pool) {
    unsigned int off;
    return page_pool_alloc_frag(pool, &off, PAGE_SIZE, GFP_ATOMIC);
}

void page_pool_put_full_page(struct page_pool *pool, struct page *page, bool allow_direct) {
    (void) pool;
    (void) allow_direct;
    put_page(page);
}

/* sk_buff */
static struct sk_buff *kc_skb_new(void) {
    struct sk_buff *skb = calloc(1, sizeof(*skb));
    if (skb)
        refcount_set(&skb->users, 1);
    return skb;
}

/* As kmalloc_size_roundup(): the slab size class a kmalloc of this size gets */
static size_t kc_kmalloc_size_roundup(size_t size) {
    static const size_t classes[] = { 8, 16, 32, 64, 96, 128, 192, 256, 512, 1024, 2048, 4096, 8192 };

    for (size_t i = 0; i < ARRAY_SIZE(classes); i++)
        if (size <= classes[i])
            return classes[i];

    return roundup_pow_of_two(size);
}

/* Sized as __alloc_skb(): data is rounded to a slab size class and the tail ends where the
 * shared info would start.  Drivers rely on that slack (mt7921u pads MCU messages past the
 * tailroom it reserves). */
struct sk_buff *alloc_skb(unsigned int size, gfp_t flags) {
    struct sk_buff *skb;
    size_t osize;
    (void) flags;

    osize = kc_kmalloc_size_roundup(SKB_DATA_ALIGN((size_t) size) +
            SKB_DATA_ALIGN(sizeof(struct skb_shared_info)));

    if ((skb = kc_skb_new()) == NULL)
        return NULL;

    if ((skb->head = malloc(osize)) == NULL) {
        free(skb);
        return NULL;
    }

    skb->data = skb->tail = skb->head;
    skb->end = skb->head + SKB_WITH_OVERHEAD(osize);
    skb->truesize = SKB_TRUESIZE(osize);
    return skb;
}

/* Wraps a page_pool or page buffer; frag_size covers the whole buffer */
struct sk_buff *build_skb(void *data, unsigned int frag_size) {
    struct sk_buff *skb;

    if ((skb = kc_skb_new()) == NULL)
        return NULL;

    skb->head = data;
    skb->data = skb->tail = data;
    skb->end = (u8 *) data + SKB_WITH_OVERHEAD(frag_size);
    skb->head_frag = true;
    skb->truesize = SKB_TRUESIZE(frag_size);
    return skb;
}

static void kc_skb_release_data(struct sk_buff *skb) {
    struct skb_shared_info *sh = skb_shinfo(skb);

    for (int i = 0; i < sh->nr_frags; i++)
        put_page(sh->frags[i].page);
    sh->nr_frags = 0;

    if (sh->frag_list) {
        kfree_skb_list(sh->frag_list);
        sh->frag_list = NULL;
    }

    if (skb->head_frag)
        put_page(virt_to_head_page(skb->head));
    else
        free(skb->head);
    skb->head = NULL;
}

void kfree_skb(struct sk_buff *skb) {
    if (skb == NULL)
        return;

    if (!refcount_dec_and_test(&skb->users))
        return;

    kc_skb_release_data(skb);
    free(skb);
}

void kfree_skb_list(struct sk_buff *skb) {
    while (skb) {
        struct sk_buff *next = skb->next;
        kfree_skb(skb);
        skb = next;
    }
}

void *kc_skb_over_panic(struct sk_buff *skb, unsigned int len, const char *what) {
    kc_printk(KERN_EMERG "skb_%s: overflow len %u, data %u, head %ld, tail %ld, end %ld\n", what, len,
            skb->len, (long) (skb->data - skb->head), (long) (skb->tail - skb->head),
            (long) (skb->end - skb->head));
    void *bt[32];
    backtrace_symbols_fd(bt, backtrace(bt, 32), 2);
    abort();
    return NULL;
}

/* Replaces the linear buffer with a kmalloc one with more head and tail room */
int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail, gfp_t gfp) {
    unsigned int headroom = skb_headroom(skb), headlen = skb_headlen(skb);
    unsigned int size = headroom + (unsigned int) nhead + headlen +
        (unsigned int) (skb->end - skb->tail) + (unsigned int) ntail;
    u8 *n;
    (void) gfp;

    if (nhead < 0 || ntail < 0)
        return -EINVAL;

    if ((n = malloc(size)) == NULL)
        return -ENOMEM;

    memcpy(n + headroom + nhead, skb->data, headlen);

    if (skb->head_frag)
        put_page(virt_to_head_page(skb->head));
    else
        free(skb->head);

    skb->head = n;
    skb->head_frag = false;
    skb->data = n + headroom + nhead;
    skb->tail = skb->data + headlen;
    skb->end = n + size;
    return 0;
}

int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len) {
    const struct skb_shared_info *sh = skb_shinfo(skb);
    unsigned int hl = skb_headlen(skb);
    u8 *out = to;

    if (offset < 0 || len < 0 || (unsigned int) offset + (unsigned int) len > skb->len)
        return -EFAULT;

    if ((unsigned int) offset < hl) {
        unsigned int n = min_t(unsigned int, (unsigned int) len, hl - (unsigned int) offset);
        memcpy(out, skb->data + offset, n);
        out += n;
        len -= (int) n;
        offset += (int) n;
    }

    unsigned int pos = hl;
    for (int i = 0; i < sh->nr_frags && len > 0; i++) {
        unsigned int fs = sh->frags[i].size;
        if ((unsigned int) offset < pos + fs) {
            unsigned int fo = (unsigned int) offset - pos;
            unsigned int n = min_t(unsigned int, (unsigned int) len, fs - fo);
            memcpy(out, skb_frag_address(&sh->frags[i]) + fo, n);
            out += n;
            len -= (int) n;
            offset += (int) n;
        }
        pos += fs;
    }

    return len == 0 ? 0 : -EFAULT;
}

/* As net/core/skbuff.c ___pskb_trim(); trimming into a frag list isn't supported */
int __pskb_trim(struct sk_buff *skb, unsigned int len) {
    struct skb_shared_info *sh = skb_shinfo(skb);
    unsigned int offset = skb_headlen(skb);
    int nfrags = sh->nr_frags;
    int i = 0;

    if (!skb_is_nonlinear(skb)) {
        __skb_trim(skb, len);
        return 0;
    }

    if (offset < len) {
        bool found = false;

        for (; i < nfrags; i++) {
            unsigned int end = offset + sh->frags[i].size;

            if (end < len) {
                offset = end;
                continue;
            }

            sh->frags[i++].size = len - offset;
            found = true;
            break;
        }

        /* len ends inside the frag list */
        if (!found)
            return -EINVAL;
    }

    sh->nr_frags = (u8) i;
    for (; i < nfrags; i++)
        put_page(sh->frags[i].page);
    if (sh->frag_list) {
        kfree_skb_list(sh->frag_list);
        sh->frag_list = NULL;
    }

    if (len > skb_headlen(skb)) {
        skb->data_len -= skb->len - len;
        skb->len = len;
    } else {
        skb->len = len;
        skb->data_len = 0;
        skb->tail = skb->data + len;
    }

    return 0;
}

int skb_linearize(struct sk_buff *skb) {
    struct skb_shared_info *sh = skb_shinfo(skb);
    unsigned int headroom = skb_headroom(skb);
    u8 *n;

    if (!skb_is_nonlinear(skb))
        return 0;

    if ((n = malloc(headroom + skb->len)) == NULL)
        return -ENOMEM;

    if (skb_copy_bits(skb, 0, n + headroom, (int) skb->len) < 0) {
        free(n);
        return -EFAULT;
    }

    unsigned int len = skb->len;
    kc_skb_release_data(skb);
    skb->head = n;
    skb->head_frag = false;
    skb->data = n + headroom;
    skb->len = len;
    skb->data_len = 0;
    skb->tail = skb->data + len;
    skb->end = skb->tail;
    sh->nr_frags = 0;
    return 0;
}

/* Zeroes pad bytes of tail room, growing it if needed; frees the skb on failure */
int skb_pad(struct sk_buff *skb, int pad) {
    if (pad <= 0)
        return 0;

    if (skb_is_nonlinear(skb) && skb_linearize(skb) < 0)
        goto drop;

    if (skb_tailroom(skb) < pad && pskb_expand_head(skb, 0, pad - skb_tailroom(skb), GFP_ATOMIC) < 0)
        goto drop;

    memset(skb->tail, 0, (size_t) pad);
    return 0;

drop:
    kfree_skb(skb);
    return -ENOMEM;
}

void skb_add_rx_frag(struct sk_buff *skb, int i, struct page *page, int off, int size,
        unsigned int truesize) {
    struct skb_shared_info *sh = skb_shinfo(skb);

    if (i >= MAX_SKB_FRAGS) {
        put_page(page);
        return;
    }

    sh->frags[i].page = page;
    sh->frags[i].offset = (unsigned int) off;
    sh->frags[i].size = (unsigned int) size;
    sh->nr_frags = (u8) (i + 1);
    skb->len += (unsigned int) size;
    skb->data_len += (unsigned int) size;
    skb->truesize += truesize;
}

struct sk_buff *skb_copy(const struct sk_buff *skb, gfp_t gfp) {
    struct sk_buff *n = alloc_skb(skb_headroom(skb) + skb->len, gfp);

    if (n == NULL)
        return NULL;

    skb_reserve(n, (int) skb_headroom(skb));
    if (skb_copy_bits(skb, 0, skb_put(n, skb->len), (int) skb->len) < 0) {
        kfree_skb(n);
        return NULL;
    }
    memcpy(n->cb, skb->cb, sizeof(n->cb));
    n->priority = skb->priority;
    n->queue_mapping = skb->queue_mapping;
    n->protocol = skb->protocol;
    n->dev = skb->dev;
    return n;
}

struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp) {
    return skb_copy(skb, gfp);
}

struct sk_buff *skb_copy_expand(const struct sk_buff *skb, int headroom, int tailroom, gfp_t gfp) {
    struct sk_buff *n = alloc_skb((unsigned int) (headroom + tailroom) + skb->len, gfp);

    if (n == NULL)
        return NULL;

    skb_reserve(n, headroom);
    if (skb_copy_bits(skb, 0, skb_put(n, skb->len), (int) skb->len) < 0) {
        kfree_skb(n);
        return NULL;
    }
    memcpy(n->cb, skb->cb, sizeof(n->cb));
    return n;
}

int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg, int offset, int len) {
    (void) skb; (void) sg; (void) offset; (void) len;
    /* Scatter-gather isn't offered by the kcompat USB core */
    return -EOPNOTSUPP;
}

/* net_device */
struct net init_net;

struct net_device *alloc_netdev_dummy(int sizeof_priv) {
    struct net_device *dev = calloc(1, sizeof(*dev) + (size_t) sizeof_priv);
    if (dev)
        snprintf(dev->name, sizeof(dev->name), "dummy");
    return dev;
}

void free_netdev(struct net_device *dev) {
    free(dev);
}
