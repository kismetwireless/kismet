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

#ifndef __KCOMPAT_SKB_H__
#define __KCOMPAT_SKB_H__

/* sk_buff, skb queues, pages, page_pool and scatterlists.
 *
 * Pages from page_pool are PAGE_SIZE data blocks preceded by their struct page in the
 * same aligned allocation, so virt_to_head_page() works on any address inside one.
 * Only page_pool and alloc_pages() memory may be passed to virt_to_head_page(). */

#include "bits.h"
#include "mem.h"
#include "sched.h"

#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)
#define PAGE_MASK (~(PAGE_SIZE - 1))
#define SMP_CACHE_BYTES 64
#define L1_CACHE_BYTES 64
#define NET_SKB_PAD 64
#define NET_IP_ALIGN 0
#define MAX_SKB_FRAGS 17

struct page_pool;
struct netmem_desc {
    struct page_pool *pp;
};
struct page {
    union {
        struct {
            atomic_t refcount;
            struct netmem_desc nmdesc;
            unsigned int order;
        };
        u8 kc_raw[1UL << 12];
    };
};
_Static_assert(sizeof(struct page) == PAGE_SIZE, "page header must be one page");

static inline void *page_address(const struct page *p) { return (u8 *) p + PAGE_SIZE; }
static inline struct page *virt_to_head_page(const void *addr) {
    return (struct page *) ((((uintptr_t) addr) & PAGE_MASK) - PAGE_SIZE);
}
#define virt_to_page virt_to_head_page
static inline struct netmem_desc *pp_page_to_nmdesc(struct page *p) { return &p->nmdesc; }
struct page *alloc_pages(gfp_t gfp, unsigned int order);
#define alloc_page(gfp) alloc_pages(gfp, 0)
#define dev_alloc_pages(order) alloc_pages(GFP_ATOMIC, order)
void __free_pages(struct page *p, unsigned int order);
#define __free_page(p) __free_pages(p, 0)
static inline void get_page(struct page *p) { atomic_inc(&p->refcount); }
void put_page(struct page *p);
static inline int page_ref_count(const struct page *p) { return atomic_read(&p->refcount); }
#define page_to_virt page_address
#define offset_in_page(p) ((unsigned long) (p) & ~PAGE_MASK)
static inline void *page_frag_alloc(void *cache, unsigned int size, gfp_t gfp) {
    (void) cache;
    return size <= PAGE_SIZE ? page_address(alloc_pages(gfp, 0)) : NULL;
}

/* page_pool */
struct page_pool_params {
    unsigned int order;
    unsigned int flags;
    unsigned int pool_size;
    int nid;
    struct device *dev;
    struct napi_struct *napi;
    int dma_dir;
    unsigned int max_len;
    unsigned int offset;
    struct net_device *netdev;
    unsigned int queue_idx;
};
#define PP_FLAG_DMA_MAP 1
#define PP_FLAG_DMA_SYNC_DEV 2
#define PP_FLAG_PAGE_FRAG 4
struct page_pool_stats {
    u64 dummy;
};
struct page_pool {
    struct page_pool_params p;
};
struct page_pool *page_pool_create(const struct page_pool_params *params);
void page_pool_destroy(struct page_pool *pool);
struct page *page_pool_alloc_frag(struct page_pool *pool, unsigned int *offset, unsigned int size,
        gfp_t gfp);
struct page *page_pool_dev_alloc_pages(struct page_pool *pool);
void page_pool_put_full_page(struct page_pool *pool, struct page *page, bool allow_direct);
#define page_pool_recycle_direct(pool, page) page_pool_put_full_page(pool, page, true)
static inline bool page_pool_get_stats(const struct page_pool *pool, struct page_pool_stats *s) {
    (void) pool; (void) s; return false;
}
static inline int page_pool_ethtool_stats_get_count(void) { return 0; }
static inline u8 *page_pool_ethtool_stats_get_strings(u8 *data) { return data; }
static inline u64 *page_pool_ethtool_stats_get(u64 *data, const void *stats) { (void) stats; return data; }
#define page_pool_get_dma_dir(pool) 0
#define page_pool_get_dma_addr(page) ((dma_addr_t) (uintptr_t) page_address(page))

/* scatterlist */
struct scatterlist {
    struct page *page;
    unsigned int offset;
    unsigned int length;
    dma_addr_t dma_address;
    bool end;
};
static inline void sg_init_table(struct scatterlist *sg, unsigned int n) {
    memset(sg, 0, sizeof(*sg) * n);
    if (n)
        sg[n - 1].end = true;
}
static inline void sg_init_marker(struct scatterlist *sg, unsigned int n) {
    if (n)
        sg[n - 1].end = true;
}
static inline void sg_set_page(struct scatterlist *sg, struct page *p, unsigned int len, unsigned int off) {
    sg->page = p; sg->length = len; sg->offset = off;
}
static inline struct page *sg_page(struct scatterlist *sg) { return sg->page; }
static inline void *sg_virt(struct scatterlist *sg) { return (u8 *) page_address(sg->page) + sg->offset; }
static inline void sg_mark_end(struct scatterlist *sg) { sg->end = true; }
static inline struct scatterlist *sg_next(struct scatterlist *sg) { return sg->end ? NULL : sg + 1; }
#define for_each_sg(sglist, sg, nr, i) \
    for ((i) = 0, (sg) = (sglist); (i) < (nr); (i)++, (sg) = sg_next(sg))

/* sk_buff */
typedef struct {
    struct page *page;
    unsigned int offset;
    unsigned int size;
} skb_frag_t;

struct sk_buff;
struct skb_shared_info {
    u8 nr_frags;
    u8 tx_flags;
    struct sk_buff *frag_list;
    skb_frag_t frags[MAX_SKB_FRAGS];
};

struct net_device;
struct sk_buff {
    union {
        struct {
            struct sk_buff *next;
            struct sk_buff *prev;
        };
        struct list_head list;
    };
    struct net_device *dev;
    char cb[48] __aligned(8);
    unsigned int len;
    unsigned int data_len;
    u16 queue_mapping;
    u16 mac_len;
    __be16 protocol;
    u8 pkt_type;
    u8 ip_summed;
    u32 priority;
    u32 mark;
    u32 hash;
    ktime_t tstamp;
    unsigned int truesize;
    refcount_t users;
    u8 *head;
    u8 *data;
    u8 *tail;
    u8 *end;
    /* head is page_pool or page memory rather than kmalloc */
    bool head_frag;
    struct skb_shared_info shinfo;
};

struct sk_buff_head {
    struct sk_buff *next;
    struct sk_buff *prev;
    u32 qlen;
    spinlock_t lock;
};

#define CHECKSUM_NONE 0
#define CHECKSUM_UNNECESSARY 1
#define CHECKSUM_COMPLETE 2
#define CHECKSUM_PARTIAL 3
#define SKB_DATA_ALIGN(x) ALIGN(x, SMP_CACHE_BYTES)
#define SKB_WITH_OVERHEAD(x) ((x) - SKB_DATA_ALIGN(sizeof(struct skb_shared_info)))
#define SKB_TRUESIZE(x) ((x) + SKB_DATA_ALIGN(sizeof(struct sk_buff)))

struct sk_buff *alloc_skb(unsigned int size, gfp_t flags);
struct sk_buff *build_skb(void *data, unsigned int frag_size);
#define napi_build_skb build_skb
#define slab_build_skb build_skb
#define dev_alloc_skb(len) __dev_alloc_skb(len, GFP_ATOMIC)
#define __dev_alloc_skb(len, gfp) alloc_skb((len) + NET_SKB_PAD, gfp) ? \
    ({ struct sk_buff *__s = alloc_skb((len) + NET_SKB_PAD, gfp); if (__s) skb_reserve(__s, NET_SKB_PAD); __s; }) : NULL
#define netdev_alloc_skb(dev, len) dev_alloc_skb(len)
void kfree_skb(struct sk_buff *skb);
#define kfree_skb_reason(skb, r) kfree_skb(skb)
#define dev_kfree_skb(skb) kfree_skb(skb)
#define dev_kfree_skb_any(skb) kfree_skb(skb)
#define dev_kfree_skb_irq(skb) kfree_skb(skb)
#define consume_skb(skb) kfree_skb(skb)
#define napi_consume_skb(skb, budget) kfree_skb(skb)
void kfree_skb_list(struct sk_buff *skb);
struct sk_buff *skb_copy(const struct sk_buff *skb, gfp_t gfp);
struct sk_buff *skb_clone(struct sk_buff *skb, gfp_t gfp);
struct sk_buff *skb_copy_expand(const struct sk_buff *skb, int headroom, int tailroom, gfp_t gfp);
int pskb_expand_head(struct sk_buff *skb, int nhead, int ntail, gfp_t gfp);
int skb_linearize(struct sk_buff *skb);
int skb_copy_bits(const struct sk_buff *skb, int offset, void *to, int len);
int skb_pad(struct sk_buff *skb, int pad);
void skb_add_rx_frag(struct sk_buff *skb, int i, struct page *page, int off, int size,
        unsigned int truesize);
int skb_to_sgvec(struct sk_buff *skb, struct scatterlist *sg, int offset, int len);

static inline struct skb_shared_info *skb_shinfo(const struct sk_buff *skb) {
    return (struct skb_shared_info *) &skb->shinfo;
}
static inline struct sk_buff *skb_get(struct sk_buff *skb) { refcount_inc(&skb->users); return skb; }
static inline unsigned int skb_headlen(const struct sk_buff *skb) { return skb->len - skb->data_len; }
static inline bool skb_is_nonlinear(const struct sk_buff *skb) { return skb->data_len != 0; }
static inline unsigned int skb_headroom(const struct sk_buff *skb) { return (unsigned int) (skb->data - skb->head); }
static inline int skb_tailroom(const struct sk_buff *skb) {
    return skb_is_nonlinear(skb) ? 0 : (int) (skb->end - skb->tail);
}
static inline u8 *skb_tail_pointer(const struct sk_buff *skb) { return skb->tail; }
static inline u8 *skb_end_pointer(const struct sk_buff *skb) { return skb->end; }
static inline void skb_reserve(struct sk_buff *skb, int len) { skb->data += len; skb->tail += len; }
void *kc_skb_over_panic(struct sk_buff *skb, unsigned int len, const char *what);
static inline void *skb_put(struct sk_buff *skb, unsigned int len) {
    u8 *t = skb->tail;
    if (unlikely(skb_is_nonlinear(skb) || skb->tail + len > skb->end))
        return kc_skb_over_panic(skb, len, "put");
    skb->tail += len;
    skb->len += len;
    return t;
}
#define __skb_put skb_put
static inline void *skb_put_zero(struct sk_buff *skb, unsigned int len) {
    void *p = skb_put(skb, len);
    memset(p, 0, len);
    return p;
}
static inline void *skb_put_data(struct sk_buff *skb, const void *data, unsigned int len) {
    void *p = skb_put(skb, len);
    memcpy(p, data, len);
    return p;
}
#define __skb_put_zero skb_put_zero
#define __skb_put_data skb_put_data
static inline void skb_put_u8(struct sk_buff *skb, u8 v) { *(u8 *) skb_put(skb, 1) = v; }
static inline void *skb_push(struct sk_buff *skb, unsigned int len) {
    if (unlikely(skb->data - len < skb->head))
        return kc_skb_over_panic(skb, len, "push");
    skb->data -= len;
    skb->len += len;
    return skb->data;
}
#define __skb_push skb_push
static inline void *skb_pull(struct sk_buff *skb, unsigned int len) {
    if (unlikely(len > skb_headlen(skb)))
        return NULL;
    skb->len -= len;
    skb->data += len;
    return skb->data;
}
#define __skb_pull skb_pull
static inline void *skb_pull_inline(struct sk_buff *skb, unsigned int len) { return skb_pull(skb, len); }
static inline void __skb_trim(struct sk_buff *skb, unsigned int len) {
    if (skb_is_nonlinear(skb))
        return;
    skb->len = len;
    skb->tail = skb->data + len;
}
static inline void skb_trim(struct sk_buff *skb, unsigned int len) {
    if (skb->len > len)
        __skb_trim(skb, len);
}
static inline int skb_put_padto(struct sk_buff *skb, unsigned int len) {
    if (skb->len < len) {
        unsigned int pad = len - skb->len;
        if (skb_pad(skb, (int) pad))
            return -ENOMEM;
        skb_put(skb, pad);
    }
    return 0;
}
static inline int skb_cow_head(struct sk_buff *skb, unsigned int headroom) {
    if (skb_headroom(skb) >= headroom)
        return 0;
    return pskb_expand_head(skb, (int) (headroom - skb_headroom(skb)), 0, GFP_ATOMIC);
}
#define skb_cow(skb, headroom) skb_cow_head(skb, headroom)
static inline u16 skb_get_queue_mapping(const struct sk_buff *skb) { return skb->queue_mapping; }
static inline void skb_set_queue_mapping(struct sk_buff *skb, u16 q) { skb->queue_mapping = q; }
static inline void skb_mark_for_recycle(struct sk_buff *skb) { (void) skb; }
static inline void skb_reset_mac_header(struct sk_buff *skb) { (void) skb; }
static inline void skb_reset_network_header(struct sk_buff *skb) { (void) skb; }
static inline void skb_reset_transport_header(struct sk_buff *skb) { (void) skb; }
static inline void skb_set_network_header(struct sk_buff *skb, int o) { (void) skb; (void) o; }
static inline void skb_orphan(struct sk_buff *skb) { (void) skb; }
static inline void skb_checksum_none_assert(const struct sk_buff *skb) { (void) skb; }
static inline bool skb_has_frag_list(const struct sk_buff *skb) { return skb->shinfo.frag_list != NULL; }
#define skb_walk_frags(skb, iter) for (iter = skb_shinfo(skb)->frag_list; iter; iter = iter->next)
static inline void *skb_frag_address(const skb_frag_t *f) { return (u8 *) page_address(f->page) + f->offset; }
static inline unsigned int skb_frag_size(const skb_frag_t *f) { return f->size; }
static inline struct page *skb_frag_page(const skb_frag_t *f) { return f->page; }
#define skb_list_walk_safe(first, skb, next_skb) \
    for ((skb) = (first), (next_skb) = (skb) ? (skb)->next : NULL; (skb); \
         (skb) = (next_skb), (next_skb) = (skb) ? (skb)->next : NULL)
static inline void skb_mark_not_on_list(struct sk_buff *skb) { skb->next = NULL; }
static inline void skb_list_del_init(struct sk_buff *skb) { list_del_init(&skb->list); }

/* skb queues */
static inline void __skb_queue_head_init(struct sk_buff_head *l) {
    l->prev = l->next = (struct sk_buff *) l;
    l->qlen = 0;
}
static inline void skb_queue_head_init(struct sk_buff_head *l) {
    spin_lock_init(&l->lock);
    __skb_queue_head_init(l);
}
static inline bool skb_queue_empty(const struct sk_buff_head *l) { return l->next == (const struct sk_buff *) l; }
#define skb_queue_empty_lockless skb_queue_empty
static inline u32 skb_queue_len(const struct sk_buff_head *l) { return l->qlen; }
#define skb_queue_len_lockless skb_queue_len
static inline bool skb_queue_is_last(const struct sk_buff_head *l, const struct sk_buff *s) {
    return s->next == (const struct sk_buff *) l;
}
static inline struct sk_buff *skb_peek(const struct sk_buff_head *l) {
    struct sk_buff *s = l->next;
    return s == (const struct sk_buff *) l ? NULL : s;
}
static inline struct sk_buff *skb_peek_tail(const struct sk_buff_head *l) {
    struct sk_buff *s = l->prev;
    return s == (const struct sk_buff *) l ? NULL : s;
}
static inline void __skb_insert(struct sk_buff *n, struct sk_buff *prev, struct sk_buff *next,
        struct sk_buff_head *l) {
    n->next = next; n->prev = prev; next->prev = n; prev->next = n; l->qlen++;
}
static inline void __skb_queue_tail(struct sk_buff_head *l, struct sk_buff *n) {
    __skb_insert(n, l->prev, (struct sk_buff *) l, l);
}
static inline void __skb_queue_head(struct sk_buff_head *l, struct sk_buff *n) {
    __skb_insert(n, (struct sk_buff *) l, l->next, l);
}
static inline void __skb_unlink(struct sk_buff *s, struct sk_buff_head *l) {
    struct sk_buff *next = s->next, *prev = s->prev;
    l->qlen--;
    next->prev = prev; prev->next = next;
    s->next = s->prev = NULL;
}
static inline struct sk_buff *__skb_dequeue(struct sk_buff_head *l) {
    struct sk_buff *s = skb_peek(l);
    if (s)
        __skb_unlink(s, l);
    return s;
}
static inline struct sk_buff *__skb_dequeue_tail(struct sk_buff_head *l) {
    struct sk_buff *s = skb_peek_tail(l);
    if (s)
        __skb_unlink(s, l);
    return s;
}
static inline void skb_queue_tail(struct sk_buff_head *l, struct sk_buff *n) {
    spin_lock(&l->lock); __skb_queue_tail(l, n); spin_unlock(&l->lock);
}
static inline void skb_queue_head(struct sk_buff_head *l, struct sk_buff *n) {
    spin_lock(&l->lock); __skb_queue_head(l, n); spin_unlock(&l->lock);
}
static inline struct sk_buff *skb_dequeue(struct sk_buff_head *l) {
    struct sk_buff *s;
    spin_lock(&l->lock); s = __skb_dequeue(l); spin_unlock(&l->lock);
    return s;
}
static inline struct sk_buff *skb_dequeue_tail(struct sk_buff_head *l) {
    struct sk_buff *s;
    spin_lock(&l->lock); s = __skb_dequeue_tail(l); spin_unlock(&l->lock);
    return s;
}
static inline void skb_unlink(struct sk_buff *s, struct sk_buff_head *l) {
    spin_lock(&l->lock); __skb_unlink(s, l); spin_unlock(&l->lock);
}
static inline void __skb_queue_purge(struct sk_buff_head *l) {
    struct sk_buff *s;
    while ((s = __skb_dequeue(l)) != NULL)
        kfree_skb(s);
}
static inline void skb_queue_purge(struct sk_buff_head *l) {
    struct sk_buff *s;
    while ((s = skb_dequeue(l)) != NULL)
        kfree_skb(s);
}
static inline void __skb_queue_splice(const struct sk_buff_head *list, struct sk_buff *prev,
        struct sk_buff *next) {
    struct sk_buff *first = list->next, *last = list->prev;
    first->prev = prev; prev->next = first; last->next = next; next->prev = last;
}
static inline void skb_queue_splice_tail_init(struct sk_buff_head *list, struct sk_buff_head *head) {
    if (!skb_queue_empty(list)) {
        __skb_queue_splice(list, head->prev, (struct sk_buff *) head);
        head->qlen += list->qlen;
        __skb_queue_head_init(list);
    }
}
static inline void skb_queue_splice_init(struct sk_buff_head *list, struct sk_buff_head *head) {
    if (!skb_queue_empty(list)) {
        __skb_queue_splice(list, (struct sk_buff *) head, head->next);
        head->qlen += list->qlen;
        __skb_queue_head_init(list);
    }
}
#define skb_queue_splice_tail skb_queue_splice_tail_init
#define skb_queue_walk(queue, skb) \
    for (skb = (queue)->next; skb != (struct sk_buff *) (queue); skb = skb->next)
#define skb_queue_walk_safe(queue, skb, tmp) \
    for (skb = (queue)->next, tmp = skb->next; skb != (struct sk_buff *) (queue); skb = tmp, tmp = skb->next)

#endif
