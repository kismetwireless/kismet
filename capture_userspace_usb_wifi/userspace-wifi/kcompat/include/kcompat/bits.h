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

#ifndef __KCOMPAT_BITS_H__
#define __KCOMPAT_BITS_H__

/* Byte order, unaligned access and bitfield helpers */

#include "base.h"

#define swab16(x) __builtin_bswap16(x)
#define swab32(x) __builtin_bswap32(x)
#define swab64(x) __builtin_bswap64(x)

/* Little-endian host */
#define cpu_to_le16(x) ((__le16) (u16) (x))
#define cpu_to_le32(x) ((__le32) (u32) (x))
#define cpu_to_le64(x) ((__le64) (u64) (x))
#define le16_to_cpu(x) ((u16) (__le16) (x))
#define le32_to_cpu(x) ((u32) (__le32) (x))
#define le64_to_cpu(x) ((u64) (__le64) (x))
#define cpu_to_be16(x) ((__be16) swab16((u16) (x)))
#define cpu_to_be32(x) ((__be32) swab32((u32) (x)))
#define cpu_to_be64(x) ((__be64) swab64((u64) (x)))
#define be16_to_cpu(x) swab16((u16) (x))
#define be32_to_cpu(x) swab32((u32) (x))
#define be64_to_cpu(x) swab64((u64) (x))
#define __cpu_to_le16 cpu_to_le16
#define __cpu_to_le32 cpu_to_le32
#define __le16_to_cpu le16_to_cpu
#define __le32_to_cpu le32_to_cpu
#define __cpu_to_be16 cpu_to_be16
#define __cpu_to_be32 cpu_to_be32
#define __be16_to_cpu be16_to_cpu
#define __be32_to_cpu be32_to_cpu

static inline u16 le16_to_cpup(const __le16 *p) { return le16_to_cpu(*p); }
static inline u32 le32_to_cpup(const __le32 *p) { return le32_to_cpu(*p); }
static inline u64 le64_to_cpup(const __le64 *p) { return le64_to_cpu(*p); }
static inline u16 be16_to_cpup(const __be16 *p) { return be16_to_cpu(*p); }
static inline u32 be32_to_cpup(const __be32 *p) { return be32_to_cpu(*p); }
static inline void le16_add_cpu(__le16 *var, u16 val) { *var = cpu_to_le16(le16_to_cpu(*var) + val); }
static inline void le32_add_cpu(__le32 *var, u32 val) { *var = cpu_to_le32(le32_to_cpu(*var) + val); }
static inline void cpu_to_le32_array(u32 *buf, unsigned int words) { (void) buf; (void) words; }
static inline void le32_to_cpu_array(u32 *buf, unsigned int words) { (void) buf; (void) words; }

/* Unaligned access through memcpy */
#define __kc_get_unaligned_t(type, ptr) ({ type __v; memcpy(&__v, (ptr), sizeof(__v)); __v; })
#define __kc_put_unaligned_t(type, val, ptr) do { type __v = (val); memcpy((ptr), &__v, sizeof(__v)); } while (0)
#define get_unaligned(ptr) __kc_get_unaligned_t(typeof(*(ptr)), ptr)
#define put_unaligned(val, ptr) __kc_put_unaligned_t(typeof(*(ptr)), val, ptr)
static inline u16 get_unaligned_le16(const void *p) { return __kc_get_unaligned_t(u16, p); }
static inline u32 get_unaligned_le32(const void *p) { return __kc_get_unaligned_t(u32, p); }
static inline u64 get_unaligned_le64(const void *p) { return __kc_get_unaligned_t(u64, p); }
static inline u16 get_unaligned_be16(const void *p) { return swab16(__kc_get_unaligned_t(u16, p)); }
static inline u32 get_unaligned_be32(const void *p) { return swab32(__kc_get_unaligned_t(u32, p)); }
static inline u64 get_unaligned_be64(const void *p) { return swab64(__kc_get_unaligned_t(u64, p)); }
static inline void put_unaligned_le16(u16 v, void *p) { __kc_put_unaligned_t(u16, v, p); }
static inline void put_unaligned_le32(u32 v, void *p) { __kc_put_unaligned_t(u32, v, p); }
static inline void put_unaligned_le64(u64 v, void *p) { __kc_put_unaligned_t(u64, v, p); }
static inline void put_unaligned_be16(u16 v, void *p) { __kc_put_unaligned_t(u16, swab16(v), p); }
static inline void put_unaligned_be32(u32 v, void *p) { __kc_put_unaligned_t(u32, swab32(v), p); }
static inline void put_unaligned_be64(u64 v, void *p) { __kc_put_unaligned_t(u64, swab64(v), p); }
static inline u32 get_unaligned_le24(const void *p) {
    const u8 *b = p;
    return b[0] | (b[1] << 8) | ((u32) b[2] << 16);
}
static inline void put_unaligned_le24(u32 v, void *p) {
    u8 *b = p;
    b[0] = v & 0xff; b[1] = (v >> 8) & 0xff; b[2] = (v >> 16) & 0xff;
}

/* bitfield.h */
#define __bf_shf(x) (__builtin_ffsll(x) - 1)
#define FIELD_MAX(mask) ((typeof(mask)) ((mask) >> __bf_shf(mask)))
#define FIELD_FIT(mask, val) (!((((typeof(mask)) (val)) << __bf_shf(mask)) & ~(mask)))
#define FIELD_PREP(mask, val) ((typeof(mask)) ((((typeof(mask)) (val)) << __bf_shf(mask)) & (mask)))
#define FIELD_GET(mask, reg) ((typeof(mask)) (((reg) & (mask)) >> __bf_shf(mask)))
#define FIELD_PREP_CONST(mask, val) FIELD_PREP(mask, val)
#define FIELD_MODIFY(mask, reg, val) \
    (*(reg) = (*(reg) & ~(mask)) | FIELD_PREP(mask, val))

static inline u64 __kc_field_mask(u64 field) { return field / (field & -field); }

#define __KC_MAKE_OP(type, base, to, from) \
static inline __##type type##_encode_bits(base v, base field) { \
    return to((v & (base) __kc_field_mask(field)) * (field & -field)); \
} \
static inline __##type type##_replace_bits(__##type old, base val, base field) { \
    return (old & ~to(field)) | type##_encode_bits(val, field); \
} \
static inline void type##p_replace_bits(__##type *p, base val, base field) { \
    *p = (*p & ~to(field)) | type##_encode_bits(val, field); \
} \
static inline base type##_get_bits(__##type v, base field) { \
    return (from(v) & field) / (field & -field); \
}
#define __KC_IDENT(x) (x)
typedef u8 __u8_t;
typedef u16 __u16_t;
typedef u32 __u32_t;
typedef u64 __u64_t;
#define __KC_MAKE_HOST_OP(type) \
static inline type type##_encode_bits(type v, type field) { \
    return (v & (type) __kc_field_mask(field)) * (field & -field); \
} \
static inline type type##_replace_bits(type old, type val, type field) { \
    return (old & ~field) | type##_encode_bits(val, field); \
} \
static inline void type##p_replace_bits(type *p, type val, type field) { \
    *p = (*p & ~field) | type##_encode_bits(val, field); \
} \
static inline type type##_get_bits(type v, type field) { \
    return (v & field) / (field & -field); \
}
__KC_MAKE_HOST_OP(u8)
__KC_MAKE_HOST_OP(u16)
__KC_MAKE_HOST_OP(u32)
__KC_MAKE_HOST_OP(u64)
__KC_MAKE_OP(le16, u16, cpu_to_le16, le16_to_cpu)
__KC_MAKE_OP(le32, u32, cpu_to_le32, le32_to_cpu)
__KC_MAKE_OP(le64, u64, cpu_to_le64, le64_to_cpu)
__KC_MAKE_OP(be16, u16, cpu_to_be16, be16_to_cpu)
__KC_MAKE_OP(be32, u32, cpu_to_be32, be32_to_cpu)
__KC_MAKE_OP(be64, u64, cpu_to_be64, be64_to_cpu)

/* Doubly linked lists, as include/linux/list.h */
struct list_head {
    struct list_head *next, *prev;
};
struct hlist_head {
    struct hlist_node *first;
};
struct hlist_node {
    struct hlist_node *next, **pprev;
};

#define LIST_HEAD_INIT(name) { &(name), &(name) }
#define LIST_HEAD(name) struct list_head name = LIST_HEAD_INIT(name)
static inline void INIT_LIST_HEAD(struct list_head *l) { l->next = l; l->prev = l; }
static inline void __list_add(struct list_head *n, struct list_head *prev, struct list_head *next) {
    next->prev = n; n->next = next; n->prev = prev; prev->next = n;
}
static inline void list_add(struct list_head *n, struct list_head *head) { __list_add(n, head, head->next); }
static inline void list_add_tail(struct list_head *n, struct list_head *head) { __list_add(n, head->prev, head); }
static inline void __list_del(struct list_head *prev, struct list_head *next) { next->prev = prev; prev->next = next; }
static inline void list_del(struct list_head *e) { __list_del(e->prev, e->next); e->next = e->prev = NULL; }
static inline void list_del_init(struct list_head *e) { __list_del(e->prev, e->next); INIT_LIST_HEAD(e); }
static inline void list_move(struct list_head *l, struct list_head *h) { __list_del(l->prev, l->next); list_add(l, h); }
static inline void list_move_tail(struct list_head *l, struct list_head *h) { __list_del(l->prev, l->next); list_add_tail(l, h); }
static inline bool list_empty(const struct list_head *h) { return h->next == h; }
static inline bool list_is_singular(const struct list_head *h) { return !list_empty(h) && h->next == h->prev; }
static inline void list_splice_init(struct list_head *list, struct list_head *head) {
    if (!list_empty(list)) {
        struct list_head *first = list->next, *last = list->prev, *at = head->next;
        first->prev = head; head->next = first; last->next = at; at->prev = last;
        INIT_LIST_HEAD(list);
    }
}
static inline void list_splice_tail_init(struct list_head *list, struct list_head *head) {
    if (!list_empty(list)) {
        struct list_head *first = list->next, *last = list->prev, *at = head->prev;
        first->prev = at; at->next = first; last->next = head; head->prev = last;
        INIT_LIST_HEAD(list);
    }
}
#define list_entry(ptr, type, member) container_of(ptr, type, member)
#define list_first_entry(ptr, type, member) list_entry((ptr)->next, type, member)
#define list_last_entry(ptr, type, member) list_entry((ptr)->prev, type, member)
#define list_first_entry_or_null(ptr, type, member) \
    (!list_empty(ptr) ? list_first_entry(ptr, type, member) : NULL)
#define list_next_entry(pos, member) list_entry((pos)->member.next, typeof(*(pos)), member)
#define list_entry_is_head(pos, head, member) (&(pos)->member == (head))
#define list_for_each(pos, head) for (pos = (head)->next; pos != (head); pos = pos->next)
#define list_for_each_safe(pos, n, head) \
    for (pos = (head)->next, n = pos->next; pos != (head); pos = n, n = pos->next)
#define list_for_each_entry(pos, head, member) \
    for (pos = list_first_entry(head, typeof(*pos), member); \
         !list_entry_is_head(pos, head, member); pos = list_next_entry(pos, member))
#define list_for_each_entry_safe(pos, n, head, member) \
    for (pos = list_first_entry(head, typeof(*pos), member), n = list_next_entry(pos, member); \
         !list_entry_is_head(pos, head, member); pos = n, n = list_next_entry(n, member))
#define list_for_each_entry_rcu(pos, head, member, ...) list_for_each_entry(pos, head, member)
#define list_add_rcu list_add
#define list_add_tail_rcu list_add_tail
#define list_del_rcu list_del

#define INIT_HLIST_HEAD(ptr) ((ptr)->first = NULL)
static inline void INIT_HLIST_NODE(struct hlist_node *h) { h->next = NULL; h->pprev = NULL; }

#endif
