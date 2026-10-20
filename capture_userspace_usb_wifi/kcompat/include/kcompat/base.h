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

#ifndef __KCOMPAT_BASE_H__
#define __KCOMPAT_BASE_H__

/* Linux kernel types, compiler annotations and core macros for building unmodified
 * kernel driver code in userspace.  Semantics follow the kernel; only what the
 * drivers use is provided. */

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/types.h>

#if !defined(__BYTE_ORDER__) || __BYTE_ORDER__ != __ORDER_LITTLE_ENDIAN__
#error "kcompat currently supports little-endian hosts only"
#endif

/* Types */
typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
typedef int8_t __s8;
typedef int16_t __s16;
typedef int32_t __s32;
typedef int64_t __s64;

typedef uint16_t __le16;
typedef uint32_t __le32;
typedef uint64_t __le64;
typedef uint16_t __be16;
typedef uint32_t __be32;
typedef uint64_t __be64;
typedef int16_t __sle16;
typedef int32_t __sle32;
typedef uint16_t __sum16;
typedef uint32_t __wsum;

typedef unsigned int gfp_t;
typedef uint64_t dma_addr_t;
typedef uint64_t phys_addr_t;
typedef uint64_t resource_size_t;
typedef int64_t ktime_t;
typedef unsigned short umode_t;
typedef long long __kernel_loff_t;
#define loff_t long long
typedef unsigned char u_char;
typedef unsigned long kernel_ulong_t;

/* Compiler annotations */
#undef __packed
#define __packed __attribute__((__packed__))
#undef __aligned
#define __aligned(x) __attribute__((__aligned__(x)))
#undef __always_inline
#define __always_inline inline __attribute__((__always_inline__))
#define __maybe_unused __attribute__((__unused__))
#define __always_unused __attribute__((__unused__))
#undef __used
#define __used __attribute__((__used__))
#define __must_check __attribute__((__warn_unused_result__))
#undef __cold
#define __cold __attribute__((__cold__))
#undef __weak
#define __weak __attribute__((__weak__))
#undef __printf
#define __printf(a, b) __attribute__((__format__(printf, a, b)))
#undef __noreturn
#define __noreturn __attribute__((__noreturn__))
#define noinline __attribute__((__noinline__))
#undef __pure
#define __pure __attribute__((__pure__))
#define __init
#define __exit
#define __initconst
#define __ro_after_init
#define __read_mostly
#define __force
#define __iomem
#define __rcu
#define __user
#define __percpu
#define __bitwise
#undef __nonstring
#define __nonstring
#undef __counted_by
#define __counted_by(m)
#undef __counted_by_le
#define __counted_by_le(m)
#undef __sized_by
#define __sized_by(m)
#define __acquires(x)
#define __releases(x)
#define __must_hold(x)
#define __acquire(x) (void) 0
#define __release(x) (void) 0
#define __cond_acquires(x)
#define __no_context_analysis
#define notrace
#define memzero_explicit(p, n) do { volatile u8 *__p = (volatile u8 *) (p); for (size_t __i = 0; __i < (n); __i++) __p[__i] = 0; } while (0)
#ifndef __attribute_const__
#define __attribute_const__ __attribute__((__const__))
#endif
#define BUILD_BUG_ON_NOT_POWER_OF_2(n) BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))
#define memset_after(obj, v, member) \
    memset((u8 *) (obj) + offsetofend(typeof(*(obj)), member), v, \
           sizeof(*(obj)) - offsetofend(typeof(*(obj)), member))
#define memset_startat(obj, v, member) \
    memset((u8 *) (obj) + offsetof(typeof(*(obj)), member), v, \
           sizeof(*(obj)) - offsetof(typeof(*(obj)), member))

/* Scoped guards, as linux/cleanup.h */
#define __free(fn) __attribute__((__cleanup__(__free_##fn)))
#define DEFINE_GUARD(_name, _type, _lock, _unlock) \
    typedef _type class_##_name##_t; \
    static inline void class_##_name##_destructor(_type *p) { _type _T = *p; if (_T) { _unlock; } } \
    static inline _type class_##_name##_constructor(_type _T) { _lock; return _T; }
#define DEFINE_GUARD_COND(_name, _ext, _cond)
#define guard(_name) \
    class_##_name##_t __UNIQUE_ID(guard) __attribute__((__cleanup__(class_##_name##_destructor))) = \
        class_##_name##_constructor
#define scoped_guard(_name, args...) \
    for (class_##_name##_t __scope __attribute__((__cleanup__(class_##_name##_destructor))) = \
         class_##_name##_constructor(args), *__done = NULL; !__done; __done = (void *) 1)
#define fallthrough __attribute__((__fallthrough__))
#define __stringify_1(x...) #x
#define __stringify(x...) __stringify_1(x)
#define ___PASTE(a, b) a##b
#define __PASTE(a, b) ___PASTE(a, b)
#define __UNIQUE_ID(prefix) __PASTE(__PASTE(__UNIQUE_ID_, prefix), __COUNTER__)

#define likely(x) __builtin_expect(!!(x), 1)
#define unlikely(x) __builtin_expect(!!(x), 0)
#define barrier() __asm__ __volatile__("" ::: "memory")
#define smp_mb() __atomic_thread_fence(__ATOMIC_SEQ_CST)
#define smp_rmb() __atomic_thread_fence(__ATOMIC_ACQUIRE)
#define smp_wmb() __atomic_thread_fence(__ATOMIC_RELEASE)
#define mb() smp_mb()
#define rmb() smp_rmb()
#define wmb() smp_wmb()
#define dma_wmb() smp_wmb()
#define dma_rmb() smp_rmb()
#define smp_mb__before_atomic() smp_mb()
#define smp_mb__after_atomic() smp_mb()
#define READ_ONCE(x) __atomic_load_n(&(x), __ATOMIC_RELAXED)
#define WRITE_ONCE(x, v) __atomic_store_n(&(x), (v), __ATOMIC_RELAXED)
#define smp_load_acquire(p) __atomic_load_n(p, __ATOMIC_ACQUIRE)
#define smp_store_release(p, v) __atomic_store_n(p, v, __ATOMIC_RELEASE)
#define cpu_relax() barrier()
#define unreachable() __builtin_unreachable()
#define might_sleep() do { } while (0)
#define cond_resched() do { } while (0)

#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))
#define __is_constexpr(x) __builtin_constant_p(x)
#define BUILD_BUG_ON(c) _Static_assert(!(c), "BUILD_BUG_ON(" #c ")")
#define BUILD_BUG_ON_ZERO(e) 0
#define BUILD_BUG_ON_MSG(c, m) _Static_assert(!(c), m)
#define __must_be_array(a) 0
#ifndef static_assert
#define static_assert(expr, ...) _Static_assert(expr, #expr)
#endif

/* Kconfig; IS_ENABLED() as in the kernel */
#define __ARG_PLACEHOLDER_1 0,
#define __take_second_arg(__ignored, val, ...) val
#define __is_defined(x) ___is_defined(x)
#define ___is_defined(val) ____is_defined(__ARG_PLACEHOLDER_##val)
#define ____is_defined(arg1_or_junk) __take_second_arg(arg1_or_junk 1, 0)
#define __or(x, y) ___or(x, y)
#define ___or(x, y) ____or(__ARG_PLACEHOLDER_##x, y)
#define ____or(arg1_or_junk, y) __take_second_arg(arg1_or_junk 1, y)
#define IS_BUILTIN(option) __is_defined(option)
#define IS_MODULE(option) __is_defined(option##_MODULE)
#define IS_REACHABLE(option) __or(IS_BUILTIN(option), IS_MODULE(option))
#define IS_ENABLED(option) __or(IS_BUILTIN(option), IS_MODULE(option))

/* Core macros */
#define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#define container_of(ptr, type, member) \
    ((type *) (void *) ((char *) (ptr) - offsetof(type, member)))
#define container_of_const(ptr, type, member) container_of(ptr, type, member)
#define sizeof_field(t, m) sizeof(((t *) 0)->m)
#define offsetofend(t, m) (offsetof(t, m) + sizeof_field(t, m))
#define typeof_member(t, m) typeof(((t *) 0)->m)

#define min(a, b) ({ typeof(a) _a = (a); typeof(b) _b = (b); _a < _b ? _a : _b; })
#define max(a, b) ({ typeof(a) _a = (a); typeof(b) _b = (b); _a > _b ? _a : _b; })
#define min_t(t, a, b) ({ t _a = (t) (a); t _b = (t) (b); _a < _b ? _a : _b; })
#define max_t(t, a, b) ({ t _a = (t) (a); t _b = (t) (b); _a > _b ? _a : _b; })
#define min3(a, b, c) min(min(a, b), c)
#define max3(a, b, c) max(max(a, b), c)
#define umin(a, b) min_t(unsigned long long, a, b)
#define umax(a, b) max_t(unsigned long long, a, b)
#define clamp(v, lo, hi) min(max(v, lo), hi)
#define clamp_t(t, v, lo, hi) min_t(t, max_t(t, v, lo), hi)
#define clamp_val(v, lo, hi) clamp_t(typeof(v), v, lo, hi)
#define swap(a, b) do { typeof(a) _t = (a); (a) = (b); (b) = _t; } while (0)
#define abs(x) ({ typeof(x) _x = (x); _x < 0 ? -_x : _x; })
#define abs_diff(a, b) ({ typeof(a) _a = (a); typeof(b) _b = (b); _a > _b ? _a - _b : _b - _a; })
static inline s32 sign_extend32(u32 value, int index) {
    u8 shift = (u8) (31 - index);
    return (s32) (value << shift) >> shift;
}
#define bcd2bin(x) ((unsigned int) (((x) & 0x0f) + (((x) >> 4) & 0x0f) * 10))

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))
#define DIV_ROUND_UP_ULL(n, d) DIV_ROUND_UP((unsigned long long) (n), (d))
#define DIV_ROUND_CLOSEST(x, d) ({ typeof(x) _x = (x); typeof(d) _d = (d); \
    (((typeof(x)) -1) > 0 || ((typeof(d)) -1) > 0 || ((_x) > 0) == ((_d) > 0)) ? \
    (((_x) + ((_d) / 2)) / (_d)) : (((_x) - ((_d) / 2)) / (_d)); })
#define roundup(x, y) ((((x) + ((y) - 1)) / (y)) * (y))
#define rounddown(x, y) ((x) - ((x) % (y)))
#define __round_mask(x, y) ((typeof(x)) ((y) - 1))
#define round_up(x, y) ((((x) - 1) | __round_mask(x, y)) + 1)
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define ALIGN(x, a) (((x) + ((typeof(x)) (a) - 1)) & ~((typeof(x)) (a) - 1))
#define ALIGN_DOWN(x, a) ALIGN((x) - ((a) - 1), (a))
#define PTR_ALIGN(p, a) ((typeof(p)) ALIGN((unsigned long) (p), (a)))
#define IS_ALIGNED(x, a) (((x) & ((typeof(x)) (a) - 1)) == 0)

#define BITS_PER_BYTE 8
#define BITS_PER_LONG (sizeof(long) * 8)
#define BITS_PER_LONG_LONG 64
#define BIT(n) (1UL << (n))
#define BIT_ULL(n) (1ULL << (n))
#define BIT_MASK(n) (1UL << ((n) % BITS_PER_LONG))
#define BIT_WORD(n) ((n) / BITS_PER_LONG)
#define BITS_TO_LONGS(n) DIV_ROUND_UP(n, BITS_PER_LONG)
#define BITS_TO_U32(n) DIV_ROUND_UP(n, 32)
#define GENMASK(h, l) (((~0UL) - (1UL << (l)) + 1) & (~0UL >> (BITS_PER_LONG - 1 - (h))))
#define GENMASK_ULL(h, l) (((~0ULL) - (1ULL << (l)) + 1) & (~0ULL >> (63 - (h))))
#define GENMASK_U8(h, l) ((u8) GENMASK(h, l))
#define GENMASK_U16(h, l) ((u16) GENMASK(h, l))
#define GENMASK_U32(h, l) ((u32) GENMASK(h, l))
#define BIT_U8(n) ((u8) BIT(n))
#define BIT_U16(n) ((u16) BIT(n))
#define BIT_U32(n) ((u32) BIT(n))
#define DECLARE_BITMAP(name, bits) unsigned long name[BITS_TO_LONGS(bits)]

#define U8_MAX ((u8) ~0U)
#define S8_MAX ((s8) (U8_MAX >> 1))
#define S8_MIN ((s8) (-S8_MAX - 1))
#define U16_MAX ((u16) ~0U)
#define S16_MAX ((s16) (U16_MAX >> 1))
#define S16_MIN ((s16) (-S16_MAX - 1))
#define U32_MAX ((u32) ~0U)
#define S32_MAX ((s32) (U32_MAX >> 1))
#define S32_MIN ((s32) (-S32_MAX - 1))
#define U64_MAX ((u64) ~0ULL)
#define S64_MAX ((s64) (U64_MAX >> 1))
#define S64_MIN ((s64) (-S64_MAX - 1))
#define SIZE_MAX_K ((size_t) ~(size_t) 0)

#define upper_32_bits(n) ((u32) (((n) >> 16) >> 16))
#define lower_32_bits(n) ((u32) ((n) & 0xffffffff))
#define upper_16_bits(n) ((u16) ((n) >> 16))
#define lower_16_bits(n) ((u16) ((n) & 0xffff))

/* Flexible arrays and sizes; overflow saturates as in the kernel */
static inline size_t __kc_size_mul(size_t a, size_t b) {
    size_t r;
    return __builtin_mul_overflow(a, b, &r) ? (size_t) -1 : r;
}
static inline size_t __kc_size_add(size_t a, size_t b) {
    size_t r;
    return __builtin_add_overflow(a, b, &r) ? (size_t) -1 : r;
}
#define size_mul(a, b) __kc_size_mul(a, b)
#define size_add(a, b) __kc_size_add(a, b)
#define array_size(a, b) size_mul(a, b)
#define flex_array_size(p, member, count) size_mul(count, sizeof(*(p)->member))
#define struct_size(p, member, count) size_add(sizeof(*(p)), flex_array_size(p, member, count))
#define struct_size_t(type, member, count) struct_size((type *) NULL, member, count)
#define check_add_overflow(a, b, d) __builtin_add_overflow(a, b, d)
#define check_mul_overflow(a, b, d) __builtin_mul_overflow(a, b, d)
#define check_sub_overflow(a, b, d) __builtin_sub_overflow(a, b, d)

#define __struct_group(TAG, NAME, ATTRS, MEMBERS...) \
    union { struct { MEMBERS } ATTRS; struct TAG { MEMBERS } ATTRS NAME; } ATTRS
#define struct_group(NAME, MEMBERS...) __struct_group(, NAME, , MEMBERS)
#define struct_group_attr(NAME, ATTRS, MEMBERS...) __struct_group(, NAME, ATTRS, MEMBERS)
#define struct_group_tagged(TAG, NAME, MEMBERS...) __struct_group(TAG, NAME, , MEMBERS)
#define DECLARE_FLEX_ARRAY(TYPE, NAME) struct { struct { } __empty_##NAME; TYPE NAME[]; }
#define __DECLARE_FLEX_ARRAY(TYPE, NAME) DECLARE_FLEX_ARRAY(TYPE, NAME)

/* Division */
static inline u64 div_u64(u64 n, u32 d) { return n / d; }
static inline s64 div_s64(s64 n, s32 d) { return n / d; }
static inline u64 div64_u64(u64 n, u64 d) { return n / d; }
static inline s64 div64_s64(s64 n, s64 d) { return n / d; }
static inline u64 div_u64_rem(u64 n, u32 d, u32 *r) { *r = (u32) (n % d); return n / d; }
#define do_div(n, base) ({ u32 __rem = (u32) ((n) % (base)); (n) /= (base); __rem; })
#define mult_frac(x, n, d) (((x) / (d)) * (n) + (((x) % (d)) * (n)) / (d))

/* Bit counting */
static inline unsigned int hweight8(unsigned int w) { return __builtin_popcount(w & 0xff); }
static inline unsigned int hweight16(unsigned int w) { return __builtin_popcount(w & 0xffff); }
static inline unsigned int hweight32(unsigned int w) { return __builtin_popcount(w); }
static inline unsigned long hweight64(u64 w) { return __builtin_popcountll(w); }
static inline unsigned long hweight_long(unsigned long w) { return __builtin_popcountl(w); }
static inline int kc_ffs(int x) { return __builtin_ffs(x); }
#define ffs kc_ffs
static inline int kc_fls(unsigned int x) { return x ? 32 - __builtin_clz(x) : 0; }
#define fls kc_fls
static inline int kc_fls64(u64 x) { return x ? 64 - __builtin_clzll(x) : 0; }
#define fls64 kc_fls64
static inline unsigned long __ffs(unsigned long x) { return __builtin_ctzl(x); }
static inline unsigned long __fls(unsigned long x) { return BITS_PER_LONG - 1 - __builtin_clzl(x); }
static inline unsigned int __ffs64(u64 x) { return __builtin_ctzll(x); }
static inline unsigned long ffz(unsigned long x) { return __builtin_ctzl(~x); }
#define ilog2(n) ((n) ? 63 - __builtin_clzll((u64) (n)) : -1)
static inline bool is_power_of_2(unsigned long n) { return n != 0 && (n & (n - 1)) == 0; }
static inline unsigned long roundup_pow_of_two(unsigned long n) {
    return n <= 1 ? 1 : 1UL << fls64(n - 1);
}
static inline unsigned long rounddown_pow_of_two(unsigned long n) {
    return n ? 1UL << (fls64(n) - 1) : 0;
}
#define order_base_2(n) ((n) > 1 ? ilog2((n) - 1) + 1 : 0)

/* Atomic bit operations on unsigned long bitmaps */
static inline void set_bit(long nr, volatile unsigned long *addr) {
    __atomic_fetch_or(&addr[BIT_WORD(nr)], BIT_MASK(nr), __ATOMIC_SEQ_CST);
}
static inline void clear_bit(long nr, volatile unsigned long *addr) {
    __atomic_fetch_and(&addr[BIT_WORD(nr)], ~BIT_MASK(nr), __ATOMIC_SEQ_CST);
}
static inline void change_bit(long nr, volatile unsigned long *addr) {
    __atomic_fetch_xor(&addr[BIT_WORD(nr)], BIT_MASK(nr), __ATOMIC_SEQ_CST);
}
static inline bool test_bit(long nr, const volatile unsigned long *addr) {
    return (__atomic_load_n(&addr[BIT_WORD(nr)], __ATOMIC_SEQ_CST) & BIT_MASK(nr)) != 0;
}
static inline bool test_and_set_bit(long nr, volatile unsigned long *addr) {
    return (__atomic_fetch_or(&addr[BIT_WORD(nr)], BIT_MASK(nr), __ATOMIC_SEQ_CST) & BIT_MASK(nr)) != 0;
}
static inline bool test_and_clear_bit(long nr, volatile unsigned long *addr) {
    return (__atomic_fetch_and(&addr[BIT_WORD(nr)], ~BIT_MASK(nr), __ATOMIC_SEQ_CST) & BIT_MASK(nr)) != 0;
}
#define __set_bit(nr, addr) set_bit(nr, addr)
#define __clear_bit(nr, addr) clear_bit(nr, addr)
#define __test_and_set_bit(nr, addr) test_and_set_bit(nr, addr)
#define __test_and_clear_bit(nr, addr) test_and_clear_bit(nr, addr)
#define __assign_bit(nr, addr, v) ((v) ? set_bit(nr, addr) : clear_bit(nr, addr))
#define assign_bit(nr, addr, v) __assign_bit(nr, addr, v)
#define set_bit_unlock(nr, addr) set_bit(nr, addr)
#define clear_bit_unlock(nr, addr) clear_bit(nr, addr)
#define test_and_set_bit_lock(nr, addr) test_and_set_bit(nr, addr)

static inline unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
        unsigned long offset) {
    for (; offset < size; offset++)
        if (addr[BIT_WORD(offset)] & BIT_MASK(offset))
            return offset;
    return size;
}
static inline unsigned long find_next_zero_bit(const unsigned long *addr, unsigned long size,
        unsigned long offset) {
    for (; offset < size; offset++)
        if (!(addr[BIT_WORD(offset)] & BIT_MASK(offset)))
            return offset;
    return size;
}
#define find_first_bit(addr, size) find_next_bit(addr, size, 0)
#define find_first_zero_bit(addr, size) find_next_zero_bit(addr, size, 0)
#define for_each_set_bit(bit, addr, size) \
    for ((bit) = find_first_bit(addr, size); (bit) < (size); (bit) = find_next_bit(addr, size, (bit) + 1))
#define for_each_clear_bit(bit, addr, size) \
    for ((bit) = find_first_zero_bit(addr, size); (bit) < (size); \
         (bit) = find_next_zero_bit(addr, size, (bit) + 1))
static inline void bitmap_zero(unsigned long *dst, unsigned int nbits) {
    memset(dst, 0, BITS_TO_LONGS(nbits) * sizeof(unsigned long));
}
static inline void bitmap_fill(unsigned long *dst, unsigned int nbits) {
    memset(dst, 0xff, BITS_TO_LONGS(nbits) * sizeof(unsigned long));
}
static inline bool bitmap_empty(const unsigned long *src, unsigned int nbits) {
    return find_first_bit(src, nbits) >= nbits;
}
static inline unsigned int bitmap_weight(const unsigned long *src, unsigned int nbits) {
    unsigned int w = 0;
    for (unsigned int i = 0; i < nbits; i++)
        w += (src[BIT_WORD(i)] & BIT_MASK(i)) != 0;
    return w;
}

/* Errors */
#define ERESTARTSYS 512
#ifndef EREMOTEIO
#define EREMOTEIO 121
#endif
#ifndef EBADMSG
#define EBADMSG 74
#endif
#define ENOIOCTLCMD 515
#define EPROBE_DEFER 517
#define ENOTSUPP 524
#ifndef ECOMM
#define ECOMM 70
#endif
#define MAX_ERRNO 4095
#define IS_ERR_VALUE(x) unlikely((unsigned long) (void *) (x) >= (unsigned long) -MAX_ERRNO)
static inline void *ERR_PTR(long error) { return (void *) error; }
static inline long PTR_ERR(const void *ptr) { return (long) ptr; }
static inline bool IS_ERR(const void *ptr) { return IS_ERR_VALUE((unsigned long) ptr); }
static inline bool IS_ERR_OR_NULL(const void *ptr) { return !ptr || IS_ERR(ptr); }
static inline void *ERR_CAST(const void *ptr) { return (void *) ptr; }
static inline int PTR_ERR_OR_ZERO(const void *ptr) { return IS_ERR(ptr) ? (int) PTR_ERR(ptr) : 0; }

/* Logging; routed through kc_printk so a consumer can redirect it */
#define KERN_EMERG "<0>"
#define KERN_ALERT "<1>"
#define KERN_CRIT "<2>"
#define KERN_ERR "<3>"
#define KERN_WARNING "<4>"
#define KERN_NOTICE "<5>"
#define KERN_INFO "<6>"
#define KERN_DEBUG "<7>"
#define KERN_CONT ""
#define KERN_DEFAULT ""
void kc_printk(const char *fmt, ...) __printf(1, 2);
#define printk(fmt, ...) kc_printk(fmt, ##__VA_ARGS__)
#define printk_once(fmt, ...) printk(fmt, ##__VA_ARGS__)
enum { DUMP_PREFIX_NONE, DUMP_PREFIX_ADDRESS, DUMP_PREFIX_OFFSET };
void print_hex_dump(const char *level, const char *prefix_str, int prefix_type, int rowsize,
        int groupsize, const void *buf, size_t len, bool ascii);
#define pr_fmt(fmt) fmt
#define pr_emerg(fmt, ...) printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_err(fmt, ...) printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define pr_warn(fmt, ...) printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define pr_notice(fmt, ...) printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define pr_info(fmt, ...) printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#define pr_debug(fmt, ...) printk(KERN_DEBUG pr_fmt(fmt), ##__VA_ARGS__)
#define pr_cont(fmt, ...) printk(fmt, ##__VA_ARGS__)
#define pr_err_ratelimited pr_err
#define pr_warn_ratelimited pr_warn
#define pr_info_ratelimited pr_info
#define pr_debug_ratelimited pr_debug
#define pr_warn_once pr_warn
#define pr_err_once pr_err
#define pr_info_once pr_info
#define net_ratelimit() 1
#define printk_ratelimit() 1

#define WARN(cond, fmt, ...) ({ int __c = !!(cond); \
    if (unlikely(__c)) kc_printk(KERN_WARNING "WARNING at %s:%d: " fmt, __FILE__, __LINE__, ##__VA_ARGS__); \
    unlikely(__c); })
#define WARN_ON(cond) ({ int __c = !!(cond); \
    if (unlikely(__c)) kc_printk(KERN_WARNING "WARNING: %s at %s:%d\n", #cond, __FILE__, __LINE__); \
    unlikely(__c); })
#define WARN_ONCE(cond, fmt, ...) WARN(cond, fmt, ##__VA_ARGS__)
#define WARN_ON_ONCE(cond) WARN_ON(cond)
#define WARN_ON_SMP(cond) WARN_ON(cond)
#define BUG() do { kc_printk(KERN_EMERG "BUG at %s:%d\n", __FILE__, __LINE__); abort(); } while (0)
#define BUG_ON(cond) do { if (unlikely(cond)) BUG(); } while (0)
#define lockdep_assert_held(l) do { (void) (l); } while (0)
#define lockdep_assert_not_held(l) do { (void) (l); } while (0)
#define lockdep_is_held(l) 1

/* Modules; drivers register through constructors */
struct module;
#define THIS_MODULE ((struct module *) 0)
#ifndef KBUILD_MODNAME
#define KBUILD_MODNAME "kcompat"
#endif
#define EXPORT_SYMBOL(sym)
#define EXPORT_SYMBOL_GPL(sym)
#define EXPORT_SYMBOL_NS_GPL(sym, ns)
#define MODULE_LICENSE(x)
#define MODULE_AUTHOR(x)
#define MODULE_DESCRIPTION(x)
#define MODULE_VERSION(x)
#define MODULE_FIRMWARE(x)
#define MODULE_DEVICE_TABLE(type, name)
#define MODULE_IMPORT_NS(ns)
#define MODULE_PARM_DESC(p, d)
#define module_param(name, type, perm)
#define module_param_named(name, value, type, perm)
#define module_init(fn) static void __attribute__((constructor)) __kc_init_##fn(void) { fn(); }
#define module_exit(fn)

/* Strings */
int kc_scnprintf(char *buf, size_t size, const char *fmt, ...) __printf(3, 4);
#define scnprintf kc_scnprintf
#define strscpy(dst, src, ...) ({ size_t __n = sizeof(dst); \
    strncpy(dst, src, __n); (dst)[__n - 1] = 0; (ssize_t) strlen(dst); })
#define strscpy_pad strscpy
static inline int kstrtou8(const char *s, unsigned int base, u8 *res) {
    char *end; unsigned long v = strtoul(s, &end, base);
    if (end == s || v > U8_MAX) return -EINVAL;
    *res = (u8) v; return 0;
}
static inline int kstrtou32(const char *s, unsigned int base, u32 *res) {
    char *end; unsigned long v = strtoul(s, &end, base);
    if (end == s || v > U32_MAX) return -EINVAL;
    *res = (u32) v; return 0;
}
static inline int kstrtobool(const char *s, bool *res) {
    if (!s) return -EINVAL;
    switch (s[0]) {
        case 'y': case 'Y': case '1': *res = true; return 0;
        case 'n': case 'N': case '0': *res = false; return 0;
        default: return -EINVAL;
    }
}

#endif
