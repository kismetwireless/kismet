/*
 * GPL-2.0-or-later
 *
 * Userspace port (C) 2019 Hak5 Inc
 *
 */

#ifndef __USERSPACE_KERNEL_H__
#define __USERSPACE_KERNEL_H__ 

/*
 * Define some kernel nomenclature and functions that we just transpose into
 * normal gcc-isms, along with modified BUG_ON, WARN_ON, etc.
 */

#if !defined(_WIN32)
#define __packed __attribute__((packed))
#define __aligned(nr)  __attribute__((aligned (nr)))
#else
#define __packed
#define __aligned(nr)
#endif

#define __rcu

#ifndef __attribute_const__
#define __attribute_const__
#endif

#if defined(_MSC_VER)
/* Hack all constant compares to be true for MSC */
#define __builtin_constant_p(x) (1)

/* Use ternary to simulate builtin choose expr */
#define __builtin_choose_expr(e, t, f) ((e) ? (t) : (f))
#endif

/* 
 * Just test
 */
#define unlikely(x) (x)

#define BUILD_BUG_ON(condition) ((void)sizeof(char[1 - 2*!!(condition)]))
#define BUILD_BUG_ON_ZERO(e) (sizeof(struct { int:-!!(e); }))

/* Force a compilation error if a constant expression is not a power of 2 */
#define __BUILD_BUG_ON_NOT_POWER_OF_2(n)	\
	BUILD_BUG_ON(((n) & ((n) - 1)) != 0)
#define BUILD_BUG_ON_NOT_POWER_OF_2(n)			\
	BUILD_BUG_ON((n) == 0 || (((n) & ((n) - 1)) != 0))

#define BUG_ON(condition) do { if (unlikely(condition)) BUG(); } while (0)
#define BUG() do { \
	fprintf(stderr, "BUG: failure at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
    exit(-1); \
} while (0)

#define WARN_ONCE(condition, fmt, ...)					\
    do { if (condition) fprintf(stderr, "%s: WARNING - " fmt, __func__, ##__VA_ARGS__); } while (0)
#define WARN_ON_ONCE(condition)	 (condition)
#define WARN_ON(condition) do { if (unlikely(condition)) WARN(); } while (0)
#define WARN() do { \
	fprintf(stderr, "WARNING: warning at %s:%d/%s()!\n", __FILE__, __LINE__, __func__); \
} while (0)

#define READ_ONCE(x)    (x)
#define WRITE_ONCE(t, v)    ((t) = (v))

/*
 * We don't currently do kernel mutexes; this could be re-def'd to pthread 
 * mutexes if we need to
 */
#if 0
#define mutex_lock(x)       pthread_mutex_lock((x))
#define mutex_unlock(x)     pthread_mutex_unlock((x))
#else
#define mutex_lock(x)
#define mutex_unlock(x)
#endif


/*
 * Just treat sleeps and delays as usleeps
 */
#define msleep(x)  usleep(x * 1000)
#define udelay(x)  usleep(x)
#define usleep_range(x, y)  usleep(y)

/* 
 * Modified and simplified from the kernel macros 
 */

#define __cmp(x, y, op)	((x) op (y) ? (x) : (y))

/**
 * min_t - return minimum of two values, using the specified type
 * @type: data type to use
 * @x: first value
 * @y: second value
 */
#define min_t(type, x, y)	__cmp((type)(x), (type)(y), <)

/**
 * max_t - return maximum of two values, using the specified type
 * @type: data type to use
 * @x: first value
 * @y: second value
 */
#define max_t(type, x, y)	__cmp((type)(x), (type)(y), >)

/**
 * max - return maximum of two values of the same or compatible types
 * @x: first value
 * @y: second value
 */
#define max(x, y)	__cmp(x, y, >)

/*
 * This looks more complex than it should be. But we need to
 * get the type for the ~ right in round_down (it needs to be
 * as wide as the result!), and we want to evaluate the macro
 * arguments just once each.
 */
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
/**
 * round_up - round up to next specified power of 2
 * @x: the value to round
 * @y: multiple to round up to (must be a power of 2)
 *
 * Rounds @x up to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding up, use roundup() below.
 */
#ifndef round_up
#define round_up(x, y) ((((x)-1) | __round_mask(x, y))+1)
#endif
/**
 * round_down - round down to next specified power of 2
 * @x: the value to round
 * @y: multiple to round down to (must be a power of 2)
 *
 * Rounds @x down to next multiple of @y (which must be a power of 2).
 * To perform arbitrary rounding down, use rounddown() below.
 */
#ifndef round_down
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#endif

/**
 * FIELD_SIZEOF - get the size of a struct's field
 * @t: the target struct
 * @f: the target struct's field
 * Return: the size of @f in the struct definition without having a
 * declared instance of @t.
 */
#define FIELD_SIZEOF(t, f) (sizeof(((t*)0)->f))

#define DIV_ROUND_UP __KERNEL_DIV_ROUND_UP

#define DIV_ROUND_DOWN_ULL(ll, d) \
	({ unsigned long long _tmp = (ll); do_div(_tmp, d); _tmp; })

#define DIV_ROUND_UP_ULL(ll, d) \
	DIV_ROUND_DOWN_ULL((unsigned long long)(ll) + (d) - 1, (d))

#if BITS_PER_LONG == 32
# define DIV_ROUND_UP_SECTOR_T(ll,d) DIV_ROUND_UP_ULL(ll, d)
#else
# define DIV_ROUND_UP_SECTOR_T(ll,d) DIV_ROUND_UP(ll,d)
#endif

/**
 * roundup - round up to the next specified multiple
 * @x: the value to up
 * @y: multiple to round up to
 *
 * Rounds @x up to next multiple of @y. If @y will always be a power
 * of 2, consider using the faster round_up().
 */
#ifndef roundup
#define roundup(x, y) (					\
{							\
	typeof(y) __y = y;				\
	(((x) + (__y - 1)) / __y) * __y;		\
}							\
)
#endif
/**
 * rounddown - round down to next specified multiple
 * @x: the value to round
 * @y: multiple to round down to
 *
 * Rounds @x down to next multiple of @y. If @y will always be a power
 * of 2, consider using the faster round_down().
 */
#ifndef rounddown
#define rounddown(x, y) (				\
{							\
	typeof(x) __x = (x);				\
	__x - (__x % (y));				\
}							\
)
#endif

/*
 * Divide positive or negative dividend by positive or negative divisor
 * and round to closest integer. Result is undefined for negative
 * divisors if the dividend variable type is unsigned and for negative
 * dividends if the divisor variable type is unsigned.
 */
#define DIV_ROUND_CLOSEST(x, divisor)(			\
{							\
	typeof(x) __x = x;				\
	typeof(divisor) __d = divisor;			\
	(((typeof(x))-1) > 0 ||				\
	 ((typeof(divisor))-1) > 0 ||			\
	 (((__x) > 0) == ((__d) > 0))) ?		\
		(((__x) + ((__d) / 2)) / (__d)) :	\
		(((__x) - ((__d) / 2)) / (__d));	\
}							\
)
/*
 * Same as above but for u64 dividends. divisor must be a 32-bit
 * number.
 */
#define DIV_ROUND_CLOSEST_ULL(x, divisor)(		\
{							\
	typeof(divisor) __d = divisor;			\
	unsigned long long _tmp = (x) + (__d) / 2;	\
	do_div(_tmp, __d);				\
	_tmp;						\
}							\
)

#define __KERNEL_DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

/* Are two types/vars the same type (ignoring qualifiers)? */
#define __same_type(a, b) __builtin_types_compatible_p(typeof(a), typeof(b))

/* &a[0] degrades to a pointer: a different type from an array */
#define __must_be_array(a)	BUILD_BUG_ON_ZERO(__same_type((a), &(a)[0]))

/**
 * ARRAY_SIZE - get the number of elements in array @arr
 * @arr: array to be sized
 */
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

/*
 * Kluge in ENOTSUPP which isn't in userspace
 */
#define ENOTSUPP 524

/*
 * Kluge in symbol masking
 */
#define EXPORT_SYMBOL_GPL(x) 
#define EXPORT_SYMBOL(x)

#define GFP_KERNEL
/*
 * Hack kalloc to malloc
 */
#define kcalloc(nelem, sz, type)     malloc(nelem * sz)


#define kfree(n)    free(n)

#endif /* ifndef KERNEL_H */

