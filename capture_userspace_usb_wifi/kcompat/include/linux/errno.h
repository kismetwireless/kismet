/* Emulated kernel header; see kcompat/kcompat.h */
#ifdef __linux__
/* glibc's errno.h gets the error numbers from here, so defer to the uapi header */
#include_next <linux/errno.h>
#else
#include <kcompat/kcompat.h>
#endif
