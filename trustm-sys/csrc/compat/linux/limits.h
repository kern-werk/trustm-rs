/*
 * Fallback for toolchains without Linux UAPI headers. Included via -idirafter,
 * so a real <linux/limits.h> from the sysroot takes precedence when present.
 * The Infineon Linux PAL only needs NAME_MAX; libc's <limits.h> provides it.
 */
#ifndef _TMC_COMPAT_LINUX_LIMITS_H
#define _TMC_COMPAT_LINUX_LIMITS_H

#include <limits.h>

#ifndef NAME_MAX
#define NAME_MAX 255
#endif
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

#endif /* _TMC_COMPAT_LINUX_LIMITS_H */
