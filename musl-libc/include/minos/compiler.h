#ifndef __MINOS_COMPILER_H_
#define __MINOS_COMPILER_H_

#define __section(S)		__attribute__((__section__(#S)))
#define __used			__attribute__((__used__))
#define __unused		__attribute__((__unused__))
#define __align(x)		__attribute__((__aligned__(x)))
#define __packed		__attribute__((__packed__))
#define unused(__arg__)		(void)(__arg__)

#ifndef likely
#define likely(x) __builtin_expect(!!(x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect(!!(x), 0)
#endif

#ifndef __noreturn
#define __noreturn __attribute__((noreturn))
#endif

#ifndef barrier
#define barrier() __asm__ __volatile__("" ::: "memory")
#endif

#ifndef weak
#define weak __attribute__((__weak__))
#endif

#ifndef hidden
#define hidden __attribute__((__visibility__("hidden")))
#endif

#ifndef weak_alias
#define weak_alias(old, new) \
        extern __typeof(old) new __attribute__((__weak__, __alias__(#old)))
#endif

#endif
