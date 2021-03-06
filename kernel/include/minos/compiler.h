#ifndef __MINOS_COMPILER_H_
#define __MINOS_COMPILER_H_

#define __cache_line_size__	(64)

#define __section(S)		__attribute__((__section__(#S)))
#define __used			__attribute__((__used__))
#define __unused		__attribute__((__unused__))
#define __align(x)		__attribute__((__aligned__(x)))
#define __cache_line_align	__align(__cache_line_size__)
#define __packed		__attribute__((__packed__))
#define __noreturn		__attribute__((noreturn))
#define likely(x)		__builtin_expect(!!(x), 1)
#define unlikely(x)		__builtin_expect(!!(x), 0)
#define barrier()		__asm__ __volatile__("" ::: "memory")
#define unused(__arg__)		(void)(__arg__)

#define __user
#define __guest

#ifndef weak_alias
#define weak_alias(old, new) \
        extern __typeof(old) new __attribute__((__weak__, __alias__(#old)))
#endif

#endif
