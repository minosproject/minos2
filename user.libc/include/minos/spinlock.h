#ifndef __LIBMINOS_SPINLOCK_H__
#define __LIBMINOS_SPINLOCK_H__

typedef struct spinlock {
	int value;
} spinlock_t;

extern void raw_spin_lock(spinlock_t *l);
extern void raw_spin_unlock(spinlock_t *l);

static inline void spinlock_init(spinlock_t *lock)
{
	lock->value = 0;
}

#define DEFINE_SPINLOCK(name)	\
	spinlock_t name = {	\
		.lock = 0,	\
	}

#define spin_lock(l)			\
	do {				\
		raw_spin_lock(l);	\
	} while (0)

#define spin_unlock(l)			\
	do {				\
		raw_spin_unlock(l);	\
	} while (0)

#endif
