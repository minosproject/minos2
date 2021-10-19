#ifndef _MUTEX_H_
#define _MUTEX_H_

#ifdef __cplusplus
extern "C" {
#endif

struct mutex {
	int lock;
};

#define DEFINE_MUTEX(name)	\
	struct mutex name = {	\
		.lock = 0,	\
	}

int mutex_lock(struct mutex *m);
void mutex_unlock(struct mutex *m);

#ifdef __cplusplus
}
#endif

#endif
