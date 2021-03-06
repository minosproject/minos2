#ifndef __MINOS_CONSOLE_H__
#define __MINOS_CONSOLE_H__

#include <minos/types.h>

struct console {
	char *name;
	int (*init)(char *arg);
	void (*putc)(char ch);
	char (*getc)(void);
};

#define DEFINE_CONSOLE(n, console_name, init_fn, putc_fn, getc_fn) \
	static struct console __console_##n __used __section(".__console") = { \
		.name = console_name,	\
		.init = init_fn,	\
		.putc = putc_fn,	\
		.getc = getc_fn,	\
	}

void console_init(char *name);
void console_putc(char ch);
char console_getc(void);
void console_puts(char *buf, int len);

void console_recv(const char *buf, int cnt);
int console_gets(char *buf, int max, uint32_t timeout);

#endif
