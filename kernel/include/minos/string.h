#ifndef _STRING_H
#define _STRING_H

#include <minos/types.h>
#include <minos/varlist.h>

long absolute(long num);
long num_to_str(char *buf, unsigned long num, int bdho);
long itoa(char *buf, int num);
long ltoa(char *buf, long num);
long uitoa(char *buf, unsigned int num);
long ultoa(char *buf, unsigned long num);
long hextoa(char *buf, unsigned long num);
long octtoa(char *buf, unsigned long num);
long bintoa(char *buf, unsigned long num);
size_t strlen(const char *s);
char *strcpy(char *des, const char *src);
char *strncpy(char *des, const char *src, int len);
int strcmp(const char *src, const char *dst);
int memcmp(const char *src, const char *dst, size_t size);
int strncmp(const char *src, const char *dst, int n);
char *strchr(const char *src, char ch);
void memset(void *base, char ch, int size);
void *memmove(void *dest, const void *src, size_t n);
size_t strnlen(const char *s, size_t maxlen);
void *memcpy(void *dest, const void *src, size_t n);
void *memchr(const void *s, int c, size_t n);
int vsprintf(char *buf, const char *fmt, va_list arg);
int sprintf(char *str, const char *format, ...);
char *strrchr(const char *s, int c);
unsigned long strtoul(const char *cp, char **endp, unsigned int base);
char *strsep(char **stringp, const char *delim);

static inline int is_digit(char ch)
{
	return ((ch <= '9') && (ch >= '0'));
}

static inline int isalpha(char ch)
{
	return (((ch >= 'a') && (ch <= 'z')) ||
			((ch >= 'A') && (ch <= 'Z')));
}

#define atoi(str) strtoul((str), NULL, 10)

#endif
