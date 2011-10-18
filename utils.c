/*
** Copyright (C) 2010,2011 - Hagen Paul Pfeifer <hagen@jauu.net>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#include "ldnsd.h"
#include <arpa/inet.h>


void average_init(struct average *a)
{
	memset(a, 0, sizeof(*a));
}

#define	DEPTH_NS 8
int32_t exponential_average(int32_t prev_avg, int32_t val, uint8_t depth)
{
	return ((depth - 1) * prev_avg +  val)/depth;
}

void average_add(struct average *avg, int32_t val)
{
	avg->sum -= avg->entries[avg->pos];
	avg->sum += val;
	avg->entries[avg->pos++] = val;
	if (unlikely(avg->pos == AVG_ENTRIES)) {
		avg->init = 1;
		avg->pos = 0;
	}
}

int32_t average_value(struct average *avg)
{
	if (!unlikely(avg->init)) {
		if (avg->pos)
			return avg->sum / avg->pos;
		return 0;
	}

	return avg->sum / AVG_ENTRIES;
}

int subtime(struct timeval *op1, struct timeval *op2,
		struct timeval *result)
{
	int borrow = 0, sign = 0;
	struct timeval *temp_time;

	if (TIME_LT(op1, op2)) {
		temp_time = op1;
		op1  = op2;
		op2  = temp_time;
		sign = 1;
	}

	if (op1->tv_usec >= op2->tv_usec) {
		result->tv_usec = op1->tv_usec-op2->tv_usec;
	} else {
		result->tv_usec = (op1->tv_usec + 1000000) - op2->tv_usec;
		borrow = 1;
	}
	result->tv_sec = (op1->tv_sec-op2->tv_sec) - borrow;

	return sign;
}


double tv_to_sec(struct timeval *tv)
{
	return (double)tv->tv_sec + (double)tv->tv_usec / 1000000;
}


void msg(const char *format, ...)
{
	va_list ap;
	struct timeval tv;

	gettimeofday(&tv, NULL);
	fprintf(stderr, "[%ld.%06ld] ", tv.tv_sec, tv.tv_usec);

	va_start(ap, format);
	vfprintf(stderr, format, ap);
	va_end(ap);

	fputs("\n", stderr);
}


static void err_doit(int sys_error, const char *file,
		const int line_no, const char *fmt, va_list ap)
{
	int errno_save;
	char buf[MAXERRMSG];

	errno_save = errno;

	vsnprintf(buf, sizeof(buf) - 1, fmt, ap);
	if (sys_error) {
		size_t len = strlen(buf);
		snprintf(buf + len,  sizeof buf - len, " (%s)",
				strerror(errno_save));
	}

	fprintf(stderr, "ERROR [%s:%d]: %s\n", file, line_no, buf);
	fflush(NULL);

	errno = errno_save;
}


void x_err_ret(const char *file, int line_no, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(0, file, line_no, fmt, ap);
	va_end(ap);
}


void x_err_sys(const char *file, int line_no, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	err_doit(1, file, line_no, fmt, ap);
	va_end(ap);
}


void * xmalloc(size_t size)
{
	void *ptr = malloc(size);
	if (!ptr)
		err_sys_die(EXIT_FAILMEM, "failure in malloc!\n");
	return ptr;
}


void *xzalloc(size_t size)
{
	void *ptr = xmalloc(size);
	memset(ptr, 0, size);
	return ptr;
}


void xfree(void *ptr)
{
	free(ptr); ptr = NULL;
}


void xsetsockopt(int s, int level, int optname,
		const void *optval, socklen_t optlen, const char *str)
{
	int ret = setsockopt(s, level, optname, optval, optlen);
	if (ret)
		err_sys_die(EXIT_FAILNET, "Can't set socketoption %s", str);
}


void xgetaddrinfo(const char *node, const char *service,
		struct addrinfo *hints, struct addrinfo **res)
{
	int ret;

	ret = getaddrinfo(node, service, hints, res);
	if (unlikely(ret != 0)) {
		err_msg_die(EXIT_FAILNET, "Call to getaddrinfo() failed: %s!\n",
				(ret == EAI_SYSTEM) ?  strerror(errno) : gai_strerror(ret));
	}

	return;
}


int nodelay(int fd, int flag)
{
	int ret = 0; socklen_t ret_size;

	if (getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &ret, &ret_size) < 0)
		return -1;

	if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
		return -1;

	return ret;
}


void xfstat(int filedes, struct stat *buf, const char *s)
{
	if (fstat(filedes, buf))
		err_sys_die(EXIT_FAILMISC, "Can't fstat file %s", s);
}


unsigned long long xstrtoull(const char *str)
{
	char *endptr;
	long long val;

	errno = 0;
	val = strtoll(str, &endptr, 10);
	if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
			|| (errno != 0 && val == 0)) {
		err_sys_die(EXIT_FAILURE, "strtoll failure");
	}

	if (endptr == str) {
		err_msg_die(EXIT_FAILURE, "No digits found in commandline");
	}

	return val;
}


int xatoi(const char *str)
{
	long val;
	char *endptr;

	val = strtol(str, &endptr, 10);
	if ((val == LONG_MIN || val == LONG_MAX) && errno != 0)
		err_sys_die(EXIT_FAILURE, "strtoll failure");

	if (endptr == str)
		err_msg_die(EXIT_FAILURE, "No digits found in commandline");

	if (val > INT_MAX)
		return INT_MAX;

	if (val < INT_MIN)
		return INT_MIN;

	if ('\0' != *endptr)
		err_msg_die(EXIT_FAILURE,
				"To many characters on input: \"%s\"", str);

	return val;
}


char *xstrdup(const char *s)
{
	char *ptr = strdup(s);
	if (!ptr)
		err_sys_die(EXIT_FAILMEM, "failed to duplicate string");

	return ptr;
}

void hex_print(char *ptr, size_t len)
{
	size_t i;
	char *c;

	for (i = 0; i < len; i++) {
		c = ptr;
		fprintf(stderr, "%02hhx ", c[i]);
		if (i != 0 && i % 16 == 0)
			fputs("\n", stderr);
	}
	fputs("\n", stderr);
}

/* return bool */
int ip_valid_addr(int family, const char *str)
{
	int ret;
	char buf[sizeof(struct in6_addr)];

	ret = inet_pton(family, str, buf);
	if (ret <= 0)
		return 0;

	return 1;
}
