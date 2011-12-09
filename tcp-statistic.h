/*
** Copyright (C) 2011 - Hagen Paul Pfeifer <hagen@jauu.net>
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

#ifndef TCP_STATISTIC_H
#define	TCP_STATISTIC_H

#include <sys/types.h>

#define DEFAULT_TCP_STATISTIC_BACKLOG 128
#define DEFAULT_TCP_STATISTIC_PORT "9999"

struct request_response_tlv {
	uint16_t	type;
	uint16_t	lenght;
	unsigned char	value[0];
};


#endif /* TCP_STATISTIC_H */
