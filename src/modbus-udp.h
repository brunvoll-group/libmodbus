/*
 * Copyright © 2017 Andrii Gumega <gumegaandrej@gmail.com>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef _MODBUS_UDP_H_
#define _MODBUS_UDP_H_

#include "modbus.h"

MODBUS_BEGIN_DECLS

#if defined(_WIN32) && !defined(__CYGWIN__)
/* Win32 with MinGW, supplement to <errno.h> */
#include <winsock2.h>
#define ECONNRESET   WSAECONNRESET
#define ECONNREFUSED WSAECONNREFUSED
#define ETIMEDOUT    WSAETIMEDOUT
#define ENOPROTOOPT  WSAENOPROTOOPT
#endif

#define MODBUS_UDP_DEFAULT_PORT   502
#define MODBUS_UDP_SLAVE         0xFF   // AWG ??

/* Modbus_Application_Protocol_V1_1b.pdf Chapter 4 Section 1 Page 5
 * TCP MODBUS ADU = 253 bytes + MBAP (7 bytes) = 260 bytes
 * AWG ??
 */
#define MODBUS_UDP_MAX_ADU_LENGTH  260

MODBUS_API modbus_t* modbus_new_udp(const char* ip_address, int port);
MODBUS_API int modbus_udp_listen(modbus_t* ctx, int nb_connection);
MODBUS_API int modbus_udp_accept(modbus_t* ctx, int* socket);

MODBUS_API modbus_t* modbus_new_udp_pi(const char* node, const char* service);
MODBUS_API int modbus_udp_pi_listen(modbus_t* ctx, int nb_connection);
MODBUS_API int modbus_udp_pi_accept(modbus_t *ctx, int *socket);

MODBUS_END_DECLS

#endif /* _MODBUS_UDP_H_ */
