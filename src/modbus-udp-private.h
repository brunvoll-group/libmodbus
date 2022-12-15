/*
 * Copyright © 2017 Andrii Gumega <gumegaandrej@gmail.com>
 * Copyright © 2022 Ladislav Sopko <ladislav.sopko@gmail.com>
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

#ifndef _MODBUS_UDP_PRIVATE_H_
#define _MODBUS_UDP_PRIVATE_H_

#define _MODBUS_UDP_HEADER_LENGTH      7
#define _MODBUS_UDP_PRESET_REQ_LENGTH 12
#define _MODBUS_UDP_PRESET_RSP_LENGTH  8

#define _MODBUS_UDP_CHECKSUM_LENGTH    0

typedef struct _modbus_udp {
    /* UDP port */
    int port;
    /* IP address */
    char ip[16];
    struct sockaddr_in si_other;
} modbus_udp_t;

/**
* In UDP there is used recvfrom, and it will return whole UDP datagram packet, 
* so we will cache it for time it is consumed by modbus core, 
* we can simulate TCP behaviour
* so modbus core will work as is without any changes.
*/
typedef struct _modbus_udp_packet_cache {
    /* current position*/
    int position;
    /* current size */
    int size;
    /* data */
    uint8_t* data[MODBUS_UDP_MAX_ADU_LENGTH]; 
} modbus_udp_cache_t;

#define _MODBUS_UDP_PI_NODE_LENGTH    1025
#define _MODBUS_UDP_PI_SERVICE_LENGTH   32

typedef struct _modbus_udp_pi {
    /* UDP port */
    int port;
    /* Node */
    char node[_MODBUS_UDP_PI_NODE_LENGTH];
    /* Service */
    char service[_MODBUS_UDP_PI_SERVICE_LENGTH];
} modbus_udp_pi_t;

#endif /* _MODBUS_UDP_PRIVATE_H_ */
