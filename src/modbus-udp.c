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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <signal.h>
#include <sys/types.h>

#if defined(_WIN32)
# define OS_WIN32
/* ws2_32.dll has getaddrinfo and freeaddrinfo on Windows XP and later.
 * minwg32 headers check WINVER before allowing the use of these */
# ifndef WINVER
# define WINVER 0x0501
# endif
# include <ws2tcpip.h>
# define SHUT_RDWR 2
# define close closesocket
#else
# include <sys/socket.h>
# include <sys/ioctl.h>

#if defined(__OpenBSD__) || (defined(__FreeBSD__) && __FreeBSD__ < 5)
# define OS_BSD
# include <netinet/in_systm.h>
#endif

# include <netinet/in.h>
# include <netinet/ip.h>
# include <netinet/udp.h>
# include <arpa/inet.h>
# include <poll.h>
# include <netdb.h>

#include <errno.h>
#endif

#if !defined(MSG_NOSIGNAL)
#define MSG_NOSIGNAL 0
#endif

#include "modbus-private.h"

#include "modbus-udp.h"
#include "modbus-udp-private.h"

#ifdef OS_WIN32
static int _modbus_udp_init_win32(void)
{
    /* Initialise Windows Socket API */
    WSADATA wsaData;

    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        fprintf(stderr, "WSAStartup() returned error code %d\n",
                (unsigned int)GetLastError());
        errno = EIO;
        return -1;
    }
    return 0;
}
#endif

static int _modbus_set_slave(modbus_t *ctx, int slave)
{
    /* Broadcast address is 0 (MODBUS_BROADCAST_ADDRESS) */
    if (slave >= 0 && slave <= 247) {
        ctx->slave = slave;
    } else if (slave == MODBUS_UDP_SLAVE) {
        /* The special value MODBUS_UDP_SLAVE (0xFF) can be used in UDP mode to
         * restore the default value. */
        ctx->slave = slave;
    } else {
        errno = EINVAL;
        return -1;
    }

    return 0;
}

/* Builds a UDP request header */
int _modbus_udp_build_request_basis(modbus_t *ctx, int function,
                                    int addr, int nb,
                                    uint8_t *req)
{

    /* 
        AWG ??
    Extract from MODBUS Messaging on TCP/IP Implementation Guide V1.0b
       (page 23/46):
       The transaction identifier is used to associate the future response
       with the request. So, at a time, on a TCP connection, this identifier
       must be unique. */
    static uint16_t t_id = 0;

    /* Transaction ID */
    if (t_id < UINT16_MAX)
        t_id++;
    else
        t_id = 0;
    req[0] = t_id >> 8;
    req[1] = t_id & 0x00ff;

    /* Protocol Modbus */
    req[2] = 0;
    req[3] = 0;

    /* Length will be defined later by set_req_length_udp at offsets 4      AWG ??
       and 5 */

    req[6] = ctx->slave;
    req[7] = function;
    req[8] = addr >> 8;
    req[9] = addr & 0x00ff;
    req[10] = nb >> 8;
    req[11] = nb & 0x00ff;

    return _MODBUS_UDP_PRESET_REQ_LENGTH;
}

/* Builds a UDP response header */
int _modbus_udp_build_response_basis(sft_t *sft, uint8_t *rsp)
{
    /* 
        AWG ??
    Extract from MODBUS Messaging on TCP/IP Implementation
       Guide V1.0b (page 23/46):
       The transaction identifier is used to associate the future
       response with the request. */
    rsp[0] = sft->t_id >> 8;
    rsp[1] = sft->t_id & 0x00ff;

    /* Protocol Modbus */
    rsp[2] = 0;
    rsp[3] = 0;

    /* Length will be set later by send_msg (4 and 5) */

    /* The slave ID is copied from the indication */
    rsp[6] = sft->slave;
    rsp[7] = sft->function;

    return _MODBUS_UDP_PRESET_RSP_LENGTH;
}


int _modbus_udp_prepare_response_tid(const uint8_t *req, int *req_length)
{
    return (req[0] << 8) + req[1];
}

int _modbus_udp_send_msg_pre(uint8_t *req, int req_length)
{
    /* Substract the header length to the message length */
    int mbap_length = req_length - 6;

    req[4] = mbap_length >> 8;
    req[5] = mbap_length & 0x00FF;

    return req_length;
}

ssize_t _modbus_udp_send(modbus_t *ctx, const uint8_t *req, int req_length)
{
    /* MSG_NOSIGNAL
       Requests not to send SIGPIPE on errors on stream oriented
       sockets when the other end breaks the connection.  The EPIPE
       error is still returned. */
    modbus_udp_t *ctx_udp = ctx->backend_data;
    return sendto(ctx->s, (const char*)req, req_length, MSG_NOSIGNAL, 
        (struct sockaddr *)&ctx_udp->si_other, sizeof(ctx_udp->si_other));
}

ssize_t _modbus_udp_recv(modbus_t *ctx, uint8_t *rsp, int rsp_length)
{
    modbus_udp_t *ctx_udp = ctx->backend_data;
    socklen_t slen = sizeof(ctx_udp->si_other);
    ssize_t recvsize = recvfrom(ctx->s, (char *)rsp, MODBUS_UDP_MAX_ADU_LENGTH, 0, 
            (struct sockaddr *) &ctx_udp->si_other, &slen);
    return recvsize;
}

int _modbus_udp_check_integrity(modbus_t *ctx, uint8_t *msg, const int msg_length)
{
    return msg_length;
}

int _modbus_udp_pre_check_confirmation(modbus_t *ctx, const uint8_t *req,
                                       const uint8_t *rsp, int rsp_length)
{
    /* Check TID */
    if (req[0] != rsp[0] || req[1] != rsp[1]) {
        if (ctx->debug) {
            fprintf(stderr, "Invalid TID received 0x%X (not 0x%X)\n",
                    (rsp[0] << 8) + rsp[1], (req[0] << 8) + req[1]);
        }
        errno = EMBBADDATA;
        return -1;
    } else {
        return 0;
    }
}

static int _modbus_udp_set_ipv4_options(int s)
{
    int rc;
    int option;

    /* AWG ?? */
    /* Set the TCP no delay flag */
    /* SOL_TCP = IPPROTO_TCP */
    option = 1;

#ifndef OS_WIN32
    /**
     * Cygwin defines IPTOS_LOWDELAY but can't handle that flag so it's
     * necessary to workaround that problem.
     **/
    /* Set the IP low delay option */
    printf("OS_WIN32");
    option = IPTOS_LOWDELAY;
    rc = setsockopt(s, IPPROTO_IP, IP_TOS,
                    (const void *)&option, sizeof(int));
    if (rc == -1) {
        return -1;
    }
#endif

    return 0;
}

/* Establishes a modbus UDP connection with a Modbus server. */
static int _modbus_udp_connect(modbus_t *ctx)
{
    int rc;
    //struct sockaddr_in addr;
    modbus_udp_t *ctx_udp = ctx->backend_data;

#ifdef OS_WIN32
    if (_modbus_udp_init_win32() == -1) {
        return -1;
    }
#endif

    //ctx->s = socket(PF_INET, SOCK_STREAM, 0);
    ctx->s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (ctx->s == -1) {
        printf("error socket creation: %s\n", strerror(errno));
        return -1;
    }

    if (ctx->debug) {
        printf("Connecting to %s\n", ctx_udp->ip);
    }

    memset((char *) &ctx_udp->si_other, 0, sizeof(ctx_udp->si_other));
    ctx_udp->si_other.sin_family = AF_INET;
    ctx_udp->si_other.sin_port = htons(ctx_udp->port);

    rc = inet_aton(ctx_udp->ip, &ctx_udp->si_other.sin_addr);
    if (rc == 0) 
    {
        // fprintf(stderr, "inet_aton() failed\n");
        // exit(1);
        printf("error bind: %s\n", strerror(errno));
        close(ctx->s);
        return -1;
    }

    return 0;
}

/* Establishes a modbus UDP PI connection with a Modbus server. */
static int _modbus_udp_pi_connect(modbus_t *ctx)
{
    int rc;
    struct addrinfo *ai_list;
    struct addrinfo *ai_ptr;
    struct addrinfo ai_hints;
    modbus_udp_pi_t *ctx_udp_pi = ctx->backend_data;

#ifdef OS_WIN32
    if (_modbus_udp_init_win32() == -1) {
        return -1;
    }
#endif

    memset(&ai_hints, 0, sizeof(ai_hints));
#ifdef AI_ADDRCONFIG
    ai_hints.ai_flags |= AI_ADDRCONFIG;
#endif
    ai_hints.ai_family = AF_UNSPEC;
    ai_hints.ai_socktype = SOCK_STREAM;
    ai_hints.ai_addr = NULL;
    ai_hints.ai_canonname = NULL;
    ai_hints.ai_next = NULL;

    ai_list = NULL;
    rc = getaddrinfo(ctx_udp_pi->node, ctx_udp_pi->service,
                     &ai_hints, &ai_list);
    if (rc != 0)
        return rc;

    for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
        int s;

        s = socket(ai_ptr->ai_family, ai_ptr->ai_socktype, ai_ptr->ai_protocol);
        if (s < 0)
            continue;

        if (ai_ptr->ai_family == AF_INET)
            _modbus_udp_set_ipv4_options(s);

        rc = connect(s, ai_ptr->ai_addr, ai_ptr->ai_addrlen);
        if (rc != 0) {
            close(s);
            continue;
        }

        ctx->s = s;
        break;
    }

    freeaddrinfo(ai_list);

    if (ctx->s < 0) {
        return -1;
    }

    return 0;
}

/* Closes the network connection and socket in UDP mode */
void _modbus_udp_close(modbus_t *ctx)
{
    shutdown(ctx->s, SHUT_RDWR);
    close(ctx->s);
}

int _modbus_udp_flush(modbus_t *ctx)
{
    int rc;
    int rc_sum = 0;

    do {
        /* Extract the garbage from the socket */
        char devnull[MODBUS_UDP_MAX_ADU_LENGTH];
#ifndef OS_WIN32
        rc = recv(ctx->s, devnull, MODBUS_UDP_MAX_ADU_LENGTH, MSG_DONTWAIT);
#else
        /* On Win32, it's a bit more complicated to not wait */
        fd_set rfds;
        struct timeval tv;

        tv.tv_sec = 0;
        tv.tv_usec = 0;
        FD_ZERO(&rfds);
        FD_SET(ctx->s, &rfds);
        rc = select(ctx->s+1, &rfds, NULL, NULL, &tv);
        if (rc == -1) {
            return -1;
        }

        if (rc == 1) {
            /* There is data to flush */
            rc = recv(ctx->s, devnull, MODBUS_UDP_MAX_ADU_LENGTH, 0);
        }
#endif
        if (rc > 0) {
            rc_sum += rc;
        }
    } while (rc == MODBUS_UDP_MAX_ADU_LENGTH);

    return rc_sum;
}

/* Listens for any request from one or many modbus masters in UDP */
int modbus_udp_listen(modbus_t *ctx, int nb_connection)
{
    int new_socket;
    int yes;
    struct sockaddr_in addr;
    modbus_udp_t *ctx_udp = ctx->backend_data;

#ifdef OS_WIN32
    if (_modbus_udp_init_win32() == -1) {
        return -1;
    }
#endif

    new_socket = socket(PF_INET, SOCK_STREAM, IPPROTO_UDP);     // AWG ??
    if (new_socket == -1) {
        return -1;
    }

    yes = 1;
    if (setsockopt(new_socket, SOL_SOCKET, SO_REUSEADDR,
                   (char *) &yes, sizeof(yes)) == -1) {
        close(new_socket);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    /* If the modbus port is < to 1024, we need the setuid root. */
    addr.sin_port = htons(ctx_udp->port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(new_socket, (struct sockaddr *)&addr, sizeof(addr)) == -1) {
        close(new_socket);
        return -1;
    }

    if (listen(new_socket, nb_connection) == -1) {
        close(new_socket);
        return -1;
    }

    return new_socket;
}

int modbus_udp_pi_listen(modbus_t *ctx, int nb_connection)
{
    int rc;
    struct addrinfo *ai_list;
    struct addrinfo *ai_ptr;
    struct addrinfo ai_hints;
    const char *node;
    const char *service;
    int new_socket;
    modbus_udp_pi_t *ctx_udp_pi = ctx->backend_data;

    if (ctx_udp_pi->node[0] == 0)
        node = NULL; /* == any */
    else
        node = ctx_udp_pi->node;

    if (ctx_udp_pi->service[0] == 0)
        service = "502";
    else
        service = ctx_udp_pi->service;

    memset(&ai_hints, 0, sizeof (ai_hints));
    ai_hints.ai_flags |= AI_PASSIVE;
#ifdef AI_ADDRCONFIG
    ai_hints.ai_flags |= AI_ADDRCONFIG;
#endif
    ai_hints.ai_family = AF_UNSPEC;
    ai_hints.ai_socktype = SOCK_STREAM;
    ai_hints.ai_addr = NULL;
    ai_hints.ai_canonname = NULL;
    ai_hints.ai_next = NULL;

    ai_list = NULL;
    rc = getaddrinfo(node, service, &ai_hints, &ai_list);
    if (rc != 0)
        return -1;

    new_socket = -1;
    for (ai_ptr = ai_list; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next) {
        int s;

        s = socket(ai_ptr->ai_family, ai_ptr->ai_socktype,
                            ai_ptr->ai_protocol);
        if (s < 0) {
            if (ctx->debug) {
                perror("socket");
            }
            continue;
        } else {
            int yes = 1;
            rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR,
                            (void *) &yes, sizeof (yes));
            if (rc != 0) {
                close(s);
                if (ctx->debug) {
                    perror("setsockopt");
                }
                continue;
            }
        }

        rc = bind(s, ai_ptr->ai_addr, ai_ptr->ai_addrlen);
        if (rc != 0) {
            close(s);
            if (ctx->debug) {
                perror("bind");
            }
            continue;
        }

        rc = listen(s, nb_connection);
        if (rc != 0) {
            close(s);
            if (ctx->debug) {
                perror("listen");
            }
            continue;
        }

        new_socket = s;
        break;
    }
    freeaddrinfo(ai_list);

    if (new_socket < 0) {
        return -1;
    }

    return new_socket;
}

/* On success, the function return a non-negative integer that is a descriptor
   for the accepted socket. On error, -1 is returned, and errno is set
   appropriately. */
int modbus_udp_accept(modbus_t *ctx, int *socket)
{
    struct sockaddr_in addr;
    socklen_t addrlen;

    addrlen = sizeof(addr);
    ctx->s = accept(*socket, (struct sockaddr *)&addr, &addrlen);
    if (ctx->s == -1) {
        close(*socket);
        *socket = 0;
        return -1;
    }

    if (ctx->debug) {
        printf("The client connection from %s is accepted\n",
               inet_ntoa(addr.sin_addr));
    }

    return ctx->s;
}

int modbus_udp_pi_accept(modbus_t *ctx, int *socket)
{
    struct sockaddr_storage addr;
    socklen_t addrlen;

    addrlen = sizeof(addr);
    ctx->s = accept(*socket, (void *)&addr, &addrlen);
    if (ctx->s == -1) {
        close(*socket);
        *socket = 0;
    }

    if (ctx->debug) {
        printf("The client connection is accepted.\n");
    }

    return ctx->s;
}

int _modbus_udp_select(modbus_t *ctx, fd_set *rfds, struct timeval *tv, int length_to_read)
{
    int s_rc;
    while ((s_rc = select(ctx->s+1, rfds, NULL, NULL, tv)) == -1) {
        if (errno == EINTR) {
            if (ctx->debug) {
                fprintf(stderr, "A non blocked signal was caught\n");
            }
            /* Necessary after an error */
            FD_ZERO(rfds);
            FD_SET(ctx->s, rfds);
        } else {
            return -1;
        }
    }

    if (s_rc == 0) {
        errno = ETIMEDOUT;
        return -1;
    }

    return s_rc;
}

int _modbus_udp_filter_request(modbus_t *ctx, int slave)
{
    return 0;
}

const modbus_backend_t _modbus_udp_backend = {
    _MODBUS_BACKEND_TYPE_UDP,
    _MODBUS_UDP_HEADER_LENGTH,
    _MODBUS_UDP_CHECKSUM_LENGTH,
    MODBUS_UDP_MAX_ADU_LENGTH,
    _modbus_set_slave,
    _modbus_udp_build_request_basis,
    _modbus_udp_build_response_basis,
    _modbus_udp_prepare_response_tid,
    _modbus_udp_send_msg_pre,
    _modbus_udp_send,
    _modbus_udp_recv,
    _modbus_udp_check_integrity,
    _modbus_udp_pre_check_confirmation,
    _modbus_udp_connect,
    _modbus_udp_close,
    _modbus_udp_flush,
    _modbus_udp_select,
    _modbus_udp_filter_request
};


const modbus_backend_t _modbus_udp_pi_backend = {
    _MODBUS_BACKEND_TYPE_UDP,
    _MODBUS_UDP_HEADER_LENGTH,
    _MODBUS_UDP_CHECKSUM_LENGTH,
    MODBUS_UDP_MAX_ADU_LENGTH,
    _modbus_set_slave,
    _modbus_udp_build_request_basis,
    _modbus_udp_build_response_basis,
    _modbus_udp_prepare_response_tid,
    _modbus_udp_send_msg_pre,
    _modbus_udp_send,
    _modbus_udp_recv,
    _modbus_udp_check_integrity,
    _modbus_udp_pre_check_confirmation,
    _modbus_udp_pi_connect,
    _modbus_udp_close,
    _modbus_udp_flush,
    _modbus_udp_select,
    _modbus_udp_filter_request
};

modbus_t* modbus_new_udp(const char *ip, int port)
{
    modbus_t *ctx;
    modbus_udp_t *ctx_udp;
    size_t dest_size;
    size_t ret_size;

#if defined(OS_BSD)
    /* MSG_NOSIGNAL is unsupported on *BSD so we install an ignore
       handler for SIGPIPE. */
    struct sigaction sa;

    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL) < 0) {
        /* The debug flag can't be set here... */
        fprintf(stderr, "Coud not install SIGPIPE handler.\n");
        return NULL;
    }
#endif

    ctx = (modbus_t *) malloc(sizeof(modbus_t));
    _modbus_init_common(ctx);

    /* Could be changed after to reach a remote serial Modbus device */
    ctx->slave = MODBUS_UDP_SLAVE;

    ctx->backend = &(_modbus_udp_backend);

    ctx->backend_data = (modbus_udp_t *) malloc(sizeof(modbus_udp_t));
    ctx_udp = (modbus_udp_t *)ctx->backend_data;

    dest_size = sizeof(char) * 16;
    ret_size = strlcpy(ctx_udp->ip, ip, dest_size);
    if (ret_size == 0) {
        fprintf(stderr, "The IP string is empty\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    if (ret_size >= dest_size) {
        fprintf(stderr, "The IP string has been truncated\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    ctx_udp->port = port;

    return ctx;
}


modbus_t* modbus_new_udp_pi(const char *node, const char *service)
{
    modbus_t *ctx;
    modbus_udp_pi_t *ctx_udp_pi;
    size_t dest_size;
    size_t ret_size;

    ctx = (modbus_t *) malloc(sizeof(modbus_t));
    _modbus_init_common(ctx);

    /* Could be changed after to reach a remote serial Modbus device */
    ctx->slave = MODBUS_UDP_SLAVE;

    ctx->backend = &(_modbus_udp_pi_backend);

    ctx->backend_data = (modbus_udp_pi_t *) malloc(sizeof(modbus_udp_pi_t));
    ctx_udp_pi = (modbus_udp_pi_t *)ctx->backend_data;

    dest_size = sizeof(char) * _MODBUS_UDP_PI_NODE_LENGTH;
    ret_size = strlcpy(ctx_udp_pi->node, node, dest_size);
    if (ret_size == 0) {
        fprintf(stderr, "The node string is empty\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    if (ret_size >= dest_size) {
        fprintf(stderr, "The node string has been truncated\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    dest_size = sizeof(char) * _MODBUS_UDP_PI_SERVICE_LENGTH;
    ret_size = strlcpy(ctx_udp_pi->service, service, dest_size);
    if (ret_size == 0) {
        fprintf(stderr, "The service string is empty\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    if (ret_size >= dest_size) {
        fprintf(stderr, "The service string has been truncated\n");
        modbus_free(ctx);
        errno = EINVAL;
        return NULL;
    }

    return ctx;
}
