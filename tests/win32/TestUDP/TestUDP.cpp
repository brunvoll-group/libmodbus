// TestUDP.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#include "..\..\..\src\modbus.h"

int main()
{
    #if(1)
    int socket;
    modbus_t* ctx;
    modbus_mapping_t* mb_mapping;

    //ctx = modbus_new_udp("127.0.0.1", 502);
    ctx = modbus_new_udp("0.0.0.0", 502);
   modbus_set_debug(ctx, TRUE);

    mb_mapping = modbus_mapping_new(0xffff, 0xffff, 0xffff, 0xffff);
    if (mb_mapping == NULL) {
        fprintf(stderr, "Failed to allocate the mapping: %s\n",
            modbus_strerror(errno));
        modbus_free(ctx);
        return -1;
    }

    socket = modbus_udp_listen(ctx, 1);
    //modbus_udp_accept(ctx, &socket);

    for (;;) {
        uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
        int rc;

        rc = modbus_receive(ctx, query);
        if (rc != -1) {
            /* rc is the query size */
            modbus_reply(ctx, query, rc, mb_mapping);
        }
        else {
            /* Connection closed by the client or error */
            break;
        }
    }

    printf("Quit the loop: %s\n", modbus_strerror(errno));

    modbus_mapping_free(mb_mapping);
    modbus_close(ctx);
    modbus_free(ctx);
    #else


    int s = -1;
    modbus_t *ctx;
    modbus_mapping_t *mb_mapping;

    ctx = modbus_new_tcp("127.0.0.1", 63137);
    modbus_set_debug(ctx, TRUE);

    mb_mapping = modbus_mapping_new(500, 500, 500, 500);
    if (mb_mapping == NULL) {
        fprintf(stderr, "Failed to allocate the mapping: %s\n", modbus_strerror(errno));
        modbus_free(ctx);
        return -1;
    }

    s = modbus_tcp_listen(ctx, 1);
    modbus_tcp_accept(ctx, &s);

    for (;;) {
        uint8_t query[MODBUS_TCP_MAX_ADU_LENGTH];
        int rc;

        rc = modbus_receive(ctx, query);
        if (rc > 0) {
            /* rc is the query size */
            modbus_reply(ctx, query, rc, mb_mapping);
        } else if (rc == -1) {
            /* Connection closed by the client or error */
            break;
        }
    }

    printf("Quit the loop: %s\n", modbus_strerror(errno));

    if (s != -1) {
        //close(s);
    }
    modbus_mapping_free(mb_mapping);
    modbus_close(ctx);
    modbus_free(ctx);

    return 0;
    #endif
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
