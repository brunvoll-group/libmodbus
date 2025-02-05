#include <stdio.h>
#ifndef _MSC_VER
#include <unistd.h>
#endif
#include <errno.h>
#include <stdlib.h>

#include <modbus.h>

int main(void)
{
    modbus_t* ctx;
    modbus_mapping_t* mb_mapping;

    ctx = modbus_new_udp("0.0.0.0", 1502);
    modbus_set_debug(ctx, TRUE);

    mb_mapping = modbus_mapping_new(500, 500, 500, 500);
    if (mb_mapping == NULL) {
        fprintf(stderr, "Failed to allocate the mapping: %s\n",
            modbus_strerror(errno));
        modbus_free(ctx);
        return -1;
    }

    modbus_udp_listen(ctx, 1);

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
}
