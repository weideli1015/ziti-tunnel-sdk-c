#ifndef ZITI_TUNNELER_SDK_UTUN_H
#define ZITI_TUNNELER_SDK_UTUN_H

#include <net/if.h>
#include "ziti/netif_driver.h"

struct netif_handle_s {
    int  fd;
    char name[IFNAMSIZ];
};

extern netif_driver utun_open(char *error, size_t error_len, uint32_t tun_ip, const char *dns_ip_range);

#endif //ZITI_TUNNELER_SDK_UTUN_H
