#include <stdint.h>


struct pbuf;


int gatekeep(struct pbuf* p, uint32_t dest);


#define LWIP_HOOK_IP4_CANFORWARD(p, dest) gatekeep((p), (dest))