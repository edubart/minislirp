#ifdef _WIN32
/* as defined in sdkddkver.h */
#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600 /* Vista */
#endif
#include <ws2tcpip.h>
#endif

#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>

uint16_t compute_checksum(uint8_t *Data, size_t Size);
