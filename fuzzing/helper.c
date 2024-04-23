#include "helper.h"

/// Function to compute the checksum of the ip header, should be compatible with
/// TCP and UDP checksum calculation too.
uint16_t compute_checksum(uint8_t *Data, size_t Size)
{
    uint32_t sum = 0;
    uint16_t *Data_as_u16 = (uint16_t *)Data;

    for (size_t i = 0; i < Size/2; i++)
    {
        uint16_t val = ntohs(*(Data_as_u16 + i));
        sum += val;
    }
    if (Size % 2 == 1) sum += Data[Size-1] << 8;

    uint16_t carry = sum >> 16;
    uint32_t sum_val = carry + (sum & 0xFFFF);
    uint16_t result = (sum_val >> 16) + (sum_val & 0xFFFF);
    return ~result;
}
