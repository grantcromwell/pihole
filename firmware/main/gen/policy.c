#include <stdint.h>


struct Range
{
    uint32_t start;
    uint32_t end;

};


const uint32_t upstream[] =
{
    0x09090909u,
    0x95707070u,
};


const int nupstream = 2;


const int ports[] =
{
    53,
    853,
    5353,
    -1,
};


const int nports = 3;


const struct Range deny[] =
{
    {0x00000000u, 0x00ffffffu},
    {0x64400000u, 0x647fffffu},
    {0xa9fe0000u, 0xa9feffffu},
    {0xe0000000u, 0xffffffffu},
    {0, 0},
};


const int ndeny = 4;