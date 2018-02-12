#pragma once

#include <stdlib.h>
#include <string.h>

#include "md5.h"

typedef unsigned char hmac_byte, *hmac_pbyte;
typedef unsigned short hmac_ushort, *hmac_pushort;
typedef unsigned int hmac_ulong, *hmac_pulong;
typedef unsigned long long hmac_ulonglong, *hmac_pulonglong;

typedef hmac_ulong(*hashFunction)(hmac_byte*, hmac_ulonglong, hmac_byte**);

hmac_ulong hmac(hmac_pbyte key, hmac_ulonglong keyLen, hmac_pbyte message, hmac_ulonglong messageLen, hashFunction hashFunc, hmac_ushort blockSize, hmac_ushort digestSize, hmac_pbyte *digest);