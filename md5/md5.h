#pragma once

#include <stdlib.h>
#include <string.h>

//RFC: https://www.ietf.org/rfc/rfc1321.txt

#define MD5_BLOCKSIZE 64
#define MD5_DIGESTSIZE 16

#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

// F(X,Y,Z) = XY v not(X) Z
#define F(X, Y, Z) (((X) & (Y)) | (~(X) & (Z)))

// G(X, Y, Z) = XZ v Y not(Z)
#define G(X, Y, Z) ((X) & (Z) | (Y) & ~(Z))

// H(X, Y, Z) = X xor Y xor Z
#define H(X, Y, Z) ((X) ^ (Y) ^ (Z))

// I(X, Y, Z) = Y xor (X v not(Z))
#define I(X, Y, Z) ((Y) ^ ((X) | ~(Z)))

typedef unsigned char md5_byte, *md5_pbyte;
typedef unsigned short md5_ushort, *md5_pushort;
typedef unsigned int md5_ulong, *md5_pulong;
typedef unsigned long long md5_ulonglong, *md5_pulonglong;

md5_ulong md5(md5_pbyte message, md5_ulonglong messageLen, md5_pbyte *digest);