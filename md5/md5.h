#include "stdafx.h"

#include <windows.h>

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


DWORD md5(PBYTE message, DWORD64 messageLen, PBYTE *digest);