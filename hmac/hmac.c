#include "stdafx.h"
#include "hmac.h"

DWORD hmac(PBYTE key, DWORD64 keyLen, PBYTE message, DWORD64 messageLen, hashFunction hashFunc, USHORT blockSize, USHORT digestSize, PBYTE *digest) {

	PBYTE blockKey = NULL, oKeyPad = NULL, iKeyPad = NULL, hash = NULL;
	PBYTE temp1 = NULL, temp2 = NULL;
	DWORD64 temp1Len = 0, temp2Len = 0;
	DWORD result = 0;
	USHORT i = 0;

	blockKey = (PBYTE)LocalAlloc(LPTR, blockSize);
	if (blockKey == NULL) {
		result = 1;
		goto close;
	}

	oKeyPad = (PBYTE)LocalAlloc(LPTR, blockSize);
	if (oKeyPad == NULL) {
		result = 2;
		goto close;
	}

	iKeyPad = (PBYTE)LocalAlloc(LPTR, blockSize);
	if (iKeyPad == NULL) {
		result = 3;
		goto close;
	}

	if (keyLen > blockSize) {
		if (hashFunc(key, keyLen, &hash) != 0) {
			result = 4;
			goto close;
		}
		memcpy(blockKey, hash, digestSize);
		LocalFree(hash);
	}
	else {
		memcpy(blockKey, key, keyLen);
	}

	for (i = 0; i < blockSize; i++) {
		oKeyPad[i] = blockKey[i] ^ 0x5c;
		iKeyPad[i] = blockKey[i] ^ 0x36;
	}

	temp1Len = messageLen + blockSize;
	temp2Len = blockSize + digestSize;

	temp1 = (PBYTE)LocalAlloc(LPTR, temp1Len);
	if (temp1 == NULL) {
		result = 5;
		goto close;
	}

	temp2 = (PBYTE)LocalAlloc(LPTR, temp2Len);
	if (temp2 == NULL) {
		result = 6;
		goto close;
	}

	memcpy(temp1, iKeyPad, blockSize);
	memcpy(temp1 + blockSize, message, messageLen);

	if (hashFunc(temp1, temp1Len, &hash) != 0) {
		result = 7;
		goto close;
	}

	memcpy(temp2, oKeyPad, blockSize);
	memcpy(temp2 + blockSize, hash, digestSize);
	LocalFree(hash);

	if (hashFunc(temp2, temp2Len, &hash) != 0) {
		result = 8;
		goto close;
	}

	*digest = hash;
	result = 0;

close:
	if (blockKey) {
		LocalFree(blockKey);
	}

	if (oKeyPad) {
		LocalFree(oKeyPad);
	}

	if (iKeyPad) {
		LocalFree(iKeyPad);
	}

	if (temp1) {
		LocalFree(temp1);
	}

	if (temp2) {
		LocalFree(temp2);
	}

	return result;
}
