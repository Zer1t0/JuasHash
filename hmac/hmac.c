#include "hmac.h"

hmac_ulong hmac(hmac_pbyte key, hmac_ulonglong keyLen, hmac_pbyte message, hmac_ulonglong messageLen, hashFunction hashFunc, hmac_ushort blockSize, hmac_ushort digestSize, hmac_pbyte *digest) {

	hmac_pbyte blockKey = NULL, oKeyPad = NULL, iKeyPad = NULL, hash = NULL;
	hmac_pbyte temp1 = NULL, temp2 = NULL;
	hmac_ulonglong temp1Len = 0, temp2Len = 0;
	hmac_ulong result = 0;
	hmac_ushort i = 0;

	blockKey = (hmac_pbyte)calloc(blockSize, 1);
	if (blockKey == NULL) {
		result = 1;
		goto close;
	}

	oKeyPad = (hmac_pbyte)malloc(blockSize);
	if (oKeyPad == NULL) {
		result = 2;
		goto close;
	}

	iKeyPad = (hmac_pbyte)malloc(blockSize);
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
		free(hash);
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

	temp1 = (hmac_pbyte)malloc(temp1Len);
	if (temp1 == NULL) {
		result = 5;
		goto close;
	}

	temp2 = (hmac_pbyte)malloc(temp2Len);
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
	free(hash);

	if (hashFunc(temp2, temp2Len, &hash) != 0) {
		result = 8;
		goto close;
	}

	*digest = hash;
	result = 0;

close:
	if (blockKey) {
		free(blockKey);
	}

	if (oKeyPad) {
		free(oKeyPad);
	}

	if (iKeyPad) {
		free(iKeyPad);
	}

	if (temp1) {
		free(temp1);
	}

	if (temp2) {
		free(temp2);
	}

	return result;
}
