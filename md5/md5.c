#include "md5.h"

const md5_ulong T[64] = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
	0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
	0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,

	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
	0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
	0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,

	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
	0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
	0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,

	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
	0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
	0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

md5_ulong md5(md5_pbyte message, md5_ulonglong messageLen, md5_pbyte *digest) {

	md5_ushort mod64 = 0, paddingLen = 0;
	md5_pulong M = NULL;
	md5_ulonglong paddedMsgLen = 0, i = 0, N = 0, messageLenBits = 0;
	md5_ulong A = 0, B = 0, C = 0, D = 0;
	md5_ulong AA = 0, BB = 0, CC = 0, DD = 0;
	md5_byte j = 0;
	md5_pbyte hash = 0, byteM = NULL;
	md5_ulong X[16];

	// calculate padding size
	mod64 = messageLen % 64;
	if (mod64 >= 56) {
		paddingLen = (56 + 64) - mod64;
	}else {
		paddingLen = 56 - mod64;
	}

	// adding pading to buffer
	paddedMsgLen = messageLen + paddingLen + sizeof(md5_ulonglong);

	 M = (md5_pulong)malloc(paddedMsgLen);
	if (M == NULL) {
		return 1;
	}

	byteM = (md5_pbyte)M;

	memcpy(byteM, message, messageLen);
	*(byteM + messageLen) = 0x80; // set first bit to 1
	memset(byteM + messageLen + 1, 0, paddingLen - 1);
	messageLenBits = messageLen * 8;

	memcpy(byteM + messageLen + paddingLen, &messageLenBits, sizeof(md5_ulonglong));

	N = paddedMsgLen / 4;

	// Initialize MD Buffer
	A = 0x67452301;
	B = 0xefcdab89;
	C = 0x98badcfe;
	D = 0x10325476;

	for (i = 0; i < N/16; i ++) {

		for (j = 0; j < 16; j++) {
			X[j] = M[i * 16 + j];
		}

		AA = A;
		BB = B;
		CC = C;
		DD = D;

		/* Round 1. */
		/* Let [abcd k s i] denote the operation
		a = b + ((a + F(b,c,d) + X[k] + T[i]) <<< s). */

		/*[ABCD  0  7  1]*/
		A = B + (ROTATE_LEFT((A + F(B, C, D) + X[0] + T[0]), 7)); // 0
		/*[DABC  1 12  2]*/
		D = A + (ROTATE_LEFT((D + F(A, B, C) + X[1] + T[1]), 12)); // 1
		/*[CDAB  2 17  3]*/
		C = D + (ROTATE_LEFT((C + F(D, A, B) + X[2] + T[2]), 17)); // 2
		/*[BCDA  3 22  4]*/
		B = C + (ROTATE_LEFT((B + F(C, D, A) + X[3] + T[3]), 22)); // 3
		/*[ABCD  4  7  5]*/
		A = B + (ROTATE_LEFT((A + F(B, C, D) + X[4] + T[4]), 7)); // 4
		/*[DABC  5 12  6]*/
		D = A + (ROTATE_LEFT((D + F(A, B, C) + X[5] + T[5]), 12)); // 5
		/*[CDAB  6 17  7]*/
		C = D + (ROTATE_LEFT((C + F(D, A, B) + X[6] + T[6]), 17)); // 6
		/*[BCDA  7 22  8]*/
		B = C + (ROTATE_LEFT((B + F(C, D, A) + X[7] + T[7]), 22)); // 7
		/*[ABCD  8  7  9]*/
		A = B + (ROTATE_LEFT((A + F(B, C, D) + X[8] + T[8]), 7)); // 8
		/*[DABC  9 12 10]*/
		D = A + (ROTATE_LEFT((D + F(A, B, C) + X[9] + T[9]), 12)); // 9
		/*[CDAB 10 17 11]*/
		C = D + (ROTATE_LEFT((C + F(D, A, B) + X[10] + T[10]), 17)); // 10
		/*[BCDA 11 22 12]*/
		B = C + (ROTATE_LEFT((B + F(C, D, A) + X[11] + T[11]), 22)); // 11
		/*[ABCD 12  7 13]*/
		A = B + (ROTATE_LEFT((A + F(B, C, D) + X[12] + T[12]), 7)); // 12
		/*[DABC 13 12 14]*/
		D = A + (ROTATE_LEFT((D + F(A, B, C) + X[13] + T[13]), 12)); // 13
		/*[CDAB 14 17 15]*/
		C = D + (ROTATE_LEFT((C + F(D, A, B) + X[14] + T[14]), 17)); // 14
		/*[BCDA 15 22 16]*/
		B = C + (ROTATE_LEFT((B + F(C, D, A) + X[15] + T[15]), 22)); // 15


		/* Round 2. */
		/* Let [abcd k s i] denote the operation
          a = b + ((a + G(b,c,d) + X[k] + T[i]) <<< s). */
		
		  /*[ABCD  1  5 17]*/
		A = B + (ROTATE_LEFT((A + G(B, C, D) + X[1] + T[16]), 5)); // 16
		/*[DABC  6  9 18]*/
		D = A + (ROTATE_LEFT((D + G(A, B, C) + X[6] + T[17]), 9)); // 17
		/*[CDAB 11 14 19]*/
		C = D + (ROTATE_LEFT((C + G(D, A, B) + X[11] + T[18]), 14)); // 18
		/*[BCDA  0 20 20]*/
		B = C + (ROTATE_LEFT((B + G(C, D, A) + X[0] + T[19]), 20)); // 19
		/*[ABCD  5  5 21]*/
		A = B + (ROTATE_LEFT((A + G(B, C, D) + X[5] + T[20]), 5)); // 20
		/*[DABC 10  9 22]*/
		D = A + (ROTATE_LEFT((D + G(A, B, C) + X[10] + T[21]), 9)); // 21
		/*[CDAB 15 14 23]*/
		C = D + (ROTATE_LEFT((C + G(D, A, B) + X[15] + T[22]), 14)); // 22
		/*[BCDA  4 20 24]*/
		B = C + (ROTATE_LEFT((B + G(C, D, A) + X[4] + T[23]), 20)); // 23
		/*[ABCD  9  5 25]*/
		A = B + (ROTATE_LEFT((A + G(B, C, D) + X[9] + T[24]), 5)); // 24
		/*[DABC 14  9 26]*/
		D = A + (ROTATE_LEFT((D + G(A, B, C) + X[14] + T[25]), 9)); // 25
		/*[CDAB  3 14 27]*/
		C = D + (ROTATE_LEFT((C + G(D, A, B) + X[3] + T[26]), 14)); // 26
		/*[BCDA  8 20 28]*/
		B = C + (ROTATE_LEFT((B + G(C, D, A) + X[8] + T[27]), 20)); // 27
		/*[ABCD 13  5 29]*/
		A = B + (ROTATE_LEFT((A + G(B, C, D) + X[13] + T[28]), 5)); // 28
		/*[DABC  2  9 30]*/
		D = A + (ROTATE_LEFT((D + G(A, B, C) + X[2] + T[29]), 9)); // 29
		/*[CDAB  7 14 31]*/
		C = D + (ROTATE_LEFT((C + G(D, A, B) + X[7] + T[30]), 14)); // 30
		/*[BCDA 12 20 32]*/
		B = C + (ROTATE_LEFT((B + G(C, D, A) + X[12] + T[31]), 20)); // 31


		/* Round 3. */
		/* Let [abcd k s t] denote the operation
          a = b + ((a + H(b,c,d) + X[k] + T[i]) <<< s). */

		/*[ABCD  5  4 33]*/
		A = B + (ROTATE_LEFT((A + H(B, C, D) + X[5] + T[32]), 4)); // 32
		/*[DABC  8 11 34]*/
		D = A + (ROTATE_LEFT((D + H(A, B, C) + X[8] + T[33]), 11)); // 33
		/*[CDAB 11 16 35]*/
		C = D + (ROTATE_LEFT((C + H(D, A, B) + X[11] + T[34]), 16)); // 34
		/*[BCDA 14 23 36]*/
		B = C + (ROTATE_LEFT((B + H(C, D, A) + X[14] + T[35]), 23)); // 35
		/*[ABCD  1  4 37]*/
		A = B + (ROTATE_LEFT((A + H(B, C, D) + X[1] + T[36]), 4)); // 36
		/*[DABC  4 11 38]*/
		D = A + (ROTATE_LEFT((D + H(A, B, C) + X[4] + T[37]), 11)); // 37
		/*[CDAB  7 16 39]*/
		C = D + (ROTATE_LEFT((C + H(D, A, B) + X[7] + T[38]), 16)); // 38
		/*[BCDA 10 23 40]*/
		B = C + (ROTATE_LEFT((B + H(C, D, A) + X[10] + T[39]), 23)); // 39
		/*[ABCD 13  4 41]*/
		A = B + (ROTATE_LEFT((A + H(B, C, D) + X[13] + T[40]), 4)); // 40
		/*[DABC  0 11 42]*/
		D = A + (ROTATE_LEFT((D + H(A, B, C) + X[0] + T[41]), 11)); // 41
		/*[CDAB  3 16 43]*/
		C = D + (ROTATE_LEFT((C + H(D, A, B) + X[3] + T[42]), 16)); // 42
		/*[BCDA  6 23 44]*/
		B = C + (ROTATE_LEFT((B + H(C, D, A) + X[6] + T[43]), 23)); // 43
		/*[ABCD  9  4 45]*/
		A = B + (ROTATE_LEFT((A + H(B, C, D) + X[9] + T[44]), 4)); // 44
		/*[DABC 12 11 46]*/
		D = A + (ROTATE_LEFT((D + H(A, B, C) + X[12] + T[45]), 11)); // 45
		/*[CDAB 15 16 47]*/
		C = D + (ROTATE_LEFT((C + H(D, A, B) + X[15] + T[46]), 16)); // 46
		/*[BCDA  2 23 48]*/
		B = C + (ROTATE_LEFT((B + H(C, D, A) + X[2] + T[47]), 23)); // 47


		/* Round 4. */
		/* Let [abcd k s t] denote the operation
          a = b + ((a + I(b,c,d) + X[k] + T[i]) <<< s). */
		
		/*[ABCD  0  6 49]*/
		A = B + (ROTATE_LEFT((A + I(B, C, D) + X[0] + T[48]), 6)); // 48
		/*[DABC  7 10 50]*/
		D = A + (ROTATE_LEFT((D + I(A, B, C) + X[7] + T[49]), 10)); // 49
		/*[CDAB 14 15 51]*/
		C = D + (ROTATE_LEFT((C + I(D, A, B) + X[14] + T[50]), 15)); // 50
		/*[BCDA  5 21 52]*/
		B = C + (ROTATE_LEFT((B + I(C, D, A) + X[5] + T[51]), 21)); // 51
		/*[ABCD 12  6 53]*/
		A = B + (ROTATE_LEFT((A + I(B, C, D) + X[12] + T[52]), 6)); // 52
		/*[DABC  3 10 54]*/
		D = A + (ROTATE_LEFT((D + I(A, B, C) + X[3] + T[53]), 10)); // 53
		/*[CDAB 10 15 55]*/
		C = D + (ROTATE_LEFT((C + I(D, A, B) + X[10] + T[54]), 15)); // 54
		/*[BCDA  1 21 56]*/
		B = C + (ROTATE_LEFT((B + I(C, D, A) + X[1] + T[55]), 21)); // 55
		/*[ABCD  8  6 57]*/
		A = B + (ROTATE_LEFT((A + I(B, C, D) + X[8] + T[56]), 6)); // 56
		/*[DABC 15 10 58]*/
		D = A + (ROTATE_LEFT((D + I(A, B, C) + X[15] + T[57]), 10)); // 57
		/*[CDAB  6 15 59]*/
		C = D + (ROTATE_LEFT((C + I(D, A, B) + X[6] + T[58]), 15)); // 58
		/*[BCDA 13 21 60]*/
		B = C + (ROTATE_LEFT((B + I(C, D, A) + X[13] + T[59]), 21)); // 59
		/*[ABCD  4  6 61]*/
		A = B + (ROTATE_LEFT((A + I(B, C, D) + X[4] + T[60]), 6)); // 60
		/*[DABC 11 10 62]*/
		D = A + (ROTATE_LEFT((D + I(A, B, C) + X[11] + T[61]), 10)); // 61
		/*[CDAB  2 15 63]*/
		C = D + (ROTATE_LEFT((C + I(D, A, B) + X[2] + T[62]), 15)); // 62
		/*[BCDA  9 21 64]*/
		B = C + (ROTATE_LEFT((B + I(C, D, A) + X[9] + T[63]), 21)); // 63

		A = A + AA;
		B = B + BB;
		C = C + CC;
		D = D + DD;
	}

	hash = (md5_pbyte)malloc(16);
	if (hash == NULL) {
		return 2;
	}

	memcpy(hash, &A, sizeof(md5_ulong));
	memcpy(hash + 4, &B, sizeof(md5_ulong));
	memcpy(hash + 8, &C, sizeof(md5_ulong));
	memcpy(hash + 12, &D, sizeof(md5_ulong));
	*digest = hash;
	return 0;
}
