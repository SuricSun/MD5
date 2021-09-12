/*
* �ڴ�С��ƽ̨������
*
* MD5�İ�ȫ����Զ��Բ���SHA-2 SHA-3
* ����MD5���ٶȸߣ��ڰ�ȫ�Բ���Ҫ������½�����MD5�������У��ͣ�����HashMap�ȵ�
*
* MD5�㷨��С���ֽ�����ζ�����е�������С���ֽ����ϲŻ�ʹ��ȷ�ģ�����ڴ�˻��������еĻ�����Ҫ������Ҫ����Ķ��ֽ�����(u32 u64)��Ҫ�����ֽ���ת��������ͨ��MD5CopyMemory������Switch32/64bit��ɵ�
* Ҳ����ÿ��chunk��64byte����Ϊ16��u32����ÿ��u32����Decode8to32
*/
#include<memory.h>
#include<stdint.h>

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

#define ROTATE_LEFT_U32(x, n) (((x) << (n)) | ((x) >> (32u-(n))))

#define ROUND0_U32(x, y, z) (((x) & (y)) | ((~(x)) & (z)))
#define ROUND1_U32(x, y, z) (((x) & (z)) | ((y) & (~(z))))
#define ROUND2_U32(x, y, z) ((x) ^ (y) ^ (z))
#define ROUND3_U32(x, y, z) ((y) ^ ((x) | (~(z))))

#define ROUND0_WRAPPER_U32(a, b, c, d, block_elem, sihft_amout, sin_table_elem) \
{ \
 (a) += ROUND0_U32((b), (c), (d)) + (block_elem) + (sin_table_elem); \
 (a) = ROTATE_LEFT_U32((a), (sihft_amout)); \
 (a) += (b); \
}
#define ROUND1_WRAPPER_U32(a, b, c, d, block_elem, sihft_amout, sin_table_elem) \
{ \
 (a) += ROUND1_U32((b), (c), (d)) + (block_elem) + (sin_table_elem); \
 (a) = ROTATE_LEFT_U32((a), (sihft_amout)); \
 (a) += (b); \
}
#define ROUND2_WRAPPER_U32(a, b, c, d, block_elem, sihft_amout, sin_table_elem) \
{ \
 (a) += ROUND2_U32((b), (c), (d)) + (block_elem) + (sin_table_elem); \
 (a) = ROTATE_LEFT_U32((a), (sihft_amout)); \
 (a) += (b); \
}
#define ROUND3_WRAPPER_U32(a, b, c, d, block_elem, sihft_amout, sin_table_elem) \
{ \
 (a) += ROUND3_U32 ((b), (c), (d)) + (block_elem) + (sin_table_elem); \
 (a) = ROTATE_LEFT_U32((a), (sihft_amout)); \
 (a) += (b); \
}

#define ROUND0_SHIFT0 7u
#define ROUND0_SHIFT1 12u
#define ROUND0_SHIFT2 17u
#define ROUND0_SHIFT3 22u

#define ROUND1_SHIFT0 5u
#define ROUND1_SHIFT1 9u
#define ROUND1_SHIFT2 14u
#define ROUND1_SHIFT3 20u

#define ROUND2_SHIFT0 4u
#define ROUND2_SHIFT1 11u
#define ROUND2_SHIFT2 16u
#define ROUND2_SHIFT3 23u

#define ROUND3_SHIFT0 6u
#define ROUND3_SHIFT1 10u
#define ROUND3_SHIFT2 15u
#define ROUND3_SHIFT3 21u

//ת���ֽ���
u32 Swap32bit(u32 _32bit) {

	u8* p_32bit = (u8*)&_32bit;

	//0 and 3
	p_32bit[0] = p_32bit[0] ^ p_32bit[3];
	p_32bit[3] = p_32bit[0] ^ p_32bit[3];
	p_32bit[0] = p_32bit[0] ^ p_32bit[3];
	//1 and 2
	p_32bit[1] = p_32bit[1] ^ p_32bit[2];
	p_32bit[2] = p_32bit[1] ^ p_32bit[2];
	p_32bit[1] = p_32bit[1] ^ p_32bit[2];

	return _32bit;
}

//ת���ֽ���
u64 Swap64bit(u64 _64bit) {

	u8* p_64bit = (u8*)&_64bit;

	//0 and 7
	p_64bit[0] = p_64bit[0] ^ p_64bit[7];
	p_64bit[7] = p_64bit[0] ^ p_64bit[7];
	p_64bit[0] = p_64bit[0] ^ p_64bit[7];
	//1 and 6
	p_64bit[1] = p_64bit[1] ^ p_64bit[6];
	p_64bit[6] = p_64bit[1] ^ p_64bit[6];
	p_64bit[1] = p_64bit[1] ^ p_64bit[6];
	//2 and 5
	p_64bit[2] = p_64bit[2] ^ p_64bit[5];
	p_64bit[5] = p_64bit[2] ^ p_64bit[5];
	p_64bit[2] = p_64bit[2] ^ p_64bit[5];
	//3 and 4
	p_64bit[3] = p_64bit[3] ^ p_64bit[4];
	p_64bit[4] = p_64bit[3] ^ p_64bit[4];
	p_64bit[3] = p_64bit[3] ^ p_64bit[4];

	return _64bit;
}

/*
*����������ڰ�input���Ƶ�output��
*���������ǰCPU�Ǵ���ֽ���ִ��u32Ϊ���ֵ�Swap����
* ���ȱ�����4�ı���(4 ,8 ,24 ,...)
*/
void MD5CopyMemory(u8* p_input, u32 inputLenInByte, u8* p_output) {

	u32* p_u32output = (u32*)p_output;
	u32 inputI = 0u;
	u32 howManyU32 = inputLenInByte / 4u;
	//64byte��16��u32
	//ִ��16��Swap����
	for (u32 i = 0u; i < howManyU32; i++) {

		inputI = i * 4;
		p_u32output[i] =
			((u32)(p_input[inputI]))
			|
			((u32)(p_input[inputI + 1u]) << 8u)
			|
			((u32)(p_input[inputI + 2u]) << 16u)
			|
			((u32)(p_input[inputI + 3u]) << 24u);
	}
}

//���֧��2^32 byte�ı���
int MD5(u8* p_msg, u32 lenInByte, u8* $128bitHash) {

	/*
	Step 1. Append Padding Bits

		The message is "padded" (extended)so that its length(in bits) is
		congruent to 448, modulo 512. That is, the message is extended so
		that it is just 64 bits shy of being a multiple of 512 bits long.
		Padding is always performed, even if the length of the message is
		already congruent to 448, modulo 512.

		Padding is performed as follows : a single "1" bit is appended to the
		message, and then "0" bits are appended so that the length in bits of
		the padded message becomes congruent to 448, modulo 512. In all, at
		least one bitand at most 512 bits are appended.
	*/

	if (lenInByte < 0) {

		return -1;
	}

	if ($128bitHash == nullptr) {

		return -2;
	}

	if (p_msg == nullptr) {

		return -3;
	}

	//������Ҫ������bits
	u32 trailingByteCntInOriginalMsg = lenInByte % 64;
	u32 paddingBytesCnt = 0u;

	if (trailingByteCntInOriginalMsg < 56u) {

		paddingBytesCnt = 56u - trailingByteCntInOriginalMsg;
	}
	else {

		paddingBytesCnt = 120u - trailingByteCntInOriginalMsg;
	}

	//һ��block (512 bit / 64 byte / u32 * 16)
	//����lastBlock
	//����֤(trailingByteCntInOriginalMsg + paddingBytesCnt + 8u) / 64һ��������������������
	//����ֵֻ���� 64 or 128
	u32 howManyBytesToCreate = (trailingByteCntInOriginalMsg + paddingBytesCnt + 8u);
	//1 chunk = 64 byte
	u8* p_last1or2Block = new u8[howManyBytesToCreate];

	if (p_last1or2Block == nullptr) {

		return -4;
	}

	//����trailingOriginalMsg
	memcpy_s(p_last1or2Block, trailingByteCntInOriginalMsg, p_msg + lenInByte - trailingByteCntInOriginalMsg, trailingByteCntInOriginalMsg);

	//���paddingBytes
	p_last1or2Block[trailingByteCntInOriginalMsg] = 0b1000'0000u;//8 bits
	//ԭ���õ���for���0��̫���ˣ�ֱ����memset���0
	memset(&p_last1or2Block[trailingByteCntInOriginalMsg + 1u], 0, howManyBytesToCreate - (trailingByteCntInOriginalMsg + 1u));

	/*
	Step 2. Append Length

		A 64 - bit representation of b(the length of the message before the
			padding bits were added) is appended to the result of the previous
		step.In the unlikely event that b is greater than 2 ^ 64, then only
		the low - order 64 bits of b are used. (These bits are appended as two
			32 - bit words and appended low - order word first in accordance with the
			previous conventions.)

		At this point the resulting message(after padding with bits and with
			b) has a length that is an exact multiple of 512 bits.Equivalently,
		this message has a length that is an exact multiple of 16 (32 - bit)
		words.Let M[0 ... N - 1] denote the words of the resulting message,
	where N is a multiple of 16.
	*/

	bool isBigEndian = false;

	u16 tmp = 0x00'11u;

	if (((u8*)(&tmp))[0] == 0x00u) {

		isBigEndian = true;
	}

	u64 lenInBitLE = (u64)lenInByte * 8u;

	//�ѳ���ת��ΪС���ֽ���
	if (isBigEndian) {

		lenInBitLE = Swap64bit(lenInBitLE);
	}

	//��ӵ�paddingĩβ
	*(u64*)(&p_last1or2Block[howManyBytesToCreate - 8u]) = lenInBitLE;

	/*
	Step 3. Initialize MD Buffer

		A four - word buffer(A, B, C, D) is used to compute the message digest.
		Here each of A, B, C, D is a 32 - bit register.These registers are
		initialized to the following values in hexadecimal, low - order bytes
		first):
			word A : 01 23 45 67
			word B : 89 ab cd ef
			word C : fe dc ba 98
			word D : 76 54 32 10
	*/

	//��ʼ��
	u32 hashBufferABCD[4];

	hashBufferABCD[0] = 0x67'45'23'01u;
	hashBufferABCD[1] = 0xef'cd'ab'89u;
	hashBufferABCD[2] = 0x98'ba'dc'feu;
	hashBufferABCD[3] = 0x10'32'54'76u;

	/*
	Step 4. Process Message in 16-Word Blocks
	*/

	//��ȡԭʼ���ĵĵ�������
	u32 maxBlockI = lenInByte / 64;
	u8* p_copySource = p_msg;
	u32* p_curBlock = new u32[16];

	//�Ƿ��Ѿ�����1or2Block��
	bool isPhase2 = false;

	u32 i = 0u;

	while (true) {

		if (i < maxBlockI) {

			//u32 * 16 each block
			MD5CopyMemory(&p_copySource[i * 64u], 64u, (u8*)p_curBlock);
		}
		else if ((i == maxBlockI) && (isPhase2 == false)) {

			//isPhase2 == false���ܽ���phase2�ĵ���
			//��ʼ����֮ǰ������1or2Block
			isPhase2 = true;
			i = 0u;
			maxBlockI = howManyBytesToCreate / 64u;
			p_copySource = p_last1or2Block;
			continue;
		}
		else {

			//i > originalMsgI
			break;
		}

		//��ʼ�����㷨
		u32 a = hashBufferABCD[0];
		u32 b = hashBufferABCD[1];
		u32 c = hashBufferABCD[2];
		u32 d = hashBufferABCD[3];

		/* Round 1 */
		ROUND0_WRAPPER_U32(a, b, c, d, p_curBlock[ 0], ROUND0_SHIFT0, 0xd76aa478u);  /* 1 */
		ROUND0_WRAPPER_U32(d, a, b, c, p_curBlock[ 1], ROUND0_SHIFT1, 0xe8c7b756u);  /* 2 */
		ROUND0_WRAPPER_U32(c, d, a, b, p_curBlock[ 2], ROUND0_SHIFT2, 0x242070dbu);  /* 3 */
		ROUND0_WRAPPER_U32(b, c, d, a, p_curBlock[ 3], ROUND0_SHIFT3, 0xc1bdceeeu);  /* 4 */
		ROUND0_WRAPPER_U32(a, b, c, d, p_curBlock[ 4], ROUND0_SHIFT0, 0xf57c0fafu);  /* 5 */
		ROUND0_WRAPPER_U32(d, a, b, c, p_curBlock[ 5], ROUND0_SHIFT1, 0x4787c62au);  /* 6 */
		ROUND0_WRAPPER_U32(c, d, a, b, p_curBlock[ 6], ROUND0_SHIFT2, 0xa8304613u);  /* 7 */
		ROUND0_WRAPPER_U32(b, c, d, a, p_curBlock[ 7], ROUND0_SHIFT3, 0xfd469501u);  /* 8 */
		ROUND0_WRAPPER_U32(a, b, c, d, p_curBlock[ 8], ROUND0_SHIFT0, 0x698098d8u);  /* 9 */
		ROUND0_WRAPPER_U32(d, a, b, c, p_curBlock[ 9], ROUND0_SHIFT1, 0x8b44f7afu);  /* 10 */
		ROUND0_WRAPPER_U32(c, d, a, b, p_curBlock[10], ROUND0_SHIFT2, 0xffff5bb1u);  /* 11 */
		ROUND0_WRAPPER_U32(b, c, d, a, p_curBlock[11], ROUND0_SHIFT3, 0x895cd7beu);  /* 12 */
		ROUND0_WRAPPER_U32(a, b, c, d, p_curBlock[12], ROUND0_SHIFT0, 0x6b901122u);  /* 13 */
		ROUND0_WRAPPER_U32(d, a, b, c, p_curBlock[13], ROUND0_SHIFT1, 0xfd987193u);  /* 14 */
		ROUND0_WRAPPER_U32(c, d, a, b, p_curBlock[14], ROUND0_SHIFT2, 0xa679438eu);  /* 15 */
		ROUND0_WRAPPER_U32(b, c, d, a, p_curBlock[15], ROUND0_SHIFT3, 0x49b40821u);  /* 16 */

		/* Round 2 */
		ROUND1_WRAPPER_U32(a, b, c, d, p_curBlock[ 1], ROUND1_SHIFT0, 0xf61e2562u);  /* 17 */
		ROUND1_WRAPPER_U32(d, a, b, c, p_curBlock[ 6], ROUND1_SHIFT1, 0xc040b340u);  /* 18 */
		ROUND1_WRAPPER_U32(c, d, a, b, p_curBlock[11], ROUND1_SHIFT2, 0x265e5a51u);  /* 19 */
		ROUND1_WRAPPER_U32(b, c, d, a, p_curBlock[ 0], ROUND1_SHIFT3, 0xe9b6c7aau);  /* 20 */
		ROUND1_WRAPPER_U32(a, b, c, d, p_curBlock[ 5], ROUND1_SHIFT0, 0xd62f105du);  /* 21 */
		ROUND1_WRAPPER_U32(d, a, b, c, p_curBlock[10], ROUND1_SHIFT1, 0x02441453u);   /* 22 */
		ROUND1_WRAPPER_U32(c, d, a, b, p_curBlock[15], ROUND1_SHIFT2, 0xd8a1e681u);  /* 23 */
		ROUND1_WRAPPER_U32(b, c, d, a, p_curBlock[ 4], ROUND1_SHIFT3, 0xe7d3fbc8u);  /* 24 */
		ROUND1_WRAPPER_U32(a, b, c, d, p_curBlock[ 9], ROUND1_SHIFT0, 0x21e1cde6u);  /* 25 */
		ROUND1_WRAPPER_U32(d, a, b, c, p_curBlock[14], ROUND1_SHIFT1, 0xc33707d6u);  /* 26 */
		ROUND1_WRAPPER_U32(c, d, a, b, p_curBlock[ 3], ROUND1_SHIFT2, 0xf4d50d87u);  /* 27 */
		ROUND1_WRAPPER_U32(b, c, d, a, p_curBlock[ 8], ROUND1_SHIFT3, 0x455a14edu);  /* 28 */
		ROUND1_WRAPPER_U32(a, b, c, d, p_curBlock[13], ROUND1_SHIFT0, 0xa9e3e905u);  /* 29 */
		ROUND1_WRAPPER_U32(d, a, b, c, p_curBlock[ 2], ROUND1_SHIFT1, 0xfcefa3f8u);  /* 30 */
		ROUND1_WRAPPER_U32(c, d, a, b, p_curBlock[ 7], ROUND1_SHIFT2, 0x676f02d9u);  /* 31 */
		ROUND1_WRAPPER_U32(b, c, d, a, p_curBlock[12], ROUND1_SHIFT3, 0x8d2a4c8au);  /* 32 */

		/* Round 3 */
		ROUND2_WRAPPER_U32(a, b, c, d, p_curBlock[ 5], ROUND2_SHIFT0, 0xfffa3942u);  /* 33 */
		ROUND2_WRAPPER_U32(d, a, b, c, p_curBlock[ 8], ROUND2_SHIFT1, 0x8771f681u);  /* 34 */
		ROUND2_WRAPPER_U32(c, d, a, b, p_curBlock[11], ROUND2_SHIFT2, 0x6d9d6122u);  /* 35 */
		ROUND2_WRAPPER_U32(b, c, d, a, p_curBlock[14], ROUND2_SHIFT3, 0xfde5380cu);  /* 36 */
		ROUND2_WRAPPER_U32(a, b, c, d, p_curBlock[ 1], ROUND2_SHIFT0, 0xa4beea44u);  /* 37 */
		ROUND2_WRAPPER_U32(d, a, b, c, p_curBlock[ 4], ROUND2_SHIFT1, 0x4bdecfa9u);  /* 38 */
		ROUND2_WRAPPER_U32(c, d, a, b, p_curBlock[ 7], ROUND2_SHIFT2, 0xf6bb4b60u);  /* 39 */
		ROUND2_WRAPPER_U32(b, c, d, a, p_curBlock[10], ROUND2_SHIFT3, 0xbebfbc70u);  /* 40 */
		ROUND2_WRAPPER_U32(a, b, c, d, p_curBlock[13], ROUND2_SHIFT0, 0x289b7ec6u);  /* 41 */
		ROUND2_WRAPPER_U32(d, a, b, c, p_curBlock[ 0], ROUND2_SHIFT1, 0xeaa127fau);  /* 42 */
		ROUND2_WRAPPER_U32(c, d, a, b, p_curBlock[ 3], ROUND2_SHIFT2, 0xd4ef3085u);  /* 43 */
		ROUND2_WRAPPER_U32(b, c, d, a, p_curBlock[ 6], ROUND2_SHIFT3, 0x04881d05u);   /* 44 */
		ROUND2_WRAPPER_U32(a, b, c, d, p_curBlock[ 9], ROUND2_SHIFT0, 0xd9d4d039u);  /* 45 */
		ROUND2_WRAPPER_U32(d, a, b, c, p_curBlock[12], ROUND2_SHIFT1, 0xe6db99e5u);  /* 46 */
		ROUND2_WRAPPER_U32(c, d, a, b, p_curBlock[15], ROUND2_SHIFT2, 0x1fa27cf8u);  /* 47 */
		ROUND2_WRAPPER_U32(b, c, d, a, p_curBlock[ 2], ROUND2_SHIFT3, 0xc4ac5665u);  /* 48 */

		/* Round 4 */
		ROUND3_WRAPPER_U32(a, b, c, d, p_curBlock[ 0], ROUND3_SHIFT0, 0xf4292244u);  /* 49 */
		ROUND3_WRAPPER_U32(d, a, b, c, p_curBlock[ 7], ROUND3_SHIFT1, 0x432aff97u);  /* 50 */
		ROUND3_WRAPPER_U32(c, d, a, b, p_curBlock[14], ROUND3_SHIFT2, 0xab9423a7u);  /* 51 */
		ROUND3_WRAPPER_U32(b, c, d, a, p_curBlock[ 5], ROUND3_SHIFT3, 0xfc93a039u);  /* 52 */
		ROUND3_WRAPPER_U32(a, b, c, d, p_curBlock[12], ROUND3_SHIFT0, 0x655b59c3u);  /* 53 */
		ROUND3_WRAPPER_U32(d, a, b, c, p_curBlock[ 3], ROUND3_SHIFT1, 0x8f0ccc92u);  /* 54 */
		ROUND3_WRAPPER_U32(c, d, a, b, p_curBlock[10], ROUND3_SHIFT2, 0xffeff47du);  /* 55 */
		ROUND3_WRAPPER_U32(b, c, d, a, p_curBlock[ 1], ROUND3_SHIFT3, 0x85845dd1u);  /* 56 */
		ROUND3_WRAPPER_U32(a, b, c, d, p_curBlock[ 8], ROUND3_SHIFT0, 0x6fa87e4fu);  /* 57 */
		ROUND3_WRAPPER_U32(d, a, b, c, p_curBlock[15], ROUND3_SHIFT1, 0xfe2ce6e0u);  /* 58 */
		ROUND3_WRAPPER_U32(c, d, a, b, p_curBlock[ 6], ROUND3_SHIFT2, 0xa3014314u);  /* 59 */
		ROUND3_WRAPPER_U32(b, c, d, a, p_curBlock[13], ROUND3_SHIFT3, 0x4e0811a1u);  /* 60 */
		ROUND3_WRAPPER_U32(a, b, c, d, p_curBlock[ 4], ROUND3_SHIFT0, 0xf7537e82u);  /* 61 */
		ROUND3_WRAPPER_U32(d, a, b, c, p_curBlock[11], ROUND3_SHIFT1, 0xbd3af235u);  /* 62 */
		ROUND3_WRAPPER_U32(c, d, a, b, p_curBlock[ 2], ROUND3_SHIFT2, 0x2ad7d2bbu);  /* 63 */
		ROUND3_WRAPPER_U32(b, c, d, a, p_curBlock[ 9], ROUND3_SHIFT3, 0xeb86d391u);  /* 64 */

		hashBufferABCD[0] += a;
		hashBufferABCD[1] += b;
		hashBufferABCD[2] += c;
		hashBufferABCD[3] += d;

		i++;
	}

	//�����ǰCPU�Ǵ���򣬰�128bit�ֳ�4��32bit��ת����С����
	MD5CopyMemory((u8*)hashBufferABCD, 16, $128bitHash);

	//�ͷű���
	delete[] p_last1or2Block;
	delete[] p_curBlock;

	return 0;
}
