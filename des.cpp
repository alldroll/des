#include "des.h"
#include <vector>
#include <iostream>

using namespace std;

/*
	DES(X,K,E)
		-- X is a 64-bit input value
		-- K is a 64-bit key
		-- E is TRUE if we are encrypting, else FALSE
	(1) Apply permutation IP to X, resulting in value LR (64 bits).
	(2) Apply selector PC1 to K, resulting in value CD (56 bits).
	(3) For ROUND = 1, 2, ..., 16:
		(3a) if E is TRUE then
			if SHIFTS[ROUND] = 1
			then apply permutation LSH1 to CD (in place).
			else apply permutation LSH2 to CD (in place).
		(3b) Apply selector PC2 to CD resulting in value KI (48 bits)
		(3c) If E is FALSE then
			if SHIFTS[17-ROUND] = 1 
			then apply permutation RSH1 to CD (in place).
			else apply permutation RSH2 to CD (in place).
		(3d) Apply selector E to LR, resulting in value RE (48 bits).
		(3e) XOR RE with KI, resulting in value RX (48 bits).
		(3f) Break RX into 8 6-bit blocks, and replace the i-th block
		     Yi with the result of looking up Yi in S-box i.  
		     Concatenate these 4-bit results together to get the 32-bit
		     value SOUT.
		(3g) Apply permutation P to SOUT resulting in value FOUT (32 
		     bits).
		(3h) Replace the left half of LR with the XOR of FOUT and the
		     left half of LR.
		(3i) If ROUND is not 16, apply permutation SWAP to LR (in
		     place).
	(4) Apply permutation IPINV to LR resulting in value OUT (64 bits).
	    Return OUT as the result of this DES operation.
*/

#define KEY_PART_SIZE (KEY_SIZE / 2)

#define COMPRESSED_KEY_SIZE 48

#define BLOCK_PART_SIZE (BLOCK_SIZE / 2)

typedef bitset<KEY_PART_SIZE> KeyPartT;
typedef bitset<COMPRESSED_KEY_SIZE> CompressedKeyT;
typedef bitset<BLOCK_PART_SIZE> BlockPartT;


static const int shifts[16] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};

static const int IP[BLOCK_SIZE] = 
{
	58,    50,   42,    34,    26,   18,    10,    2,
	60,    52,   44,    36,    28,   20,    12,    4,
	62,    54,   46,    38,    30,   22,    14,    6,
	64,    56,   48,    40,    32,   24,    16,    8,
	57,    49,   41,    33,    25,   17,     9,    1,
	59,    51,   43,    35,    27,   19,    11,    3,
	61,    53,   45,    37,    29,   21,    13,    5,
	63,    55,   47,    39,    31,   23,    15,    7
};

static const int IPINV[BLOCK_SIZE] = 
{
	40,     8,   48,    16,    56,   24,    64,   32,
	39,     7,   47,    15,    55,   23,    63,   31,
	38,     6,   46,    14,    54,   22,    62,   30,
	37,     5,   45,    13,    53,   21,    61,   29,
	36,     4,   44,    12,    52,   20,    60,   28,
	35,     3,   43,    11,    51,   19,    59,   27,
	34,     2,   42,    10,    50,   18,    58,   26,
	33,     1,   41,     9,    49,   17,    57,   25
};

static const int PC1[KEY_SIZE] = 
{
	57,  49,    41,   33,    25,    17,    9,
	1,   58,    50,   42,    34,    26,   18,
	10,   2,    59,   51,    43,    35,   27,
	19,  11,     3,   60,    52,    44,   36,
	63,  55,    47,   39,    31,    23,   15,
	7,   62,    54,   46,    38,    30,   22,
	14,   6,    61,   53,    45,    37,   29,
	21,  13,     5,   28,    20,    12,    4
};

static const int PC2[COMPRESSED_KEY_SIZE] =
{
	14,    17,   11,    24,     1,    5,
	3,     28,   15,     6,    21,   10,
	23,    19,   12,     4,    26,    8,
	16,     7,   27,    20,    13,    2,
	41,    52,   31,    37,    47,   55,
	30,    40,   51,    45,    33,   48,
	44,    49,   39,    56,    34,   53,
	46,    42,   50,    36,    29,   32
};

static const int E[COMPRESSED_KEY_SIZE] =
{
	32,     1,    2,     3,     4,    5,
	 4,     5,    6,     7,     8,    9,
	 8,     9,   10,    11,    12,   13,
	12,    13,   14,    15,    16,   17,
	16,    17,   18,    19,    20,   21,
	20,    21,   22,    23,    24,   25,
	24,    25,   26,    27,    28,   29,
	28,    29,   30,    31,    32,    1
};

static const int P[BLOCK_PART_SIZE] =
{
	16,   7,  20,  21,
	29,  12,  28,  17,
	1,  15,  23,  26,
	5,  18,  31,  10,
	2,   8,  24,  14,
	32,  27,   3,   9,
	19,  13,  30,   6,
	22,  11,   4,  25 
};

static const int S[8][4][16] = 
{
	{
		{14,  4,  13,  1,   2, 15,  11,  8,   3, 10,   6, 12,   5,  9,   0,  7},
		{ 0, 15,   7,  4,  14,  2,  13,  1,  10,  6,  12, 11,   9,  5,   3,  8},
		{ 4,  1,  14,  8,  13,  6,   2, 11,  15, 12,   9,  7,   3, 10,   5,  0},
		{15, 12,   8,  2,   4,  9,   1,  7,   5, 11,   3, 14,  10,  0,   6, 13}
	},

	{
		{15,  1,   8, 14,   6, 11,   3,  4,   9,  7,   2, 13,  12,  0,   5, 10},
		{ 3, 13,   4,  7,  15,  2,   8, 14,  12,  0,   1, 10,   6,  9,  11,  5},
		{ 0, 14,   7, 11,  10,  4,  13,  1,   5,  8,  12,  6,   9,  3,   2, 15},
		{13,  8,  10,  1,   3, 15,   4,  2,  11,  6,   7, 12,   0,  5,  14,  9}
	},

	{
		{10,  0,   9, 14,   6,  3,  15,  5,   1, 13,  12,  7, 11,  4,   2,  8},
		{13,  7,   0,  9,   3,  4,   6, 10,   2,  8,   5, 14, 12, 11,  15,  1},
		{13,  6,   4,  9,   8, 15,   3,  0,  11,  1,   2, 12,  5, 10,  14,  7},
		{ 1, 10,  13,  0,   6,  9,   8,  7,   4, 15,  14,  3, 11,  5,   2, 12}
	},

	{
		{ 7, 13,  14,  3,   0,  6,   9, 10,   1,  2,  8,  5,  11, 12,   4, 15},
		{13,  8,  11,  5,   6, 15,   0,  3,   4,  7,  2, 12,   1, 10,  14,  9},
		{10,  6,   9,  0,  12, 11,   7, 13,  15,  1,  3, 14,   5,  2,   8,  4},
		{ 3, 15,   0,  6,  10,  1,  13,  8,   9,  4,  5, 11,  12,  7,   2, 14}
	},

	{
		{ 2, 12,   4,  1,   7, 10,  11,  6,   8,  5,   3, 15,  13, 0,  14,  9},
		{14, 11,   2, 12,   4,  7,  13,  1,   5,  0,  15, 10,   3, 9,   8,  6},
		{ 4,  2,   1, 11,  10, 13,   7,  8,  15,  9,  12,  5,   6, 3,   0, 14},
		{11,  8,  12,  7,   1, 14,   2, 13,   6, 15,   0,  9,  10, 4,   5,  3}
	},

	{
		{12,  1,  10, 15,   9,  2,   6,  8,   0, 13,   3,  4, 14,  7,   5, 11},
		{10, 15,   4,  2,   7, 12,   9,  5,   6,  1,  13, 14,  0, 11,   3,  8},
		{ 9, 14,  15,  5,   2,  8,  12,  3,   7,  0,   4, 10,  1, 13,  11,  6},
		{ 4,  3,   2, 12,   9,  5,  15, 10,  11, 14,   1,  7,  6,  0,   8, 13}
	},

	{
		{ 4, 11,   2, 14,  15,  0,   8, 13,   3, 12,  9,  7,  5, 10,   6,  1},
		{13,  0,  11,  7,   4,  9,   1, 10,  14,  3,  5, 12,  2, 15,   8,  6},
		{ 1,  4,  11, 13,  12,  3,   7, 14,  10, 15,  6,  8,  0,  5,   9,  2},
		{ 6, 11,  13,  8,   1,  4,  10,  7,   9,  5,  0, 15, 14,  2,   3, 12}
	},

	{
		{13,  2,  8,  4,  6, 15,  11,  1,  10,  9,   3, 14,   5,  0,  12,  7},
		{ 1, 15, 13,  8, 10,  3,   7,  4,  12,  5,   6, 11,   0, 14,   9,  2},
		{ 7, 11,  4,  1,  9, 12,  14,  2,   0,  6,  10, 13,  15,  3,   5,  8},
		{ 2,  1, 14,  7,  4, 10,   8, 13,  15, 12,   9,  0,   3,  5,   6, 11}
	}
};


template<size_t BEFORE, size_t AFTER>
static bitset<AFTER> permutation(bitset<BEFORE> t, int* pMatrix);

template<size_t N>
static void split(bitset<N> cd, bitset<N / 2>& c, bitset<N / 2>& d);

template<size_t N>
static bitset<N * 2> join(bitset<N> c, bitset<N> d);

static BlockT ip(BlockT x);

static KeyT pc1(BlockT k);

static KeyPartT shift(KeyPartT c);

static CompressedKeyT pc2(KeyT cd);

static CompressedKeyT e(BlockPartT part);

static BlockPartT p(BlockPartT part);

static BlockPartT f(BlockPartT p, CompressedKeyT k);

static BlockT ipinv(BlockT lr);


template<size_t BEFORE, size_t AFTER>
static bitset<AFTER> permutation(bitset<BEFORE> t, int* pMatrix)
{
	bitset<AFTER> r;
	for (int i = 0; i < AFTER; ++i)
		r[i] = t[pMatrix[i] - 1];
	return r;
}

template<size_t N>
static void split(bitset<N> cd, bitset<N / 2>& c, bitset<N / 2>& d)
{
	size_t partSize = N / 2;
	for (int i = 0; i < partSize; i++)
	{
		c[i] = cd[i];
		d[i] = cd[partSize + i];
	}
}

template<size_t N>
static bitset<N * 2> join(bitset<N> c, bitset<N> d)
{
	bitset<N * 2> cd;
	for (int i = 0; i < N; ++i)
	{
		cd[i] = c[i];
		cd[N + i] = d[i];
	}
	return cd;
}

static BlockT ip(BlockT x)
{
    return permutation<BLOCK_SIZE, BLOCK_SIZE>(x, (int*)IP);
}

static KeyT pc1(BlockT k)
{
	return permutation<BLOCK_SIZE, KEY_SIZE>(k, (int*)PC1);
}

static CompressedKeyT pc2(KeyT cd)
{
	return permutation<KEY_SIZE, COMPRESSED_KEY_SIZE>(cd, (int*)PC2);
}

static CompressedKeyT e(BlockPartT part)
{
	return permutation<BLOCK_PART_SIZE, COMPRESSED_KEY_SIZE>(part, (int*)E); 
}

static BlockPartT p(BlockPartT part)
{
	return permutation<BLOCK_PART_SIZE, BLOCK_PART_SIZE>(part, (int*)P); 
}

static BlockT ipinv(BlockT x)
{
	return permutation<BLOCK_SIZE, BLOCK_SIZE>(x, (int*)IPINV);
}

static KeyPartT shift(KeyPartT c, int shift)
{
	KeyPartT res;
	for (int i = 0; i < KEY_PART_SIZE; ++i)
		res[i] = c[(i + shift) % KEY_PART_SIZE];
	return res;
}

static BlockPartT f(BlockPartT part, CompressedKeyT k)
{
	BlockPartT res;
	CompressedKeyT expanded = e(part);
	expanded ^= k;

	for (int i = 0; i < 8; ++i)
	{
		int k = (i + 1) * 6;
		bitset<2> a;
		bitset<4> b;

		a.set(0, expanded[k - 6]);
		a.set(1, expanded[k - 1]);

		for (int j = 0; j < 4; ++j)
			b.set(j, expanded[k - 5 + j]);

		bitset<4> dblock(S[i][a.to_ulong()][b.to_ulong()]);

		for (int j = 0; j < 4; ++j)
			res[i * 4 + j] = dblock[4 - j - 1];
	}

	return p(res);
}

BlockT des(BlockT x, BlockT k, DesStateT state)
{
	BlockT lr = ip(x);
	KeyT cd = pc1(k);
	BlockPartT left, right;

	split(lr, left, right);

	for (int i = 0; i < 16; ++i)
	{
		int round = i;
		KeyPartT c, d;

		split(cd, c, d);

		c = shift(c, shifts[round]);
		d = shift(d, shifts[round]);

		cd = join(c, d);

		if (state == ENCRYPT)
			round = 16 - i - 1;

		CompressedKeyT cKey = pc2(cd);

		left ^= f(right, cKey);
		// if (round != (16 - 1))
		// 	swap(left, right);
	}

	lr = join(left, right);

	return ipinv(lr);
}

BlockT get64bit(const char* c)
{
	BlockT block;
	for (int i = 0; i < 8; i++)
	{
		bitset<8> t(c[i]);
		for (int j = 0; j < 8; j++)
			block[i * 8 + j] = t[j];
	}
	return block;
}