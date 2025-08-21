#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include "DES_tables.h"

#define DES_BLOCK_BITS 64
#define DES_KEY_BITS 64
#define DES_SUBKEY_BITS 48
#define DES_HALF_BLOCK_BITS 32
#define DES_HALF_KEY_BITS 28
#define DES_ROUNDS 16
#define S_BOXES 8

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;

template<int N, int INW = 64>
inline u64 permute(u64 x, const int(&tab)[N]) {
	u64 y = 0;
	for (int i = 0; i < N; i++) {
		y |= ((x >> (INW - tab[i])) & 1ULL) << (N - i - 1);
	}
	return y;
}

u32 rotation_l(u32 num, u32 n) {
	return (((num << n) & 0x0fffffff) | (num >> (28 - n)));
}

inline u64 expand_e(u32 r) {
	u64 e = 0;
	for (int i = 0; i < DES_SUBKEY_BITS; i++) {
		e |= (u64)((r >> (DES_HALF_BLOCK_BITS - e_boxes[i])) & 1U) << (DES_SUBKEY_BITS - i - 1);
	}
	return e;
}

inline u32 sb_and_pb(u64 x48) {
	u32 out32 = 0;
	for (int i = 0; i < S_BOXES; i++) {
		u8 chunk = (x48 >> (42 - 6 * i)) & 0x3Fu;
		int row = ((chunk & 0x20) >> 4) | (chunk & 0x01);
		int col = (chunk >> 1) & 0x0F;
		out32 = (out32 << 4) | s_boxes[i][row][col];
	}

	u32 p = permute<32, 32>(out32, p_boxes);
	return p;
}

u32 f(u32 right, u64 subkey) {
	u64 RPT_48bit = expand_e(right);
	RPT_48bit = (RPT_48bit ^ subkey);
	u32 res = sb_and_pb(RPT_48bit);
	return res;
}

// init_round: encrypt(0), decrypt(15)
u64 feistel_rounds(u32 LPT, u32 RPT, const u64(&round_keys)[DES_ROUNDS], int init_round) {
	u64 res = 0;
	for (int i = 0; i < DES_ROUNDS; i++) {
		u32 temp_RPT = RPT;
		u32 f_result = f(RPT, round_keys[abs(i - init_round)]);
		RPT = f_result ^ LPT;
		LPT = temp_RPT;
	}
	// 마지막 라운드에서는 swap하지 않음. 그러므로 한번 더 스왑
	u32 temp_swap = LPT;
	LPT = RPT;
	RPT = temp_swap;

	res = ((u64)LPT << 32) | RPT;
	return res;
}

int main() {
	u64 plain_text = 0x00;
	u64 cipher_text = 0x00;
	u64 key = 0x00; // key with parity bits
	u64 round_keys[16] = { 0x00, };

	printf("평문 (16진수 16자리) 입력:"); // test vector : 0x4E6F772069732074 (ASCII: "Now is the time for all ")
	scanf_s("%llx", &plain_text);

	printf("키 (16진수 16자리) 입력:"); // test vector : 0x0123456789ABCDEF
	scanf_s("%llx", &key);
	
	// Key schedule
	u64 key_56bit = permute<56,64>(key, pc1);
	u32 key_28bit_l = (u32)(key_56bit >> 28);
	u32 key_28bit_r = (u32)(key_56bit & 0x0fffffff);
	for (int i = 0; i < 16; i++) {
		key_28bit_l = rotation_l(key_28bit_l, rotations[i]);
		key_28bit_r = rotation_l(key_28bit_r, rotations[i]);

		u64 subkey_48bit = 0x00;
		subkey_48bit = ((u64)key_28bit_l) << 28;
		subkey_48bit = (subkey_48bit | key_28bit_r);

		round_keys[i] = permute<48,56>(subkey_48bit, pc2);
	}

	// Encryption
	plain_text = permute<64, 64>(plain_text, ip_table);
	u32 LPT = (u32)(plain_text >> 32);
	u32 RPT = (u32)((plain_text << 32) >> 32);
	//init_round: encrypt(0), decrypt(15)
	u64 final_text = feistel_rounds(LPT, RPT, round_keys, 0);
	cipher_text = permute<64,64>(final_text, fp_table);

	// decryption
	u64 permuted_cipher_text = permute<64, 64>(cipher_text, ip_table);
	u32 dec_LPT = (u32)(permuted_cipher_text >> 32);
	u32 dec_RPT = (u32)((permuted_cipher_text << 32) >> 32);
	u64 dec_final_text = feistel_rounds(dec_LPT, dec_RPT, round_keys, 15);
	u64 rec_plain_text = permute<64, 64>(dec_final_text, fp_table);
	
	printf("암호문 (Ciphertext): 0x%016llX\n", cipher_text); // test vector : 0x3FA40E8A984D4815
	printf("복호화된 평문: 0x%016llX\n", rec_plain_text);
	return 0;
}