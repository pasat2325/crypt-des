#include <stdio.h>
#include <stdint.h>
#include "DES_tables.h"

typedef uint64_t u64;
typedef uint32_t u32;
typedef uint8_t u8;

u64 pc(u64 var, int pc[], int number) {
	u64 numb = 0x00;
	u64 aft_ch = 0x00;

	for (int i = 0; i < number; i++) {
		numb = var >> ((number + 8) - pc[i]);
		if (number == 56) {
			numb = numb << (number + 7);
			numb = numb >> (i + 8);
			aft_ch = (aft_ch | numb);
		}
		else { // number == 48
			numb = numb << (number + 15);
			numb = numb >> (i + 16);
			aft_ch = (aft_ch | numb);
		}
	}
	return aft_ch;
}

u64 ip(u64 p_text, int ip_table[]) {
	u64 num = 0x00;
	u64 after_permutation = 0x00;

	for (int i = 0; i < 64; i++) {
		num = p_text >> (64 - ip_table[i]);
		num = num << 63;
		num = num >> i;

		after_permutation = (after_permutation | num);
	}
	return after_permutation;
}

u32 rotation_l(u32 num, u32 n) {
	return (((num << n) & 0x0fffffff) | (num >> (28 - n)));
}

u32 f(u32 right, u64 subkey) {
	u64 save = 0x00;
	u64 temp = 0x00;

	for (int i = 0; i < 48; i++) {
		temp = temp & 0x00;
		temp = (u64)(right >> (32 - e_boxes[i]));
		temp = temp << 63;
		temp = temp >> (i + 16);

		save = (save | temp);
	}
	
	save = (save ^ subkey);

	u8 rows[8] = { 0x00, };
	u8 cols[8] = { 0x00, };
	u8 numb = 0x00;

	temp = save;
	for (int i = 7; i >= 0; i--) {
		numb = temp;

		rows[i] = numb & 0b00100001;
		rows[i] = (rows[i] & 0b00000001) | ((rows[i] >> 5) << 1);

		cols[i] = (numb >> 1) & 0b1111;

		temp = temp >> 6;
	}

	u32 aft = 0x00;
	u32 out = 0x00;
	int row = 0x00;
	int col = 0x00;

	for (int i = 0; i < 8; i++) {
		out = out & 0x00;
		out = s_boxes[i][rows[i]][cols[i]];
		out = out << (28 - 4 * i);
		aft = (aft | out);
	}
	
	u32 num = 0x00;
	u32 after_permutation = 0x00;
	temp = aft;

	for (int i = 0; i < 32; i++) {
		num = temp >> (32 - p_boxes[i]);
		num = num << 31;
		num = num >> i;

		after_permutation = (after_permutation | num);
	}
	return after_permutation;
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
	
	u64 key_56bit = pc(key, pc1, 56);
	u32 c = (u32)(key_56bit >> 28);
	u32 d = (u32)(key_56bit & 0x0fffffff);

	for (int i = 0; i < 16; i++) {
		c = rotation_l(c, rotations[i]);
		d = rotation_l(d, rotations[i]);

		u64 round_key = 0x00;

		round_key = ((u64)c) << 28;
		round_key = (round_key | d);

		round_keys[i] = pc(round_key, pc2, 48);
	}

	plain_text = ip(plain_text, ip_table);
	u32 left = (u32)(plain_text >> 32);
	u32 right = (u32)((plain_text << 32) >> 32);

	for (int i = 0; i < 16; i++) {
		u32 temp_right = right;
		u32 f_result = f(right, round_keys[i]);

		right = left ^ f_result;
		left = temp_right;
	}
	// 마지막 16번 라운드에서는 swap하지 않음. 그러므로 한번 더 스왑
	u32 temp_swap = left;
	left = right;
	right = temp_swap;

	u64 final_text = ((u64)left << 32) | right;
	cipher_text = ip(final_text, fp_table);

	printf("암호문 (Ciphertext): 0x%016llx\n", cipher_text); // test vector : 0x3FA40E8A984D4815

	return 0;
}