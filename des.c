#include <stdio.h>
#include <stdint.h>

#include "des.h"

// Code base from: https://github.com/tfpf/data-encryption-standard.git
// Fixed bugs.
// Checking correctness with: http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm

#define FIRSTBIT 0x8000000000000000

int power(int x, int y) {
    int result = 1;
    for (int i = 0; i < y; ++i)
        result *= x;
    return result;
}

#if TEST
void printbits(uint64_t v) {
	for(int ii = 0; ii < 64; ii++) {
		if(((v << ii) & FIRSTBIT) == (uint64_t)0) {
			printf("0");
		}
		else {
			printf("1");
		}
	}
}

void write_sbox(char file_name[], uint8_t value) {
  char content[256];
  sprintf(content, "%d\n", value);
  FILE *pFile = fopen(file_name, "a");
  fprintf(pFile, content);
  fclose(pFile);
}

void write_roundoutput(char file_name[], uint64_t value) {
  char content[256];
  sprintf(content, "%ld\n", value);
  FILE *pFile = fopen(file_name, "a");
  fprintf(pFile, content);
  fclose(pFile);
}

#endif

void addbit(uint64_t *block, uint64_t from, int position_from, int position_to) {
	if(((from << (position_from)) & FIRSTBIT) != 0) {
		*block += (FIRSTBIT >> position_to);
	}
}

void Permutation(uint64_t *data, int initial) {
	uint64_t data_temp = 0;

	for(int ii = 0; ii < 64; ii++) {
		if(initial == 1) {
			addbit(&data_temp, *data, InitialPermutation[ii] - 1, ii);
		}
		else {
			addbit(&data_temp, *data, FinalPermutation[ii] - 1, ii);
		}
	}
	*data = data_temp;
}

void key_schedule(uint64_t *key, uint64_t *next_key, int round) {
	uint64_t key_left = 0;
	uint64_t key_right = 0;
	uint64_t key_left_temp = 0;
	uint64_t key_right_temp = 0;

	*next_key = 0;
	if(round == 0) {
		for(int ii = 0; ii < 56; ii++) {
			if(ii < 28) {
				addbit(&key_left, *key, PC1[ii] - 1, ii);
			}
			else {
				addbit(&key_right, *key, PC1[ii] - 1, ii % 28);
			}
		}
	}
	else {
		for(int ii = 0; ii < 56; ii++) {
			if(ii < 28) {
				addbit(&key_left, *key, ii, ii);
			}
			else {
				addbit(&key_right, *key, ii, ii % 28);
			}
		}
	}

	key_left_temp = Rotations[round] == 1 ? FIRSTBIT : 0xC000000000000000;
	key_right_temp = Rotations[round] == 1 ? FIRSTBIT : 0xC000000000000000;
	key_left_temp = (key_left & key_left_temp) >> (28 - Rotations[round]);
	key_right_temp = (key_right & key_right_temp) >> (28 - Rotations[round]);
	key_left_temp += (key_left << Rotations[round]);
	key_right_temp += (key_right << Rotations[round]);
	
	for(int ii = 0; ii < 56; ii++){
		if(ii < 28) {
			addbit(next_key, key_left_temp, ii, ii);
		}
		else {
			addbit(next_key, key_right_temp, ii % 28, ii);
		}
	}

	*key = 0;
	for(int ii = 0; ii < 48; ii++) {
		addbit(key, *next_key, PC2[ii] - 1, ii);
	}
}

void rounds(uint64_t *data, uint64_t key) {
	uint64_t right_block = 0;
	uint64_t right_block_temp = 0;
	for(int ii = 0; ii < 48; ii++) {
		addbit(&right_block, *data, DesExpansion[ii] + 31, ii);
	}
	
	right_block = right_block ^ key;
	int coordx, coordy;
	uint64_t substitued;
	for(int ii = 0; ii < 8; ii++) {
		coordx = ((right_block << 6 * ii) & FIRSTBIT) == FIRSTBIT ? 2 : 0;
		if(((right_block << (6 * ii + 5)) & FIRSTBIT) == FIRSTBIT) {
			coordx++;
		}
		coordy = 0;
		for(int jj = 1; jj < 5; jj++) {
			if(((right_block << (6 * ii + jj)) & FIRSTBIT) == FIRSTBIT) {
				coordy += (1 << (4 - jj)); 
			}
		}
		substitued = DesSbox[ii][coordx][coordy];
		#if TEST
		if(ii == 0) {
		  printf("block: %d, coordx: %d, coordy: %d => SBOX: %ld\n", ii, coordx, coordy, substitued);
		  write_sbox("des_sbox.txt", substitued);
		}
		#endif
		substitued = substitued << (60 - 4 * ii);
		right_block_temp += substitued;
	}
	right_block = right_block_temp;
	right_block_temp = 0;
	for(int ii = 0; ii < 32; ii++) {
		addbit(&right_block_temp, right_block, Pbox[ii] - 1, ii);
	}
	right_block = right_block_temp;
	right_block = right_block ^ *data;
	*data = (*data << 32) + (right_block >> 32);
}

int main(void) {
  #if ROUND==0
  uint64_t data = 0xc68db51d3916fbbf;
  #endif
  #if ROUND==1
  uint64_t data = 0x2686b9296b7f28a5;
  #endif
  #if ROUND==2
  uint64_t data = 0x85b19fca78c5f675;
  #endif
  #if ROUND==3
  uint64_t data = 0x1767383f5899c1be;
  #endif
  #if ROUND==4
  uint64_t data = 0x3f93d7a4a165e7e2;
  #endif
  #if ROUND==5
  uint64_t data = 0x1290d8319e8e05ea;
  #endif
  #if ROUND==6
  uint64_t data = 0x40d29b9501c12794;
  #endif
  #if ROUND==7
  uint64_t data = 0x9e6a3f2efe8e55d7;
  #endif
  #if ROUND==8
  uint64_t data = 0x0bda32f9b1800122;
  #endif
  #if ROUND==9
  uint64_t data = 0xfc03470597f41754;
  #endif
  #if ROUND==10
  uint64_t data = 0xde638137aec38c89;
  #endif
  #if ROUND==11
  uint64_t data = 0x228793a7738a8cd7;
  #endif
  #if ROUND==12
  uint64_t data = 0x6cf755861991efc4;
  #endif
  #if ROUND==13
  uint64_t data = 0x9b65be62e09b54cf;
  #endif
  #if ROUND==14
  uint64_t data = 0x90c144fdbbcf91fe;
  #endif
  #if ROUND==15
  uint64_t data = 0x8998c6602c3ef495;
  #endif
  #if ROUND==16
  uint64_t data = 0xd6a31c911a7dbaf3;
  #endif
  #if ROUND==17
  uint64_t data = 0x4cf144cb15fd9d7c;
  #endif
  #if ROUND==18
  uint64_t data = 0x49deea3c48f7bb39;
  #endif
  #if ROUND==19
  uint64_t data = 0x6e56b8739920b05f;
  #endif
  #if ROUND==20
  uint64_t data = 0x16416abff375e300;
  #endif
  #if ROUND==21
  uint64_t data = 0xc2689ca55a3d8c86;
  #endif
  #if ROUND==22
  uint64_t data = 0xad07d05f49f1608a;
  #endif
  #if ROUND==23
  uint64_t data = 0xe40107fa1031eb8d;
  #endif
  #if ROUND==24
  uint64_t data = 0xe6292ea1b75cdafd;
  #endif
  #if ROUND==25
  uint64_t data = 0xe34ba5553a42fb99;
  #endif
  #if ROUND==26
  uint64_t data = 0x87364fa96d93c8c8;
  #endif
  #if ROUND==27
  uint64_t data = 0xb2e6003ea3cd6655;
  #endif
  #if ROUND==28
  uint64_t data = 0x4ab3aa2b7835134e;
  #endif
  #if ROUND==29
  uint64_t data = 0x09696cdf694316ff;
  #endif
  #if ROUND==30
  uint64_t data = 0xa5d18a102d9e0e1a;
  #endif
  #if ROUND==31
  uint64_t data = 0x01591cf8d0207630;
  #endif
  #if ROUND==32
  uint64_t data = 0x78cd8ab4dee84ba0;
  #endif
  #if ROUND==33
  uint64_t data = 0xea5a052a4da8e113;
  #endif
  #if ROUND==34
  uint64_t data = 0xe0cd523519d4caf3;
  #endif
  #if ROUND==35
  uint64_t data = 0x8bd96cffff025604;
  #endif
  #if ROUND==36
  uint64_t data = 0xc7e2396d521dcbcc;
  #endif
  #if ROUND==37
  uint64_t data = 0xafb1ff0c949299ef;
  #endif
  #if ROUND==38
  uint64_t data = 0xf867cb38ea0ee6c6;
  #endif
  #if ROUND==39
  uint64_t data = 0x04d5dea49be9f06a;
  #endif
  #if ROUND==40
  uint64_t data = 0xa7e1b5f63486ea73;
  #endif
  #if ROUND==41
  uint64_t data = 0xb13f2c35d29b772e;
  #endif
  #if ROUND==42
  uint64_t data = 0xd5e9acc231af9ceb;
  #endif
  #if ROUND==43
  uint64_t data = 0x7f82a194fcc1327d;
  #endif
  #if ROUND==44
  uint64_t data = 0xc2ff18e084249e5e;
  #endif
  #if ROUND==45
  uint64_t data = 0xd2f200243dd0386c;
  #endif
  #if ROUND==46
  uint64_t data = 0xf7a8ce44ee4fa0dc;
  #endif
  #if ROUND==47
  uint64_t data = 0xbf0e33e6fe0d1652;
  #endif
  #if ROUND==48
  uint64_t data = 0x434e03df8eda2904;
  #endif
  #if ROUND==49
  uint64_t data = 0x4f1ceaf8c4f6832d;
  #endif
  #if ROUND==50
  uint64_t data = 0x7d4f85bc1cc55f84;
  #endif
  #if ROUND==51
  uint64_t data = 0x6fd72438787bddcf;
  #endif
  #if ROUND==52
  uint64_t data = 0xe6d2e3c93f9a549f;
  #endif
  #if ROUND==53
  uint64_t data = 0xac88d6978dfac516;
  #endif
  #if ROUND==54
  uint64_t data = 0x6e89514911e9cb44;
  #endif
  #if ROUND==55
  uint64_t data = 0xd9cba0c92d95d48f;
  #endif
  #if ROUND==56
  uint64_t data = 0x816d28d7f6452d8d;
  #endif
  #if ROUND==57
  uint64_t data = 0x91ccf83c984e4945;
  #endif
  #if ROUND==58
  uint64_t data = 0xf4ee878eadd58f41;
  #endif
  #if ROUND==59
  uint64_t data = 0x4afe3206c283f559;
  #endif
  #if ROUND==60
  uint64_t data = 0x2336b7dbc9028ee9;
  #endif
  #if ROUND==61
  uint64_t data = 0x46cde5859119b8d1;
  #endif
  #if ROUND==62
  uint64_t data = 0x3a6269064e1dea41;
  #endif
  #if ROUND==63
  uint64_t data = 0xd3b159ceec60f990;
  #endif
  #if ROUND==64
  uint64_t data = 0x97085e685a16d277;
  #endif
  #if ROUND==65
  uint64_t data = 0x063c0ba03a244aec;
  #endif
  #if ROUND==66
  uint64_t data = 0x6856f0c82d9a7508;
  #endif
  #if ROUND==67
  uint64_t data = 0x0eb8fd3a97adebc5;
  #endif
  #if ROUND==68
  uint64_t data = 0xaf3fc01ef0e61464;
  #endif
  #if ROUND==69
  uint64_t data = 0xd6f601902af0fed6;
  #endif
  #if ROUND==70
  uint64_t data = 0x53963c36c3daf616;
  #endif
  #if ROUND==71
  uint64_t data = 0x1edc8e93953dec53;
  #endif
  #if ROUND==72
  uint64_t data = 0x2aa2855b791c54c4;
  #endif
  #if ROUND==73
  uint64_t data = 0x8ac296321cf3e87d;
  #endif
  #if ROUND==74
  uint64_t data = 0x45eeaf6340767e20;
  #endif
  #if ROUND==75
  uint64_t data = 0x77cd7e97fd2e3a37;
  #endif
  #if ROUND==76
  uint64_t data = 0x152daed5dbb37df3;
  #endif
  #if ROUND==77
  uint64_t data = 0x22f8d2f1caba0f13;
  #endif
  #if ROUND==78
  uint64_t data = 0xc90765c7c0cfe09e;
  #endif
  #if ROUND==79
  uint64_t data = 0x4700890df25c68d7;
  #endif
  #if ROUND==80
  uint64_t data = 0xf2bbb40576a7e126;
  #endif
  #if ROUND==81
  uint64_t data = 0x1838e897ae2a49f5;
  #endif
  #if ROUND==82
  uint64_t data = 0x7987eb93af29090f;
  #endif
  #if ROUND==83
  uint64_t data = 0xd78d8a16bae090a5;
  #endif
  #if ROUND==84
  uint64_t data = 0xb81688ddaa05f185;
  #endif
  #if ROUND==85
  uint64_t data = 0x95544c63d859fff2;
  #endif
  #if ROUND==86
  uint64_t data = 0x127b30c0e8bbf707;
  #endif
  #if ROUND==87
  uint64_t data = 0xe9f7d1b181216485;
  #endif
  #if ROUND==88
  uint64_t data = 0x022a88965fb9f502;
  #endif
  #if ROUND==89
  uint64_t data = 0xbf9a4d7535de8f72;
  #endif
  #if ROUND==90
  uint64_t data = 0x083bcfa119c66293;
  #endif
  #if ROUND==91
  uint64_t data = 0x275e35989a8acf67;
  #endif
  #if ROUND==92
  uint64_t data = 0xd5f536d316fba61a;
  #endif
  #if ROUND==93
  uint64_t data = 0x77b5a1dfa66f727f;
  #endif
  #if ROUND==94
  uint64_t data = 0x763dcf23ad87eacd;
  #endif
  #if ROUND==95
  uint64_t data = 0xf1622a4e29984f2d;
  #endif
  #if ROUND==96
  uint64_t data = 0x4989f9d508d069f5;
  #endif
  #if ROUND==97
  uint64_t data = 0x6ba6951b9f41b72e;
  #endif
  #if ROUND==98
  uint64_t data = 0xc32fd3947bd2ffef;
  #endif
  #if ROUND==99
  uint64_t data = 0x65e99459d18d9b83;
  #endif
  #if ROUND==100
  uint64_t data = 0x79ae198c8d719935;
  #endif
  #if ROUND==101
  uint64_t data = 0x1740037db67c1a18;
  #endif
  #if ROUND==102
  uint64_t data = 0xeee2b6149a72f2a1;
  #endif
  #if ROUND==103
  uint64_t data = 0x3168651cf0165b35;
  #endif
  #if ROUND==104
  uint64_t data = 0xb8738bf677ab7ed1;
  #endif
  #if ROUND==105
  uint64_t data = 0x6c82d199a7adc36e;
  #endif
  #if ROUND==106
  uint64_t data = 0xe46e941718588404;
  #endif
  #if ROUND==107
  uint64_t data = 0x41a10966460e7ea5;
  #endif
  #if ROUND==108
  uint64_t data = 0x0d130ceb9bebc3ae;
  #endif
  #if ROUND==109
  uint64_t data = 0x022fc3aae67b37a4;
  #endif
  #if ROUND==110
  uint64_t data = 0xaf70e2d95736c865;
  #endif
  #if ROUND==111
  uint64_t data = 0x69bd3d1674c8ec78;
  #endif
  #if ROUND==112
  uint64_t data = 0x4685375c2f7c000a;
  #endif
  #if ROUND==113
  uint64_t data = 0x536250396a0a32f7;
  #endif
  #if ROUND==114
  uint64_t data = 0x6dc4eb8744ce055c;
  #endif
  #if ROUND==115
  uint64_t data = 0xc196660ec6f7acad;
  #endif
  #if ROUND==116
  uint64_t data = 0x4df45e9a8c052be0;
  #endif
  #if ROUND==117
  uint64_t data = 0x7073d1ffed774939;
  #endif
  #if ROUND==118
  uint64_t data = 0x45c837422febc005;
  #endif
  #if ROUND==119
  uint64_t data = 0x1a8e35dcfacb0f59;
  #endif
  #if ROUND==120
  uint64_t data = 0x344c36aa24b548ad;
  #endif
  #if ROUND==121
  uint64_t data = 0x021bacc3dcf0aeb0;
  #endif
  #if ROUND==122
  uint64_t data = 0xedbd6fc513798620;
  #endif
  #if ROUND==123
  uint64_t data = 0xd19df729e933425e;
  #endif
  #if ROUND==124
  uint64_t data = 0xedf1d57aa5d7db55;
  #endif
  #if ROUND==125
  uint64_t data = 0x53ebe400499e7afe;
  #endif
  #if ROUND==126
  uint64_t data = 0x79a00bfd2fe87c7a;
  #endif
  #if ROUND==127
  uint64_t data = 0xfd22ca439cd5c203;
  #endif
  #if ROUND==128
  uint64_t data = 0x999812f419d91797;
  #endif
  #if ROUND==129
  uint64_t data = 0x8f85dd8dd005a76b;
  #endif
  #if ROUND==130
  uint64_t data = 0x29601a2809551cdb;
  #endif
  #if ROUND==131
  uint64_t data = 0xef35b2c105bb9891;
  #endif
  #if ROUND==132
  uint64_t data = 0x6bd8d66a9387ec43;
  #endif
  #if ROUND==133
  uint64_t data = 0xf22ba5fc8a13c148;
  #endif
  #if ROUND==134
  uint64_t data = 0xa4d450f2a7177dde;
  #endif
  #if ROUND==135
  uint64_t data = 0x463621cc9f581452;
  #endif
  #if ROUND==136
  uint64_t data = 0xe67afee066e6594d;
  #endif
  #if ROUND==137
  uint64_t data = 0x42da94ae7592191f;
  #endif
  #if ROUND==138
  uint64_t data = 0x9f4f97db386e6a84;
  #endif
  #if ROUND==139
  uint64_t data = 0xb652dbafa7d42267;
  #endif
  #if ROUND==140
  uint64_t data = 0xce3feb6f90124256;
  #endif
  #if ROUND==141
  uint64_t data = 0x195df8ffc8a3c498;
  #endif
  #if ROUND==142
  uint64_t data = 0x50a5fac4b6eaf48e;
  #endif
  #if ROUND==143
  uint64_t data = 0x1adb31f5ed000805;
  #endif
  #if ROUND==144
  uint64_t data = 0xd9985ea1661882c8;
  #endif
  #if ROUND==145
  uint64_t data = 0x6605a80f97f80054;
  #endif
  #if ROUND==146
  uint64_t data = 0x94eb981bd76e8671;
  #endif
  #if ROUND==147
  uint64_t data = 0x19c8fc9baeffe1d2;
  #endif
  #if ROUND==148
  uint64_t data = 0x7d6ccf68678f8359;
  #endif
  #if ROUND==149
  uint64_t data = 0xa9c75e697ea79417;
  #endif
  #if ROUND==150
  uint64_t data = 0x3a734a35c43998a4;
  #endif
  #if ROUND==151
  uint64_t data = 0xa00cd860b00be603;
  #endif
  #if ROUND==152
  uint64_t data = 0x5a1b0441e13f832f;
  #endif
  #if ROUND==153
  uint64_t data = 0x31011250548f537d;
  #endif
  #if ROUND==154
  uint64_t data = 0x69bd3ec2dcd6d39b;
  #endif
  #if ROUND==155
  uint64_t data = 0x2804661b96f51653;
  #endif
  #if ROUND==156
  uint64_t data = 0xa64ae811f989ab9a;
  #endif
  #if ROUND==157
  uint64_t data = 0xf9ec2d7260b603a0;
  #endif
  #if ROUND==158
  uint64_t data = 0x1606ef88bc6ece84;
  #endif
  #if ROUND==159
  uint64_t data = 0xe34f0c6521e394a2;
  #endif
  #if ROUND==160
  uint64_t data = 0xf1c4de7afdccd6b6;
  #endif
  #if ROUND==161
  uint64_t data = 0xdb724f49560661da;
  #endif
  #if ROUND==162
  uint64_t data = 0xe0ab9a82c74dec4e;
  #endif
  #if ROUND==163
  uint64_t data = 0xbacd4cbce049526a;
  #endif
  #if ROUND==164
  uint64_t data = 0x3b54ae04af7092db;
  #endif
  #if ROUND==165
  uint64_t data = 0x14e0b1878f2be403;
  #endif
  #if ROUND==166
  uint64_t data = 0x1c12e5e2ae0b2145;
  #endif
  #if ROUND==167
  uint64_t data = 0xd3704463f9ad35a4;
  #endif
  #if ROUND==168
  uint64_t data = 0x86ca4a313d518c87;
  #endif
  #if ROUND==169
  uint64_t data = 0xafc5b0f03d85e241;
  #endif
  #if ROUND==170
  uint64_t data = 0x972586a6f5846576;
  #endif
  #if ROUND==171
  uint64_t data = 0xf885ba6564c18eb7;
  #endif
  #if ROUND==172
  uint64_t data = 0x0656654277f7df24;
  #endif
  #if ROUND==173
  uint64_t data = 0xd75f0d3bfe4ea4a2;
  #endif
  #if ROUND==174
  uint64_t data = 0x831a7f62b639a3a8;
  #endif
  #if ROUND==175
  uint64_t data = 0xe0c6728dfe4dbe06;
  #endif
  #if ROUND==176
  uint64_t data = 0xaefde724e987562c;
  #endif
  #if ROUND==177
  uint64_t data = 0x119450ce449f1714;
  #endif
  #if ROUND==178
  uint64_t data = 0xa29c680ecf8a252e;
  #endif
  #if ROUND==179
  uint64_t data = 0xc2eb32d3bc893c09;
  #endif
  #if ROUND==180
  uint64_t data = 0xe23358e68078968a;
  #endif
  #if ROUND==181
  uint64_t data = 0x1dc8962c60fe2385;
  #endif
  #if ROUND==182
  uint64_t data = 0x74b944466742994d;
  #endif
  #if ROUND==183
  uint64_t data = 0xad902b8bdeffb3e2;
  #endif
  #if ROUND==184
  uint64_t data = 0x764e0fc6113c8153;
  #endif
  #if ROUND==185
  uint64_t data = 0x75164456b02fbccc;
  #endif
  #if ROUND==186
  uint64_t data = 0x75d08cf2b07a3cc0;
  #endif
  #if ROUND==187
  uint64_t data = 0xcb5ae6a637f49ca8;
  #endif
  #if ROUND==188
  uint64_t data = 0xa6182e2a45e85aa4;
  #endif
  #if ROUND==189
  uint64_t data = 0x25f17cd4dd129fd3;
  #endif
  #if ROUND==190
  uint64_t data = 0x18ffc1e6bcea6f53;
  #endif
  #if ROUND==191
  uint64_t data = 0x556fd5bd93e75d5f;
  #endif
  #if ROUND==192
  uint64_t data = 0x982be9c48bbd4a38;
  #endif
  #if ROUND==193
  uint64_t data = 0xdfb9d4683a5e9327;
  #endif
  #if ROUND==194
  uint64_t data = 0x408fe050baa91e75;
  #endif
  #if ROUND==195
  uint64_t data = 0xac52e11060f9990d;
  #endif
  #if ROUND==196
  uint64_t data = 0x25f9043c39690033;
  #endif
  #if ROUND==197
  uint64_t data = 0xfa752f5ae631c574;
  #endif
  #if ROUND==198
  uint64_t data = 0x713ea2964f386631;
  #endif
  #if ROUND==199
  uint64_t data = 0xa13f581d5222a0a4;
  #endif
  #if ROUND==200
  uint64_t data = 0x89e760313e14988c;
  #endif
  #if ROUND==201
  uint64_t data = 0xb512e240a8a56410;
  #endif
  #if ROUND==202
  uint64_t data = 0x23ca8fd8654d487d;
  #endif
  #if ROUND==203
  uint64_t data = 0x55db23994519fb82;
  #endif
  #if ROUND==204
  uint64_t data = 0x8ecd13607d85f041;
  #endif
  #if ROUND==205
  uint64_t data = 0x7cda43a5467719cd;
  #endif
  #if ROUND==206
  uint64_t data = 0x20a0fdaddbd43d5a;
  #endif
  #if ROUND==207
  uint64_t data = 0x7eba341a4123bae5;
  #endif
  #if ROUND==208
  uint64_t data = 0xe582ef150614c463;
  #endif
  #if ROUND==209
  uint64_t data = 0x87dcb8ea95d56fbc;
  #endif
  #if ROUND==210
  uint64_t data = 0x2781fc3a925e10dc;
  #endif
  #if ROUND==211
  uint64_t data = 0x54c6c040cbe7660c;
  #endif
  #if ROUND==212
  uint64_t data = 0xebad477ceb7aa443;
  #endif
  #if ROUND==213
  uint64_t data = 0xb4fe3bbc26399de2;
  #endif
  #if ROUND==214
  uint64_t data = 0x28edab758e9dc88d;
  #endif
  #if ROUND==215
  uint64_t data = 0x4adb5120be38a024;
  #endif
  #if ROUND==216
  uint64_t data = 0x0ab0fa1b2e5cb221;
  #endif
  #if ROUND==217
  uint64_t data = 0x1b3571a34ab08c2b;
  #endif
  #if ROUND==218
  uint64_t data = 0x3e7fdf825bf205d2;
  #endif
  #if ROUND==219
  uint64_t data = 0x088d6132709e09ac;
  #endif
  #if ROUND==220
  uint64_t data = 0xe07ec387d4751536;
  #endif
  #if ROUND==221
  uint64_t data = 0x454d7ab29484ddf2;
  #endif
  #if ROUND==222
  uint64_t data = 0xcbe8701968ef4276;
  #endif
  #if ROUND==223
  uint64_t data = 0x4f2305acffc5f185;
  #endif
  #if ROUND==224
  uint64_t data = 0x5fe921c93ee45ec1;
  #endif
  #if ROUND==225
  uint64_t data = 0xbcad6ce0ef7482ae;
  #endif
  #if ROUND==226
  uint64_t data = 0xc5e91d1fa3b48182;
  #endif
  #if ROUND==227
  uint64_t data = 0x6cd6f1ce8194ddb8;
  #endif
  #if ROUND==228
  uint64_t data = 0xda38af6b73d867f9;
  #endif
  #if ROUND==229
  uint64_t data = 0x15b5a64f89044aed;
  #endif
  #if ROUND==230
  uint64_t data = 0x3001f8151286a007;
  #endif
  #if ROUND==231
  uint64_t data = 0x9e36993ae2c49e09;
  #endif
  #if ROUND==232
  uint64_t data = 0x7f4cbd9f87d86d98;
  #endif
  #if ROUND==233
  uint64_t data = 0x4d509a9440ec8937;
  #endif
  #if ROUND==234
  uint64_t data = 0x308ee2a7c801e109;
  #endif
  #if ROUND==235
  uint64_t data = 0xf7e6d88b6444dbf0;
  #endif
  #if ROUND==236
  uint64_t data = 0xacb2ea67897b722b;
  #endif
  #if ROUND==237
  uint64_t data = 0xc1e640bb78495163;
  #endif
  #if ROUND==238
  uint64_t data = 0xf8dfb40311d2021f;
  #endif
  #if ROUND==239
  uint64_t data = 0x19c9c8c2a628dcff;
  #endif
  #if ROUND==240
  uint64_t data = 0x6275f3f6e665e0ed;
  #endif
  #if ROUND==241
  uint64_t data = 0x169a5ff5850a9eac;
  #endif
  #if ROUND==242
  uint64_t data = 0x5c9d772a62635819;
  #endif
  #if ROUND==243
  uint64_t data = 0x7c64413fbad810e4;
  #endif
  #if ROUND==244
  uint64_t data = 0x7dfdd75f6de20598;
  #endif
  #if ROUND==245
  uint64_t data = 0x5b85bfbcab0fc5c1;
  #endif
  #if ROUND==246
  uint64_t data = 0xa963dc388ac7bb8a;
  #endif
  #if ROUND==247
  uint64_t data = 0x39d7e88fae007981;
  #endif
  #if ROUND==248
  uint64_t data = 0xbae24dd5974e24df;
  #endif
  #if ROUND==249
  uint64_t data = 0x57ef811807e71142;
  #endif
  #if ROUND==250
  uint64_t data = 0xc436630cfc1a27c1;
  #endif
  #if ROUND==251
  uint64_t data = 0xd84906cf6cc2fbaf;
  #endif
  #if ROUND==252
  uint64_t data = 0xa784841a4d1fd878;
  #endif
  #if ROUND==253
  uint64_t data = 0x4cadbc06dcfeb873;
  #endif
  #if ROUND==254
  uint64_t data = 0x609808f458183506;
  #endif
  #if ROUND==255
  uint64_t data = 0x9f8d2c95a86c6f18;
  #endif
  #if ROUND==300 
  uint64_t data = 0x0123456789ABCDEF; // Vector example of http://page.math.tu-berlin.de/~kant/teaching/hess/krypto-ws2006/des.htm.
  #endif
  
  uint64_t key  = 1383827165325090801;
  
  
  
  #if TEST
  printf("Plaintext:\t"); printbits(data); printf("\n");
  printf("Key:\t\t"); printbits(key); printf("\n");
  #endif
  
  // Round keys
  #if FIRSTROUNDONLY
  uint64_t next_key;
  key_schedule(&key, &next_key, 0);
  #else
  uint64_t a_key[16];
	a_key[0] = key;
	uint64_t next_key;
	for(int ii = 0; ii < 16; ii++) {
		key_schedule(&a_key[ii], &next_key, ii);
		if(ii != 15) {
			a_key[ii + 1] = next_key;
		}
	}  
  #endif
  
  // initial permutation
  Permutation(&data, 1);

  // 1 round or full des
  #if FIRSTROUNDONLY
  rounds(&data, key);
  
  #if TEST
  printf("Roundoutput: %ld\n", data);
  write_roundoutput("des_roundoutput.txt", data);
  #endif
  #else
  for(int ii = 0; ii < 16; ii++) {
    rounds(&data, a_key[ii]);
  } 
  
  // Reverse order
  uint64_t reverse = 0;
  for(int ii = 0; ii < 32; ii++) {
    addbit(&reverse, data, ii + 32, ii);
  }
  for(int ii = 0; ii < 32; ii++) {
    addbit(&reverse, data, ii, ii + 32);
  }
  data = reverse;
  
  // final permutation
  Permutation(&data, 0);
  
  #endif

  // display encrypted or decrypted
  #if TEST
  printf("Ciphertext:\t"); printbits(data); printf("\n");
  #endif
  return 0;
}
