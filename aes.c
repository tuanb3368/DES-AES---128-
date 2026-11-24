#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Bảng S-box của AES
uint8_t SBOX[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Hằng số Rcon cho mở rộng khóa
uint8_t RCON[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

// In state theo thứ tự cột (giống cách viết trong FIPS 197)
void print_state(char *label, uint8_t s[4][4]) {
    printf("%-14s= ", label);
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            printf("%02x", s[r][c]);
    printf("\n");
}

// Mở rộng khóa: 4 word khóa -> 44 word (11 khóa vòng)
void key_expansion(uint8_t key[16], uint8_t w[44][4]) {
    for (int i = 0; i < 4; i++)
        for (int j = 0; j < 4; j++)
            w[i][j] = key[4 * i + j];

    for (int i = 4; i < 44; i++) {
        uint8_t temp[4];
        for (int j = 0; j < 4; j++) temp[j] = w[i - 1][j];

        if (i % 4 == 0) {
            // RotWord: xoay trái 1 byte
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            // SubWord
            for (int j = 0; j < 4; j++) temp[j] = SBOX[temp[j]];
            temp[0] ^= RCON[i / 4 - 1];
        }

        for (int j = 0; j < 4; j++) w[i][j] = w[i - 4][j] ^ temp[j];
    }
}

void add_round_key(uint8_t s[4][4], uint8_t w[44][4], int round) {
    for (int c = 0; c < 4; c++)
        for (int r = 0; r < 4; r++)
            s[r][c] ^= w[round * 4 + c][r];
}

void sub_bytes(uint8_t s[4][4]) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            s[r][c] = SBOX[s[r][c]];
}

// Hàng r dịch trái r byte
void shift_rows(uint8_t s[4][4]) {
    for (int r = 1; r < 4; r++) {
        uint8_t temp[4];
        for (int c = 0; c < 4; c++) temp[c] = s[r][(c + r) % 4];
        for (int c = 0; c < 4; c++) s[r][c] = temp[c];
    }
}

// Nhân 2 trong GF(2^8)
uint8_t xtime(uint8_t x) {
    if (x & 0x80) return (uint8_t)((x << 1) ^ 0x1B);
    return (uint8_t)(x << 1);
}

void mix_columns(uint8_t s[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
        s[0][c] = xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3;
        s[1][c] = a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3;
        s[2][c] = a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3);
        s[3][c] = (xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3);
    }
}

void aes_encrypt(uint8_t in[16], uint8_t key[16], uint8_t out[16]) {
    uint8_t w[44][4];
    uint8_t s[4][4];

    key_expansion(key, w);
    printf("--- Mo rong khoa ---\n");
    for (int round = 0; round <= 10; round++) {
        printf("K%-2d = ", round);
        for (int i = 0; i < 4; i++)
            for (int j = 0; j < 4; j++)
                printf("%02x", w[round * 4 + i][j]);
        printf("\n");
    }

    // Nạp 16 byte vào state theo cột
    for (int i = 0; i < 16; i++) s[i % 4][i / 4] = in[i];

    printf("--- Ma hoa ---\n");
    print_state("Input", s);
    add_round_key(s, w, 0);
    print_state("AddRoundKey 0", s);

    for (int round = 1; round <= 10; round++) {
        printf("Vong %d:\n", round);
        sub_bytes(s);
        print_state("  SubBytes", s);
        shift_rows(s);
        print_state("  ShiftRows", s);
        if (round != 10) {
            mix_columns(s);
            print_state("  MixColumns", s);
        }
        add_round_key(s, w, round);
        print_state("  AddRoundKey", s);
    }

    for (int i = 0; i < 16; i++) out[i] = s[i % 4][i / 4];
}

void hex_to_bytes(char *hex, uint8_t out[16]) {
    for (int i = 0; i < 16; i++) sscanf(hex + 2 * i, "%2hhx", &out[i]);
}

int main() {
    // test1: không có đáp án ("") nên chỉ in các bước
    char *name[2] = {"test1", "test2"};
    char *p[2] = {"00000000000000000000000000000011", "3243f6a8885a308d313198a2e0370734"};
    char *k[2] = {"00000000000000000000000000000000", "2b7e151628aed2a6abf7158809cf4f3c"};
    char *c[2] = {"", "3925841d02dc09fbdc118597196a0b32"};

    for (int t = 0; t < 2; t++) {
        uint8_t in[16], key[16], out[16];
        char got[33];
        hex_to_bytes(p[t], in);
        hex_to_bytes(k[t], key);

        printf("========== AES-128 %s ==========\n", name[t]);
        printf("Plaintext  = %s\n", p[t]);
        printf("Key        = %s\n", k[t]);
        aes_encrypt(in, key, out);
        for (int i = 0; i < 16; i++) snprintf(got + 2 * i, 3, "%02x", out[i]);
        printf("Ciphertext = %s\n", got);
        if (strlen(c[t]) > 0) {
            if (strcmp(got, c[t]) == 0) printf("PASS\n");
            else printf("FAIL (dung phai la %s)\n", c[t]);
        }
        printf("\n");
    }
    return 0;
}
