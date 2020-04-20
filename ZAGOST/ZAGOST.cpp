#include <omp.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <iostream>
#include <fstream>

#define LSHIFT_nBIT(x, L, N) (((x << L) | (x >> (-L & (N - 1)))) & (((uint64_t)1 << N) - 1))
//#define ENCRYPT_IN_FILE   // if u want to write encypted code to file(encryptedtomb.txt)
//#define SMALL_MESSAGE // if u want to print message

unsigned int thread_count = 5;

// 1 | 4 -> 0xC
static const uint8_t Sbox[8][16] = {
    {0xF, 0xC, 0x2, 0xA, 0x6, 0x4, 0x5, 0x0, 0x7, 0x9, 0xE, 0xD, 0x1, 0xB, 0x8, 0x3},
    {0xB, 0x6, 0x3, 0x4, 0xC, 0xF, 0xE, 0x2, 0x7, 0xD, 0x8, 0x0, 0x5, 0xA, 0x9, 0x1},
    {0x1, 0xC, 0xB, 0x0, 0xF, 0xE, 0x6, 0x5, 0xA, 0xD, 0x4, 0x8, 0x9, 0x3, 0x7, 0x2},
    {0x1, 0x5, 0xE, 0xC, 0xA, 0x7, 0x0, 0xD, 0x6, 0x2, 0xB, 0x4, 0x9, 0x3, 0xF, 0x8},
    {0x0, 0xC, 0x8, 0x9, 0xD, 0x2, 0xA, 0xB, 0x7, 0x3, 0x6, 0x5, 0x4, 0xE, 0xF, 0x1},
    {0x8, 0x0, 0xF, 0x3, 0x2, 0x5, 0xE, 0xB, 0x1, 0xA, 0x4, 0x7, 0xC, 0x9, 0xD, 0x6},
    {0x3, 0x0, 0x6, 0xF, 0x1, 0xE, 0x9, 0x2, 0xD, 0x8, 0xC, 0x4, 0xB, 0xA, 0x5, 0x7},
    {0x1, 0xA, 0x6, 0x8, 0xF, 0xB, 0x0, 0x4, 0xC, 0x3, 0x5, 0x9, 0x7, 0xD, 0x2, 0xE},
};

void print_array_codes(uint8_t* array, size_t length)
{
    printf("[ ");
    for (size_t i = 0; i < length; i++)
        printf("%d ", array[i]);
    printf("]\n");
    return;
}

void split256bit_to_32bits(uint8_t* key256, uint32_t* keys32)
{
    uint8_t* p8 = key256;
    for (uint32_t* p32 = keys32; p32 < keys32 + 8; ++p32)
    {
        for (uint8_t i = 0; i < 4; ++i)
        {
            *p32 = (*p32 << 8) | *(p8 + i);
        }
        p8 += 4;
    }
}

void split_64bits_to_32bits(uint64_t block64, uint32_t* block32_1, uint32_t* block32_2)
{
    *block32_2 = (uint32_t)block64;

    *block32_1 = (uint32_t)(block64 >> 32);
}

uint64_t join_8bits_to_64bits(uint8_t* blocks8)
{
    uint64_t block64;

    for (uint8_t* p = blocks8; p < blocks8 + 8; ++p)
    {
        block64 = (block64 << 8) | *p;
    }
    return block64;
}

void split_32its_to_8bits(uint32_t block32, uint8_t* block8)
{
    for (uint8_t i = 0; i < 4; ++i)
    {
        block8[i] = (uint8_t)(block32 >> (24 - (i * 8)));
    }
}

void substitution_table_by_4bits(uint8_t* blocks4b, uint8_t sbox_row)
{
    uint8_t block4b_1, block4b_2;
    for (uint8_t i = 0; i < 4; i++)
    {
        block4b_1 = Sbox[sbox_row][blocks4b[i] & 0x0F];

        block4b_2 = Sbox[sbox_row][blocks4b[i] >> 4];

        blocks4b[i] = block4b_2;

        blocks4b[i] = (blocks4b[i] << 4) | block4b_1;
    }
}

uint32_t join_4bits_to_32bits(uint8_t* blocks4b)
{
    uint32_t block32;
    for (uint8_t i = 0; i < 4; ++i)
    {
        block32 = (block32 << 8) | blocks4b[i];
    }
    return block32;
}

uint32_t substitution_table(uint32_t block32, uint8_t sbox_row)
{
    uint8_t blocks4bits[4];
    split_32its_to_8bits(block32, blocks4bits);
    substitution_table_by_4bits(blocks4bits, sbox_row);
    return join_4bits_to_32bits(blocks4bits);

}

void round_of_feistel_cipher(uint32_t* block32_1, uint32_t* block32_2, uint32_t* keys32, uint8_t round)
{
    uint32_t result_of_iter, temp;
    // RES = (N1 + Ki) mod 2^32
    result_of_iter = (*block32_1 + keys32[round % 8]) % UINT32_MAX;
    
    // RES = RES -> Sbox
    result_of_iter = substitution_table(result_of_iter, round % 8);

    // RES = RES << 11
    result_of_iter = (uint32_t)LSHIFT_nBIT(result_of_iter, 11, 32);

    temp = *block32_1;
    *block32_1 = result_of_iter ^ *block32_2;
    *block32_2 = temp;
    return;
}

void feistel_cipher(uint8_t mode, uint32_t* block32_1, uint32_t* block32_2, uint32_t* keys32)
{
    switch (mode)
    {
    case 'E':
    {
        for (uint8_t round = 0; round < 24; ++round)
            round_of_feistel_cipher(block32_1, block32_2, keys32, round);

        for (uint8_t round = 31; round >= 24; --round)
            round_of_feistel_cipher(block32_1, block32_2, keys32, round);
        break;
    }
    case 'D':
        for (uint8_t round = 0; round < 8; ++round)
            round_of_feistel_cipher(block32_1, block32_2, keys32, round);

        for (uint8_t round = 31; round >= 8; --round)
            round_of_feistel_cipher(block32_1, block32_2, keys32, round);
        break;
    }
}

void split_64bit_to_8bit(uint64_t block64, uint8_t* block8b)
{
    for (size_t i = 0; i < 8; ++i)
    {
        block8b[i] = (uint8_t)(block64 >> ((7 - i) * 8));
    }
    return;
}

uint64_t join_32bit_to_64bit(uint32_t block32_1, uint32_t block32_2)
{
    uint64_t block64;
    block64 = block32_2;
    block64 = (block64 << 32) | block32_1;
    return block64;
}

uint8_t* ECBGOST(uint8_t* to, uint8_t mode, uint8_t* key256, uint8_t* from, size_t length)
{
    length = length % 8 == 0 ? length : length + (8 - (length % 8));
    uint32_t N1, N2, key32[8];
    split256bit_to_32bits(key256, key32);
    uint8_t* buff = new uint8_t[length];
    long buff_size = length / thread_count;
    buff_size = buff_size % 8 == 0 ? buff_size : buff_size + (8 - (buff_size % 8));
#pragma omp parallel for private(to,key256,length,N1,N2,key32) shared(buff,buff_size)num_threads(thread_count) 
    for (long j = 0; j < thread_count; j++)
    {
        for (long i = 0; i < buff_size; i += 8)
        {
            split_64bits_to_32bits(join_8bits_to_64bits((from+j*buff_size) + i), &N1, &N2);
            feistel_cipher(mode, &N1, &N2, key32);
            split_64bit_to_8bit(join_32bit_to_64bit(N1, N2), ((buff+j*buff_size) + i));
        }
    }
    return buff;
}

unsigned int getFileLength(std::ifstream *file)
{
    file->seekg(0, std::ios::end);
    size_t size = file->tellg();
    file->seekg(std::ios::beg);
    return size;
}

int main(int argc, char* argv[])
{
    uint8_t *encrypted, *decrypted;
	uint8_t key256[] = "uwus_wo_w_rassgwen_GOST_28147_89";	// 32 length
	uint8_t *buffer,ch;
    size_t file_size = 0;
    size_t position = 0;
    char path[64];
    printf("Thread count:\n");
    std::cin >> thread_count;
    printf("File path:\n");
    std::cin >> path;
    std::ifstream fi(path);

    if (fi.is_open())
        file_size = getFileLength(&fi);

    buffer = new uint8_t [file_size];
    encrypted = new uint8_t[file_size];
    decrypted = new uint8_t[file_size];

    // Read input
    fi.read(reinterpret_cast<char*>(buffer), file_size);
    buffer[file_size] = '\0';
#ifdef SMALL_MESSAGE
    printf("\nInput message:\n");
    print_array_codes(buffer, file_size);
    printf("%s\n", buffer);
#endif // SMALL_MESSAGE
    double start_time = clock();
    encrypted = ECBGOST(encrypted, 'E', key256, buffer, file_size);
    double end_time = clock();
    double search_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    printf("ENCRYPT takes: %lf\n", search_time);
#ifdef SMALL_MESSAGE
    printf("Encrypted message:\n");
    print_array_codes(encrypted, file_size);
    printf("%s\n", encrypted);
#endif // SMALL_MESSAGE
#ifdef ENCRYPT_IN_FILE
    std::ofstream fo("encryptedtomb.txt", std::ios::trunc);
    fo << encrypted;
    fo.close();
#endif // ENCRYPT_IN_FILE
#ifdef SMALL_MESSAGE
    printf("Decrypted message:\n");
    decrypted = ECBGOST(decrypted, 'D', key256, encrypted, file_size);
    print_array_codes(decrypted, file_size);
    printf("%s\n", decrypted);
#endif // SMALL_MESSAGE
#ifdef ENCRYPT_IN_FILE
    std::ofstream foo("decryptedtomb.txt", std::ios::trunc);
    foo << decrypted;
    foo.close();
#endif // ENCRYPT_IN_FILE

	return 0;
}