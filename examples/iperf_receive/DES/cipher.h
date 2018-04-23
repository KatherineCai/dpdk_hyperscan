#ifndef CIPHER_H
#define CIPHER_H

int des_key_init(char* keyTableBase, int keyTableSize, long long initSeed);
int get_key_from_userID(char* userID,long long* key,char* keyTableBase);
int own_encrypt(char* strIn, char* strOut, long long key);
int own_decrypt(char* strIn, char* strOut, long long key);

#define INIT_SEED 0x5555555555555557
#define TABLE_SIZE (1024*16) 

#define TEST_USERID {(char)(0x00), (char)(0x00), (char)(0x00), (char)(0x00),  \
                     (char)(0x00), (char)(0x00), (char)(0x00), (char)(0x0f),  \
                     (char)(0x00), (char)(0x00), (char)(0x00), (char)(0x00),  \
                     (char)(0x00), (char)(0x00), (char)(0x00), (char)(0x10)};

#define TEST_DATA   {(char)(0x11), (char)(0x00), (char)(0x00), (char)(0x00),  \
                     (char)(0x00), (char)(0x00), (char)(0x00), (char)(0x00)};
#define ENCRYPT 0x00001234
#endif
