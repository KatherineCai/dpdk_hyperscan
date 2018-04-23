#include "payload_cipher.h"

char * keyTableBase;

void initKeyTable()
{
	long long seed_l = INIT_SEED; 
	keyTableBase = (char*)calloc(TABLE_SIZE, sizeof(long long));
	des_key_init(keyTableBase, TABLE_SIZE, seed_l);
}


void encrypt(uint8_t *plain, long long key, uint8_t *ciphertext)
{
	own_encrypt(plain, ciphertext, key);
}

void decrypt(uint8_t *plain, long long key, uint8_t *cipher)
{
	own_decrypt(cipher, plain, key);
}


void encrypt_payload(uint8_t *payload, uint8_t *userID, uint8_t *ciphertext)
{
    int i;
    uint8_t plain[CIPHER_SIZE];
	long long key;

	get_key_from_userID(userID, &key, keyTableBase);
    for (i=0; i<GROUPS; i++) {
        memcpy(plain, payload + i*CIPHER_SIZE, CIPHER_SIZE); 
        encrypt(plain, key, ciphertext + i*CIPHER_SIZE);
    }
}

void decrypt_payload(uint8_t *payload, uint8_t *userID, uint8_t *ciphertext)
{
    int i;
    uint8_t cipher[CIPHER_SIZE];
	long long key;

	get_key_from_userID(userID, &key, keyTableBase);
    for (i=0; i<GROUPS; i++) {
        memcpy(cipher, ciphertext + i*CIPHER_SIZE, CIPHER_SIZE); 
        decrypt(payload + i*CIPHER_SIZE, key, cipher);
    }
}
