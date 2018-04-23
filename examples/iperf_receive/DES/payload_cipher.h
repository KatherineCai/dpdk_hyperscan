#ifndef PAYLOAD_CIPHER_H
#define PAYLOAD_CIPHER_H

#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include "cipher.h"


/*
 * The size of encrypted payload is 8*16
 */
#define CIPHER_SIZE 8
#define GROUPS		16

void initKeyTable();
void encrypt_payload(uint8_t *payload, uint8_t *userID, uint8_t *ciphertext);
void decrypt_payload(uint8_t *payload, uint8_t *userID, uint8_t *ciphertext);

#endif
