/*
 * Copyright (c) 2010  Axel Neumann
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

/*
 * Alternative cryptographic libraries are:
 * libtomcrypt and gcrypt
 */

#define BMX6_CRYPTLIB CYASSL
//#define BMX6_CRYPTLIB POLARSSL

#define XKEY_N_MOD 256
#define XKEY_E_VAL 65537


typedef struct CRYPTKEY_T {
    uint8_t nativeBackendKey;
    void *backendKey;
    uint32_t rawKeyLen;
    uint8_t *rawKey;
} CRYPTKEY_T;



void cryptKeyMake( CRYPTKEY_T *key, int32_t keyBitSize );
void cryptKeyFromDer( CRYPTKEY_T *key, uint8_t *der, int32_t derSz);
void cryptKeyFromRaw( CRYPTKEY_T *cryptKey, uint8_t *rawKey, uint32_t rawKeyLen );
void cryptKeyToDer( CRYPTKEY_T *cryptKey, uint8_t *der, int32_t *derSz );

void cryptKeyFree( CRYPTKEY_T *key );

int cryptEncrypt( uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen, CRYPTKEY_T *pubKey);
int cryptDecrypt(uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen, CRYPTKEY_T *privKey);
int cryptSign( uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen, CRYPTKEY_T *privKey);
int cryptVerify(uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen, CRYPTKEY_T *pubKey);

void init_crypt(void);
void cleanup_crypt(void);

