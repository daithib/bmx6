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

#define CRYPT_DER_BUF_SZ 4096

#define CRYPT_KEY_N_MIN 512
#define CRYPT_KEY_E_VAL 65537

#define CRYPT_SHA1_LEN 20

#define CRYPT_RSA512_TYPE  0
#define CRYPT_RSA512_LEN   64
#define CRYPT_RSA512_NAME  "RSA512"
#define CRYPT_RSA1024_TYPE 1
#define CRYPT_RSA1024_LEN  128
#define CRYPT_RSA1024_NAME "RSA1024"
#define CRYPT_RSA2048_TYPE 2
#define CRYPT_RSA2048_LEN  256
#define CRYPT_RSA2048_NAME "RSA2048"
#define CRYPT_RSA4096_TYPE 3
#define CRYPT_RSA4096_LEN  512
#define CRYPT_RSA4096_NAME "RSA4096"


typedef struct CRYPTSHA1_T {
	union {
		uint8_t u8[CRYPT_SHA1_LEN];
		uint32_t u32[CRYPT_SHA1_LEN/sizeof(uint32_t)];
	} h;
} CRYPTSHA1_T;


typedef struct CRYPTKEY_T {
    void *backendKey;
    uint16_t rawKeyLen;
    uint8_t nativeBackendKey;
    uint8_t rawKeyType;
    uint8_t *rawKey;
} CRYPTKEY_T;

extern const CRYPTKEY_T CYRYPTKEY_ZERO;

int cryptKeyMakeDer( int32_t keyBitSize, char *tmp_path );
CRYPTKEY_T *cryptKeyFromDer( char *tmp_path );
CRYPTKEY_T *cryptPubKeyFromRaw( uint8_t *rawKey, uint16_t rawKeyLen );
void cryptKeyFree( CRYPTKEY_T **key );

int cryptEncrypt( uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen, CRYPTKEY_T *pubKey);
int cryptDecrypt(uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen);
int cryptSign( uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen);
int cryptVerify(uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen, CRYPTKEY_T *pubKey);

void cryptRand( void *out, int32_t outLen);

void cryptShaAtomic( void *in, int32_t len, CRYPTSHA1_T *sha);
void cryptShaNew( void *in, int32_t len);
void cryptShaUpdate( void *in, int32_t len);
void cryptShaFinal( CRYPTSHA1_T *sha);

char *cryptShaAsString( CRYPTSHA1_T *sha);
char *cryptShaAsShortStr( CRYPTSHA1_T *sha);

int cryptKeyTypeByLen(int len);
int cryptKeyLenByType(int type);
char *cryptKeyTypeAsString(int type);



void init_crypt(void);
void cleanup_crypt(void);

