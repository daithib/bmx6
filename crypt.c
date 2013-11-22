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

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>

#include <unistd.h>
#include <errno.h>
#include <stdint.h>

#include "bmx.h"
#include "crypt.h"
#include "tools.h"
//#include "crypt.h"


const CRYPTKEY_T CYRYPTKEY_ZERO = { .nativeBackendKey=0, .backendKey=NULL, .rawKeyLen=0, .rawKey=NULL };

static uint8_t shaClean = NO;

/******************* accessing cyassl: ***************************************/
#if BMX6_CRYPTLIB == CYASSL

#define XKEY_DP_SZ sizeof( mp_digit)
#define XDER_BUF_SZ 4096


#define CYASSL_KEY_GEN
#define CYASSL_TEST_CERT
#define CYASSL_CERT_GEN

#include <cyassl/ctaocrypt/settings.h>
#include <cyassl/ctaocrypt/rsa.h>
#include <cyassl/ctaocrypt/asn_public.h>
#include <cyassl/ctaocrypt/asn.h>
#include <cyassl/ctaocrypt/ecc.h>
#include <cyassl/ssl.h>

RNG cryptRng;
Sha cryptSha;

STATIC_FUNC
void * clone_to_nbo(void *in, uint32_t len) {
	uint8_t *out;
	uint32_t i;

	if ( htonl(47) == 47 ) {
		out = in;
	} else {
		out = debugMallocReset(len, -300000);
		for (i=0; i<len; i++)
			out[i] = ((uint8_t*)in)[len-i-1];
	}

	return (void*)out;
}


STATIC_FUNC
uint8_t * mp_int_get_raw( mp_int *in, uint32_t *rawLen) {

	int s = XKEY_DP_SZ;
	int u = in->used;
	*rawLen = ( ( ((s*u*8)-((u)*4)) / XKEY_N_MOD ) * XKEY_N_MOD) / 8;
	int w = ((*rawLen*8) / ((s*8)-4)) + (((*rawLen*8) % ((s*8)-4)) ? 1 : 0);
	int zeros = (s*u)-(*rawLen);


	dbgf_sys(DBGT_INFO, "s=%d u=%d rawLen=%d w=%d zeros=%d", s, u, *rawLen, w, zeros );
	dbgf_sys(DBGT_INFO, " in:\n%s", memAsHexStringSep( in->dp, (u*s), 16, "\n"));

	assertion(-500000, (u == w));

	mp_digit *nbo = clone_to_nbo(in->dp, (u*s));
	mp_digit *tmp = debugMallocReset(u*s, -300000);

	int i = u-1; // i:= u-1 .. 0
	int r = 0;   // r:= 0 .. u-1
	while (i>=0) {
		if (s==8) {
			*((uint64_t*)(((uint8_t*)&(tmp[i]))+(r/2))) = nbo[i];
			if (i>=1)
				*((uint64_t*)(((uint8_t*)&(tmp[i-1]))+1+(r/2))) = htobe64( (be64toh(nbo[i-1])<<4) | (be64toh(nbo[i])>>((s-1)*8)));
		} else if (s==4) {
			*((uint32_t*)(((uint8_t*)&(tmp[i]))+(r/2))) = nbo[i];
			if (i>=1)
				*((uint32_t*)(((uint8_t*)&(tmp[i-1]))+1+(r/2))) = htobe32( (be32toh(nbo[i-1])<<4) | (be32toh(nbo[i])>>((s-1)*8)));
		} else {
			cleanup_all(-500000);
		}
		i-=2;
		r+=2;
	}

	if (nbo != in->dp)
		debugFree(nbo, -300000);

	uint8_t *begin = ((uint8_t*)tmp) + zeros;
	
	uint8_t *raw = debugMalloc(*rawLen, -300000);
	memcpy(raw, begin, *rawLen);
	
	dbgf_sys(DBGT_INFO, "raw:\n%s", memAsHexStringSep( raw, *rawLen, 16, "\n"));

	assertion(-500000, (*rawLen >= (XKEY_N_MOD/8))); // too small key!?
	assertion(-500000, (!is_zero( begin, 4))); // strange key with 4 leading octets!
	assertion(-500000, (is_zero(tmp, zeros)));

	debugFree(tmp, -300000);


	return raw;
}

STATIC_FUNC
int mp_int_put_raw( mp_int *out, uint8_t *raw, uint32_t rawLen) {

	int s = XKEY_DP_SZ;
	int u = ((rawLen*8) / ((s*8)-4)) + (((rawLen*8) % ((s*8)-4)) ? 1 : 0);
	int zeros = (s*u)-(rawLen);

	mp_digit *in  = debugMallocReset(u*s, -300000);
	memcpy( (((uint8_t*)in)+zeros), raw, rawLen );

	mp_digit *tmp = debugMallocReset(u*s, -300000);

	int i = u-1; // i:= u-1 .. 0
	int r = 0;   // r:= 0 .. u-1
	while (i>=0) {
		if (s==8) {
			tmp[i] = htobe64( ((be64toh( *((uint64_t*)(((uint8_t*)&(in[i]))+(r/2)))))<<4)>>4 );

			if (i>=1)
				tmp[i-1] = htobe64( (be64toh(*((uint64_t*)(((uint8_t*)&(in[i-1]))+1+(r/2)))))>>4);

		} else if (s==4) {

			tmp[i] = htobe32( ((be32toh( *((uint32_t*)(((uint8_t*)&(in[i]))+(r/2)))))<<4)>>4 );

			if (i>=1)
				tmp[i-1] = htobe32( (be32toh(*((uint32_t*)(((uint8_t*)&(in[i-1]))+1+(r/2)))))>>4);
			
		} else {
			cleanup_all(-500000);
		}
		i-=2;
		r+=2;
	}

	debugFree(in, -300000);
	dbgf_all(DBGT_INFO, "tmp:\n%s", memAsHexStringSep( tmp, (u*s), 16, "\n"));

	out->dp = clone_to_nbo(tmp, (u*s));

	dbgf_all(DBGT_INFO, "out:\n%s", memAsHexStringSep( out->dp, (u*s), 16, "\n"));

	if (out->dp != tmp)
		debugFree(tmp, -300000);

	return u;
}







void cryptKeyFree( CRYPTKEY_T *cryptKey ) {

	if (cryptKey->backendKey) {

		RsaKey *key = cryptKey->backendKey;

		if (cryptKey->nativeBackendKey) {
			FreeRsaKey(key);
		} else {
			debugFree(key->n.dp, -300000);
			debugFree(key->e.dp, -300000);
		}

		debugFree(cryptKey->backendKey, -300000);
	}

	if (cryptKey->rawKey) {
		debugFree(cryptKey->rawKey, -300000);
	}
	
	*cryptKey = CYRYPTKEY_ZERO;
}

void cryptKeyFromRaw( CRYPTKEY_T *cryptKey, uint8_t *rawKey, uint32_t rawKeyLen ) {

	assertion(-500000, (!cryptKey->backendKey && !cryptKey->rawKey));

	cryptKey->nativeBackendKey = 0;
	cryptKey->backendKey = debugMalloc(sizeof(RsaKey), -300000);
	RsaKey *key = cryptKey->backendKey;

	key->type = RSA_PUBLIC;

	key->e.dp = debugMallocReset(sizeof (mp_digit) * 4, -300000);
	key->e.dp[0] = XKEY_E_VAL;
	key->e.alloc = 4;
	key->e.used  = 1;
	key->e.sign  = MP_ZPOS;

	int used = mp_int_put_raw( &key->n, rawKey, rawKeyLen );
	key->n.alloc = used;
	key->n.used  = used;
	key->n.sign  = MP_ZPOS;

	cryptKey->rawKeyLen = rawKeyLen;
	cryptKey->rawKey = debugMalloc(rawKeyLen,-300000);
	memcpy(cryptKey->rawKey, rawKey, rawKeyLen);
}

STATIC_FUNC
void cryptKeyAddRaw( CRYPTKEY_T *cryptKey) {

	assertion(-500000, (cryptKey->backendKey && !cryptKey->rawKey));

	RsaKey *key = cryptKey->backendKey;
	int keyNLen = (key->n.used * XKEY_DP_SZ);
	int keyELen = (key->e.used * XKEY_DP_SZ);

	dbgf_sys(DBGT_INFO, "type=%d",key->type);
	dbgf_sys(DBGT_INFO, "pub N: alloc=%d sign=%d used=%d sizeof=%d len=%d bits=%d",
		key->n.alloc, key->n.sign, key->n.used, XKEY_DP_SZ, keyNLen, keyNLen*8 );

	dbgf_sys(DBGT_INFO, "pub E: alloc=%d sign=%d used=%d sizeof=%d len=%d bits=%d E:\n%s",
		key->e.alloc, key->e.sign, key->e.used, XKEY_DP_SZ, keyELen, keyELen*8,
		memAsHexStringSep( key->e.dp, keyELen, 4, NULL));

	dbgf_sys(DBGT_INFO, "E=%d", (uint32_t)key->e.dp[0]);

	assertion(-500000, (key->type == RSA_PUBLIC || key->type == RSA_PRIVATE));
	assertion(-500000, (key->e.dp[0] == XKEY_E_VAL));

	cryptKey->rawKeyLen = 0;
	cryptKey->rawKey = mp_int_get_raw(&key->n, &cryptKey->rawKeyLen);

	CRYPTKEY_T test = CYRYPTKEY_ZERO;
	cryptKeyFromRaw(&test, cryptKey->rawKey, cryptKey->rawKeyLen);
	assertion(-500000, !memcmp(((RsaKey*)(cryptKey->backendKey))->n.dp, ((RsaKey*)(test.backendKey))->n.dp, (((RsaKey*)(cryptKey->backendKey))->n.used * XKEY_DP_SZ)));
	cryptKeyFree(&test);
}


void cryptKeyMake( CRYPTKEY_T *cryptKey, int32_t keyBitSize ) {

	assertion(-500000, (!cryptKey->backendKey && !cryptKey->rawKey));

	cryptKey->backendKey = debugMalloc(sizeof(RsaKey), -300000);

	RsaKey *key = cryptKey->backendKey;
	int ret;

	cryptKey->nativeBackendKey = 1;

	InitRsaKey(key, 0);

	if ((ret = MakeRsaKey(key, keyBitSize, XKEY_E_VAL, &cryptRng)) != 0) {
		dbgf_sys(DBGT_ERR, "Failed making rsa key! ret=%d", ret);
		cleanup_all(-500000);
	}

	dbgf_sys(DBGT_INFO, "NEW Key: alloc=%d sign=%d used=%d sizeof=%ld len=%ld bits=%ld N:\n%s",
		key->n.alloc, key->n.sign, key->n.used, XKEY_DP_SZ, (key->n.used * XKEY_DP_SZ), (key->n.used * XKEY_DP_SZ)*8,
		memAsHexStringSep( key->n.dp, (key->n.used * XKEY_DP_SZ), 16, "\n")
		);

	cryptKeyAddRaw(cryptKey);
}

void cryptKeyToDer( CRYPTKEY_T *cryptKey, uint8_t *der, int32_t *derSz ) {

	RsaKey *key = cryptKey->backendKey;

	if ((*derSz = RsaKeyToDer(key, der, *derSz)) < 0) {
		dbgf_sys(DBGT_ERR, "Failed translating rsa key to der! derSz=%d", derSz)
		cleanup_all(-500000);
	}

	// read this with:
	//    dumpasn1 key.der
	//    note that all first INTEGER bytes are not zero (unlike with openssl certificates), but after conversion they are.
	// convert to pem with openssl:
	//    openssl rsa -in rsa-test/key.der -inform DER -out rsa-test/openssl.pem -outform PEM
	// extract public key with openssl:
	//    openssl rsa -in rsa-test/key.der -inform DER -pubout -out rsa-test/openssl.der.pub -outform DER
}

void cryptKeyFromDer( CRYPTKEY_T *cryptKey, uint8_t *der, int32_t derSz ) {

	assertion(-500000, (!cryptKey->backendKey && !cryptKey->rawKey));

	cryptKey->backendKey = debugMalloc(sizeof(RsaKey), -300000);

	RsaKey *key = cryptKey->backendKey;
	int    ret;
	word32 idx = 0;

	cryptKey->nativeBackendKey = 1;

	InitRsaKey(key, 0);

	if ((ret = RsaPrivateKeyDecode(der, &idx, key, derSz)) != 0) {
		dbgf_sys(DBGT_ERR, "can not decode ret=%d", ret);
		cleanup_all(-500000);
	}

	cryptKeyAddRaw(cryptKey);
}



int cryptEncrypt( uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen, CRYPTKEY_T *pubKey) {

	RsaKey *key = pubKey->backendKey;

	if ((*outLen = RsaPublicEncrypt(in, inLen, out, *outLen, key, &cryptRng)) < 0)
		return FAILURE;
	else
		return SUCCESS;
}

int cryptDecrypt(uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen, CRYPTKEY_T *privKey) {

	RsaKey *key = privKey->backendKey;

	if ((*outLen = RsaPrivateDecrypt(in, inLen, out, *outLen, key)) < 0)
		return FAILURE;
	else
		return SUCCESS;
}

int cryptSign( uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen, CRYPTKEY_T *privKey) {

	RsaKey *key = privKey->backendKey;

	if ((*outLen = RsaSSL_Sign(in, inLen, out, *outLen, key, &cryptRng)) < 0)
		return FAILURE;
	else
		return SUCCESS;
}

int cryptVerify(uint8_t *in, int32_t inLen, uint8_t *out, int32_t *outLen, CRYPTKEY_T *pubKey) {

	RsaKey *key = pubKey->backendKey;

	if ((*outLen = RsaSSL_Verify(in, inLen, out, *outLen, key)) < 0)
		return FAILURE;
	else
		return SUCCESS;
}

STATIC_FUNC
void cryptRngInit( void ) {

	if ((InitRng(&cryptRng)) != 0)
		cleanup_all(-500525);
}

STATIC_FUNC
void cryptRngFree( void ) {
}

void cryptRand( void *out, int32_t outLen) {
	RNG_GenerateBlock(&cryptRng, (byte*)out, outLen);
}


STATIC_FUNC
void cryptShaInit( void ) {
	InitSha(&cryptSha);
	shaClean = YES;
}

STATIC_FUNC
void cryptShaFree( void ) {
}

void cryptShaAtomic( void *in, int32_t len, CRYPTSHA1_T *sha) {
	assertion(-500000, (shaClean==YES));
	ShaUpdate(&cryptSha, (byte*) in, len);
	ShaFinal(&cryptSha, (byte*) sha);
}

void cryptShaNew( void *in, int32_t len) {
	assertion(-500000, (shaClean==YES));
	shaClean = NO;
	ShaUpdate(&cryptSha, (byte*) in, len);
}

void cryptShaUpdate( void *in, int32_t len) {
	assertion(-500000, (shaClean==NO));
	ShaUpdate(&cryptSha, (byte*)in, len);
}

void cryptShaFinal( CRYPTSHA1_T *sha) {
	assertion(-500000, (shaClean==NO));
	ShaFinal(&cryptSha, (byte*) sha);
	shaClean = YES;
}

/******************* accessing polarssl: *************************************/
#elif BMX6_CRYPTLIB == POLARSSL



/*****************************************************************************/
#else
# error "Please fix crypto lib"
#endif



void init_crypt(void) {
	
	cryptRngInit();
	cryptShaInit();
}

void cleanup_crypt(void) {

	cryptRngFree();
	cryptShaFree();
}
