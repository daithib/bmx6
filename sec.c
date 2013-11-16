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

#define CYASSL_KEY_GEN
#define CYASSL_TEST_CERT
#define CYASSL_CERT_GEN

#include <cyassl/ctaocrypt/settings.h>

/*
#include <cyassl/ctaocrypt/asn_public.h>
#include <cyassl/ctaocrypt/md2.h>
#include <cyassl/ctaocrypt/md5.h>
#include <cyassl/ctaocrypt/md4.h>
#include <cyassl/ctaocrypt/sha.h>
#include <cyassl/ctaocrypt/sha256.h>
#include <cyassl/ctaocrypt/sha512.h>
#include <cyassl/ctaocrypt/arc4.h>
#include <cyassl/ctaocrypt/random.h>
#include <cyassl/ctaocrypt/coding.h>
#include <cyassl/ctaocrypt/des3.h>
#include <cyassl/ctaocrypt/aes.h>
#include <cyassl/ctaocrypt/camellia.h>
#include <cyassl/ctaocrypt/hmac.h>
#include <cyassl/ctaocrypt/dh.h>
#include <cyassl/ctaocrypt/dsa.h>
#include <cyassl/ctaocrypt/hc128.h>
#include <cyassl/ctaocrypt/rabbit.h>
#include <cyassl/ctaocrypt/pwdbased.h>
#include <cyassl/ctaocrypt/ripemd.h>
*/

#include <cyassl/ctaocrypt/rsa.h>
#include <cyassl/ctaocrypt/asn_public.h>
#include <cyassl/ctaocrypt/asn.h>
#include <cyassl/ctaocrypt/ecc.h>


#include <cyassl/ssl.h>
//#include <cyassl/internal.h>


#include "bmx.h"
#include "msg.h"
#include "schedule.h"
#include "tools.h"
#include "plugin.h"
#include "sec.h"

#define CODE_CATEGORY_NAME "sec"

char key_path[MAX_PATH_SIZE] = DEF_KEY_PATH;

RNG    rng;

#define XKEY_N_MOD 256
#define XKEY_E_VAL 65537
#define XKEY_DP_SZ sizeof( mp_digit)
#define XDER_BUF_SZ 4096



#ifdef UNDEFINED
/* init a new mp_int */
int mp_init (mp_int * a)
{
  int i;

  /* allocate memory required and clear it */
  a->dp = OPT_CAST(mp_digit) XMALLOC (sizeof (mp_digit) * MP_PREC, 0,
                                      DYNAMIC_TYPE_BIGINT);
  if (a->dp == NULL) {
    return MP_MEM;
  }

  /* set the digits to zero */
  for (i = 0; i < MP_PREC; i++) {
      a->dp[i] = 0;
  }

  /* set the used to zero, allocated digits to the default precision
   * and sign to positive */
  a->used  = 0;
  a->alloc = MP_PREC;
  a->sign  = MP_ZPOS;

  return MP_OKAY;
}



/* reads a unsigned char array, assumes the msb is stored first [big endian] */
int mp_read_unsigned_bin (mp_int * a, const unsigned char *b, int c)
{
  int     res;

  /* make sure there are at least two digits */
  if (a->alloc < 2) {
     if ((res = mp_grow(a, 2)) != MP_OKAY) {
        return res;
     }
  }

  /* zero the int */
  mp_zero (a);

  /* read the bytes in */
  while (c-- > 0) {
    if ((res = mp_mul_2d (a, 8, a)) != MP_OKAY) {
      return res;
    }

#ifndef MP_8BIT
      a->dp[0] |= *b++;
      a->used += 1;
#else
      a->dp[0] = (*b & MP_MASK);
      a->dp[1] |= ((*b++ >> 7U) & 1);
      a->used += 2;
#endif
  }
  mp_clamp (a);
  return MP_OKAY;
}

static int GetInt(mp_int* mpi, const byte* input, word32* inOutIdx, word32 maxIdx)
{
    word32 i = *inOutIdx;
    byte   b = input[i++];
    int    length;

    if (b != ASN_INTEGER)
        return ASN_PARSE_E;

    if (GetLength(input, &i, &length, maxIdx) < 0)
        return ASN_PARSE_E;

    if ( (b = input[i++]) == 0x00)
        length--;
    else
        i--;

    if (mp_init(mpi) != MP_OKAY)
        return MP_INIT_E;

    if (mp_read_unsigned_bin(mpi, (byte*)input + i, length) != 0) {
        mp_clear(mpi);
        return ASN_GETINT_E;
    }

    *inOutIdx = i + length;
    return 0;
}


int RsaPublicKeyDecode2(const byte* input, word32* inOutIdx, RsaKey* key, word32 inSz)
{
    int    length;

    if (GetSequence(input, inOutIdx, &length, inSz) < 0)
        return ASN_PARSE_E;

    key->type = RSA_PUBLIC;

    if (GetInt(&key->n,  input, inOutIdx, inSz) < 0 ||
        GetInt(&key->e,  input, inOutIdx, inSz) < 0 )  return ASN_RSA_KEY_E;

    return 0;
}

#endif


STATIC_FUNC
int create_description_tlv_pubkey(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	uint32_t pubkey_len;
	
	byte tmp[2000];
	word32 idx=0;
	RsaKey key;
	InitRsaKey(&key, 0);
	RsaPublicKeyDecode(tmp, &idx, &key, sizeof(tmp));


	dbgf_track(DBGT_INFO, "added description rsa pubkey len=%d", pubkey_len);

	return (sizeof (struct description_msg_pubkey) + pubkey_len);
}

STATIC_FUNC
int process_description_tlv_pubkey(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        return it->frame_msgs_length;
}


STATIC_FUNC
int create_description_tlv_signature(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	uint32_t signature_len;

	dbgf_track(DBGT_INFO, "added description rsa pubkey len=%d", signature_len);

	return (sizeof (struct description_msg_pubkey) + signature_len);
}

STATIC_FUNC
int process_description_tlv_signature(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
        return it->frame_msgs_length;
}


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


uint8_t* bmx_cyassl_get_raw_pubKey(RsaKey *key, uint32_t *rawNLen) {

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

	return mp_int_get_raw(&key->n, rawNLen);
}

RsaKey *bmx_cyassl_get_pubKey( uint8_t *rawN, uint32_t rawNLen) {

	RsaKey *key = debugMalloc(sizeof(RsaKey), -300000);

	key->type = RSA_PUBLIC;

	key->e.dp = debugMallocReset(sizeof (mp_digit) * 4, -300000);
	key->e.dp[0] = XKEY_E_VAL;
	key->e.alloc = 4;
	key->e.used  = 1;
	key->e.sign  = MP_ZPOS;

	int used = mp_int_put_raw( &key->n, rawN, rawNLen );
	key->n.alloc = used;
	key->n.used  = used;
	key->n.sign  = MP_ZPOS;

	return key;
}


void bmx_cyassl_free_key( RsaKey *key ) {

	debugFree(key->n.dp, -300000);
	debugFree(key->e.dp, -300000);
	debugFree(key, -300000);
}

int32_t rsa_create( int keyBitSize ) {

	FILE* keyFile;

	if (!(keyFile = fopen(key_path, "rb"))) {

		RsaKey key;
		byte  der[XDER_BUF_SZ];
		int   derSz = 0;
		int ret;

		InitRsaKey(&key, 0);

		dbgf_sys(DBGT_INFO, "Creating new %d bit key to %s!", keyBitSize, key_path);

		if ((ret = MakeRsaKey(&key, keyBitSize, 65537, &rng)) != 0) {
			dbgf_sys(DBGT_ERR, "Failed making rsa key! ret=%d", ret)
			return FAILURE;
		}

		dbgf_sys(DBGT_INFO, "NEW Key: alloc=%d sign=%d used=%d sizeof=%ld len=%ld bits=%ld N:\n%s",
			key.n.alloc, key.n.sign, key.n.used, sizeof(key.n.dp[0]), (key.n.used * sizeof(key.n.dp[0])), (key.n.used * sizeof(key.n.dp[0]))*8,
			memAsHexStringSep( key.n.dp, (key.n.used * sizeof(key.n.dp[0])), 16, "\n")
//			memAsHexStringSep( nbo, (key.n.used * sizeof(key.n.dp[0])), 8, "\n")
			);

		if ((derSz = RsaKeyToDer(&key, der, XDER_BUF_SZ)) < 0) {
			dbgf_sys(DBGT_ERR, "Failed translating rsa key to der! derSz=%d", derSz)
			return FAILURE;
		}

		// read this with:
		//    dumpasn1 key.der
		//    note that all first INTEGER bytes are not zero (unlike with openssl certificates), but after conversion they are.
		// convert to pem with openssl:
		//    openssl rsa -in rsa-test/key.der -inform DER -out rsa-test/openssl.pem -outform PEM
		// extract public key with openssl:
		//    openssl rsa -in rsa-test/key.der -inform DER -pubout -out rsa-test/openssl.der.pub -outform DER

		if (!(keyFile = fopen(key_path, "wb"))) {
			dbgf_sys(DBGT_ERR, "Failed writing %s! ret=%d", key_path, ret)
			return FAILURE;
		}

		if ((ret = (int)fwrite(der, 1, derSz, keyFile)) != derSz)
			return FAILURE;

		FreeRsaKey(&key);
	}
	
	fclose(keyFile);

	return SUCCESS;
}

int32_t rsa_test(void) {

	// test with: ./bmx6 f=0 d=0 --keyDir=$(pwdd)/rsa-test/key.der

	int    ret;
	RsaKey key;

	byte  der[XDER_BUF_SZ];
	int   derSz = 0;
	FILE* keyFile;


	InitRsaKey(&key, 0);

	{
		word32 idx = 0;

		if (!(keyFile = fopen(key_path, "rb"))) {
			dbgf_sys(DBGT_ERR, "can not open %s: %s", key_path, strerror(errno));
			return FAILURE;
		}

		if(((derSz = (int)fread(der, 1, sizeof(der), keyFile)) <= 0) || derSz == sizeof(der)) {
			dbgf_sys(DBGT_ERR, "can not read %s: %s", key_path, strerror(errno));
			return FAILURE;
		} else {
			dbgf_sys(DBGT_INFO, "read %d bytes from %s", derSz, key_path);
		}

		fclose(keyFile);

		if ((ret = RsaPrivateKeyDecode(der, &idx, &key, derSz)) != 0) {
			dbgf_sys(DBGT_ERR, "can not decode %s: %d", key_path, ret);
			return FAILURE;
		}


		uint32_t pubRawLen = 0;
		uint8_t *pubRaw = bmx_cyassl_get_raw_pubKey(&key, &pubRawLen);
		RsaKey *pubKey = bmx_cyassl_get_pubKey(pubRaw, pubRawLen);

		assertion(-500000, !memcmp(key.n.dp, pubKey->n.dp, (key.n.used * sizeof(key.n.dp[0]))));


		byte   in[] = "Everyone gets Friday off.";
		word32 inLen = (word32)strlen((char*)in);
		byte   enc[256];
		int    encLen;
		byte   plain[256];

		int i, repetitions = 100;

		for (i=0; i<repetitions; i++) {

		memset(plain, 0, sizeof(plain));

		if ((encLen = RsaPublicEncrypt(in, inLen, enc, sizeof(enc), pubKey, &rng)) < 0) {
			dbgf_sys(DBGT_ERR, "Failed RsaPublicEncrypt");
			return FAILURE;
		} else {
			dbgf_track(DBGT_INFO, "Succeeded RsaPublicEncrypt inLen=%d outLen=%d inData=%s outData=%s",
				inLen, encLen, memAsHexString((char*)in, inLen), memAsHexString((char*)enc, encLen));
		}

		if ((ret = RsaPrivateDecrypt(enc, encLen, plain, sizeof(plain), &key)) < 0 || memcmp(plain, in, inLen)) {
			dbgf_sys(DBGT_ERR, "Failed RsaPrivateDecrypt");
			return FAILURE;
		} else {
			dbgf_track(DBGT_INFO, "Succeeded RsaPrivateDecrypt inLen=%d outLen=%d inData=%s outData=%s",
				encLen, ret, memAsHexString((char*)enc, encLen), memAsHexString((char*)plain, ret));
		}



		memset(plain, 0, sizeof(plain));

		if ((encLen = RsaSSL_Sign(in, inLen, enc, sizeof(enc), &key, &rng)) < 0) {
			dbgf_sys(DBGT_ERR, "Failed RsaSSL_Sign");
			return FAILURE;
		} else {
			dbgf_track(DBGT_INFO, "Succeeded RsaSSL_Sign inLen=%d outLen=%d inData=%s outData=%s",
				inLen, encLen, memAsHexString((char*)in, inLen), memAsHexString((char*)enc, encLen));
		}

		if ((ret = RsaSSL_Verify(enc, encLen, plain, sizeof(plain), pubKey)) < 0 || memcmp(plain, in, inLen)) {
			dbgf_sys(DBGT_ERR, "Failed RsaSSL_Verify");
			return FAILURE;
		} else {
			dbgf_track(DBGT_INFO, "Succeeded RsaSSL_Verify inLen=%d outLen=%d inData=%s outData=%s",
				encLen, ret, memAsHexString((char*)enc, encLen), memAsHexString((char*)plain, ret));
		}

		}


		debugFree(pubRaw, -300000);
		bmx_cyassl_free_key( pubKey );

	}


        FreeRsaKey(&key);

	cleanup_all(0);
	
	return SUCCESS;
}

STATIC_FUNC
int32_t opt_key_path(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	char tmp_path[MAX_PATH_SIZE] = "";

	if ( cmd == OPT_CHECK ) {

		if ( wordlen( patch->val )+1 >= MAX_PATH_SIZE  ||  patch->val[0] != '/' )
			return FAILURE;

		snprintf( tmp_path, wordlen(patch->val)+1, "%s", patch->val );

//		if ( check_file( tmp_path, YES/*regular*/,YES/*read*/, NO/*writable*/, NO/*executable*/ ) == FAILURE )
//			return FAILURE;

                strcpy(key_path, tmp_path);
		dbgf_sys(DBGT_INFO, "testing rsa crypto in %s=%s", ARG_KEY_PATH, key_path);

		if (rsa_create(1024) != SUCCESS)
			return FAILURE;
		
		return rsa_test();


	} else 	if ( cmd == OPT_SET_POST  &&  initializing ) {

//		if ( check_file( key_path, YES/*regular*/,YES/*read*/, NO/*writable*/, NO/*executable*/ ) == FAILURE )
//			return FAILURE;

        }

	return SUCCESS;
}


STATIC_FUNC
struct opt_type sec_options[]=
{
	{ODI,0,ARG_KEY_PATH,		0,  4,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_KEY_PATH,	opt_key_path,
			ARG_DIR_FORM,	"set path to rsa der-encoded private key file (used as permanent public ID"},

};


STATIC_FUNC
int32_t init_sec( void )
{
	if ((InitRng(&rng)) != 0)
		return FAILURE;

	register_options_array( sec_options, sizeof( sec_options ), CODE_CATEGORY_NAME );

        struct frame_handl handl;
        memset(&handl, 0, sizeof ( handl));


//      static const struct field_format ref_format[] = DESCRIPTION_MSG_REF_FORMAT;
        handl.name = "PUBKEY";
        handl.min_msg_size = sizeof (struct description_msg_pubkey);
        handl.fixed_msg_size = 0;
        handl.is_relevant = 0;
	handl.dextReferencing = (int32_t*)&always_fref;
        handl.tx_frame_handler = create_description_tlv_pubkey;
        handl.rx_frame_handler = process_description_tlv_pubkey;
//	handl.msg_format = ref_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_PUBKEY, &handl);

        handl.name = "SIGNATURE";
        handl.min_msg_size = sizeof (struct description_msg_signature);
        handl.fixed_msg_size = 0;
        handl.is_relevant = 0;
        handl.tx_frame_handler = create_description_tlv_signature;
        handl.rx_frame_handler = process_description_tlv_signature;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_SIGNATURE, &handl);

        return SUCCESS;
}

STATIC_FUNC
void cleanup_sec( void )
{
}


struct plugin *sec_get_plugin( void ) {

	static struct plugin sec_plugin;
	memset( &sec_plugin, 0, sizeof ( struct plugin ) );

	sec_plugin.plugin_name = CODE_CATEGORY_NAME;
	sec_plugin.plugin_size = sizeof ( struct plugin );
        sec_plugin.cb_init = init_sec;
	sec_plugin.cb_cleanup = cleanup_sec;

        return &sec_plugin;
}
