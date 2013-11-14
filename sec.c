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


uint8_t * clone_to_nbo(void *in, uint32_t len) {
	uint8_t *out = debugMallocReset(len, -300000);
	uint32_t i;

	if ( htonl(47) == 47 ) {
		memcpy(out, in, len);
	} else {
		for (i=0; i<len; i++)
			out[i] = ((uint8_t*)in)[len-i-1];
	}

	return out;
}

char key_path[MAX_PATH_SIZE] = DEF_KEY_PATH;


int32_t rsa_test(void) {

	// test with: ./bmx6 f=0 d=0 --keyDir=$(pwdd)/rsa-test/key.der

	{
		uint64_t tho = 0x0123456789abcdef;
		uint64_t tno = htobe64(tho);
		uint8_t *tp = clone_to_nbo(&tho, sizeof(tho));
		dbgf_sys(DBGT_INFO, "tno=%s tp=%s",
			memAsHexString(&tno, sizeof(tno)),
			memAsHexString(tp, sizeof(uint64_t)));
		debugFree(tp, -300000);
	}

	int    ret;
	RNG    rng;
#define FOURK_BUF 4096


	if ((ret = InitRng(&rng)) != 0)
		return FAILURE;

        RsaKey key;


	byte  der[FOURK_BUF];
	int   derSz = 0;
	FILE* keyFile;

	InitRsaKey(&key, 0);

	if (!(keyFile = fopen(key_path, "rb"))) {

		int keyBitSize = 512

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

		if ((derSz = RsaKeyToDer(&key, der, FOURK_BUF)) < 0) {
			dbgf_sys(DBGT_ERR, "Failed translating rsa key to der! derSz=%d", derSz)
			return FAILURE;
		}

		// read this with:
		//    dumpasn1 key.der
		//    note that all first INTEGER bytes are not zero (unlike with openssl certificates), but after conversion they are.
		// convert to pem with openssl:
		//    openssl rsa -in rsa-test/key.der -inform DER -out rsa-test/openssl.pem -outform PEM

		if (!(keyFile = fopen(key_path, "wb"))) {
			dbgf_sys(DBGT_ERR, "Failed writing %s! ret=%d", key_path, ret)
			return FAILURE;
		}

		if ((ret = (int)fwrite(der, 1, derSz, keyFile)) != derSz)
			return FAILURE;

		fclose(keyFile);
	}

	if (0) { //translate to pem:
		byte*  pem;
		int    pemSz = 0;
		FILE* pemFile;
		char tmp_path[MAX_PATH_SIZE] = "";

		if ((pem = (byte*)malloc(FOURK_BUF)) == NULL)
			return FAILURE;

		if((pemSz = DerToPem(der, derSz, pem, FOURK_BUF, PRIVATEKEY_TYPE)) < 0)
			return FAILURE;

		sprintf(tmp_path, "%s%s",key_path, ".pem");
		// read this with:
		//    cat key.pem
		// convert to pem with openssl:
		//    openssl rsa -in rsa-test/key.der.pem -inform PEM -out rsa-test/openssl.der -outform DER

		if (!(pemFile = fopen(tmp_path, "wb")))
			return FAILURE;

		ret = (int)fwrite(pem, 1, pemSz, pemFile);
		fclose(pemFile);

		free(pem);
	}

	FreeRsaKey(&key);


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

		uint8_t *nbo = clone_to_nbo((uint8_t*)key.n.dp, (key.n.used * sizeof(key.n.dp[0])));

		dbgf_sys(DBGT_INFO, "pub Key: alloc=%d sign=%d used=%d sizeof=%ld len=%ld bits=%ld N:\n%s",
			key.n.alloc, key.n.sign, key.n.used, sizeof(key.n.dp[0]), (key.n.used * sizeof(key.n.dp[0])), (key.n.used * sizeof(key.n.dp[0]))*8,
//			memAsHexStringSep( key.n.dp, (key.n.used * sizeof(key.n.dp[0])), 16, "\n")
			memAsHexStringSep( nbo, (key.n.used * sizeof(key.n.dp[0])), 8, "\n")
			);

		debugFree(nbo, -300000);

		dbgf_sys(DBGT_INFO, "alloc=%d sign=%d used=%d sizeof=%ld len=%ld E:\n%s",
			key.e.alloc, key.e.sign, key.e.used, sizeof(key.e.dp[0]), (key.e.used * sizeof(key.e.dp[0])),
			memAsHexStringSep( key.e.dp, (key.e.used * sizeof(key.e.dp[0])), 4, NULL));

		dbgf_sys(DBGT_INFO, "E=%ld", key.e.dp[0]);

	}


	{
		Cert  myCert;
		byte  derCert[FOURK_BUF];
		FILE* derFile;
		int   certSz;
		char  tmp_path[MAX_PATH_SIZE] = "";
		sprintf(tmp_path, "%s%s",key_path, ".cert");

		InitCert(&myCert);

		strncpy(myCert.subject.country, "US", CTC_NAME_SIZE);
		strncpy(myCert.subject.state, "OR", CTC_NAME_SIZE);
		strncpy(myCert.subject.locality, "Portland", CTC_NAME_SIZE);
		strncpy(myCert.subject.org, "yaSSL", CTC_NAME_SIZE);
		strncpy(myCert.subject.unit, "Development", CTC_NAME_SIZE);
		strncpy(myCert.subject.commonName, "www.yassl.com", CTC_NAME_SIZE);
		strncpy(myCert.subject.email, "info@yassl.com", CTC_NAME_SIZE);
		myCert.isCA    = 1;
		myCert.sigType = CTC_SHA256wRSA;

		if ((certSz = MakeSelfCert(&myCert, derCert, FOURK_BUF, &key, &rng)) < 0) {
			dbgf_sys(DBGT_ERR,"Failed creating cert %s, certSz=%d", tmp_path, certSz);
			return FAILURE;
		}


		if (!(derFile = fopen(tmp_path, "wb"))) {
			dbgf_sys(DBGT_ERR,"Failed opening %s", tmp_path);
			return FAILURE;
		}
		
		if ((ret = (int)fwrite(derCert, 1, certSz, derFile)) != certSz) {
			dbgf_sys(DBGT_ERR,"Failed writing %s", tmp_path);
			return FAILURE;
		}
		fclose(derFile);
	}
        FreeRsaKey(&key);

	{

		byte  derCert[FOURK_BUF];
		FILE* derFile;
		int   certSz;
		char  tmp_path[MAX_PATH_SIZE] = "";
		sprintf(tmp_path, "%s%s",key_path, ".cert");

		if (!(derFile = fopen(tmp_path, "rb"))) {
			dbgf_sys(DBGT_ERR,"Failed opening %s", tmp_path);
			return FAILURE;
		}

		if ((certSz = (int)fread(derCert, 1, sizeof(derCert), derFile)) <= 0) {
			dbgf_sys(DBGT_ERR,"Failed reading %s", tmp_path);
			return FAILURE;
		}
		fclose(derFile);

		DecodedCert decode;
		InitDecodedCert(&decode, derCert, certSz, 0);
		if ((ret = ParseCert(&decode, CERT_TYPE, NO_VERIFY, 0)) != 0) {
			dbgf_sys(DBGT_ERR,"Failed testing cert %s, ret=%d", tmp_path, ret);
			return FAILURE;
		}

		RsaKey key;
		InitRsaKey(&key, 0);
		word32 idx = 0;

		if((ret = RsaPublicKeyDecode(decode.publicKey, &idx, &key, decode.pubKeySize)) != 0 ) {
			dbgf_sys(DBGT_ERR,"Failed using cert %s, ret=%d", tmp_path, ret);
			return FAILURE;
		}

/*		dbgf_sys(DBGT_INFO, "certKey: alloc=%d sign=%d used=%d sizeof=%ld len=%ld bits=%ld N:\n%s",
			key.n.alloc, key.n.sign, key.n.used, sizeof(key.n.dp[0]), (key.n.used * sizeof(key.n.dp[0])), (key.n.used * sizeof(key.n.dp[0]))*8,
			memAsHexStringSep( key.n.dp, (key.n.used * sizeof(key.n.dp[0])), 16, "\n")
			//			memAsHexStringSep( nbo, (key.n.used * sizeof(key.n.dp[0])), 8, "\n")
			);
*/
		FreeDecodedCert(&decode);
		FreeRsaKey(&key);

//		CYASSL_CERT_MANAGER *cm = CyaSSL_CertManagerNew();
	}


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
