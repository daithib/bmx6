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


STATIC_FUNC
struct opt_type msg_options[]=
{
//       ord parent long_name             shrt Attributes                            *ival              min                 max                default              *func,*syntax,*help

#ifndef LESS_OPTIONS
        {ODI, 0, ARG_UDPD_SIZE,            0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &pref_udpd_size, MIN_UDPD_SIZE,      MAX_UDPD_SIZE,     DEF_UDPD_SIZE,0,      0,
			ARG_VALUE_FORM,	HLP_UDPD_SIZE}
        ,
	{ODI,0,ARG_FREF,                   0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &dextReferencing,MIN_FREF,           MAX_FREF,          DEF_FREF,0,           opt_update_dext_method,
			ARG_VALUE_FORM, HLP_FREF},
	{ODI,0,ARG_FZIP,                   0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &dextCompression,MIN_FZIP,           MAX_FZIP,          DEF_FZIP,0,           opt_update_dext_method,
			ARG_VALUE_FORM, HLP_FZIP},

	{ODI,0,ARG_DESC_FRAME_SIZE,         0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &desc_frame_size_out,MIN_DESC_FRAME_SIZE,MAX_DESC_FRAME_SIZE,DEF_DESC_FRAME_SIZE,0,opt_update_dext_method,
			ARG_VALUE_FORM, HLP_DESC_FRAME_SIZE},
	{ODI,0,ARG_VRT_FRAME_DATA_SIZE_OUT,0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &vrt_frame_data_size_out,MIN_VRT_FRAME_DATA_SIZE,MAX_VRT_FRAME_DATA_SIZE,DEF_VRT_FRAME_DATA_SIZE,0,  opt_update_dext_method,
			ARG_VALUE_FORM, HLP_VRT_FRAME_DATA_SIZE_OUT},
	{ODI,0,ARG_VRT_FRAME_DATA_SIZE_IN, 0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &vrt_frame_data_size_in,MIN_VRT_FRAME_DATA_SIZE,MAX_VRT_FRAME_DATA_SIZE,DEF_VRT_FRAME_DATA_SIZE,0,  opt_update_dext_method,
			ARG_VALUE_FORM, HLP_VRT_FRAME_DATA_SIZE_IN},
	{ODI,0,ARG_VRT_DESC_SIZE_OUT,      0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &vrt_desc_size_out,MIN_VRT_DESC_SIZE,MAX_VRT_DESC_SIZE,DEF_VRT_DESC_SIZE,0,   opt_update_dext_method,
			ARG_VALUE_FORM, HLP_VRT_DESC_SIZE_OUT},
	{ODI,0,ARG_VRT_DESC_SIZE_IN,       0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY,      &vrt_desc_size_in,MIN_VRT_DESC_SIZE,MAX_VRT_DESC_SIZE,DEF_VRT_DESC_SIZE,0,    opt_update_dext_method,
			ARG_VALUE_FORM, HLP_VRT_DESC_SIZE_IN},

        {ODI, 0, ARG_OGM_SQN_RANGE,        0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &ogmSqnRange,    MIN_OGM_SQN_RANGE,  MAX_OGM_SQN_RANGE, DEF_OGM_SQN_RANGE,0,  0,
			ARG_VALUE_FORM,	"set average OGM sequence number range (affects frequency of bmx6 description updates)"}
        ,
        {ODI, 0, ARG_OGM_TX_ITERS,         0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &ogm_adv_tx_iters,MIN_OGM_TX_ITERS,MAX_OGM_TX_ITERS,DEF_OGM_TX_ITERS,0,       0,
			ARG_VALUE_FORM,	"set maximum resend attempts for ogm aggregations"}
        ,
        {ODI, 0, ARG_UNSOLICITED_DESC_ADVS,0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &desc_adv_tx_unsolicited,MIN_UNSOLICITED_DESC_ADVS,MAX_UNSOLICITED_DESC_ADVS,DEF_DESC_ADV_UNSOLICITED,0,0,
			ARG_VALUE_FORM,	"send unsolicited description advertisements after receiving a new one"}
        ,
        {ODI, 0, ARG_DREF_ADV_UNSOLICITED, 0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &dref_adv_tx_unsolicited,MIN_DREF_ADV_UNSOLICITED,MAX_DREF_ADV_UNSOLICITED,DEF_DREF_ADV_UNSOLICITED,0,0,
			ARG_VALUE_FORM,	"send unsolicited description-reference advertisements after receiving a new one"}
        ,
        {ODI, 0, ARG_DSC0_REQS_TX_ITERS,   0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &desc_req_tx_iters,MIN_DSC0_REQS_TX_ITERS,MAX_DSC0_REQS_TX_ITERS,DEF_DESC_REQ_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for description requests"}
        ,
        {ODI, 0, ARG_DHS0_REQS_TX_ITERS,   0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &dhash_req_tx_iters,MIN_DHS0_REQS_TX_ITERS,MAX_DHS0_REQS_TX_ITERS,DEF_DHASH_REQ_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for description-hash requests"}
        ,
        {ODI, 0, ARG_DSC0_ADVS_TX_ITERS,   0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &desc_adv_tx_iters,MIN_DSC0_ADVS_TX_ITERS,MAX_DSC0_ADVS_TX_ITERS,DEF_DESC_ADV_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for descriptions"}
        ,
        {ODI, 0, ARG_DHS0_ADVS_TX_ITERS,   0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &dhash_adv_tx_iters,MIN_DHS0_ADVS_TX_ITERS,MAX_DHS0_ADVS_TX_ITERS,DEF_DHASH_ADV_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for description hashes"}
        ,
        {ODI, 0, ARG_OGM_ACK_TX_ITERS,     0,  9,0, A_PS1, A_ADM, A_DYI, A_CFA, A_ANY, &ogm_ack_tx_iters,MIN_OGM_ACK_TX_ITERS,MAX_OGM_ACK_TX_ITERS,DEF_OGM_ACK_TX_ITERS,0,0,
			ARG_VALUE_FORM,	"set tx iterations for ogm acknowledgements"}
        ,
#endif
	{ODI, 0, ARG_DESCRIPTIONS,	   0,  9,2, A_PS0N,A_USR, A_DYN, A_ARG, A_ANY, 0,               0,                  0,                 0,0,                  opt_show_descriptions,
			0,		HLP_DESCRIPTIONS}
        ,
	{ODI,ARG_DESCRIPTIONS,ARG_DESCRIPTION_TYPE,'t',9,2,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,0,	        MIN_DESCRIPTION_TYPE,MAX_DESCRIPTION_TYPE,DEF_DESCRIPTION_TYPE,0,opt_show_descriptions,
			"<TYPE>",	HLP_DESCRIPTION_TYPE}
        ,
	{ODI,ARG_DESCRIPTIONS,ARG_DESCRIPTION_NAME,'n',9,2,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,0,		0,	            0,                 0,0,                  opt_show_descriptions,
			"<NAME>",	"only show description of nodes with given name"}
        ,
	{ODI,ARG_DESCRIPTIONS,ARG_RELEVANCE,       'r',9,2,A_CS1,A_USR,A_DYN,A_ARG,A_ANY,0,	        MIN_RELEVANCE,	    MAX_RELEVANCE,     DEF_RELEVANCE,0,      opt_show_descriptions,
			ARG_VALUE_FORM,	HLP_ARG_RELEVANCE}
	,
	{ODI, 0, ARG_REFERENCES,	   0,  9,2, A_PS0N,A_USR, A_DYN, A_ARG, A_ANY, 0,               0,                  0,                 0,0,                  opt_status,
			0,		HLP_REFERENCES}


};


STATIC_FUNC
int32_t init_sec( void )
{

	register_options_array( msg_options, sizeof( msg_options ), CODE_CATEGORY_NAME );

        struct frame_handl handl;
        memset(&handl, 0, sizeof ( handl));


//      static const struct field_format ref_format[] = DESCRIPTION_MSG_REF_FORMAT;
        handl.name = "PUBKEY";
        handl.min_msg_size = sizeof (struct description_msg_pubkey);
        handl.fixed_msg_size = 0;
        handl.is_relevant = 0;
	handl.dextReferencing = &always_fref;
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
