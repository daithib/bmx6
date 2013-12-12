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


#include "list.h"
#include "control.h"
#include "bmx.h"
#include "crypt.h"
#include "avl.h"
#include "node.h"
#include "metrics.h"
#include "msg.h"
//#include "schedule.h"
#include "tools.h"
#include "plugin.h"
#include "sec.h"
//#include "ip.h"

#define CODE_CATEGORY_NAME "sec"

char key_path[MAX_PATH_SIZE] = DEF_KEY_PATH;






STATIC_FUNC
int create_description_tlv_pubkey(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	assertion(-500000, (my_PubKey));

        if ((int)(sizeof(struct dsc_msg_pubkey) + my_PubKey->rawKeyLen) > tx_iterator_cache_data_space_pref(it))
		return TLV_TX_DATA_FULL;

	struct dsc_msg_pubkey *msg = ((struct dsc_msg_pubkey*) tx_iterator_cache_msg_ptr(it));

	msg->type = my_PubKey->rawKeyType;

	memcpy(msg->key, my_PubKey->rawKey, my_PubKey->rawKeyLen);
	dbgf_track(DBGT_INFO, "added description rsa pubkey len=%d", my_PubKey->rawKeyLen);

	return (sizeof(struct dsc_msg_pubkey) + my_PubKey->rawKeyLen);
}

STATIC_FUNC
int process_description_tlv_pubkey(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

//	return TLV_RX_DATA_IGNORED;

	char *goto_error_code = NULL;
	
	if (it->op != TLV_OP_TEST 
#ifdef EXTREME_PARANOIA
		&& it->op != TLV_OP_NEW
#endif
		)
		return it->frame_data_length;

	int32_t key_len = it->frame_data_length - sizeof(struct dsc_msg_pubkey);
	struct dsc_msg_pubkey *msg = (struct dsc_msg_pubkey*)(it->frame_data);

	if ( !cryptKeyTypeAsString(msg->type) || cryptKeyLenByType(msg->type) != key_len )
		goto_error( finish, "1");

finish: {
	dbgf_sys(goto_error_code?DBGT_ERR:DBGT_INFO, 
		"%s %s verifying msg_type=%s msg_key_len=%d == key_len=%d problem?=%s",
		tlv_op_str(it->op), goto_error_code?"Failed":"Succeeded", cryptKeyTypeAsString(msg->type),
		cryptKeyLenByType(msg->type), key_len, goto_error_code);

	if (goto_error_code)
		return TLV_RX_DATA_FAILURE;
	else
		return it->frame_data_length;
}
}

STATIC_FUNC
int create_description_tlv_signature(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	int32_t keySpace = tx_iterator_cache_data_space_pref(it) - sizeof(struct dsc_msg_signature);

	if (keySpace < my_PubKey->rawKeyLen)
		return TLV_TX_DATA_FULL;

	uint8_t *sign_start = it->frames_out_ptr - sizeof (struct description);
	uint32_t sign_len = sizeof (struct description) + it->frames_out_pos;

	struct dsc_msg_signature *msg = (struct dsc_msg_signature*) tx_iterator_cache_msg_ptr(it);

	msg->type = my_PubKey->rawKeyType;

	CRYPTSHA1_T sha;
	cryptShaAtomic(sign_start, sign_len, &sha);

	cryptSign((uint8_t*)&sha, sizeof(sha), msg->signature, &keySpace);

	dbgf_sys(DBGT_INFO, "added len=%d description rsa-%d signature over hash=%s over len=%d bytes desc.name=%s", 
		(sizeof(struct dsc_msg_signature) + keySpace), (keySpace*8), memAsHexString(&sha, sizeof(sha)),
		sign_len, ((struct description*)sign_start)->globalId.name );

	assertion(-500000, (keySpace == my_PubKey->rawKeyLen));

	return (sizeof(struct dsc_msg_signature) + keySpace);
}

STATIC_FUNC
int process_description_tlv_signature(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	return TLV_RX_DATA_IGNORED;
	
	assertion(-500000, (it->frame_data_length == it->frame_msgs_length && it->frame_data == it->msg));

	if (it->op != TLV_OP_TEST 
#ifdef EXTREME_PARANOIA
		&& it->op != TLV_OP_NEW
#endif	
		)
		return it->frame_data_length;

	char *goto_error_code = NULL;
	int32_t sign_len = it->frame_data_length - sizeof(struct dsc_msg_signature);
	struct dsc_msg_signature *msg = (struct dsc_msg_signature*)(it->frame_data);
	uint8_t *desc_start = (uint8_t*)it->desc;
	int32_t desc_len = it->desc_len - (sizeof(struct tlv_hdr) + it->frame_data_length);
	CRYPTSHA1_T desc_sha;
	CRYPTKEY_T *pkey = NULL;
	
	if ( !cryptKeyTypeAsString(msg->type) || cryptKeyLenByType(msg->type) != sign_len || desc_len < (int)sizeof(struct description))
		goto_error( finish, "1");

	cryptShaAtomic(desc_start, desc_len, &desc_sha);
	
	uint8_t *pkey_frame_data;
	int32_t pkey_len = get_desc_frame_data(&pkey_frame_data, it->frames_in, it->frames_length, BMX_DSC_TLV_PUBKEY) - sizeof(struct dsc_msg_pubkey);

	if (pkey_len != sign_len)
		goto_error( finish, "2");

	pkey = cryptPubKeyFromRaw(((struct dsc_msg_pubkey*)pkey_frame_data)->key, pkey_len);
	
	CRYPTSHA1_T plain_sha;
	int32_t plain_len = sizeof(plain_sha);

	if (cryptVerify(msg->signature, sign_len, (uint8_t*)&plain_sha, &plain_len, pkey) != SUCCESS )
		goto_error( finish, "3");
	
	if (plain_len != sizeof(desc_sha) || memcmp(&plain_sha, &desc_sha, sizeof(desc_sha)))
		goto_error( finish, "4");
	
finish: {
	dbgf_sys(goto_error_code?DBGT_ERR:DBGT_INFO, 
		"%s %s verifying  desc_len=%d desc_sha=%s \n"
		"signature=%s\n"
		"sign_type=%s sign_type_len=%d == sign_len=%d == pkey_len=%d pkey=%s \n"
		"plain_len=%d==%d plain_sha=%s problem?=%s",
		tlv_op_str(it->op), goto_error_code?"Failed":"Succeeded", desc_len, memAsHexString(&desc_sha, sizeof(desc_sha)),
		memAsHexString(msg->signature, sign_len), cryptKeyTypeAsString(msg->type), cryptKeyLenByType(msg->type), 
		sign_len, pkey_len, pkey ? memAsHexString(pkey->rawKey, pkey->rawKeyLen) : "---",
		plain_len, sizeof(plain_sha), memAsHexString(&plain_sha, sizeof(plain_sha)), goto_error_code);
}	
	cryptKeyFree(&pkey);
	
	if (goto_error_code)
		return TLV_RX_DATA_FAILURE;
	else
		return it->frame_data_length;
}

STATIC_FUNC
int create_description_tlv_sha(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	struct dsc_msg_sha *msg = ((struct dsc_msg_sha*) tx_iterator_cache_msg_ptr(it));

	msg->expInLen = htonl(it->dext->dlen);
	cryptShaAtomic(it->dext->data, it->dext->dlen, &msg->expInSha);

	dbgf_sys(DBGT_INFO, "added description expInlen=%d expInsha=%s expIn=%s", 
		ntohl(msg->expInLen), memAsHexString(&msg->expInSha, sizeof(SHA1_T)), memAsHexString(it->dext->data, it->dext->dlen));

	return sizeof(struct dsc_msg_sha);
}

STATIC_FUNC
int process_description_tlv_sha(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

//	return TLV_RX_DATA_IGNORED;
	
	if (it->op != TLV_OP_TEST 
#ifdef EXTREME_PARANOIA
		&& it->op != TLV_OP_NEW
#endif	
		)
		return it->frame_data_length;

	char *goto_error_code = NULL;
	struct dsc_msg_sha *msg = ((struct dsc_msg_sha*) it->frame_data);
	int32_t expInLen = (int32_t)(((uint8_t*)it->frame_hdr) - it->frames_in);
	
	assertion(-500000, (expInLen>0));
	
	if( (int)ntohl(msg->expInLen) != expInLen )
		goto_error(finish, "1");

	SHA1_T expInSha;
	cryptShaAtomic(it->frames_in, expInLen, &expInSha);
	
	if (memcmp(&msg->expInSha, &expInSha, sizeof(SHA1_T)))
		goto_error(finish, "2"); 

finish: {
	dbgf_sys(goto_error_code?DBGT_ERR:DBGT_INFO, 
		"%s %s verifying  expInLen=%d == msg.expInLen=%d expInSha=%s == msg.expInSha=%s  problem?=%s expIn=%s",
		tlv_op_str(it->op), goto_error_code?"Failed":"Succeeded", expInLen, ntohl(msg->expInLen), 
		memAsHexString(&expInSha, sizeof(expInSha)), memAsHexString(&msg->expInSha, sizeof(expInSha)),
		goto_error_code, memAsHexString(it->frames_in, expInLen) );

	if (goto_error_code)
		return TLV_RX_DATA_FAILURE;
	else
		return it->frame_data_length;
}
}

int32_t rsa_create( char *tmp_path, uint16_t keyBitSize ) {

	FILE* keyFile;

	if (!(keyFile = fopen(tmp_path, "rb"))) {

		if (cryptKeyMakeDer(keyBitSize, tmp_path) != SUCCESS) {
			dbgf_sys(DBGT_ERR, "Failed creating new %d bit key to %s!", keyBitSize, tmp_path);
			return FAILURE;
		}

	} else {
		fclose(keyFile);
	}

	return SUCCESS;
}

int32_t rsa_load( char *tmp_path ) {

	// test with: ./bmx6 f=0 d=0 --keyDir=$(pwdd)/rsa-test/key.der


	dbgf_sys(DBGT_INFO, "testing %s=%s", ARG_KEY_PATH, tmp_path);

	if (!(my_PubKey = cryptKeyFromDer( tmp_path ))) {
		return FAILURE;
	}

	uint8_t in[] = "Everyone gets Friday off.";
	int32_t inLen = strlen((char*)in);
	uint8_t enc[256];
	int32_t encLen;
	uint8_t plain[256];
	int32_t plainLen;

	encLen = sizeof(enc);
	plainLen = sizeof(plain);
	memset(plain, 0, sizeof(plain));

	if (cryptEncrypt(in, inLen, enc, &encLen, my_PubKey) != SUCCESS) {
		dbgf_sys(DBGT_ERR, "Failed Encrypt inLen=%d outLen=%d inData=%s outData=%s",
			inLen, encLen, memAsHexString((char*)in, inLen), memAsHexString((char*)enc, encLen));
		return FAILURE;
	}

	if (cryptDecrypt(enc, encLen, plain, &plainLen) != SUCCESS ||
		inLen != plainLen || memcmp(plain, in, inLen)) {
		dbgf_sys(DBGT_ERR, "Failed Decrypt inLen=%d outLen=%d inData=%s outData=%s",
			encLen, plainLen, memAsHexString((char*)enc, encLen), memAsHexString((char*)plain, plainLen));
		return FAILURE;
	}



	encLen = sizeof(enc);
	plainLen = sizeof(plain);
	memset(plain, 0, sizeof(plain));

	if (cryptSign(in, inLen, enc, &encLen) != SUCCESS) {
		dbgf_sys(DBGT_ERR, "Failed Sign inLen=%d outLen=%d inData=%s outData=%s",
			inLen, encLen, memAsHexString((char*)in, inLen), memAsHexString((char*)enc, encLen));
		return FAILURE;
	}

	if (cryptVerify(enc, encLen, plain, &plainLen, my_PubKey) != SUCCESS ||
		inLen != plainLen || memcmp(plain, in, inLen)) {
		dbgf_sys(DBGT_ERR, "Failed Verify inLen=%d outLen=%d inData=%s outData=%s",
			encLen, plainLen, memAsHexString((char*)enc, encLen), memAsHexString((char*)plain, plainLen));
		return FAILURE;
	}

	
	return SUCCESS;
}

STATIC_FUNC
int32_t opt_key_path(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	char tmp_path[MAX_PATH_SIZE] = "";
	static uint8_t checked = NO;

	if ( (cmd == OPT_CHECK || cmd == OPT_SET_POST) && initializing && !checked ) {

		if (cmd == OPT_CHECK) {
			if ( wordlen( patch->val )+1 >= MAX_PATH_SIZE  ||  patch->val[0] != '/' )
				return FAILURE;

			snprintf( tmp_path, wordlen(patch->val)+1, "%s", patch->val );
		} else {
			strcpy( tmp_path, key_path );
		}

		char *slash = strrchr(tmp_path, '/');
		if (slash) {
			*slash = 0;
			if ( check_dir( tmp_path, YES, YES) == FAILURE ) {
				dbgf_sys(DBGT_ERR, "dir=%s does not exist and can not be created!", tmp_path);
				return FAILURE;
			}
			*slash = '/';
		}

		if ( check_file( tmp_path, YES/*regular*/,YES/*read*/, NO/*writable*/, NO/*executable*/ ) == FAILURE ) {
			if (rsa_create(tmp_path, 1024) != SUCCESS) {
				dbgf_sys(DBGT_ERR, "key=%s does not exist and can not be created!", tmp_path);
				return FAILURE;
			}
		}

		if (rsa_load( tmp_path ) == SUCCESS ) {
			dbgf_sys(DBGT_INFO, "Successfully initialized %d bit RSA key=%s !", (my_PubKey->rawKeyLen * 8), tmp_path);
		} else {
			dbgf_sys(DBGT_ERR, "key=%s invalid!", tmp_path);
			return FAILURE;
		}



		strcpy(key_path, tmp_path);

		checked = YES;

        }

	return SUCCESS;
}


STATIC_FUNC
struct opt_type sec_options[]=
{
//order must be before ARG_HOSTNAME (which initializes self via init_self):
	{ODI,0,ARG_KEY_PATH,		0,  4,1,A_PS1,A_ADM,A_INI,A_CFA,A_ANY,	0,		0,		0,		0,DEF_KEY_PATH,	opt_key_path,
			ARG_DIR_FORM,	"set path to rsa der-encoded private key file (used as permanent public ID"},

};


STATIC_FUNC
int32_t init_sec( void )
{
	register_options_array( sec_options, sizeof( sec_options ), CODE_CATEGORY_NAME );

        struct frame_handl handl;
        memset(&handl, 0, sizeof ( handl));

	static const struct field_format pubkey_format[] = DESCRIPTION_MSG_PUBKEY_FORMAT;
        handl.name = "PUBKEY";
        handl.min_msg_size = sizeof(struct dsc_msg_pubkey);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&always_fref;
        handl.tx_frame_handler = create_description_tlv_pubkey;
        handl.rx_frame_handler = process_description_tlv_pubkey;
	handl.msg_format = pubkey_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_PUBKEY, &handl);

	static const struct field_format sha_format[] = DESCRIPTION_MSG_SHA_FORMAT;
        handl.name = "EXP_SHA";
        handl.min_msg_size = sizeof(struct dsc_msg_sha);
        handl.fixed_msg_size = 1;
        handl.tx_frame_handler = create_description_tlv_sha;
        handl.rx_frame_handler = process_description_tlv_sha;
	handl.msg_format = sha_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_SHA, &handl);

	static const struct field_format signature_format[] = DESCRIPTION_MSG_SIGNATURE_FORMAT;
        handl.name = "SIGNATURE";
        handl.min_msg_size = sizeof(struct dsc_msg_signature);
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = create_description_tlv_signature;
        handl.rx_frame_handler = process_description_tlv_signature;
	handl.msg_format = signature_format;
        register_frame_handler(description_tlv_handl, BMX_DSC_TLV_SIGNATURE, &handl);

        return SUCCESS;
}

STATIC_FUNC
void cleanup_sec( void )
{
        cryptKeyFree(&my_PubKey);

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
