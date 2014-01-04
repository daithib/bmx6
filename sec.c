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


static int32_t descVerification = DEF_DESC_VERIFY;




STATIC_FUNC
int create_dsc_tlv_pubkey(struct tx_frame_iterator *it)
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
int process_dsc_tlv_pubkey(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

//	return TLV_RX_DATA_IGNORED;

	char *goto_error_code = NULL;
	
	if (it->op != TLV_OP_TEST )
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
int create_dsc_tlv_signature(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	static struct dsc_msg_signature *desc_msg = NULL;
	static int32_t dataOffset = 0;

	if (it->frame_type==BMX_DSC_TLV_SIGNATURE) {

		assertion(-500000, (!desc_msg && !dataOffset));

		desc_msg = (struct dsc_msg_signature*) (it->frames_out_ptr + it->frames_out_pos + sizeof(struct tlv_hdr));

		dataOffset = it->frames_out_pos + sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_signature) + my_PubKey->rawKeyLen;

		return sizeof(struct dsc_msg_signature) + my_PubKey->rawKeyLen;

	} else {
		assertion(-500000, (it->frame_type == BMX_DSC_TLV_SIGNATURE_DUMMY));
		assertion(-500000, (desc_msg && dataOffset));
		assertion(-500000, (it->frames_out_pos > dataOffset));
		assertion(-500000, (dext_dptr(it->dext, BMX_DSC_TLV_SIGNATURE)));

		int32_t dataLen = it->frames_out_pos - dataOffset;
		uint8_t *data = it->frames_out_ptr + dataOffset;

		CRYPTSHA1_T dataSha;
		cryptShaAtomic(data, dataLen, &dataSha);
		int32_t keySpace = my_PubKey->rawKeyLen;

		struct dsc_msg_signature *dext_msg = dext_dptr(it->dext, BMX_DSC_TLV_SIGNATURE);

		dext_msg->type = my_PubKey->rawKeyType;
		cryptSign((uint8_t*)&dataSha, sizeof(dataSha), dext_msg->signature, &keySpace);
		assertion(-500000, (keySpace == my_PubKey->rawKeyLen));

		desc_msg->type = dext_msg->type;
		memcpy( desc_msg->signature, dext_msg->signature, keySpace);

		dbgf_sys(DBGT_INFO, "fixed RSA%d type=%d signature=%s of dataSha=%s over dataLen=%d data=%s (dataOffset=%d)",
			(keySpace*8), desc_msg->type, memAsHexString(desc_msg->signature, keySpace),
			cryptShaAsString(&dataSha), dataLen, memAsHexString(data, dataLen), dataOffset);

		desc_msg = NULL;
		dataOffset = 0;
		return TLV_TX_DATA_IGNORED;
	}
}

STATIC_FUNC
int process_dsc_tlv_signature(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	if (it->frame_type == BMX_DSC_TLV_SIGNATURE_DUMMY)
		return TLV_RX_DATA_PROCESSED;

	assertion(-500000, (it->frame_data_length == it->frame_msgs_length && it->frame_data == it->msg));
	assertion(-500000, (it->dhnNew && it->dhnNew->dext));

	if (it->op != TLV_OP_TEST || !descVerification)
		return TLV_RX_DATA_PROCESSED;

	char *goto_error_code = NULL;
	int32_t sign_len = it->frame_data_length - sizeof(struct dsc_msg_signature);
	struct dsc_msg_signature *msg = (struct dsc_msg_signature*)(it->frame_data);
	uint32_t dataOffset = (2*sizeof(struct tlv_hdr)) + sizeof(struct desc_hdr_rhash) + sizeof(struct desc_msg_rhash) + it->frame_data_length;
	uint8_t *data = (uint8_t*)it->dhnNew->desc_frame + dataOffset;
	int32_t dataLen = it->dhnNew->desc_frame_len - dataOffset;
	CRYPTSHA1_T desc_sha;
	CRYPTKEY_T *pkey_crypt = NULL;
	struct dsc_msg_pubkey *pkey_msg = dext_dptr(it->dhnNew->dext, BMX_DSC_TLV_PUBKEY);

	if ( !cryptKeyTypeAsString(msg->type) || cryptKeyLenByType(msg->type) != sign_len )
		goto_error( finish, "1");

	if ( !pkey_msg || !cryptKeyTypeAsString(pkey_msg->type) || cryptKeyLenByType(pkey_msg->type) != sign_len )
		goto_error( finish, "2");

	if ( dataLen < (int)sizeof(struct dsc_msg_version))
		goto_error( finish, "3");

	if ( sign_len > (descVerification/8) )
		goto_error( finish, "4");

	cryptShaAtomic(data, dataLen, &desc_sha);

	pkey_crypt = cryptPubKeyFromRaw(pkey_msg->key, sign_len);
	
	CRYPTSHA1_T plain_sha = {.h.u32={0} };
	int32_t plain_len = sizeof(plain_sha);

	if (cryptVerify(msg->signature, sign_len, (uint8_t*)&plain_sha, &plain_len, pkey_crypt) != SUCCESS )
		goto_error( finish, "5");
	
	if (plain_len != sizeof(desc_sha) || memcmp(&plain_sha, &desc_sha, sizeof(desc_sha)))
		goto_error( finish, "6");
	
finish: {
	dbgf_sys(goto_error_code?DBGT_ERR:DBGT_INFO, 
		"%s %s verifying  desc_len=%d desc_sha=%s \n"
		"sign_len=%d signature=%s\n"
		"pkey_type=%s pkey_type_len=%d pkey=%s \n"
		"plain_len=%d==%d plain_sha=%s problem?=%s",
		tlv_op_str(it->op), goto_error_code?"Failed":"Succeeded", dataLen, memAsHexString(&desc_sha, sizeof(desc_sha)),
		sign_len, memAsHexString(msg->signature, sign_len),
		pkey_msg ? cryptKeyTypeAsString(pkey_msg->type) : "---", pkey_msg ? cryptKeyLenByType(pkey_msg->type) : 0,
		pkey_crypt ? memAsHexString(pkey_crypt->rawKey, pkey_crypt->rawKeyLen) : "---",
		plain_len, sizeof(plain_sha), memAsHexString(&plain_sha, sizeof(plain_sha)), goto_error_code);
	
	cryptKeyFree(&pkey_crypt);
	
	if (goto_error_code && sign_len > (descVerification/8))
		return TLV_RX_DATA_REJECTED;
	else if (goto_error_code)
		return TLV_RX_DATA_FAILURE;
	else
		return TLV_RX_DATA_PROCESSED;
}
}

STATIC_FUNC
int create_dsc_tlv_sha(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	static struct dsc_msg_sha *desc_msg = NULL;
	static uint32_t dataOffset = 0;

	if (it->frame_type==BMX_DSC_TLV_SHA) {
		assertion(-500000, (!desc_msg && !dataOffset));

		desc_msg = (struct dsc_msg_sha*) (it->frames_out_ptr + it->frames_out_pos + sizeof(struct tlv_hdr));
		dataOffset = it->dext->dlen + sizeof(struct tlv_hdr_virtual) + sizeof(struct dsc_msg_sha);

		return sizeof(struct dsc_msg_sha);

	} else {
		assertion(-500000, (it->frame_type == BMX_DSC_TLV_SHA_DUMMY));
		assertion(-500000, (desc_msg && dataOffset));
		assertion(-500000, (it->dext->dlen > dataOffset));
		assertion(-500000, (dext_dptr(it->dext, BMX_DSC_TLV_SHA)));

		// fix my dext:
		struct dsc_msg_sha *dext_msg = dext_dptr(it->dext, BMX_DSC_TLV_SHA);
		dext_msg->dataLen = htonl(it->dext->dlen - dataOffset);
		cryptShaAtomic(it->dext->data + dataOffset, it->dext->dlen - dataOffset, &dext_msg->dataSha);

		// fix my desc_frame:
		desc_msg->dataLen = dext_msg->dataLen;
		desc_msg->dataSha = dext_msg->dataSha;

		dbgf_sys(DBGT_INFO, "fixed description SHA dataLen=%d dataSha=%s data=%s",
			ntohl(desc_msg->dataLen), cryptShaAsString(&desc_msg->dataSha),
			memAsHexString(it->dext->data + dataOffset, it->dext->dlen - dataOffset));

		desc_msg = NULL;
		dataOffset = 0;
		return TLV_TX_DATA_IGNORED;
	}
}

STATIC_FUNC
int process_dsc_tlv_sha(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	if (it->frame_type == BMX_DSC_TLV_SHA_DUMMY)
		return TLV_RX_DATA_PROCESSED;
	
	if (it->op != TLV_OP_TEST )
		return TLV_RX_DATA_PROCESSED;

	char *goto_error_code = NULL;
	struct dsc_msg_sha *msg = ((struct dsc_msg_sha*) it->frame_data);
	uint8_t *data = it->frames_in +  it->frames_pos;
	int32_t dataLen = it->frames_length - it->frames_pos;

	if (dataLen <= 0)
		goto_error(finish, "1");

	if( (int)ntohl(msg->dataLen) != dataLen )
		goto_error(finish, "1");

	SHA1_T dataSha;
	cryptShaAtomic(data, dataLen, &dataSha);
	
	if (memcmp(&msg->dataSha, &dataSha, sizeof(SHA1_T)))
		goto_error(finish, "2"); 

finish: {
	dbgf_sys(goto_error_code?DBGT_ERR:DBGT_INFO, 
		"%s %s verifying  expInLen=%d == msg.expInLen=%d expInSha=%s == msg.expInSha=%s  problem?=%s expIn=%s",
		tlv_op_str(it->op), goto_error_code?"Failed":"Succeeded", dataLen, ntohl(msg->dataLen),
		memAsHexString(&dataSha, sizeof(dataSha)), memAsHexString(&msg->dataSha, sizeof(dataSha)),
		goto_error_code, memAsHexString(data, dataLen) );

	if (goto_error_code)
		return TLV_RX_DATA_FAILURE;
	else
		return TLV_RX_DATA_PROCESSED;
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

	static uint8_t checked = NO;
	static char key_path[MAX_PATH_SIZE] = DEF_KEY_PATH;
	char tmp_path[MAX_PATH_SIZE] = "";

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
	{ODI,0,ARG_DESC_VERIFY,         0,  9,0,A_PS1,A_ADM,A_DYI,A_CFA,A_ANY, &descVerification,MIN_DESC_VERIFY,MAX_DESC_VERIFY,DEF_DESC_VERIFY,0, opt_purge_originators,
			ARG_VALUE_FORM, HLP_DESC_VERIFY},

};


void init_sec( void )
{
	register_options_array( sec_options, sizeof( sec_options ), CODE_CATEGORY_NAME );

        struct frame_handl handl;
        memset(&handl, 0, sizeof ( handl));

	static const struct field_format pubkey_format[] = DESCRIPTION_MSG_PUBKEY_FORMAT;
        handl.name = "PUBKEY";
        handl.min_msg_size = sizeof(struct dsc_msg_pubkey);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&always_fref;
        handl.tx_frame_handler = create_dsc_tlv_pubkey;
        handl.rx_frame_handler = process_dsc_tlv_pubkey;
	handl.msg_format = pubkey_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_PUBKEY, &handl);

	static const struct field_format signature_format[] = DESCRIPTION_MSG_SIGNATURE_FORMAT;
        handl.name = "SIGNATURE";
        handl.min_msg_size = sizeof(struct dsc_msg_signature);
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = create_dsc_tlv_signature;
        handl.rx_frame_handler = process_dsc_tlv_signature;
	handl.msg_format = signature_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_SIGNATURE, &handl);

        handl.name = "SIGNATURE_DUMMY";
        handl.min_msg_size = 0;
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = create_dsc_tlv_signature;
        handl.rx_frame_handler = process_dsc_tlv_signature;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_SIGNATURE_DUMMY, &handl);

	static const struct field_format sha_format[] = DESCRIPTION_MSG_SHA_FORMAT;
        handl.name = "SHA";
        handl.min_msg_size = sizeof(struct dsc_msg_sha);
        handl.fixed_msg_size = 1;
        handl.tx_frame_handler = create_dsc_tlv_sha;
        handl.rx_frame_handler = process_dsc_tlv_sha;
	handl.msg_format = sha_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_SHA, &handl);

        handl.name = "SHA_DUMMY";
        handl.min_msg_size = 0;
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = create_dsc_tlv_sha;
        handl.rx_frame_handler = process_dsc_tlv_sha;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_SHA_DUMMY, &handl);
}

void cleanup_sec( void )
{
        cryptKeyFree(&my_PubKey);

}
