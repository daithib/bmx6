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
#include <time.h>

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
#include "prof.h"
#include "sec.h"
#include "ip.h"
#include "schedule.h"

//#include "ip.h"

#define CODE_CATEGORY_NAME "sec"


static int32_t descVerification = DEF_DESC_VERIFY;

static int32_t packetVerification = DEF_PACKET_VERIFY;
static int32_t packetSigning = DEF_PACKET_SIGN;

CRYPTKEY_T *my_PubKey = NULL;
CRYPTKEY_T *my_PktKey = NULL;

static int32_t my_PktKeyBitLen = 512;



STATIC_FUNC
int create_packet_signature(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	static struct dsc_msg_signature *msg = NULL;
	static int32_t dataOffset = 0;

	if (!packetSigning)
		return TLV_TX_DATA_DONE;

	dbgf_all(DBGT_INFO, "f_type=%s msg=%p frames_out_pos=%d dataOffset=%d", it->handl->name, msg, it->frames_out_pos, dataOffset  );

	if (it->frame_type==FRAME_TYPE_SIGNATURE_ADV) {

//		assertion(-502098, (!msg && !dataOffset));

		msg = (struct dsc_msg_signature*) (it->frames_out_ptr + it->frames_out_pos + sizeof(struct tlv_hdr));

		dataOffset = it->frames_out_pos + sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_signature) + my_PktKey->rawKeyLen;

		return sizeof(struct dsc_msg_signature) + my_PktKey->rawKeyLen;

	} else {
		assertion(-502099, (it->frame_type > FRAME_TYPE_LINK_VERSION));
		assertion(-502100, (msg && dataOffset));
		assertion(-502101, (it->frames_out_pos > dataOffset));

		extern void tx_packet(void *devp);
		static struct prof_ctx prof_tx_packet_sign = { .k ={ .func=(void(*)(void))create_packet_signature}, .name=__FUNCTION__, .parent_func=(void (*) (void))tx_packet};
		prof_start(&prof_tx_packet_sign);

		int32_t dataLen = it->frames_out_pos - dataOffset;
		uint8_t *data = it->frames_out_ptr + dataOffset;

		CRYPTSHA1_T packetSha;
		cryptShaNew(&it->ttn->task.dev->if_llocal_addr->ip_addr, sizeof(IP6_T));
		cryptShaUpdate(data, dataLen);
		cryptShaFinal(&packetSha);
		size_t keySpace = my_PktKey->rawKeyLen;

		msg->type = my_PktKey->rawKeyType;
		cryptSign(&packetSha, msg->signature, keySpace, my_PktKey);

		dbgf_all(DBGT_INFO, "fixed RSA%d type=%d signature=%s of dataSha=%s over dataLen=%d data=%s (dataOffset=%d)",
			(keySpace*8), msg->type, memAsHexString(msg->signature, keySpace),
			cryptShaAsString(&packetSha), dataLen, memAsHexString(data, dataLen), dataOffset);

		msg = NULL;
		dataOffset = 0;

		prof_stop(&prof_tx_packet_sign);
		return TLV_TX_DATA_DONE;
	}
}

STATIC_FUNC
int process_packet_signature(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	assertion(-502104, (it->frame_data_length == it->frame_msgs_length && it->frame_data == it->msg));

	DHASH_T *dhash = &it->pb->p.hdr.dhash;
        struct description_cache_node *cache = NULL;
	struct dhash_node *dhn, *dhnOld;

	if ((
		(dhnOld = dhn = avl_find_item(&dhash_tree, dhash)) ||
		((cache = get_cached_description(dhash)) && (dhn = process_description(it->pb, cache, dhash))) ||
		!dhn
		) && (dhn == NULL || dhn == UNRESOLVED_PTR || dhn == REJECTED_PTR || dhn == FAILURE_PTR)) {

		if (!cache)
			schedule_tx_task(&it->pb->i.iif->dummyLink, FRAME_TYPE_DESC_REQ, SCHEDULE_MIN_MSG_SIZE, dhash, sizeof(DHASH_T));

		return TLV_RX_DATA_REJECTED;

	}

	assertion(-500000, (dhn));
	assertion(-500000, (dhn->on));

	char *goto_error_code = NULL;
	int32_t sign_len = it->frame_data_length - sizeof(struct dsc_msg_signature);
	struct dsc_msg_signature *msg = (struct dsc_msg_signature*)(it->frame_data);
	uint8_t *data = it->frame_data + it->frame_data_length;
	int32_t dataLen = it->frames_length - it->frames_pos;
	CRYPTSHA1_T packetSha = {.h.u32={0}};
	CRYPTKEY_T *pkey = NULL;
	struct dsc_msg_pubkey *pkey_msg = NULL;

	if ( !cryptKeyTypeAsString(msg->type) || cryptKeyLenByType(msg->type) != sign_len )
		goto_error( finish, "1");
	
	if ( dataLen <= (int)sizeof(struct tlv_hdr))
		goto_error( finish, "2");

	if ( sign_len > (packetVerification/8) )
		goto_error( finish, "3");


	if (dhn->local && dhn->local->pktKey) {
		
		pkey = dhn->local->pktKey;

		if ( pkey->rawKeyType != msg->type )
			goto_error( finish, "4");

		assertion(-500000, (pkey && cryptPubKeyCheck(pkey) == SUCCESS));

		
	} else if ((pkey_msg = dext_dptr(dhn->dext, BMX_DSC_TLV_PKT_PUBKEY))) {

		pkey = cryptPubKeyFromRaw(pkey_msg->key, cryptKeyLenByType(pkey_msg->type));

		if (!pkey)
			goto_error( finish, "5");

		if ( pkey->rawKeyType != msg->type )
			goto_error( finish, "6");

		assertion(-500000, (pkey && cryptPubKeyCheck(pkey) == SUCCESS));

	} else  {
		goto_error( finish, "7");
	}


	cryptShaNew(&it->pb->i.llip, sizeof(IPX_T));
	cryptShaUpdate(data, dataLen);
	cryptShaFinal(&packetSha);

	if (cryptVerify(msg->signature, sign_len, &packetSha, pkey) != SUCCESS )
		goto_error( finish, "8");

	it->pb->i.verifiedLinkDhn = dhn;



finish:{
	dbgf(goto_error_code ? DBGL_SYS : DBGL_ALL, goto_error_code ? DBGT_ERR : DBGT_INFO,
		"%s verifying  data_len=%d data_sha=%s \n"
		"sign_len=%d signature=%s\n"
		"pkey_msg_type=%s pkey_msg_len=%d pkey_type=%s pkey=%s \n"
		"problem?=%s",
		goto_error_code?"Failed":"Succeeded", dataLen, cryptShaAsString(&packetSha),
		sign_len, memAsHexString(msg->signature, sign_len),
		pkey_msg ? cryptKeyTypeAsString(pkey_msg->type) : "---", pkey_msg ? cryptKeyLenByType(pkey_msg->type) : 0,
		pkey ? cryptKeyTypeAsString(pkey->rawKeyType) : "---", pkey ? memAsHexString(pkey->rawKey, pkey->rawKeyLen) : "---",
		goto_error_code);

	if (pkey && !(dhn->local && dhn->local->pktKey))
			cryptKeyFree(&pkey);

	if (goto_error_code) {

		EXITERROR(-500000, (0));

		if (!dhnOld && dhn) //TODO: DO not block myIID4x reserved for this node! It was never used!
			free_orig_node(dhn->on);

		return TLV_RX_DATA_REJECTED;
	}

	if (!dhnOld && dhn) {
		if (desc_adv_tx_unsolicited)
			schedule_best_tp_links(NULL, FRAME_TYPE_DESC_ADVS, dhn->desc_frame_len, &dhn->dhash, sizeof(DHASH_T));

		if (dhash_adv_tx_unsolicited)
			schedule_best_tp_links(NULL, FRAME_TYPE_DHASH_ADV, SCHEDULE_MIN_MSG_SIZE, &dhn->myIID4orig, sizeof(IID_T));

	}

	return TLV_RX_DATA_PROCESSED;
}
}


STATIC_FUNC
int create_dsc_tlv_pubkey(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	assertion(-502097, (my_PubKey));

	struct dsc_msg_pubkey *msg = ((struct dsc_msg_pubkey*) tx_iterator_cache_msg_ptr(it));

	if ((int) (sizeof(struct dsc_msg_pubkey) +my_PubKey->rawKeyLen) > tx_iterator_cache_data_space_pref(it))
		return TLV_TX_DATA_FULL;

	msg->type = my_PubKey->rawKeyType;

	memcpy(msg->key, my_PubKey->rawKey, my_PubKey->rawKeyLen);
	dbgf_track(DBGT_INFO, "added description rsa description pubkey len=%d", my_PubKey->rawKeyLen);

	return(sizeof(struct dsc_msg_pubkey) +my_PubKey->rawKeyLen);
}

STATIC_FUNC
int create_dsc_tlv_pktkey(struct tx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	if ((int) (sizeof(struct dsc_msg_pubkey) + (my_PktKeyBitLen/8)) > tx_iterator_cache_data_space_pref(it))
		return TLV_TX_DATA_FULL;

	static struct prof_ctx prof_create_dsc_tlv_pkt_pubkey = {.k={.func=(void(*)(void))create_dsc_tlv_pktkey}, .name=__FUNCTION__, .parent_func = (void (*) (void))update_my_description};
	
	prof_start(&prof_create_dsc_tlv_pkt_pubkey);

	struct dsc_msg_pubkey *msg = ((struct dsc_msg_pubkey*) tx_iterator_cache_msg_ptr(it));

	if (my_PktKey)
		cryptKeyFree(&my_PktKey);

	my_PktKey = cryptKeyMake(my_PktKeyBitLen);

	assertion(-502097, (my_PktKey));


	msg->type = my_PktKey->rawKeyType;

	memcpy(msg->key, my_PktKey->rawKey, my_PktKey->rawKeyLen);

	dbgf_track(DBGT_INFO, "added description rsa packet pubkey len=%d", my_PktKey->rawKeyLen);
	
	prof_stop(&prof_create_dsc_tlv_pkt_pubkey);
	
	return(sizeof(struct dsc_msg_pubkey) +my_PktKey->rawKeyLen);
}



STATIC_FUNC
int process_dsc_tlv_pubKey(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;
	extern int32_t rx_frame_description_adv(struct rx_frame_iterator *it);
	static struct prof_ctx prof_process_dsc_tlv_pubKey = {.k={.func=(void(*)(void))process_dsc_tlv_pubKey}, .name=__FUNCTION__, .parent_func = (void(*)(void))rx_frame_description_adv };
	prof_start(&prof_process_dsc_tlv_pubKey);
	char *goto_error_code = NULL;
	CRYPTKEY_T *pkey = NULL;
	int32_t key_len = -1;
	struct dsc_msg_pubkey *msg = NULL;

	if (it->op == TLV_OP_TEST ) {

		key_len = it->frame_data_length - sizeof(struct dsc_msg_pubkey);
		msg = (struct dsc_msg_pubkey*) (it->frame_data);

		if (!cryptKeyTypeAsString(msg->type) || cryptKeyLenByType(msg->type) != key_len)
			goto_error(finish, "1");

		if (!(pkey = cryptPubKeyFromRaw(msg->key, key_len)))
			goto_error(finish, "2");

		if (cryptPubKeyCheck(pkey) != SUCCESS)
			goto_error(finish, "3");
	}

finish:{
	dbgf(goto_error_code ? DBGL_SYS : DBGL_ALL, goto_error_code ? DBGT_ERR : DBGT_INFO,
		"%s %s verifying %s type=%s msg_key_len=%d == key_len=%d problem?=%s",
		tlv_op_str(it->op), goto_error_code?"Failed":"Succeeded", it->handl->name,
		cryptKeyTypeAsString(msg->type), cryptKeyLenByType(msg->type), key_len, goto_error_code);

	if (pkey)
		cryptKeyFree(&pkey);

	prof_stop(&prof_process_dsc_tlv_pubKey);

	if (goto_error_code)
		return TLV_RX_DATA_FAILURE;
	else
		return it->frame_data_length;
}
}

STATIC_FUNC
int process_dsc_tlv_pktKey(struct rx_frame_iterator *it)
{
        TRACE_FUNCTION_CALL;

	static struct prof_ctx prof_process_dsc_tlv_pktKey = {.k={.func=(void(*)(void))process_dsc_tlv_pktKey}, .name=__FUNCTION__, .parent_func = (void(*)(void))rx_packet  };
	prof_start(&prof_process_dsc_tlv_pktKey);
	char *goto_error_code = NULL;
	CRYPTKEY_T *pkey = NULL;
	int32_t key_len = -1;
	struct dsc_msg_pubkey *msg = NULL;

	if (it->op == TLV_OP_TEST ) {

		key_len = it->frame_data_length - sizeof(struct dsc_msg_pubkey);
		msg = (struct dsc_msg_pubkey*) (it->frame_data);

		if (!cryptKeyTypeAsString(msg->type) || cryptKeyLenByType(msg->type) != key_len)
			goto_error(finish, "1");

		if (!(pkey = cryptPubKeyFromRaw(msg->key, key_len)))
			goto_error(finish, "2");

		if (cryptPubKeyCheck(pkey) != SUCCESS)
			goto_error(finish, "3");

	} else if (it->op == TLV_OP_DEL &&  it->onOld && it->onOld->dhn && it->onOld->dhn->local) {

		if (it->onOld->dhn->local->pktKey)
			cryptKeyFree(&it->onOld->dhn->local->pktKey);

	} else if (it->op == TLV_OP_NEW && it->onOld && it->onOld->dhn && it->onOld->dhn->local) {

		if (it->onOld->dhn->local->pktKey)
			cryptKeyFree(&it->onOld->dhn->local->pktKey);

		msg = dext_dptr(it->dhnNew->dext, BMX_DSC_TLV_PKT_PUBKEY);
		assertion(-500000, (msg));

		it->onOld->dhn->local->pktKey = cryptPubKeyFromRaw(msg->key, cryptKeyLenByType(msg->type));
		assertion(-500000, (it->onOld->dhn->local->pktKey && cryptPubKeyCheck(it->onOld->dhn->local->pktKey) == SUCCESS));
	}

finish: {
	dbgf(goto_error_code ? DBGL_SYS : DBGL_ALL, goto_error_code ? DBGT_ERR : DBGT_INFO,
		"%s %s verifying %s type=%s msg_key_len=%d == key_len=%d problem?=%s",
		tlv_op_str(it->op), goto_error_code?"Failed":"Succeeded", it->handl->name,
		cryptKeyTypeAsString(msg->type), cryptKeyLenByType(msg->type), key_len, goto_error_code);

	if (pkey)
		cryptKeyFree(&pkey);

	prof_stop(&prof_process_dsc_tlv_pktKey);

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

	if (it->frame_type==BMX_DSC_TLV_DSC_SIGNATURE) {

		assertion(-502098, (!desc_msg && !dataOffset));

		desc_msg = (struct dsc_msg_signature*) (it->frames_out_ptr + it->frames_out_pos + sizeof(struct tlv_hdr));

		dataOffset = it->frames_out_pos + sizeof(struct tlv_hdr) + sizeof(struct dsc_msg_signature) + my_PubKey->rawKeyLen;

		return sizeof(struct dsc_msg_signature) + my_PubKey->rawKeyLen;

	} else {
		assertion(-502099, (it->frame_type == BMX_DSC_TLV_SIGNATURE_DUMMY));
		assertion(-502100, (desc_msg && dataOffset));
		assertion(-502101, (it->frames_out_pos > dataOffset));
		assertion(-502102, (dext_dptr(it->dext, BMX_DSC_TLV_DSC_SIGNATURE)));

		int32_t dataLen = it->frames_out_pos - dataOffset;
		uint8_t *data = it->frames_out_ptr + dataOffset;

		CRYPTSHA1_T dataSha;
		cryptShaAtomic(data, dataLen, &dataSha);
		size_t keySpace = my_PubKey->rawKeyLen;

		struct dsc_msg_signature *dext_msg = dext_dptr(it->dext, BMX_DSC_TLV_DSC_SIGNATURE);

		dext_msg->type = my_PubKey->rawKeyType;
		cryptSign(&dataSha, dext_msg->signature, keySpace, NULL);

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

	assertion(-502104, (it->frame_data_length == it->frame_msgs_length && it->frame_data == it->msg));
	assertion(-502105, (it->dhnNew && it->dhnNew->dext));

	if (it->op != TLV_OP_TEST)
		return TLV_RX_DATA_PROCESSED;

	clock_t clock_before = (TIME_T)clock();
	char *goto_error_code = NULL;
	int32_t sign_len = it->frame_data_length - sizeof(struct dsc_msg_signature);
	struct dsc_msg_signature *msg = (struct dsc_msg_signature*)(it->frame_data);
	uint32_t dataOffset = (2*sizeof(struct tlv_hdr)) + sizeof(struct desc_hdr_rhash) + sizeof(struct desc_msg_rhash) + it->frame_data_length;
	uint8_t *data = (uint8_t*)it->dhnNew->desc_frame + dataOffset;
	int32_t dataLen = it->dhnNew->desc_frame_len - dataOffset;
	CRYPTSHA1_T dataSha;
	CRYPTKEY_T *pkey = NULL;
	struct dsc_msg_pubkey *pkey_msg = dext_dptr(it->dhnNew->dext, BMX_DSC_TLV_DSC_PUBKEY);

	if ( !cryptKeyTypeAsString(msg->type) || cryptKeyLenByType(msg->type) != sign_len )
		goto_error( finish, "1");

	if ( !pkey_msg || !cryptKeyTypeAsString(pkey_msg->type) || pkey_msg->type != msg->type)
		goto_error( finish, "2");

	if ( dataLen < (int)sizeof(struct dsc_msg_version))
		goto_error( finish, "3");

	if ( sign_len > (descVerification/8) )
		goto_error( finish, "4");

	cryptShaAtomic(data, dataLen, &dataSha);

	if (!(pkey = cryptPubKeyFromRaw(pkey_msg->key, sign_len)))
		goto_error(finish, "5");

	assertion(-500000, (pkey && cryptPubKeyCheck(pkey) == SUCCESS));

	if (cryptVerify(msg->signature, sign_len, &dataSha, pkey) != SUCCESS )
		goto_error( finish, "7");
	
	clock_t clock_after = (TIME_T)clock();
	static clock_t clock_total;
	clock_t clock_diff = (clock_after - clock_before);
	clock_total += clock_diff
	dbgf_sys(DBGT_INFO, "verified %s description signature in time=%d verified_total=%d total=%d",
		cryptKeyTypeAsString(pkey->rawKeyType), clock_diff, clock_total, clock_after);
	
finish: {

	dbgf(goto_error_code ? DBGL_SYS : DBGL_ALL, goto_error_code ? DBGT_ERR : DBGT_INFO,
		"%s verifying  data_len=%d data_sha=%s \n"
		"sign_len=%d signature=%s\n"
		"pkey_msg_type=%s pkey_msg_len=%d pkey_type=%s pkey=%s \n"
		"problem?=%s",
		goto_error_code?"Failed":"Succeeded", dataLen, cryptShaAsString(&dataSha),
		sign_len, memAsHexString(msg->signature, sign_len),
		pkey_msg ? cryptKeyTypeAsString(pkey_msg->type) : "---", pkey_msg ? cryptKeyLenByType(pkey_msg->type) : 0,
		pkey ? cryptKeyTypeAsString(pkey->rawKeyType) : "---", pkey ? memAsHexString(pkey->rawKey, pkey->rawKeyLen) : "---",
		goto_error_code);

	
	cryptKeyFree(&pkey);
	
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
		assertion(-502106, (!desc_msg && !dataOffset));

		desc_msg = (struct dsc_msg_sha*) (it->frames_out_ptr + it->frames_out_pos + sizeof(struct tlv_hdr));
		dataOffset = it->dext->dlen + sizeof(struct tlv_hdr_virtual) + sizeof(struct dsc_msg_sha);

		return sizeof(struct dsc_msg_sha);

	} else {
		assertion(-502107, (it->frame_type == BMX_DSC_TLV_SHA_DUMMY));
		assertion(-502108, (desc_msg && dataOffset));
		assertion(-502109, (it->dext->dlen > dataOffset));
		assertion(-502110, (dext_dptr(it->dext, BMX_DSC_TLV_SHA)));

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
	
	if (!cryptShasEqual(&msg->dataSha, &dataSha))
		goto_error(finish, "2"); 

finish: {
	dbgf_sys(goto_error_code?DBGT_ERR:DBGT_INFO, 
		"%s %s verifying  expInLen=%d == msg.expInLen=%d expInSha=%s == msg.expInSha=%s  problem?=%s expIn=%s",
		tlv_op_str(it->op), goto_error_code?"Failed":"Succeeded", dataLen, ntohl(msg->dataLen),
		cryptShaAsString(&dataSha), cryptShaAsString(&msg->dataSha),
		goto_error_code, memAsHexString(data, dataLen) );

	if (goto_error_code)
		return TLV_RX_DATA_FAILURE;
	else
		return TLV_RX_DATA_PROCESSED;
}
}

int32_t rsa_load( char *tmp_path ) {

	// test with: ./bmx6 f=0 d=0 --keyDir=$(pwdd)/rsa-test/key.der


	dbgf_sys(DBGT_INFO, "testing %s=%s", ARG_KEY_PATH, tmp_path);

	if (!(my_PubKey = cryptKeyFromDer( tmp_path ))) {
		return FAILURE;
	}

	uint8_t in[] = "Everyone gets Friday off.";
	size_t inLen = strlen((char*)in);
	CRYPTSHA1_T inSha;
	uint8_t enc[CRYPT_RSA_MAX_LEN];
	size_t encLen = sizeof(enc);
	uint8_t plain[CRYPT_RSA_MAX_LEN];
	size_t plainLen = sizeof(plain);

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


	cryptShaAtomic(in, inLen, &inSha);

	if (cryptSign(&inSha, enc, my_PubKey->rawKeyLen, NULL) != SUCCESS) {
		dbgf_sys(DBGT_ERR, "Failed Sign inLen=%d outLen=%d inData=%s outData=%s",
			inLen, encLen, memAsHexString((char*)in, inLen), memAsHexString((char*)enc, my_PubKey->rawKeyLen));
		return FAILURE;
	}

	if (cryptVerify(enc, my_PubKey->rawKeyLen, &inSha, my_PubKey) != SUCCESS) {
		dbgf_sys(DBGT_ERR, "Failed Verify inSha=%s", cryptShaAsString(&inSha));
		return FAILURE;
	}

	
	return SUCCESS;
}

STATIC_FUNC
int32_t opt_key_path(uint8_t cmd, uint8_t _save, struct opt_type *opt, struct opt_parent *patch, struct ctrl_node *cn)
{

	static uint8_t done = NO;
	static char key_path[MAX_PATH_SIZE] = DEF_KEY_PATH;
	char tmp_path[MAX_PATH_SIZE] = "";

	if ( (cmd == OPT_CHECK || cmd == OPT_SET_POST) && initializing && !done ) {

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

#ifndef NO_KEY_GEN
		if ( check_file( tmp_path, YES/*regular*/,YES/*read*/, NO/*writable*/, NO/*executable*/ ) == FAILURE ) {

			dbgf_sys(DBGT_ERR, "key=%s does not exist! Creating...", tmp_path);

			if (cryptKeyMakeDer(1024, tmp_path) != SUCCESS) {
				dbgf_sys(DBGT_ERR, "Failed creating new %d bit key to %s!", 1024, tmp_path);
				return FAILURE;
			}
		}
#endif
		if (rsa_load( tmp_path ) == SUCCESS ) {
			dbgf_sys(DBGT_INFO, "Successfully initialized %d bit RSA key=%s !", (my_PubKey->rawKeyLen * 8), tmp_path);
		} else {
			dbgf_sys(DBGT_ERR, "key=%s invalid!", tmp_path);
			return FAILURE;
		}

		strcpy(key_path, tmp_path);

		init_self();

		done = YES;
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

	static const struct field_format signature_format[] = DESCRIPTION_MSG_SIGNATURE_FORMAT;
        handl.name = "SIGNATURE_ADV";
	handl.rx_processUnVerifiedLink = 1;
	handl.min_msg_size = sizeof(struct dsc_msg_signature);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&never_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_packet_signature;
        handl.rx_frame_handler = process_packet_signature;
	handl.msg_format = signature_format;
        register_frame_handler(packet_frame_db, FRAME_TYPE_SIGNATURE_ADV, &handl);


	static const struct field_format pubkey_format[] = DESCRIPTION_MSG_PUBKEY_FORMAT;
        handl.name = "DSC_PUBKEY";
	handl.is_mandatory = 1;
        handl.min_msg_size = sizeof(struct dsc_msg_pubkey);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&always_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_pubkey;
        handl.rx_frame_handler = process_dsc_tlv_pubKey;
	handl.msg_format = pubkey_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_DSC_PUBKEY, &handl);

        handl.name = "DSC_SIGNATURE";
	handl.is_mandatory = 1;
	handl.min_msg_size = sizeof(struct dsc_msg_signature);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&never_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_signature;
        handl.rx_frame_handler = process_dsc_tlv_signature;
	handl.msg_format = signature_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_DSC_SIGNATURE, &handl);

        handl.name = "DSC_SIGNATURE_DUMMY";
	handl.rx_processUnVerifiedLink = 1;
        handl.tx_frame_handler = create_dsc_tlv_signature;
        handl.rx_frame_handler = process_dsc_tlv_signature;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_SIGNATURE_DUMMY, &handl);

	static const struct field_format sha_format[] = DESCRIPTION_MSG_SHA_FORMAT;
        handl.name = "DSC_SHA";
        handl.min_msg_size = sizeof(struct dsc_msg_sha);
        handl.fixed_msg_size = 1;
	handl.dextReferencing = (int32_t*)&never_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_sha;
        handl.rx_frame_handler = process_dsc_tlv_sha;
	handl.msg_format = sha_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_SHA, &handl);

        handl.name = "DSC_SHA_DUMMY";
        handl.min_msg_size = 0;
        handl.fixed_msg_size = 0;
        handl.tx_frame_handler = create_dsc_tlv_sha;
        handl.rx_frame_handler = process_dsc_tlv_sha;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_SHA_DUMMY, &handl);


        handl.name = "DSC_PKT_PUBKEY";
	handl.is_mandatory = 0;
        handl.min_msg_size = sizeof(struct dsc_msg_pubkey);
        handl.fixed_msg_size = 0;
	handl.dextReferencing = (int32_t*)&never_fref;
	handl.dextCompression = (int32_t*)&never_fzip;
        handl.tx_frame_handler = create_dsc_tlv_pktkey;
        handl.rx_frame_handler = process_dsc_tlv_pktKey;
	handl.msg_format = pubkey_format;
        register_frame_handler(description_tlv_db, BMX_DSC_TLV_PKT_PUBKEY, &handl);
}

void cleanup_sec( void )
{
        cryptKeyFree(&my_PubKey);

	if (my_PktKey)
		cryptKeyFree(&my_PktKey);

}
