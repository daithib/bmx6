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

#include <stdint.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <linux/if.h>

#define ARG_KEY_PATH "keyPath"
#define DEF_KEY_PATH "/etc/bmx6/rsa.der"

#define ARG_DESC_VERIFY "descVerification"
#define MIN_DESC_VERIFY 512
#define MAX_DESC_VERIFY 4096
#define DEF_DESC_VERIFY 4096
#define HLP_DESC_VERIFY "verify description signatures up-to given RSA key length"

#define ARG_PACKET_SIGN "packetSigning"
#define MIN_PACKET_SIGN 0
#define MAX_PACKET_SIGN 1024
#define DEF_PACKET_SIGN 512
#define HLP_PACKET_SIGN "sign outgoing packets with given RSA key length"

#define ARG_PACKET_VERIFY "packetVerification"
#define MIN_PACKET_VERIFY 0
#define MAX_PACKET_VERIFY 4096
#define DEF_PACKET_VERIFY 1024
#define HLP_PACKET_VERIFY "verify incoming packet signature up-to given RSA key length"


#define DESCRIPTION_MSG_PUBKEY_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8*sizeof(struct dsc_msg_pubkey),     1, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   1, FIELD_RELEVANCE_HIGH,  "key" }, \
FIELD_FORMAT_END }

struct dsc_msg_pubkey {
        uint8_t type;
        uint8_t key[];
} __attribute__((packed));


#define DESCRIPTION_MSG_SIGNATURE_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8*sizeof(struct dsc_msg_signature),  1, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   1, FIELD_RELEVANCE_HIGH,  "signature" }, \
FIELD_FORMAT_END }

struct dsc_msg_signature {
        uint8_t type;
        uint8_t signature[];
} __attribute__((packed));


#define DESCRIPTION_MSG_SHA_FORMAT { \
{FIELD_TYPE_UINT,          -1, 32,                        0, FIELD_RELEVANCE_HIGH,  "dataLen"}, \
{FIELD_TYPE_STRING_BINARY, -1, 8*sizeof(SHA1_T),          1, FIELD_RELEVANCE_HIGH,  "dataSha"}, \
FIELD_FORMAT_END }

struct dsc_msg_sha {
        uint32_t dataLen;
        CRYPTSHA1_T dataSha;
} __attribute__((packed));


extern CRYPTKEY_T *my_PubKey;
extern CRYPTKEY_T *my_PktKey;


void init_sec( void );
void cleanup_sec( void );
