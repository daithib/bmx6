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


#define DESCRIPTION_MSG_PUBKEY_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8*sizeof(struct dsc_msg_pubkey),     1, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   1, FIELD_RELEVANCE_HIGH,  "key" }, \
FIELD_FORMAT_END }


#define DESCRIPTION_MSG_SIGNATURE_FORMAT { \
{FIELD_TYPE_UINT,          -1, 8*sizeof(struct dsc_msg_signature),  1, FIELD_RELEVANCE_HIGH,  "type"}, \
{FIELD_TYPE_STRING_BINARY, -1, 0,                                   1, FIELD_RELEVANCE_HIGH,  "signature" }, \
FIELD_FORMAT_END }

struct dsc_msg_sha {
        uint32_t expInLen;
        CRYPTSHA1_T expInSha;
} __attribute__((packed));

struct dsc_msg_pubkey {
        uint8_t type;
        uint8_t key[];
} __attribute__((packed));

struct dsc_msg_signature {
        uint8_t type;
        uint8_t signature[];
} __attribute__((packed));


#define DESCRIPTION_MSG_SHA_FORMAT { \
{FIELD_TYPE_UINT,          -1, 32,                        0, FIELD_RELEVANCE_HIGH,  "len"}, \
{FIELD_TYPE_STRING_BINARY, -1, 8*sizeof(SHA1_T),          1, FIELD_RELEVANCE_HIGH,  "sha"}, \
FIELD_FORMAT_END }


extern CRYPTKEY_T *my_PubKey;

struct plugin *sec_get_plugin( void );

