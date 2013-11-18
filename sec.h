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
#define DEF_KEY_PATH "/etc/bmx6/rsa.pem"

struct desc_signature1 {
	union {
		uint8_t u8[RSA1024_SIGN_LEN];
		uint32_t u32[RSA1024_SIGN_LEN/sizeof(uint32_t)];
	} h;
};

typedef struct desc_signature1 SIGN1_T;

struct description_msg_signature {
	uint8_t type;
	uint8_t reserved;
//	SIGN1_T signature;        // 128 bytes
} __attribute__((packed));


struct description_msg_pubkey {
	uint8_t type;
	uint8_t reserved;
//	SIGN1_T pubkey;
} __attribute__((packed));


struct plugin *sec_get_plugin( void );

