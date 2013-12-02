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

#define SEC_DER_BUF_SZ 4096

#define DESCRIPTION_MSG_SEC_FORMAT { \
{FIELD_TYPE_STRING_BINARY, -1, 0,                         1, FIELD_RELEVANCE_LOW,  "pubKey" },  \
FIELD_FORMAT_END }

#define DESCRIPTION_MSG_SEC_FORMAT { \
{FIELD_TYPE_STRING_BINARY, -1, 0,                         1, FIELD_RELEVANCE_LOW,  "pubKey" },  \
FIELD_FORMAT_END }

#define SEC_RSA512_MIN   CRYPT_KEY_N_MIN/8
#define SEC_RSA512_TYPE  1
#define SEC_RSA512_LEN   64
#define SEC_RSA1024_TYPE 2
#define SEC_RSA1024_LEN  128
#define SEC_RSA2048_TYPE 2
#define SEC_RSA2048_LEN  256
#define SEC_RSA4096_TYPE 3
#define SEC_RSA4096_LEN  512

struct plugin *sec_get_plugin( void );

