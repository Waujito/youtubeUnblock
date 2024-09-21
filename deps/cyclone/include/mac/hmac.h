/**
 * @file hmac.h
 * @brief HMAC (Keyed-Hashing for Message Authentication)
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
 *
 * This file is part of CycloneCRYPTO Open.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.4.4
 **/

#ifndef _HMAC_H
#define _HMAC_H

//Dependencies
#include "core/crypto.h"
#include "hash/hash_algorithms.h"

//Application specific context
#ifndef HMAC_PRIVATE_CONTEXT
   #define HMAC_PRIVATE_CONTEXT
#endif

//Inner padding (ipad)
#define HMAC_IPAD 0x36
//Outer padding (opad)
#define HMAC_OPAD 0x5C

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief HMAC algorithm context
 **/

typedef struct
{
   const HashAlgo *hash;
   HashContext hashContext;
   uint8_t key[MAX_HASH_BLOCK_SIZE];
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
   HMAC_PRIVATE_CONTEXT
} HmacContext;


//HMAC related constants
extern const uint8_t HMAC_WITH_MD5_OID[8];
extern const uint8_t HMAC_WITH_TIGER_OID[8];
extern const uint8_t HMAC_WITH_RIPEMD160_OID[8];
extern const uint8_t HMAC_WITH_SHA1_OID[8];
extern const uint8_t HMAC_WITH_SHA224_OID[8];
extern const uint8_t HMAC_WITH_SHA256_OID[8];
extern const uint8_t HMAC_WITH_SHA384_OID[8];
extern const uint8_t HMAC_WITH_SHA512_OID[8];
extern const uint8_t HMAC_WITH_SHA512_224_OID[8];
extern const uint8_t HMAC_WITH_SHA512_256_OID[8];
extern const uint8_t HMAC_WITH_SHA3_224_OID[9];
extern const uint8_t HMAC_WITH_SHA3_256_OID[9];
extern const uint8_t HMAC_WITH_SHA3_384_OID[9];
extern const uint8_t HMAC_WITH_SHA3_512_OID[9];
extern const uint8_t HMAC_WITH_SM3_OID[10];

//HMAC related functions
error_t hmacCompute(const HashAlgo *hash, const void *key, size_t keyLen,
   const void *data, size_t dataLen, uint8_t *digest);

error_t hmacInit(HmacContext *context, const HashAlgo *hash,
   const void *key, size_t keyLen);

void hmacUpdate(HmacContext *context, const void *data, size_t length);
void hmacFinal(HmacContext *context, uint8_t *digest);
void hmacFinalRaw(HmacContext *context, uint8_t *digest);
void hmacDeinit(HmacContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
