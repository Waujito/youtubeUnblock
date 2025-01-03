/**
 * @file aes.h
 * @brief AES (Advanced Encryption Standard)
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

#ifndef _AES_H
#define _AES_H

//Dependencies
#include "core/crypto.h"

//Application specific context
#ifndef AES_PRIVATE_CONTEXT
   #define AES_PRIVATE_CONTEXT
#endif

//AES block size
#define AES_BLOCK_SIZE 16
//Common interface for encryption algorithms
#define AES_CIPHER_ALGO (&aesCipherAlgo)

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief AES algorithm context
 **/

typedef struct
{
   uint_t nr;
   uint32_t ek[60];
   uint32_t dk[60];
   AES_PRIVATE_CONTEXT
} AesContext;


//AES related constants
extern const uint8_t AES128_ECB_OID[9];
extern const uint8_t AES128_CBC_OID[9];
extern const uint8_t AES128_OFB_OID[9];
extern const uint8_t AES128_CFB_OID[9];
extern const uint8_t AES128_GCM_OID[9];
extern const uint8_t AES128_CCM_OID[9];
extern const uint8_t AES192_ECB_OID[9];
extern const uint8_t AES192_CBC_OID[9];
extern const uint8_t AES192_OFB_OID[9];
extern const uint8_t AES192_CFB_OID[9];
extern const uint8_t AES192_GCM_OID[9];
extern const uint8_t AES192_CCM_OID[9];
extern const uint8_t AES256_ECB_OID[9];
extern const uint8_t AES256_CBC_OID[9];
extern const uint8_t AES256_OFB_OID[9];
extern const uint8_t AES256_CFB_OID[9];
extern const uint8_t AES256_GCM_OID[9];
extern const uint8_t AES256_CCM_OID[9];
extern const CipherAlgo aesCipherAlgo;

//AES related functions
error_t aesInit(AesContext *context, const uint8_t *key, size_t keyLen);

void aesEncryptBlock(AesContext *context, const uint8_t *input,
   uint8_t *output);

void aesDecryptBlock(AesContext *context, const uint8_t *input,
   uint8_t *output);

void aesDeinit(AesContext *context);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
