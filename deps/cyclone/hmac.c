/**
 * @file hmac.c
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
 * @section Description
 *
 * HMAC is a mechanism for message authentication using cryptographic hash
 * functions. HMAC can be used with any iterative cryptographic hash
 * function (MD5, SHA-1 or SHA-256) in combination with a secret shared
 * key. Refer to RFC 2104 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.4.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "mac/hmac.h"

//Check crypto library configuration
#if (HMAC_SUPPORT == ENABLED)

//HMAC with MD5 OID (1.3.6.1.5.5.8.1.1)
const uint8_t HMAC_WITH_MD5_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x01};
//HMAC with Tiger OID (1.3.6.1.5.5.8.1.3)
const uint8_t HMAC_WITH_TIGER_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x03};
//HMAC with RIPEMD-160 OID (1.3.6.1.5.5.8.1.4)
const uint8_t HMAC_WITH_RIPEMD160_OID[8] = {0x2B, 0x06, 0x01, 0x05, 0x05, 0x08, 0x01, 0x04};
//HMAC with SHA-1 OID (1.2.840.113549.2.7)
const uint8_t HMAC_WITH_SHA1_OID[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x07};
//HMAC with SHA-224 OID (1.2.840.113549.2.8)
const uint8_t HMAC_WITH_SHA224_OID[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x08};
//HMAC with SHA-256 OID (1.2.840.113549.2.9)
const uint8_t HMAC_WITH_SHA256_OID[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x09};
//HMAC with SHA-384 OID (1.2.840.113549.2.10)
const uint8_t HMAC_WITH_SHA384_OID[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0A};
//HMAC with SHA-512 OID (1.2.840.113549.2.11)
const uint8_t HMAC_WITH_SHA512_OID[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0B};
//HMAC with SHA-512/224 OID (1.2.840.113549.2.12)
const uint8_t HMAC_WITH_SHA512_224_OID[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0C};
//HMAC with SHA-512/256 OID (1.2.840.113549.2.13)
const uint8_t HMAC_WITH_SHA512_256_OID[8] = {0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x02, 0x0D};
//HMAC with SHA-3-224 OID (2.16.840.1.101.3.4.2.13)
const uint8_t HMAC_WITH_SHA3_224_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0D};
//HMAC with SHA-3-256 OID (2.16.840.1.101.3.4.2.14)
const uint8_t HMAC_WITH_SHA3_256_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0E};
//HMAC with SHA-3-384 OID (2.16.840.1.101.3.4.2.15)
const uint8_t HMAC_WITH_SHA3_384_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0F};
//HMAC with SHA-3-512 OID (2.16.840.1.101.3.4.2.16)
const uint8_t HMAC_WITH_SHA3_512_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x10};
//HMAC with SM3 OID (1.2.156.10197.1.401.3.1)
const uint8_t HMAC_WITH_SM3_OID[10] = {0x2A, 0x81, 0x1C, 0xCF, 0x55, 0x01, 0x82, 0x91, 0x03, 0x01};


/**
 * @brief Compute HMAC using the specified hash function
 * @param[in] hash Hash algorithm used to compute HMAC
 * @param[in] key Key to use in the hash algorithm
 * @param[in] keyLen Length of the key
 * @param[in] data The input data for which to compute the hash code
 * @param[in] dataLen Length of the input data
 * @param[out] digest The computed HMAC value
 * @return Error code
 **/

__weak_func error_t hmacCompute(const HashAlgo *hash, const void *key, size_t keyLen,
   const void *data, size_t dataLen, uint8_t *digest)
{
   error_t error;
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HmacContext *context;
#else
   HmacContext context[1];
#endif

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the HMAC context
   context = cryptoAllocMem(sizeof(HmacContext));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the HMAC context
   error = hmacInit(context, hash, key, keyLen);

   //Check status code
   if(!error)
   {
      //Digest the message
      hmacUpdate(context, data, dataLen);
      //Finalize the HMAC computation
      hmacFinal(context, digest);
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Return status code
   return error;
}


/**
 * @brief Initialize HMAC calculation
 * @param[in] context Pointer to the HMAC context to initialize
 * @param[in] hash Hash algorithm used to compute HMAC
 * @param[in] key Key to use in the hash algorithm
 * @param[in] keyLen Length of the key
 * @return Error code
 **/

__weak_func error_t hmacInit(HmacContext *context, const HashAlgo *hash,
   const void *key, size_t keyLen)
{
   uint_t i;

   //Check parameters
   if(context == NULL || hash == NULL)
      return ERROR_INVALID_PARAMETER;

   //Make sure the supplied key is valid
   if(key == NULL && keyLen != 0)
      return ERROR_INVALID_PARAMETER;

   //Hash algorithm used to compute HMAC
   context->hash = hash;

   //The key is longer than the block size?
   if(keyLen > hash->blockSize)
   {
      //Initialize the hash function context
      hash->init(&context->hashContext);
      //Digest the original key
      hash->update(&context->hashContext, key, keyLen);
      //Finalize the message digest computation
      hash->final(&context->hashContext, context->key);

      //Key is padded to the right with extra zeros
      osMemset(context->key + hash->digestSize, 0,
         hash->blockSize - hash->digestSize);
   }
   else
   {
      //Copy the key
      osMemcpy(context->key, key, keyLen);
      //Key is padded to the right with extra zeros
      osMemset(context->key + keyLen, 0, hash->blockSize - keyLen);
   }

   //XOR the resulting key with ipad
   for(i = 0; i < hash->blockSize; i++)
   {
      context->key[i] ^= HMAC_IPAD;
   }

   //Initialize context for the first pass
   hash->init(&context->hashContext);
   //Start with the inner pad
   hash->update(&context->hashContext, context->key, hash->blockSize);

   //Successful initialization
   return NO_ERROR;
}


/**
 * @brief Update the HMAC context with a portion of the message being hashed
 * @param[in] context Pointer to the HMAC context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

__weak_func void hmacUpdate(HmacContext *context, const void *data, size_t length)
{
   const HashAlgo *hash;

   //Hash algorithm used to compute HMAC
   hash = context->hash;
   //Digest the message (first pass)
   hash->update(&context->hashContext, data, length);
}


/**
 * @brief Finish the HMAC calculation
 * @param[in] context Pointer to the HMAC context
 * @param[out] digest Calculated HMAC value (optional parameter)
 **/

__weak_func void hmacFinal(HmacContext *context, uint8_t *digest)
{
   uint_t i;
   const HashAlgo *hash;

   //Hash algorithm used to compute HMAC
   hash = context->hash;
   //Finish the first pass
   hash->final(&context->hashContext, context->digest);

   //XOR the original key with opad
   for(i = 0; i < hash->blockSize; i++)
   {
      context->key[i] ^= HMAC_IPAD ^ HMAC_OPAD;
   }

   //Initialize context for the second pass
   hash->init(&context->hashContext);
   //Start with outer pad
   hash->update(&context->hashContext, context->key, hash->blockSize);
   //Then digest the result of the first hash
   hash->update(&context->hashContext, context->digest, hash->digestSize);
   //Finish the second pass
   hash->final(&context->hashContext, context->digest);

   //Copy the resulting HMAC value
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, hash->digestSize);
   }
}


/**
 * @brief Release HMAC context
 * @param[in] context Pointer to the HMAC context
 **/

void hmacDeinit(HmacContext *context)
{
   //Make sure the HMAC context is valid
   if(context != NULL)
   {
      //Clear HMAC context
      osMemset(context, 0, sizeof(HmacContext));
   }
}


/**
 * @brief Finish the HMAC calculation (no padding added)
 * @param[in] context Pointer to the HMAC context
 * @param[out] digest Calculated HMAC value (optional parameter)
 **/

void hmacFinalRaw(HmacContext *context, uint8_t *digest)
{
   uint_t i;
   const HashAlgo *hash;

   //Hash algorithm used to compute HMAC
   hash = context->hash;

   //XOR the original key with opad
   for(i = 0; i < hash->blockSize; i++)
   {
      context->key[i] ^= HMAC_IPAD ^ HMAC_OPAD;
   }

   //Initialize context for the second pass
   hash->init(&context->hashContext);
   //Start with outer pad
   hash->update(&context->hashContext, context->key, hash->blockSize);
   //Then digest the result of the first hash
   hash->update(&context->hashContext, context->digest, hash->digestSize);
   //Finish the second pass
   hash->final(&context->hashContext, context->digest);

   //Copy the resulting HMAC value
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, hash->digestSize);
   }
}

#endif
