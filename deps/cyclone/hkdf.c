/**
 * @file hkdf.c
 * @brief HKDF (HMAC-based Key Derivation Function)
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
 * HKDF is a simple HMAC-based key derivation function which can be used as a
 * building block in various protocols and applications. Refer to RFC 5869 for
 * more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.4.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "kdf/hkdf.h"
#include "mac/hmac.h"

//Check crypto library configuration
#if (HKDF_SUPPORT == ENABLED)


/**
 * @brief HKDF key derivation function
 * @param[in] hash Underlying hash function
 * @param[in] ikm input keying material
 * @param[in] ikmLen Length in the input keying material
 * @param[in] salt Optional salt value (a non-secret random value)
 * @param[in] saltLen Length of the salt
 * @param[in] info Optional application specific information
 * @param[in] infoLen Length of the application specific information
 * @param[out] okm output keying material
 * @param[in] okmLen Length of the output keying material
 * @return Error code
 **/

error_t hkdf(const HashAlgo *hash, const uint8_t *ikm, size_t ikmLen,
   const uint8_t *salt, size_t saltLen, const uint8_t *info, size_t infoLen,
   uint8_t *okm, size_t okmLen)
{
   error_t error;
   uint8_t prk[MAX_HASH_DIGEST_SIZE];

   //Perform HKDF extract step
   error = hkdfExtract(hash, ikm, ikmLen, salt, saltLen, prk);

   //Check status code
   if(!error)
   {
      //Perform HKDF expand step
      error = hkdfExpand(hash, prk, hash->digestSize, info, infoLen,
         okm, okmLen);
   }

   //Return status code
   return error;
}


/**
 * @brief HKDF extract step
 * @param[in] hash Underlying hash function
 * @param[in] ikm input keying material
 * @param[in] ikmLen Length in the input keying material
 * @param[in] salt Optional salt value (a non-secret random value)
 * @param[in] saltLen Length of the salt
 * @param[out] prk Pseudorandom key
 * @return Error code
 **/

error_t hkdfExtract(const HashAlgo *hash, const uint8_t *ikm, size_t ikmLen,
   const uint8_t *salt, size_t saltLen, uint8_t *prk)
{
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HmacContext *hmacContext;
#else
   HmacContext hmacContext[1];
#endif

   //Check parameters
   if(hash == NULL || ikm == NULL || prk == NULL)
      return ERROR_INVALID_PARAMETER;

   //The salt parameter is optional
   if(salt == NULL && saltLen != 0)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the HMAC context
   hmacContext = cryptoAllocMem(sizeof(HmacContext));
   //Failed to allocate memory?
   if(hmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //The salt parameter is optional
   if(salt == NULL)
   {
      //If the salt is not provided, it is set to a string of HashLen zeros
      osMemset(hmacContext->digest, 0, hash->digestSize);
      salt = hmacContext->digest;
      saltLen = hash->digestSize;
   }

   //Compute PRK = HMAC-Hash(salt, IKM)
   hmacInit(hmacContext, hash, salt, saltLen);
   hmacUpdate(hmacContext, ikm, ikmLen);
   hmacFinal(hmacContext, prk);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hmacContext);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief HKDF expand step
 * @param[in] hash Underlying hash function
 * @param[in] prk Pseudorandom key
 * @param[in] prkLen Length of the pseudorandom key
 * @param[in] info Optional application specific information
 * @param[in] infoLen Length of the application specific information
 * @param[out] okm output keying material
 * @param[in] okmLen Length of the output keying material
 * @return Error code
 **/

error_t hkdfExpand(const HashAlgo *hash, const uint8_t *prk, size_t prkLen,
   const uint8_t *info, size_t infoLen, uint8_t *okm, size_t okmLen)
{
   uint8_t i;
   size_t tLen;
   uint8_t t[MAX_HASH_DIGEST_SIZE];
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   HmacContext *hmacContext;
#else
   HmacContext hmacContext[1];
#endif

   //Check parameters
   if(hash == NULL || prk == NULL || okm == NULL)
      return ERROR_INVALID_PARAMETER;

   //The application specific information parameter is optional
   if(info == NULL && infoLen != 0)
      return ERROR_INVALID_PARAMETER;

   //PRK must be at least HashLen octets
   if(prkLen < hash->digestSize)
      return ERROR_INVALID_LENGTH;

   //Check the length of the output keying material
   if(okmLen > (255 * hash->digestSize))
      return ERROR_INVALID_LENGTH;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the HMAC context
   hmacContext = cryptoAllocMem(sizeof(HmacContext));
   //Failed to allocate memory?
   if(hmacContext == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //T(0) is an empty string (zero length)
   tLen = 0;

   //Iterate as many times as required
   for(i = 1; okmLen > 0; i++)
   {
      //Compute T(i) = HMAC-Hash(PRK, T(i-1) | info | i)
      hmacInit(hmacContext, hash, prk, prkLen);
      hmacUpdate(hmacContext, t, tLen);
      hmacUpdate(hmacContext, info, infoLen);
      hmacUpdate(hmacContext, &i, sizeof(i));
      hmacFinal(hmacContext, t);

      //Number of octets in the current block
      tLen = MIN(okmLen, hash->digestSize);
      //Save the resulting block
      osMemcpy(okm, t, tLen);

      //Point to the next block
      okm += tLen;
      okmLen -= tLen;
   }

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(hmacContext);
#endif

   //Successful processing
   return NO_ERROR;
}

#endif
