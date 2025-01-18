/**
 * @file sha256.c
 * @brief SHA-256 (Secure Hash Algorithm 256)
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
 * SHA-256 is a secure hash algorithm for computing a condensed representation
 * of an electronic message. Refer to FIPS 180-4 for more details
 *
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.4.4
 **/

//Switch to the appropriate trace level
#define TRACE_LEVEL CRYPTO_TRACE_LEVEL

//Dependencies
#include "core/crypto.h"
#include "hash/sha256.h"

//Check crypto library configuration
#if (SHA224_SUPPORT == ENABLED || SHA256_SUPPORT == ENABLED)

//Macro to access the workspace as a circular buffer
#define W(n) w[(n) & 0x0F]

//SHA-256 auxiliary functions
#define CH(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) | ((x) & (z)) | ((y) & (z)))
#define SIGMA1(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define SIGMA2(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIGMA3(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ SHR32(x, 3))
#define SIGMA4(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ SHR32(x, 10))

//SHA-256 padding
static const uint8_t padding[64] =
{
   0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

//SHA-256 constants
static const uint32_t k[64] =
{
   0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
   0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
   0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
   0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
   0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
   0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
   0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
   0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2
};

//SHA-256 object identifier (2.16.840.1.101.3.4.2.1)
const uint8_t SHA256_OID[9] = {0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01};

//Common interface for hash algorithms
const HashAlgo sha256HashAlgo =
{
   "SHA-256",
   SHA256_OID,
   sizeof(SHA256_OID),
   sizeof(Sha256Context),
   SHA256_BLOCK_SIZE,
   SHA256_DIGEST_SIZE,
   SHA256_MIN_PAD_SIZE,
   TRUE,
   (HashAlgoCompute) sha256Compute,
   (HashAlgoInit) sha256Init,
   (HashAlgoUpdate) sha256Update,
   (HashAlgoFinal) sha256Final,
#if ((defined(MIMXRT1050_CRYPTO_HASH_SUPPORT) && MIMXRT1050_CRYPTO_HASH_SUPPORT == ENABLED) || \
   (defined(MIMXRT1060_CRYPTO_HASH_SUPPORT) && MIMXRT1060_CRYPTO_HASH_SUPPORT == ENABLED) || \
   (defined(MIMXRT1160_CRYPTO_HASH_SUPPORT) && MIMXRT1160_CRYPTO_HASH_SUPPORT == ENABLED) || \
   (defined(MIMXRT1170_CRYPTO_HASH_SUPPORT) && MIMXRT1170_CRYPTO_HASH_SUPPORT == ENABLED))
   NULL,
#else
   (HashAlgoFinalRaw) sha256FinalRaw
#endif
};


/**
 * @brief Digest a message using SHA-256
 * @param[in] data Pointer to the message being hashed
 * @param[in] length Length of the message
 * @param[out] digest Pointer to the calculated digest
 * @return Error code
 **/

__weak_func error_t sha256Compute(const void *data, size_t length, uint8_t *digest)
{
#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   Sha256Context *context;
#else
   Sha256Context context[1];
#endif

   //Check parameters
   if(data == NULL && length != 0)
      return ERROR_INVALID_PARAMETER;

   if(digest == NULL)
      return ERROR_INVALID_PARAMETER;

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Allocate a memory buffer to hold the SHA-256 context
   context = cryptoAllocMem(sizeof(Sha256Context));
   //Failed to allocate memory?
   if(context == NULL)
      return ERROR_OUT_OF_MEMORY;
#endif

   //Initialize the SHA-256 context
   sha256Init(context);
   //Digest the message
   sha256Update(context, data, length);
   //Finalize the SHA-256 message digest
   sha256Final(context, digest);

#if (CRYPTO_STATIC_MEM_SUPPORT == DISABLED)
   //Free previously allocated memory
   cryptoFreeMem(context);
#endif

   //Successful processing
   return NO_ERROR;
}


/**
 * @brief Initialize SHA-256 message digest context
 * @param[in] context Pointer to the SHA-256 context to initialize
 **/

__weak_func void sha256Init(Sha256Context *context)
{
   //Set initial hash value
   context->h[0] = 0x6A09E667;
   context->h[1] = 0xBB67AE85;
   context->h[2] = 0x3C6EF372;
   context->h[3] = 0xA54FF53A;
   context->h[4] = 0x510E527F;
   context->h[5] = 0x9B05688C;
   context->h[6] = 0x1F83D9AB;
   context->h[7] = 0x5BE0CD19;

   //Number of bytes in the buffer
   context->size = 0;
   //Total length of the message
   context->totalSize = 0;
}


/**
 * @brief Update the SHA-256 context with a portion of the message being hashed
 * @param[in] context Pointer to the SHA-256 context
 * @param[in] data Pointer to the buffer being hashed
 * @param[in] length Length of the buffer
 **/

__weak_func void sha256Update(Sha256Context *context, const void *data, size_t length)
{
   size_t n;

   //Process the incoming data
   while(length > 0)
   {
      //The buffer can hold at most 64 bytes
      n = MIN(length, 64 - context->size);

      //Copy the data to the buffer
      osMemcpy(context->buffer + context->size, data, n);

      //Update the SHA-256 context
      context->size += n;
      context->totalSize += n;
      //Advance the data pointer
      data = (uint8_t *) data + n;
      //Remaining bytes to process
      length -= n;

      //Process message in 16-word blocks
      if(context->size == 64)
      {
         //Transform the 16-word block
         sha256ProcessBlock(context);
         //Empty the buffer
         context->size = 0;
      }
   }
}


/**
 * @brief Finish the SHA-256 message digest
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest (optional parameter)
 **/

__weak_func void sha256Final(Sha256Context *context, uint8_t *digest)
{
   uint_t i;
   size_t paddingSize;
   uint64_t totalSize;

   //Length of the original message (before padding)
   totalSize = context->totalSize * 8;

   //Pad the message so that its length is congruent to 56 modulo 64
   if(context->size < 56)
   {
      paddingSize = 56 - context->size;
   }
   else
   {
      paddingSize = 64 + 56 - context->size;
   }

   //Append padding
   sha256Update(context, padding, paddingSize);

   //Append the length of the original message
   context->w[14] = htobe32((uint32_t) (totalSize >> 32));
   context->w[15] = htobe32((uint32_t) totalSize);

   //Calculate the message digest
   sha256ProcessBlock(context);

   //Convert from host byte order to big-endian byte order
   for(i = 0; i < 8; i++)
   {
      context->h[i] = htobe32(context->h[i]);
   }

   //Copy the resulting digest
   if(digest != NULL)
   {
      osMemcpy(digest, context->digest, SHA256_DIGEST_SIZE);
   }
}


/**
 * @brief Finish the SHA-256 message digest (no padding added)
 * @param[in] context Pointer to the SHA-256 context
 * @param[out] digest Calculated digest
 **/

__weak_func void sha256FinalRaw(Sha256Context *context, uint8_t *digest)
{
   uint_t i;

   //Convert from host byte order to big-endian byte order
   for(i = 0; i < 8; i++)
   {
      context->h[i] = htobe32(context->h[i]);
   }

   //Copy the resulting digest
   osMemcpy(digest, context->digest, SHA256_DIGEST_SIZE);

   //Convert from big-endian byte order to host byte order
   for(i = 0; i < 8; i++)
   {
      context->h[i] = betoh32(context->h[i]);
   }
}


/**
 * @brief Process message in 16-word blocks
 * @param[in] context Pointer to the SHA-256 context
 **/

__weak_func void sha256ProcessBlock(Sha256Context *context)
{
   uint_t i;
   uint32_t temp1;
   uint32_t temp2;

   //Initialize the 8 working registers
   uint32_t a = context->h[0];
   uint32_t b = context->h[1];
   uint32_t c = context->h[2];
   uint32_t d = context->h[3];
   uint32_t e = context->h[4];
   uint32_t f = context->h[5];
   uint32_t g = context->h[6];
   uint32_t h = context->h[7];

   //Process message in 16-word blocks
   uint32_t *w = context->w;

   //Convert from big-endian byte order to host byte order
   for(i = 0; i < 16; i++)
   {
      w[i] = betoh32(w[i]);
   }

   //SHA-256 hash computation (alternate method)
   for(i = 0; i < 64; i++)
   {
      //Prepare the message schedule
      if(i >= 16)
      {
         W(i) += SIGMA4(W(i + 14)) + W(i + 9) + SIGMA3(W(i + 1));
      }

      //Calculate T1 and T2
      temp1 = h + SIGMA2(e) + CH(e, f, g) + k[i] + W(i);
      temp2 = SIGMA1(a) + MAJ(a, b, c);

      //Update working registers
      h = g;
      g = f;
      f = e;
      e = d + temp1;
      d = c;
      c = b;
      b = a;
      a = temp1 + temp2;
   }

   //Update the hash value
   context->h[0] += a;
   context->h[1] += b;
   context->h[2] += c;
   context->h[3] += d;
   context->h[4] += e;
   context->h[5] += f;
   context->h[6] += g;
   context->h[7] += h;
}

#endif
