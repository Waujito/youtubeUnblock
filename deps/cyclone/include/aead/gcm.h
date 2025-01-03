/**
 * @file gcm.h
 * @brief Galois/Counter Mode (GCM)
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

#ifndef _GCM_H
#define _GCM_H

//Dependencies
#include "core/crypto.h"

//Precalculated table width, in bits
#ifndef GCM_TABLE_W
   #define GCM_TABLE_W 4
#elif (GCM_TABLE_W != 4 && GCM_TABLE_W != 8)
   #error GCM_TABLE_W parameter is not valid
#endif

//4-bit or 8-bit precalculated table?
#if (GCM_TABLE_W == 4)
   #define GCM_TABLE_N 16
   #define GCM_REVERSE_BITS(n) reverseInt4(n)
#else
   #define GCM_TABLE_N 256
   #define GCM_REVERSE_BITS(n) reverseInt8(n)
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief GCM context
 **/

typedef struct
{
   const CipherAlgo *cipherAlgo; ///<Cipher algorithm
   void *cipherContext;          ///<Cipher algorithm context
   uint32_t m[GCM_TABLE_N][4];   ///<Precalculated table
} GcmContext;


//GCM related functions
error_t gcmInit(GcmContext *context, const CipherAlgo *cipherAlgo,
   void *cipherContext);

error_t gcmEncrypt(GcmContext *context, const uint8_t *iv,
   size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *p,
   uint8_t *c, size_t length, uint8_t *t, size_t tLen);

error_t gcmDecrypt(GcmContext *context, const uint8_t *iv,
   size_t ivLen, const uint8_t *a, size_t aLen, const uint8_t *c,
   uint8_t *p, size_t length, const uint8_t *t, size_t tLen);

void gcmMul(GcmContext *context, uint8_t *x);
void gcmXorBlock(uint8_t *x, const uint8_t *a, const uint8_t *b, size_t n);
void gcmIncCounter(uint8_t *ctr);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
