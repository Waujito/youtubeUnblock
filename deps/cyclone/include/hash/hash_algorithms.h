/**
 * @file hash_algorithms.h
 * @brief Collection of hash algorithms
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

#ifndef _HASH_ALGORITHMS_H
#define _HASH_ALGORITHMS_H

//Dependencies
#include "core/crypto.h"
#include "hash/sha256.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


#define MAX_HASH_DIGEST_SIZE SHA256_DIGEST_SIZE
#define MAX_HASH_BLOCK_SIZE SHA256_BLOCK_SIZE
/**
 * @brief Generic hash algorithm context
 **/

typedef union
{
   uint8_t digest[MAX_HASH_DIGEST_SIZE];
   Sha256Context sha256Context;
} HashContext;


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
