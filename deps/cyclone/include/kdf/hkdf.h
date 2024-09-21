/**
 * @file hkdf.h
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
 * @author Oryx Embedded SARL (www.oryx-embedded.com)
 * @version 2.4.4
 **/

#ifndef _HKDF_H
#define _HKDF_H

//Dependencies
#include "core/crypto.h"

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//HKDF related functions
error_t hkdf(const HashAlgo *hash, const uint8_t *ikm, size_t ikmLen,
   const uint8_t *salt, size_t saltLen, const uint8_t *info, size_t infoLen,
   uint8_t *okm, size_t okmLen);

error_t hkdfExtract(const HashAlgo *hash, const uint8_t *ikm, size_t ikmLen,
   const uint8_t *salt, size_t saltLen, uint8_t *prk);

error_t hkdfExpand(const HashAlgo *hash, const uint8_t *prk, size_t prkLen,
   const uint8_t *info, size_t infoLen, uint8_t *okm, size_t okmLen);

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
