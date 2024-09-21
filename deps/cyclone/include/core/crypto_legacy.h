/**
 * @file crypto_legacy.h
 * @brief Legacy definitions
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

#ifndef _CRYPTO_LEGACY_H
#define _CRYPTO_LEGACY_H

//Deprecated functions
#define mpiReadRaw(r, data, length) mpiImport(r, data, length, MPI_FORMAT_BIG_ENDIAN)
#define mpiWriteRaw(a, data, length) mpiExport(a, data, length, MPI_FORMAT_BIG_ENDIAN)

#ifdef CURVE25519_SUPPORT
   #define X25519_SUPPORT CURVE25519_SUPPORT
#endif

#ifdef CURVE448_SUPPORT
   #define X448_SUPPORT CURVE448_SUPPORT
#endif

#define ecdsaGenerateKeyPair ecGenerateKeyPair
#define ecdsaGeneratePrivateKey ecGeneratePrivateKey
#define ecdsaGeneratePublicKey ecGeneratePublicKey

#define MAX_HASH_CONTEXT_SIZE sizeof(HashContext)
#define MAX_CIPHER_CONTEXT_SIZE sizeof(CipherContext)

#ifdef SAMD51_CRYPTO_PUKCC_SUPPORT
   #define SAMD51_CRYPTO_PKC_SUPPORT SAMD51_CRYPTO_PUKCC_SUPPORT
#endif

#ifdef SAME54_CRYPTO_PUKCC_SUPPORT
   #define SAME54_CRYPTO_PKC_SUPPORT SAME54_CRYPTO_PUKCC_SUPPORT
#endif

#define yarrowRelease yarrowDeinit

#define X509CertificateInfo X509CertInfo
#define X509SignatureAlgoId X509SignAlgoId

#define EddsaMessageChunk DataChunk

#endif
