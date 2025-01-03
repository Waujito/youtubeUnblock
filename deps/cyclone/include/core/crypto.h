/**
 * @file crypto.h
 * @brief General definitions for cryptographic algorithms
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

#ifndef _CRYPTO_H
#define _CRYPTO_H

//Dependencies
#include "os_port.h"
#include "crypto_config.h"
#include "crypto_legacy.h"
#include "cpu_endian.h"
#include "error.h"


/*
 * CycloneCRYPTO Open is licensed under GPL version 2. In particular:
 *
 * - If you link your program to CycloneCRYPTO Open, the result is a derivative
 *   work that can only be distributed under the same GPL license terms.
 *
 * - If additions or changes to CycloneCRYPTO Open are made, the result is a
 *   derivative work that can only be distributed under the same license terms.
 *
 * - The GPL license requires that you make the source code available to
 *   whoever you make the binary available to.
 *
 * - If you sell or distribute a hardware product that runs CycloneCRYPTO Open,
 *   the GPL license requires you to provide public and full access to all
 *   source code on a nondiscriminatory basis.
 *
 * If you fully understand and accept the terms of the GPL license, then edit
 * the os_port_config.h header and add the following directive:
 *
 * #define GPL_LICENSE_TERMS_ACCEPTED
 */

#ifndef GPL_LICENSE_TERMS_ACCEPTED
#endif

//Version string
#define CYCLONE_CRYPTO_VERSION_STRING "2.4.4"
//Major version
#define CYCLONE_CRYPTO_MAJOR_VERSION 2
//Minor version
#define CYCLONE_CRYPTO_MINOR_VERSION 4
//Revision number
#define CYCLONE_CRYPTO_REV_NUMBER 4

//Static memory allocation
#ifndef CRYPTO_STATIC_MEM_SUPPORT
   #define CRYPTO_STATIC_MEM_SUPPORT DISABLED
#elif (CRYPTO_STATIC_MEM_SUPPORT != ENABLED && CRYPTO_STATIC_MEM_SUPPORT != DISABLED)
   #error CRYPTO_STATIC_MEM_SUPPORT parameter is not valid
#endif

//Multiple precision integer support
#ifndef MPI_SUPPORT
   #define MPI_SUPPORT ENABLED
#elif (MPI_SUPPORT != ENABLED && MPI_SUPPORT != DISABLED)
   #error MPI_SUPPORT parameter is not valid
#endif

//Assembly optimizations for time-critical routines
#ifndef MPI_ASM_SUPPORT
   #define MPI_ASM_SUPPORT DISABLED
#elif (MPI_ASM_SUPPORT != ENABLED && MPI_ASM_SUPPORT != DISABLED)
   #error MPI_ASM_SUPPORT parameter is not valid
#endif

//Base64 encoding support
#ifndef BASE64_SUPPORT
   #define BASE64_SUPPORT ENABLED
#elif (BASE64_SUPPORT != ENABLED && BASE64_SUPPORT != DISABLED)
   #error BASE64_SUPPORT parameter is not valid
#endif

//Base64url encoding support
#ifndef BASE64URL_SUPPORT
   #define BASE64URL_SUPPORT ENABLED
#elif (BASE64URL_SUPPORT != ENABLED && BASE64URL_SUPPORT != DISABLED)
   #error BASE64URL_SUPPORT parameter is not valid
#endif

//Radix64 encoding support
#ifndef RADIX64_SUPPORT
   #define RADIX64_SUPPORT ENABLED
#elif (RADIX64_SUPPORT != ENABLED && RADIX64_SUPPORT != DISABLED)
   #error RADIX64_SUPPORT parameter is not valid
#endif

//MD2 hash support
#ifndef MD2_SUPPORT
   #define MD2_SUPPORT DISABLED
#elif (MD2_SUPPORT != ENABLED && MD2_SUPPORT != DISABLED)
   #error MD2_SUPPORT parameter is not valid
#endif

//MD4 hash support
#ifndef MD4_SUPPORT
   #define MD4_SUPPORT DISABLED
#elif (MD4_SUPPORT != ENABLED && MD4_SUPPORT != DISABLED)
   #error MD4_SUPPORT parameter is not valid
#endif

//MD5 hash support
#ifndef MD5_SUPPORT
   #define MD5_SUPPORT DISABLED
#elif (MD5_SUPPORT != ENABLED && MD5_SUPPORT != DISABLED)
   #error MD5_SUPPORT parameter is not valid
#endif

//RIPEMD-128 hash support
#ifndef RIPEMD128_SUPPORT
   #define RIPEMD128_SUPPORT DISABLED
#elif (RIPEMD128_SUPPORT != ENABLED && RIPEMD128_SUPPORT != DISABLED)
   #error RIPEMD128_SUPPORT parameter is not valid
#endif

//RIPEMD-160 hash support
#ifndef RIPEMD160_SUPPORT
   #define RIPEMD160_SUPPORT DISABLED
#elif (RIPEMD160_SUPPORT != ENABLED && RIPEMD160_SUPPORT != DISABLED)
   #error RIPEMD160_SUPPORT parameter is not valid
#endif

//SHA-1 hash support
#ifndef SHA1_SUPPORT
   #define SHA1_SUPPORT ENABLED
#elif (SHA1_SUPPORT != ENABLED && SHA1_SUPPORT != DISABLED)
   #error SHA1_SUPPORT parameter is not valid
#endif

//SHA-224 hash support
#ifndef SHA224_SUPPORT
   #define SHA224_SUPPORT ENABLED
#elif (SHA224_SUPPORT != ENABLED && SHA224_SUPPORT != DISABLED)
   #error SHA224_SUPPORT parameter is not valid
#endif

//SHA-256 hash support
#ifndef SHA256_SUPPORT
   #define SHA256_SUPPORT ENABLED
#elif (SHA256_SUPPORT != ENABLED && SHA256_SUPPORT != DISABLED)
   #error SHA256_SUPPORT parameter is not valid
#endif

//SHA-384 hash support
#ifndef SHA384_SUPPORT
   #define SHA384_SUPPORT ENABLED
#elif (SHA384_SUPPORT != ENABLED && SHA384_SUPPORT != DISABLED)
   #error SHA384_SUPPORT parameter is not valid
#endif

//SHA-512 hash support
#ifndef SHA512_SUPPORT
   #define SHA512_SUPPORT ENABLED
#elif (SHA512_SUPPORT != ENABLED && SHA512_SUPPORT != DISABLED)
   #error SHA512_SUPPORT parameter is not valid
#endif

//SHA-512/224 hash support
#ifndef SHA512_224_SUPPORT
   #define SHA512_224_SUPPORT DISABLED
#elif (SHA512_224_SUPPORT != ENABLED && SHA512_224_SUPPORT != DISABLED)
   #error SHA512_224_SUPPORT parameter is not valid
#endif

//SHA-512/256 hash support
#ifndef SHA512_256_SUPPORT
   #define SHA512_256_SUPPORT DISABLED
#elif (SHA512_256_SUPPORT != ENABLED && SHA512_256_SUPPORT != DISABLED)
   #error SHA512_256_SUPPORT parameter is not valid
#endif

//SHA3-224 hash support
#ifndef SHA3_224_SUPPORT
   #define SHA3_224_SUPPORT DISABLED
#elif (SHA3_224_SUPPORT != ENABLED && SHA3_224_SUPPORT != DISABLED)
   #error SHA3_224_SUPPORT parameter is not valid
#endif

//SHA3-256 hash support
#ifndef SHA3_256_SUPPORT
   #define SHA3_256_SUPPORT DISABLED
#elif (SHA3_256_SUPPORT != ENABLED && SHA3_256_SUPPORT != DISABLED)
   #error SHA3_256_SUPPORT parameter is not valid
#endif

//SHA3-384 hash support
#ifndef SHA3_384_SUPPORT
   #define SHA3_384_SUPPORT DISABLED
#elif (SHA3_384_SUPPORT != ENABLED && SHA3_384_SUPPORT != DISABLED)
   #error SHA3_384_SUPPORT parameter is not valid
#endif

//SHA3-512 hash support
#ifndef SHA3_512_SUPPORT
   #define SHA3_512_SUPPORT DISABLED
#elif (SHA3_512_SUPPORT != ENABLED && SHA3_512_SUPPORT != DISABLED)
   #error SHA3_512_SUPPORT parameter is not valid
#endif

//SHAKE support
#ifndef SHAKE_SUPPORT
   #define SHAKE_SUPPORT DISABLED
#elif (SHAKE_SUPPORT != ENABLED && SHAKE_SUPPORT != DISABLED)
   #error SHAKE_SUPPORT parameter is not valid
#endif

//cSHAKE support
#ifndef CSHAKE_SUPPORT
   #define CSHAKE_SUPPORT DISABLED
#elif (CSHAKE_SUPPORT != ENABLED && CSHAKE_SUPPORT != DISABLED)
   #error CSHAKE_SUPPORT parameter is not valid
#endif

//Keccak support
#ifndef KECCAK_SUPPORT
   #define KECCAK_SUPPORT DISABLED
#elif (KECCAK_SUPPORT != ENABLED && KECCAK_SUPPORT != DISABLED)
   #error KECCAK_SUPPORT parameter is not valid
#endif

//BLAKE2b support
#ifndef BLAKE2B_SUPPORT
   #define BLAKE2B_SUPPORT DISABLED
#elif (BLAKE2B_SUPPORT != ENABLED && BLAKE2B_SUPPORT != DISABLED)
   #error BLAKE2B_SUPPORT parameter is not valid
#endif

//BLAKE2b-160 hash support
#ifndef BLAKE2B160_SUPPORT
   #define BLAKE2B160_SUPPORT DISABLED
#elif (BLAKE2B160_SUPPORT != ENABLED && BLAKE2B160_SUPPORT != DISABLED)
   #error BLAKE2B160_SUPPORT parameter is not valid
#endif

//BLAKE2b-256 hash support
#ifndef BLAKE2B256_SUPPORT
   #define BLAKE2B256_SUPPORT DISABLED
#elif (BLAKE2B256_SUPPORT != ENABLED && BLAKE2B256_SUPPORT != DISABLED)
   #error BLAKE2B256_SUPPORT parameter is not valid
#endif

//BLAKE2b-384 hash support
#ifndef BLAKE2B384_SUPPORT
   #define BLAKE2B384_SUPPORT DISABLED
#elif (BLAKE2B384_SUPPORT != ENABLED && BLAKE2B384_SUPPORT != DISABLED)
   #error BLAKE2B384_SUPPORT parameter is not valid
#endif

//BLAKE2b-512 hash support
#ifndef BLAKE2B512_SUPPORT
   #define BLAKE2B512_SUPPORT DISABLED
#elif (BLAKE2B512_SUPPORT != ENABLED && BLAKE2B512_SUPPORT != DISABLED)
   #error BLAKE2B512_SUPPORT parameter is not valid
#endif

//BLAKE2s support
#ifndef BLAKE2S_SUPPORT
   #define BLAKE2S_SUPPORT DISABLED
#elif (BLAKE2S_SUPPORT != ENABLED && BLAKE2S_SUPPORT != DISABLED)
   #error BLAKE2S_SUPPORT parameter is not valid
#endif

//BLAKE2s-128 hash support
#ifndef BLAKE2S128_SUPPORT
   #define BLAKE2S128_SUPPORT DISABLED
#elif (BLAKE2S128_SUPPORT != ENABLED && BLAKE2S128_SUPPORT != DISABLED)
   #error BLAKE2S128_SUPPORT parameter is not valid
#endif

//BLAKE2s-160 hash support
#ifndef BLAKE2S160_SUPPORT
   #define BLAKE2S160_SUPPORT DISABLED
#elif (BLAKE2S160_SUPPORT != ENABLED && BLAKE2S160_SUPPORT != DISABLED)
   #error BLAKE2S160_SUPPORT parameter is not valid
#endif

//BLAKE2s-224 hash support
#ifndef BLAKE2S224_SUPPORT
   #define BLAKE2S224_SUPPORT DISABLED
#elif (BLAKE2S224_SUPPORT != ENABLED && BLAKE2S224_SUPPORT != DISABLED)
   #error BLAKE2S224_SUPPORT parameter is not valid
#endif

//BLAKE2s-256 hash support
#ifndef BLAKE2S256_SUPPORT
   #define BLAKE2S256_SUPPORT DISABLED
#elif (BLAKE2S256_SUPPORT != ENABLED && BLAKE2S256_SUPPORT != DISABLED)
   #error BLAKE2S256_SUPPORT parameter is not valid
#endif

//SM3 hash support
#ifndef SM3_SUPPORT
   #define SM3_SUPPORT DISABLED
#elif (SM3_SUPPORT != ENABLED && SM3_SUPPORT != DISABLED)
   #error SM3_SUPPORT parameter is not valid
#endif

//Tiger hash support
#ifndef TIGER_SUPPORT
   #define TIGER_SUPPORT DISABLED
#elif (TIGER_SUPPORT != ENABLED && TIGER_SUPPORT != DISABLED)
   #error TIGER_SUPPORT parameter is not valid
#endif

//Whirlpool hash support
#ifndef WHIRLPOOL_SUPPORT
   #define WHIRLPOOL_SUPPORT DISABLED
#elif (WHIRLPOOL_SUPPORT != ENABLED && WHIRLPOOL_SUPPORT != DISABLED)
   #error WHIRLPOOL_SUPPORT parameter is not valid
#endif

//CMAC support
#ifndef CMAC_SUPPORT
   #define CMAC_SUPPORT DISABLED
#elif (CMAC_SUPPORT != ENABLED && CMAC_SUPPORT != DISABLED)
   #error CMAC_SUPPORT parameter is not valid
#endif

//HMAC support
#ifndef HMAC_SUPPORT
   #define HMAC_SUPPORT ENABLED
#elif (HMAC_SUPPORT != ENABLED && HMAC_SUPPORT != DISABLED)
   #error HMAC_SUPPORT parameter is not valid
#endif

//GMAC support
#ifndef GMAC_SUPPORT
   #define GMAC_SUPPORT DISABLED
#elif (GMAC_SUPPORT != ENABLED && GMAC_SUPPORT != DISABLED)
   #error GMAC_SUPPORT parameter is not valid
#endif

//KMAC support
#ifndef KMAC_SUPPORT
   #define KMAC_SUPPORT DISABLED
#elif (KMAC_SUPPORT != ENABLED && KMAC_SUPPORT != DISABLED)
   #error KMAC_SUPPORT parameter is not valid
#endif

//XCBC-MAC support
#ifndef XCBC_MAC_SUPPORT
   #define XCBC_MAC_SUPPORT DISABLED
#elif (XCBC_MAC_SUPPORT != ENABLED && XCBC_MAC_SUPPORT != DISABLED)
   #error XCBC_MAC_SUPPORT parameter is not valid
#endif

//RC2 block cipher support
#ifndef RC2_SUPPORT
   #define RC2_SUPPORT DISABLED
#elif (RC2_SUPPORT != ENABLED && RC2_SUPPORT != DISABLED)
   #error RC2_SUPPORT parameter is not valid
#endif

//RC4 stream cipher support
#ifndef RC4_SUPPORT
   #define RC4_SUPPORT DISABLED
#elif (RC4_SUPPORT != ENABLED && RC4_SUPPORT != DISABLED)
   #error RC4_SUPPORT parameter is not valid
#endif

//RC6 block cipher support
#ifndef RC6_SUPPORT
   #define RC6_SUPPORT DISABLED
#elif (RC6_SUPPORT != ENABLED && RC6_SUPPORT != DISABLED)
   #error RC6_SUPPORT parameter is not valid
#endif

//CAST-128 block cipher support
#ifndef CAST128_SUPPORT
   #define CAST128_SUPPORT DISABLED
#elif (CAST128_SUPPORT != ENABLED && CAST128_SUPPORT != DISABLED)
   #error CAST128_SUPPORT parameter is not valid
#endif

//CAST-256 block cipher support
#ifndef CAST256_SUPPORT
   #define CAST256_SUPPORT DISABLED
#elif (CAST256_SUPPORT != ENABLED && CAST256_SUPPORT != DISABLED)
   #error CAST256_SUPPORT parameter is not valid
#endif

//IDEA block cipher support
#ifndef IDEA_SUPPORT
   #define IDEA_SUPPORT DISABLED
#elif (IDEA_SUPPORT != ENABLED && IDEA_SUPPORT != DISABLED)
   #error IDEA_SUPPORT parameter is not valid
#endif

//DES block cipher support
#ifndef DES_SUPPORT
   #define DES_SUPPORT DISABLED
#elif (DES_SUPPORT != ENABLED && DES_SUPPORT != DISABLED)
   #error DES_SUPPORT parameter is not valid
#endif

//Triple DES block cipher support
#ifndef DES3_SUPPORT
   #define DES3_SUPPORT DISABLED
#elif (DES3_SUPPORT != ENABLED && DES3_SUPPORT != DISABLED)
   #error DES3_SUPPORT parameter is not valid
#endif

//AES block cipher support
#ifndef AES_SUPPORT
   #define AES_SUPPORT ENABLED
#elif (AES_SUPPORT != ENABLED && AES_SUPPORT != DISABLED)
   #error AES_SUPPORT parameter is not valid
#endif

//Blowfish block cipher support
#ifndef BLOWFISH_SUPPORT
   #define BLOWFISH_SUPPORT DISABLED
#elif (BLOWFISH_SUPPORT != ENABLED && BLOWFISH_SUPPORT != DISABLED)
   #error BLOWFISH_SUPPORT parameter is not valid
#endif

//Twofish block cipher support
#ifndef TWOFISH_SUPPORT
   #define TWOFISH_SUPPORT DISABLED
#elif (TWOFISH_SUPPORT != ENABLED && TWOFISH_SUPPORT != DISABLED)
   #error TWOFISH_SUPPORT parameter is not valid
#endif

//MARS block cipher support
#ifndef MARS_SUPPORT
   #define MARS_SUPPORT DISABLED
#elif (MARS_SUPPORT != ENABLED && MARS_SUPPORT != DISABLED)
   #error MARS_SUPPORT parameter is not valid
#endif

//Serpent block cipher support
#ifndef SERPENT_SUPPORT
   #define SERPENT_SUPPORT DISABLED
#elif (SERPENT_SUPPORT != ENABLED && SERPENT_SUPPORT != DISABLED)
   #error SERPENT_SUPPORT parameter is not valid
#endif

//Camellia block cipher support
#ifndef CAMELLIA_SUPPORT
   #define CAMELLIA_SUPPORT DISABLED
#elif (CAMELLIA_SUPPORT != ENABLED && CAMELLIA_SUPPORT != DISABLED)
   #error CAMELLIA_SUPPORT parameter is not valid
#endif

//ARIA block cipher support
#ifndef ARIA_SUPPORT
   #define ARIA_SUPPORT DISABLED
#elif (ARIA_SUPPORT != ENABLED && ARIA_SUPPORT != DISABLED)
   #error ARIA_SUPPORT parameter is not valid
#endif

//SEED block cipher support
#ifndef SEED_SUPPORT
   #define SEED_SUPPORT DISABLED
#elif (SEED_SUPPORT != ENABLED && SEED_SUPPORT != DISABLED)
   #error SEED_SUPPORT parameter is not valid
#endif

//SM4 block cipher support
#ifndef SM4_SUPPORT
   #define SM4_SUPPORT DISABLED
#elif (SM4_SUPPORT != ENABLED && SM4_SUPPORT != DISABLED)
   #error SM4_SUPPORT parameter is not valid
#endif

//PRESENT block cipher support
#ifndef PRESENT_SUPPORT
   #define PRESENT_SUPPORT DISABLED
#elif (PRESENT_SUPPORT != ENABLED && PRESENT_SUPPORT != DISABLED)
   #error PRESENT_SUPPORT parameter is not valid
#endif

//TEA block cipher support
#ifndef TEA_SUPPORT
   #define TEA_SUPPORT DISABLED
#elif (TEA_SUPPORT != ENABLED && TEA_SUPPORT != DISABLED)
   #error TEA_SUPPORT parameter is not valid
#endif

//XTEA block cipher support
#ifndef XTEA_SUPPORT
   #define XTEA_SUPPORT DISABLED
#elif (XTEA_SUPPORT != ENABLED && XTEA_SUPPORT != DISABLED)
   #error XTEA_SUPPORT parameter is not valid
#endif

//Trivium stream cipher support
#ifndef TRIVIUM_SUPPORT
   #define TRIVIUM_SUPPORT DISABLED
#elif (TRIVIUM_SUPPORT != ENABLED && TRIVIUM_SUPPORT != DISABLED)
   #error TRIVIUM_SUPPORT parameter is not valid
#endif

//ZUC stream cipher support
#ifndef ZUC_SUPPORT
   #define ZUC_SUPPORT DISABLED
#elif (ZUC_SUPPORT != ENABLED && ZUC_SUPPORT != DISABLED)
   #error ZUC_SUPPORT parameter is not valid
#endif

//ECB mode support
#ifndef ECB_SUPPORT
   #define ECB_SUPPORT ENABLED
#elif (ECB_SUPPORT != ENABLED && ECB_SUPPORT != DISABLED)
   #error ECB_SUPPORT parameter is not valid
#endif

//CBC mode support
#ifndef CBC_SUPPORT
   #define CBC_SUPPORT ENABLED
#elif (CBC_SUPPORT != ENABLED && CBC_SUPPORT != DISABLED)
   #error CBC_SUPPORT parameter is not valid
#endif

//CFB mode support
#ifndef CFB_SUPPORT
   #define CFB_SUPPORT ENABLED
#elif (CFB_SUPPORT != ENABLED && CFB_SUPPORT != DISABLED)
   #error CFB_SUPPORT parameter is not valid
#endif

//OFB mode support
#ifndef OFB_SUPPORT
   #define OFB_SUPPORT ENABLED
#elif (OFB_SUPPORT != ENABLED && OFB_SUPPORT != DISABLED)
   #error OFB_SUPPORT parameter is not valid
#endif

//CTR mode support
#ifndef CTR_SUPPORT
   #define CTR_SUPPORT ENABLED
#elif (CTR_SUPPORT != ENABLED && CTR_SUPPORT != DISABLED)
   #error CTR_SUPPORT parameter is not valid
#endif

//XTS mode support
#ifndef XTS_SUPPORT
   #define XTS_SUPPORT ENABLED
#elif (XTS_SUPPORT != ENABLED && XTS_SUPPORT != DISABLED)
   #error XTS_SUPPORT parameter is not valid
#endif

//CCM mode support
#ifndef CCM_SUPPORT
   #define CCM_SUPPORT ENABLED
#elif (CCM_SUPPORT != ENABLED && CCM_SUPPORT != DISABLED)
   #error CCM_SUPPORT parameter is not valid
#endif

//GCM mode support
#ifndef GCM_SUPPORT
   #define GCM_SUPPORT ENABLED
#elif (GCM_SUPPORT != ENABLED && GCM_SUPPORT != DISABLED)
   #error GCM_SUPPORT parameter is not valid
#endif

//SIV mode support
#ifndef SIV_SUPPORT
   #define SIV_SUPPORT DISABLED
#elif (SIV_SUPPORT != ENABLED && SIV_SUPPORT != DISABLED)
   #error SIV_SUPPORT parameter is not valid
#endif

//Salsa20 stream cipher support
#ifndef SALSA20_SUPPORT
   #define SALSA20_SUPPORT DISABLED
#elif (SALSA20_SUPPORT != ENABLED && SALSA20_SUPPORT != DISABLED)
   #error SALSA20_SUPPORT parameter is not valid
#endif

//ChaCha stream cipher support
#ifndef CHACHA_SUPPORT
   #define CHACHA_SUPPORT DISABLED
#elif (CHACHA_SUPPORT != ENABLED && CHACHA_SUPPORT != DISABLED)
   #error CHACHA_SUPPORT parameter is not valid
#endif

//Poly1305 support
#ifndef POLY1305_SUPPORT
   #define POLY1305_SUPPORT DISABLED
#elif (POLY1305_SUPPORT != ENABLED && POLY1305_SUPPORT != DISABLED)
   #error POLY1305_SUPPORT parameter is not valid
#endif

//ChaCha20Poly1305 support
#ifndef CHACHA20_POLY1305_SUPPORT
   #define CHACHA20_POLY1305_SUPPORT DISABLED
#elif (CHACHA20_POLY1305_SUPPORT != ENABLED && CHACHA20_POLY1305_SUPPORT != DISABLED)
   #error CHACHA20_POLY1305_SUPPORT parameter is not valid
#endif

//Diffie-Hellman support
#ifndef DH_SUPPORT
   #define DH_SUPPORT DISABLED
#elif (DH_SUPPORT != ENABLED && DH_SUPPORT != DISABLED)
   #error DH_SUPPORT parameter is not valid
#endif

//RSA support
#ifndef RSA_SUPPORT
   #define RSA_SUPPORT ENABLED
#elif (RSA_SUPPORT != ENABLED && RSA_SUPPORT != DISABLED)
   #error RSA_SUPPORT parameter is not valid
#endif

//DSA support
#ifndef DSA_SUPPORT
   #define DSA_SUPPORT DISABLED
#elif (DSA_SUPPORT != ENABLED && DSA_SUPPORT != DISABLED)
   #error DSA_SUPPORT parameter is not valid
#endif

//Elliptic curve cryptography support
#ifndef EC_SUPPORT
   #define EC_SUPPORT ENABLED
#elif (EC_SUPPORT != ENABLED && EC_SUPPORT != DISABLED)
   #error EC_SUPPORT parameter is not valid
#endif

//ECDH support
#ifndef ECDH_SUPPORT
   #define ECDH_SUPPORT ENABLED
#elif (ECDH_SUPPORT != ENABLED && ECDH_SUPPORT != DISABLED)
   #error ECDH_SUPPORT parameter is not valid
#endif

//ECDSA support
#ifndef ECDSA_SUPPORT
   #define ECDSA_SUPPORT ENABLED
#elif (ECDSA_SUPPORT != ENABLED && ECDSA_SUPPORT != DISABLED)
   #error ECDSA_SUPPORT parameter is not valid
#endif

//ML-KEM-512 key encapsulation mechanism support
#ifndef MLKEM512_SUPPORT
   #define MLKEM512_SUPPORT DISABLED
#elif (MLKEM512_SUPPORT != ENABLED && MLKEM512_SUPPORT != DISABLED)
   #error MLKEM512_SUPPORT parameter is not valid
#endif

//ML-KEM-768 key encapsulation mechanism support
#ifndef MLKEM768_SUPPORT
   #define MLKEM768_SUPPORT DISABLED
#elif (MLKEM768_SUPPORT != ENABLED && MLKEM768_SUPPORT != DISABLED)
   #error MLKEM768_SUPPORT parameter is not valid
#endif

//ML-KEM-1024 key encapsulation mechanism support
#ifndef MLKEM1024_SUPPORT
   #define MLKEM1024_SUPPORT DISABLED
#elif (MLKEM1024_SUPPORT != ENABLED && MLKEM1024_SUPPORT != DISABLED)
   #error MLKEM1024_SUPPORT parameter is not valid
#endif

//Streamlined NTRU Prime 761 key encapsulation mechanism support
#ifndef SNTRUP761_SUPPORT
   #define SNTRUP761_SUPPORT DISABLED
#elif (SNTRUP761_SUPPORT != ENABLED && SNTRUP761_SUPPORT != DISABLED)
   #error SNTRUP761_SUPPORT parameter is not valid
#endif

//HKDF support
#ifndef HKDF_SUPPORT
   #define HKDF_SUPPORT DISABLED
#elif (HKDF_SUPPORT != ENABLED && HKDF_SUPPORT != DISABLED)
   #error HKDF_SUPPORT parameter is not valid
#endif

//PBKDF support
#ifndef PBKDF_SUPPORT
   #define PBKDF_SUPPORT DISABLED
#elif (PBKDF_SUPPORT != ENABLED && PBKDF_SUPPORT != DISABLED)
   #error PBKDF_SUPPORT parameter is not valid
#endif

//Concat KDF support
#ifndef CONCAT_KDF_SUPPORT
   #define CONCAT_KDF_SUPPORT DISABLED
#elif (CONCAT_KDF_SUPPORT != ENABLED && CONCAT_KDF_SUPPORT != DISABLED)
   #error CONCAT_KDF_SUPPORT parameter is not valid
#endif

//bcrypt support
#ifndef BCRYPT_SUPPORT
   #define BCRYPT_SUPPORT DISABLED
#elif (BCRYPT_SUPPORT != ENABLED && BCRYPT_SUPPORT != DISABLED)
   #error BCRYPT_SUPPORT parameter is not valid
#endif

//scrypt support
#ifndef SCRYPT_SUPPORT
   #define SCRYPT_SUPPORT DISABLED
#elif (SCRYPT_SUPPORT != ENABLED && SCRYPT_SUPPORT != DISABLED)
   #error SCRYPT_SUPPORT parameter is not valid
#endif

//MD5-crypt support
#ifndef MD5_CRYPT_SUPPORT
   #define MD5_CRYPT_SUPPORT DISABLED
#elif (MD5_CRYPT_SUPPORT != ENABLED && MD5_CRYPT_SUPPORT != DISABLED)
   #error MD5_CRYPT_SUPPORT parameter is not valid
#endif

//SHA-crypt support
#ifndef SHA_CRYPT_SUPPORT
   #define SHA_CRYPT_SUPPORT DISABLED
#elif (SHA_CRYPT_SUPPORT != ENABLED && SHA_CRYPT_SUPPORT != DISABLED)
   #error SHA_CRYPT_SUPPORT parameter is not valid
#endif

//Yarrow PRNG support
#ifndef YARROW_SUPPORT
   #define YARROW_SUPPORT ENABLED
#elif (YARROW_SUPPORT != ENABLED && YARROW_SUPPORT != DISABLED)
   #error YARROW_SUPPORT parameter is not valid
#endif

//Object identifier support
#ifndef OID_SUPPORT
   #define OID_SUPPORT ENABLED
#elif (OID_SUPPORT != ENABLED && OID_SUPPORT != DISABLED)
   #error OID_SUPPORT parameter is not valid
#endif

//ASN.1 syntax support
#ifndef ASN1_SUPPORT
   #define ASN1_SUPPORT ENABLED
#elif (ASN1_SUPPORT != ENABLED && ASN1_SUPPORT != DISABLED)
   #error ASN1_SUPPORT parameter is not valid
#endif

//PEM file support
#ifndef PEM_SUPPORT
   #define PEM_SUPPORT ENABLED
#elif (PEM_SUPPORT != ENABLED && PEM_SUPPORT != DISABLED)
   #error PEM_SUPPORT parameter is not valid
#endif

//X.509 certificate support
#ifndef X509_SUPPORT
   #define X509_SUPPORT ENABLED
#elif (X509_SUPPORT != ENABLED && X509_SUPPORT != DISABLED)
   #error X509_SUPPORT parameter is not valid
#endif

//PKCS #5 support
#ifndef PKCS5_SUPPORT
   #define PKCS5_SUPPORT DISABLED
#elif (PKCS5_SUPPORT != ENABLED && PKCS5_SUPPORT != DISABLED)
   #error PKCS5_SUPPORT parameter is not valid
#endif

//Allocate memory block
#ifndef cryptoAllocMem
   #define cryptoAllocMem(size) osAllocMem(size)
#endif

//Deallocate memory block
#ifndef cryptoFreeMem
   #define cryptoFreeMem(p) osFreeMem(p)
#endif

//Rotate left operation
#define ROL8(a, n) (((a) << (n)) | ((a) >> (8 - (n))))
#define ROL16(a, n) (((a) << (n)) | ((a) >> (16 - (n))))
#define ROL32(a, n) (((a) << (n)) | ((a) >> (32 - (n))))
#define ROL64(a, n) (((a) << (n)) | ((a) >> (64 - (n))))

//Rotate right operation
#define ROR8(a, n) (((a) >> (n)) | ((a) << (8 - (n))))
#define ROR16(a, n) (((a) >> (n)) | ((a) << (16 - (n))))
#define ROR32(a, n) (((a) >> (n)) | ((a) << (32 - (n))))
#define ROR64(a, n) (((a) >> (n)) | ((a) << (64 - (n))))

//Shift left operation
#define SHL8(a, n) ((a) << (n))
#define SHL16(a, n) ((a) << (n))
#define SHL32(a, n) ((a) << (n))
#define SHL64(a, n) ((a) << (n))

//Shift right operation
#define SHR8(a, n) ((a) >> (n))
#define SHR16(a, n) ((a) >> (n))
#define SHR32(a, n) ((a) >> (n))
#define SHR64(a, n) ((a) >> (n))

//Micellaneous macros
#define _U8(x) ((uint8_t) (x))
#define _U16(x) ((uint16_t) (x))
#define _U32(x) ((uint32_t) (x))
#define _U64(x) ((uint64_t) (x))

//Test if a 8-bit integer is zero
#define CRYPTO_TEST_Z_8(a) \
   _U8((_U8((_U8(a) | (~_U8(a) + 1U))) >> 7U) ^ 1U)

//Test if a 8-bit integer is nonzero
#define CRYPTO_TEST_NZ_8(a) \
   _U8(_U8((_U8(a) | (~_U8(a) + 1U))) >> 7U)

//Test if two 8-bit integers are equal
#define CRYPTO_TEST_EQ_8(a, b) \
   _U8((_U8(((_U8(a) ^ _U8(b)) | (~(_U8(a) ^ _U8(b)) + 1U))) >> 7U) ^ 1U)

//Test if two 8-bit integers are not equal
#define CRYPTO_TEST_NEQ_8(a, b) \
   _U8(_U8(((_U8(a) ^ _U8(b)) | (~(_U8(a) ^ _U8(b)) + 1U))) >> 7U)

//Test if a 8-bit integer is lower than another 8-bit integer
#define CRYPTO_TEST_LT_8(a, b) \
   _U8(_U8((((_U8(a) - _U8(b)) ^ _U8(b)) | (_U8(a) ^ _U8(b))) ^ _U8(a)) >> 7U)

//Test if a 8-bit integer is lower or equal than another 8-bit integer
#define CRYPTO_TEST_LTE_8(a, b) \
   _U8((_U8((((_U8(b) - _U8(a)) ^ _U8(a)) | (_U8(a) ^ _U8(b))) ^ _U8(b)) >> 7U) ^ 1U)

//Test if a 8-bit integer is greater than another 8-bit integer
#define CRYPTO_TEST_GT_8(a, b) \
   _U8(_U8((((_U8(b) - _U8(a)) ^ _U8(a)) | (_U8(a) ^ _U8(b))) ^ _U8(b)) >> 7U)

//Test if a 8-bit integer is greater or equal than another 8-bit integer
#define CRYPTO_TEST_GTE_8(a, b) \
   _U8((_U8((((_U8(a) - _U8(b)) ^ _U8(b)) | (_U8(a) ^ _U8(b))) ^ _U8(a)) >> 7U) ^ 1U)

//Select between two 8-bit integers
#define CRYPTO_SELECT_8(a, b, c) \
   _U8((_U8(a) & (_U8(c) - 1U)) | (_U8(b) & ~(_U8(c) - 1U)))

//Test if a 16-bit integer is zero
#define CRYPTO_TEST_Z_16(a) \
   _U16((_U16((_U16(a) | (~_U16(a) + 1U))) >> 15U) ^ 1U)

//Test if a 16-bit integer is nonzero
#define CRYPTO_TEST_NZ_16(a) \
   _U16(_U16((_U16(a) | (~_U16(a) + 1U))) >> 15U)

//Test if two 16-bit integers are equal
#define CRYPTO_TEST_EQ_16(a, b) \
   _U16((_U16(((_U16(a) ^ _U16(b)) | (~(_U16(a) ^ _U16(b)) + 1U))) >> 15U) ^ 1U)

//Test if two 16-bit integers are not equal
#define CRYPTO_TEST_NEQ_16(a, b) \
   _U16(_U16(((_U16(a) ^ _U16(b)) | (~(_U16(a) ^ _U16(b)) + 1U))) >> 15U)

//Test if a 16-bit integer is lower than another 16-bit integer
#define CRYPTO_TEST_LT_16(a, b) \
   _U16(_U16((((_U16(a) - _U16(b)) ^ _U16(b)) | (_U16(a) ^ _U16(b))) ^ _U16(a)) >> 15U)

//Test if a 16-bit integer is lower or equal than another 16-bit integer
#define CRYPTO_TEST_LTE_16(a, b) \
   _U16((_U16((((_U16(b) - _U16(a)) ^ _U16(a)) | (_U16(a) ^ _U16(b))) ^ _U16(b)) >> 15U) ^ 1U)

//Test if a 16-bit integer is greater than another 16-bit integer
#define CRYPTO_TEST_GT_16(a, b) \
   _U16(_U16((((_U16(b) - _U16(a)) ^ _U16(a)) | (_U16(a) ^ _U16(b))) ^ _U16(b)) >> 15U)

//Test if a 16-bit integer is greater or equal than another 16-bit integer
#define CRYPTO_TEST_GTE_16(a, b) \
   _U16((_U16((((_U16(a) - _U16(b)) ^ _U16(b)) | (_U16(a) ^ _U16(b))) ^ _U16(a)) >> 15U) ^ 1U)

//Select between two 16-bit integers
#define CRYPTO_SELECT_16(a, b, c) \
   _U16((_U16(a) & (_U16(c) - 1U)) | (_U16(b) & ~(_U16(c) - 1U)))

//Test if a 32-bit integer is zero
#define CRYPTO_TEST_Z_32(a) \
   _U32((_U32((_U32(a) | (~_U32(a) + 1U))) >> 31U) ^ 1U)

//Test if a 32-bit integer is nonzero
#define CRYPTO_TEST_NZ_32(a) \
   _U32(_U32((_U32(a) | (~_U32(a) + 1U))) >> 31U)

//Test if two 32-bit integers are equal
#define CRYPTO_TEST_EQ_32(a, b) \
   _U32((_U32(((_U32(a) ^ _U32(b)) | (~(_U32(a) ^ _U32(b)) + 1U))) >> 31U) ^ 1U)

//Test if two 32-bit integers are not equal
#define CRYPTO_TEST_NEQ_32(a, b) \
   _U32(_U32(((_U32(a) ^ _U32(b)) | (~(_U32(a) ^ _U32(b)) + 1U))) >> 31U)

//Test if a 32-bit integer is lower than another 32-bit integer
#define CRYPTO_TEST_LT_32(a, b) \
   _U32(_U32((((_U32(a) - _U32(b)) ^ _U32(b)) | (_U32(a) ^ _U32(b))) ^ _U32(a)) >> 31U)

//Test if a 32-bit integer is lower or equal than another 32-bit integer
#define CRYPTO_TEST_LTE_32(a, b) \
   _U32((_U32((((_U32(b) - _U32(a)) ^ _U32(a)) | (_U32(a) ^ _U32(b))) ^ _U32(b)) >> 31U) ^ 1U)

//Test if a 32-bit integer is greater than another 32-bit integer
#define CRYPTO_TEST_GT_32(a, b) \
   _U32(_U32((((_U32(b) - _U32(a)) ^ _U32(a)) | (_U32(a) ^ _U32(b))) ^ _U32(b)) >> 31U)

//Test if a 32-bit integer is greater or equal than another 32-bit integer
#define CRYPTO_TEST_GTE_32(a, b) \
   _U32((_U32((((_U32(a) - _U32(b)) ^ _U32(b)) | (_U32(a) ^ _U32(b))) ^ _U32(a)) >> 31U) ^ 1U)

//Select between two 32-bit integers
#define CRYPTO_SELECT_32(a, b, c) \
   _U32((_U32(a) & (_U32(c) - 1U)) | (_U32(b) & ~(_U32(c) - 1U)))

//Select between two 64-bit integers
#define CRYPTO_SELECT_64(a, b, c) \
   _U64((_U64(a) & (_U64(c) - 1U)) | (_U64(b) & ~(_U64(c) - 1U)))

//Forward declaration of PrngAlgo structure
struct _PrngAlgo;
#define PrngAlgo struct _PrngAlgo

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif


/**
 * @brief Encryption algorithm type
 **/

typedef enum
{
   CIPHER_ALGO_TYPE_STREAM = 0,
   CIPHER_ALGO_TYPE_BLOCK  = 1
} CipherAlgoType;


/**
 * @brief Cipher operation modes
 **/

typedef enum
{
   CIPHER_MODE_NULL              = 0,
   CIPHER_MODE_STREAM            = 1,
   CIPHER_MODE_ECB               = 2,
   CIPHER_MODE_CBC               = 3,
   CIPHER_MODE_CFB               = 4,
   CIPHER_MODE_OFB               = 5,
   CIPHER_MODE_CTR               = 6,
   CIPHER_MODE_CCM               = 7,
   CIPHER_MODE_GCM               = 8,
   CIPHER_MODE_CHACHA20_POLY1305 = 9,
} CipherMode;


/**
 * @brief Data chunk descriptor
 **/

typedef struct
{
   const void *buffer;
   size_t length;
} DataChunk;


//Common API for hash algorithms
typedef error_t (*HashAlgoCompute)(const void *data, size_t length,
   uint8_t *digest);

typedef void (*HashAlgoInit)(void *context);

typedef void (*HashAlgoUpdate)(void *context, const void *data, size_t length);

typedef void (*HashAlgoFinal)(void *context, uint8_t *digest);

typedef void (*HashAlgoFinalRaw)(void *context, uint8_t *digest);

//Common API for encryption algorithms
typedef error_t (*CipherAlgoInit)(void *context, const uint8_t *key,
   size_t keyLen);

typedef void (*CipherAlgoEncryptStream)(void *context, const uint8_t *input,
   uint8_t *output, size_t length);

typedef void (*CipherAlgoDecryptStream)(void *context, const uint8_t *input,
   uint8_t *output, size_t length);

typedef void (*CipherAlgoEncryptBlock)(void *context, const uint8_t *input,
   uint8_t *output);

typedef void (*CipherAlgoDecryptBlock)(void *context, const uint8_t *input,
   uint8_t *output);

typedef void (*CipherAlgoDeinit)(void *context);

//Common interface for key encapsulation mechanisms (KEM)
typedef error_t (*KemAlgoGenerateKeyPair)(const PrngAlgo *prngAlgo,
   void *prngContext, uint8_t *pk, uint8_t *sk);

typedef error_t (*KemAlgoEncapsulate)(const PrngAlgo *prngAlgo,
   void *prngContext, uint8_t *ct, uint8_t *ss, const uint8_t *pk);

typedef error_t (*KemAlgoDecapsulate)(uint8_t *ss, const uint8_t *ct,
   const uint8_t *sk);

//Common API for pseudo-random number generators (PRNG)
typedef error_t (*PrngAlgoInit)(void *context);

typedef error_t (*PrngAlgoSeed)(void *context, const uint8_t *input,
   size_t length);

typedef error_t (*PrngAlgoAddEntropy)(void *context, uint_t source,
   const uint8_t *input, size_t length, size_t entropy);

typedef error_t (*PrngAlgoRead)(void *context, uint8_t *output, size_t length);

typedef void (*PrngAlgoDeinit)(void *context);


/**
 * @brief Common interface for hash algorithms
 **/

typedef struct
{
   const char_t *name;
   const uint8_t *oid;
   size_t oidSize;
   size_t contextSize;
   size_t blockSize;
   size_t digestSize;
   size_t minPadSize;
   bool_t bigEndian;
   HashAlgoCompute compute;
   HashAlgoInit init;
   HashAlgoUpdate update;
   HashAlgoFinal final;
   HashAlgoFinalRaw finalRaw;
} HashAlgo;


/**
 * @brief Common interface for encryption algorithms
 **/

typedef struct
{
   const char_t *name;
   size_t contextSize;
   CipherAlgoType type;
   size_t blockSize;
   CipherAlgoInit init;
   CipherAlgoEncryptStream encryptStream;
   CipherAlgoDecryptStream decryptStream;
   CipherAlgoEncryptBlock encryptBlock;
   CipherAlgoDecryptBlock decryptBlock;
   CipherAlgoDeinit deinit;
} CipherAlgo;


/**
 * @brief Common interface for key encapsulation mechanisms (KEM)
 **/

typedef struct
{
   const char_t *name;
   size_t publicKeySize;
   size_t secretKeySize;
   size_t ciphertextSize;
   size_t sharedSecretSize;
   KemAlgoGenerateKeyPair generateKeyPair;
   KemAlgoEncapsulate encapsulate;
   KemAlgoDecapsulate decapsulate;
} KemAlgo;


/**
 * @brief Common interface for pseudo-random number generators (PRNG)
 **/

struct _PrngAlgo
{
   const char_t *name;
   size_t contextSize;
   PrngAlgoInit init;
   PrngAlgoSeed seed;
   PrngAlgoAddEntropy addEntropy;
   PrngAlgoRead read;
   PrngAlgoDeinit deinit;
};


//C++ guard
#ifdef __cplusplus
}
#endif

#endif
