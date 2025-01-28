/**
 * @file compiler_port.h
 * @brief Compiler specific definitions
 *
 * @section License
 *
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Copyright (C) 2010-2024 Oryx Embedded SARL. All rights reserved.
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

#ifndef _COMPILER_PORT_H
#define _COMPILER_PORT_H

//Dependencies
#include "types.h"

//ARM compiler V6?
#if defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
   #include <stdarg.h>
#endif

//C++ guard
#ifdef __cplusplus
extern "C" {
#endif

//Types
typedef char char_t;
typedef signed int int_t;
typedef unsigned int uint_t;

#if !defined(R_TYPEDEFS_H) && !defined(USE_CHIBIOS_2)
   typedef int bool_t;
#endif

//ARM compiler?
#if defined(__CC_ARM)
   #undef PRIu8
   #undef PRIu16
   #define PRIu8 "u"
   #define PRIu16 "u"
   #define PRIuSIZE "u"
   #define PRIXSIZE "X"
   #define PRIuTIME "lu"
//Microchip XC32 compiler?
#elif defined(__XC32)
   #if defined(__C32_LEGACY_LIBC__)
      #define PRIuSIZE "lu"
      #define PRIXSIZE "lX"
      #define PRIuTIME "lu"
   #else
      #define PRIuSIZE "u"
      #define PRIXSIZE "X"
      #define PRIuTIME "u"
   #endif
//NXP MCUXpresso compiler?
#elif defined(__MCUXPRESSO)
   #undef PRIu64
   #define PRIu64 "llu"
   #define PRIuSIZE "u"
   #define PRIXSIZE "X"
   #define PRIuTIME "lu"
//NXP CodeWarrior compiler?
#elif defined(__CWCC__)
   #define PRIu8 "u"
   #define PRIu16 "u"
   #define PRIu32 "u"
   #define PRIx8 "x"
   #define PRIx16 "x"
   #define PRIx32 "x"
   #define PRIX8 "X"
   #define PRIX16 "X"
   #define PRIX32 "X"
   #define PRIuSIZE "u"
   #define PRIXSIZE "X"
   #define PRIuTIME "u"
//Espressif ESP-IDF compiler?
#elif defined(IDF_VER)
   #undef PRIu8
   #undef PRIu16
   #undef PRIx8
   #undef PRIx16
   #undef PRIX8
   #undef PRIX16
   #define PRIu8 "u"
   #define PRIu16 "u"
   #define PRIx8 "x"
   #define PRIx16 "x"
   #define PRIX8 "X"
   #define PRIX16 "X"
   #define PRIuSIZE "u"
   #define PRIXSIZE "X"
   #define PRIuTIME "lu"
//Linux/FreeBSD GCC compiler
#elif defined(__linux__) || defined(__FreeBSD__)
   #define PRIuSIZE "zu"
   #define PRIXSIZE "zX"
   #define PRIuTIME "lu"
//Win32 compiler?
#elif defined(_WIN32)
   #define PRIuSIZE "Iu"
   #define PRIXSIZE "IX"
   #define PRIuTIME "lu"
//GCC compiler (with newlib-nano runtime library)?
#elif defined(__GNUC__) && defined(_NANO_FORMATTED_IO) && (_NANO_FORMATTED_IO != 0)
   #undef PRIu8
   #undef PRIu16
   #undef PRIx8
   #undef PRIx16
   #undef PRIX8
   #undef PRIX16
   #define PRIu8 "u"
   #define PRIu16 "u"
   #define PRIx8 "x"
   #define PRIx16 "x"
   #define PRIX8 "X"
   #define PRIX16 "X"
   #define PRIuSIZE "u"
   #define PRIXSIZE "X"
   #define PRIuTIME "u"
//GCC compiler (with newlib-standard runtime library)?
#else
   #define PRIuSIZE "u"
   #define PRIXSIZE "X"
   #define PRIuTIME "lu"
#endif

//ARM compiler V6?
#if defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
   int vsnprintf(char *dest, size_t size, const char *format, va_list ap);
   char *strtok_r(char *s, const char *delim, char **last);
//GCC compiler (for PowerPC architecture)?
#elif defined(__GNUC__) && defined(__PPC_EABI__)
   typedef uint32_t time_t;
   int strcasecmp(const char *s1, const char *s2);
   int strncasecmp(const char *s1, const char *s2, size_t n);
   char *strtok_r(char *s, const char *delim, char **last);
//GCC compiler?
#elif defined(__GNUC__)
   int strcasecmp(const char *s1, const char *s2);
   int strncasecmp(const char *s1, const char *s2, size_t n);
#if !(_SVID_SOURCE || _BSD_SOURCE || _POSIX_C_SOURCE >= 1 || _XOPEN_SOURCE || _POSIX_SOURCE)
   char *strtok_r(char *s, const char *delim, char **last);
#endif

//Tasking compiler?
#elif defined(__TASKING__)
   char *strtok_r(char *s, const char *delim, char **last);
//Microchip XC32 compiler?
#elif defined(__XC32)
   #define sprintf _sprintf
   int sprintf(char *str, const char *format, ...);
   int strcasecmp(const char *s1, const char *s2);
   int strncasecmp(const char *s1, const char *s2, size_t n);
   char *strtok_r(char *s, const char *delim, char **last);
//NXP CodeWarrior compiler?
#elif defined(__CWCC__)
   typedef uint32_t time_t;
   int strcasecmp(const char *s1, const char *s2);
   int strncasecmp(const char *s1, const char *s2, size_t n);
   char *strtok_r(char *s, const char *delim, char **last);
//Renesas CC-RX compiler?
#elif defined(__CCRX__)
   int strcasecmp(const char *s1, const char *s2);
   int strncasecmp(const char *s1, const char *s2, size_t n);
   char *strtok_r(char *s, const char *delim, char **last);
//TI ARM compiler?
#elif defined(__TI_ARM__)
   int strcasecmp(const char *s1, const char *s2);
   int strncasecmp(const char *s1, const char *s2, size_t n);
   char *strtok_r(char *s, const char *delim, char **last);
#endif

//ARM compiler V6?
#if defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
   #undef __packed_struct
   #define __packed_struct struct __attribute__((packed))
   #undef __packed_union
   #define __packed_union union __attribute__((packed))
//GCC compiler?
#elif defined(__GNUC__)
   #undef __packed_struct
   #define __packed_struct struct __attribute__((__packed__))
   #undef __packed_union
   #define __packed_union union __attribute__((__packed__))
//ARM compiler?
#elif defined(__CC_ARM)
   #pragma anon_unions
   #undef __packed_struct
   #define __packed_struct __packed struct
   #undef __packed_union
   #define __packed_union __packed union
//IAR compiler?
#elif defined(__IAR_SYSTEMS_ICC__)
   #undef __packed_struct
   #define __packed_struct __packed struct
   #undef __packed_union
   #define __packed_union __packed union
//Tasking compiler?
#elif defined(__TASKING__)
   #undef __packed_struct
   #define __packed_struct struct __packed__
   #undef __packed_union
   #define __packed_union union __packed__
//NXP CodeWarrior compiler?
#elif defined(__CWCC__)
   #undef __packed_struct
   #define __packed_struct struct
   #undef __packed_union
   #define __packed_union union
//Renesas CC-RX compiler?
#elif defined(__CCRX__)
   #undef __packed_struct
   #define __packed_struct struct
   #undef __packed_union
   #define __packed_union union
//TI ARM compiler?
#elif defined(__TI_ARM__)
   #undef __packed_struct
   #define __packed_struct struct __attribute__((__packed__))
   #undef __packed_union
   #define __packed_union union __attribute__((__packed__))
//Win32 compiler?
#elif defined(_WIN32)
   #undef interface
   #undef __packed_struct
   #define __packed_struct struct
   #undef __packed_union
   #define __packed_union union
#endif

#ifndef __weak_func
   //ARM compiler V6?
   #if defined(__ARMCC_VERSION) && (__ARMCC_VERSION >= 6010050)
      #define __weak_func __attribute__((weak))
   //GCC compiler?
   #elif defined(__GNUC__)
      #define __weak_func __attribute__((weak))
   //ARM compiler?
   #elif defined(__CC_ARM)
      #define __weak_func __weak
   //IAR compiler?
   #elif defined(__IAR_SYSTEMS_ICC__)
      #define __weak_func __weak
   //Tasking compiler?
   #elif defined(__TASKING__)
      #define __weak_func __attribute__((weak))
   //NXP CodeWarrior compiler?
   #elif defined(__CWCC__)
      #define __weak_func
   //Renesas CC-RX compiler?
   #elif defined(__CCRX__)
      #define __weak_func
   //TI ARM compiler?
   #elif defined(__TI_ARM__)
      #define __weak_func __attribute__((weak))
   //Win32 compiler?
   #elif defined(_WIN32)
      #define __weak_func
   #endif
#endif

//C++ guard
#ifdef __cplusplus
}
#endif

#endif
