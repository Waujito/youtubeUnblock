/**
 * @file os_port.h
 * @brief RTOS abstraction layer
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

/**
* Rewrote for youtubeUnblock
*/

#ifndef _OS_PORT_H
#define _OS_PORT_H

//Dependencies
#include "types.h"
#include "compiler_port.h"

//Compilation flags used to enable/disable features
#define ENABLED  1
#define DISABLED 0

#define timeCompare(t1, t2) ((int32_t) ((t1) - (t2)))

//Miscellaneous macros
#if !defined(__AT32F403A_407_LIBRARY_VERSION) && \
   !defined(__AT32F435_437_LIBRARY_VERSION)
  #ifndef FALSE
     #define FALSE 0
  #endif

  #ifndef TRUE
     #define TRUE 1
  #endif
#endif

#ifndef LSB
   #define LSB(x) ((x) & 0xFF)
#endif

#ifndef MSB
   #define MSB(x) (((x) >> 8) & 0xFF)
#endif

#ifndef MIN
   #define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef MAX
   #define MAX(a, b) ((a) > (b) ? (a) : (b))
#endif

#ifndef arraysize
   #define arraysize(a) (sizeof(a) / sizeof(a[0]))
#endif

//Memory management
#ifndef osAllocMem
   #define osAllocMem malloc
#endif
#ifndef osFreeMem
   #define osFreeMem free
#endif

//Fill block of memory
#ifndef osMemset
   #define osMemset(p, value, length) (void) memset(p, value, length)
#endif

//Copy block of memory
#ifndef osMemcpy
   #define osMemcpy(dest, src, length) (void) memcpy(dest, src, length)
#endif

//Move block of memory
#ifndef osMemmove
   #define osMemmove(dest, src, length) (void) memmove(dest, src, length)
#endif

//Compare two blocks of memory
#ifndef osMemcmp
   #define osMemcmp(p1, p2, length) memcmp(p1, p2, length)
#endif

//Search for the first occurrence of a given character
#ifndef osMemchr
   #define osMemchr(p, c, length) memchr(p, c, length)
#endif
#endif
