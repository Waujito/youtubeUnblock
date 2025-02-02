/*
  youtubeUnblock - https://github.com/Waujito/youtubeUnblock

  Copyright (C) 2024-2025 Vadim Vetrov <vetrovvd@gmail.com>

  This program is free software: you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation, either version 3 of the License, or
  (at your option) any later version.
  
  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.
  
  You should have received a copy of the GNU General Public License
  along with this program.  If not, see <https://www.gnu.org/licenses/>.
*/

/**
 * This is slightly optimized Aho-Corasick implementation 
 *
 * Big thanks to e-maxx http://e-maxx.ru/algo/aho_corasick
 * for the best description and reference code samples
 *
 */

/**
 *
 * This algorithm allows us to search inside the string
 * for a list of patterns in the linear time.
 *
 * The algorithm will lazily initialize itself while 
 * youtubeUnblock works. Lazy initializations considered 
 * safe for multithreading and operate without atomicity 
 * or synchronization primitives.
 *
 */

#ifndef TRIE_H
#define TRIE_H

#include "types.h"

// ASCII alphabet
#define TRIE_ALPHABET 128
// Maximum of vertexes in the trie
#define NMAX ((1 << 15) - 1)

struct trie_vertex {
	int leaf; // boolean flag
	int depth; // depth of tree (length of substring)
	int p; // parent
	uint8_t pch; // vertex char
	int link; // sufflink
	int16_t go[TRIE_ALPHABET]; // dynamically filled pushes
};
 
struct trie_container {
	struct trie_vertex *vx;
	size_t arrsz;
	size_t sz;
};

#define TRIE_STARTSZ 32
int trie_init(struct trie_container *trie);
void trie_destroy(struct trie_container *trie);

int trie_add_string(struct trie_container *trie, 
	       const uint8_t *str, size_t strlen);

/**
 * Aligns the pattern to the end 
 */
#define TRIE_OPT_MAP_TO_END (1 << 1)

/**
 * Searches the string for the patterns.
 * flags is TRIE_OPT binary mask with options for search.
 * offset, offlen are destination variables with 
 * offset of the given string and length of target.
 *
 * returns 1 if target found, 0 otherwise
 */
int trie_process_str(
	struct trie_container *trie,
	const uint8_t *str, size_t strlen,
	int flags,
	size_t *offset, size_t *offlen
);

#endif
