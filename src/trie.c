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
 */

#include "trie.h"

int trie_init(struct trie_container *trie) {
	void *vx = malloc(sizeof(struct trie_vertex) * TRIE_STARTSZ);
	if (vx == NULL) {
		return -ENOMEM;
	}
	trie->vx = vx;
	trie->arrsz = TRIE_STARTSZ;
	trie->sz = 1;

	struct trie_vertex *trx = trie->vx;
	trx->p = trx->link = -1;
	trx->leaf = 0;
	trx->depth = 0;
	trx->pch = 0;
	memset(trx->go, 0xff, sizeof(trie->vx[0].go));

	return 0;
}

void trie_destroy(struct trie_container *trie) {
	trie->arrsz = 0;
	trie->sz = 0;
	free(trie->vx);
	trie->vx = NULL;
}

/**
 *
 * Increases trie vertex container size.
 * Returns new vertex index or ret < 0 on error
 *
 */
static int trie_push_vertex(struct trie_container *trie) {
	if (trie->sz == NMAX - 1) {
		return -EINVAL;
	}

	if (trie->arrsz == trie->sz) { // realloc
		void *pt = realloc(trie->vx, 
		     sizeof(struct trie_vertex) * trie->arrsz * 2);
		if (pt == NULL) {
			return -ENOMEM;
		}

		trie->arrsz *= 2;
		trie->vx = pt;
	}

	return trie->sz++;
}


int trie_add_string(struct trie_container *trie, 
	       const uint8_t *str, size_t strlen) {
	if (trie == NULL || trie->vx == NULL) {
		return -EINVAL;
	}

	int v = 0;
	int nv;

	for (size_t i = 0; i < strlen; ++i) {
		uint8_t c = str[i];
		if (c >= TRIE_ALPHABET) {
			return -EINVAL;
		}

		if (trie->vx[v].go[c] == -1) {
			nv = trie_push_vertex(trie);
			if (nv < 0) {
				return nv;
			}
			struct trie_vertex *tvx = trie->vx + nv;

			memset(tvx->go, 0xff, sizeof(tvx->go));
			tvx->link = -1;
			tvx->p = v;
			tvx->depth = trie->vx[v].depth + 1;
			tvx->leaf = 0;
			tvx->pch = c;
			trie->vx[v].go[c] = nv;
		}
		v = trie->vx[v].go[c];
	}
	
	if (v != 0) {
		trie->vx[v].leaf = 1;
	}

	return 0;
}

static int trie_go(struct trie_container *trie,
	int v, uint8_t c);

static int trie_get_link(struct trie_container *trie,
	     int v) {
	struct trie_vertex *tvx = trie->vx + v;

	if (tvx->link == -1) {
		if (v == 0 || tvx->p == 0) {
			tvx->link = 0;
		} else {
			tvx->link = trie_go(trie, 
				trie_get_link(trie, tvx->p), tvx->pch);
		}
	}

	return tvx->link;
}

static int trie_go(struct trie_container *trie, int v, uint8_t c) {
	struct trie_vertex *tvx = trie->vx + v;

	if (tvx->go[c] == -1) {
		tvx->go[c] = v == 0 ? 0 : 
		trie_go(trie, trie_get_link(trie, v), c);
	}

	return tvx->go[c];
}


int trie_process_str(
	struct trie_container *trie,
	const uint8_t *str, size_t strlen,
	int flags,
	size_t *offset, size_t *offlen
) {
	if (trie == NULL || trie->vx == NULL) {
		return 0;
	}

	int v = 0;
	size_t i = 0;
	uint8_t c;
	int len;

	for (; i < strlen; ++i) {
		c = str[i];
		if (c >= TRIE_ALPHABET) {
			v = 0;
			continue;
		}

		v = trie->vx[v].go[c] != -1 ? trie->vx[v].go[c] : 
			trie_go(trie, v, str[i]);

		if (trie->vx[v].leaf && 
			((flags & TRIE_OPT_MAP_TO_END) != TRIE_OPT_MAP_TO_END ||
			i == strlen - 1)
		) {
			++i;
			break;
		}
	}

	len = trie->vx[v].depth;
	if (	trie->vx[v].leaf &&
		i >= len
	) {
		size_t sp = i - len;
		*offset = sp;
		*offlen = len;
		return 1;
	}

	return 0;
}
