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

#ifndef ARGS_H
#define ARGS_H
#include "types.h"
#include "config.h"

void print_version(void);
void print_usage(const char *argv0);
int  yparse_args(int argc, char *argv[]);
size_t print_config(char *buffer, size_t buffer_size);

// Initializes configuration storage.
int init_config(struct config_t *config);
// Allocates and initializes configuration section.
int init_section_config(struct section_config_t **section, struct section_config_t *prev);
// Frees configuration section
void free_config_section(struct section_config_t *config);
// Frees sections under config
void free_config(struct config_t config);

/* Prints starting messages */
void print_welcome(void);

#endif /* ARGS_H */
