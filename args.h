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
