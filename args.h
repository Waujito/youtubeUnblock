#ifndef ARGS_H
#define ARGS_H

void print_version();
void print_usage(const char *argv0);
int parse_args(int argc, char *argv[]);
int parse_sni_list();

/* Prints starting messages */
void print_welcome();

#endif /* ARGS_H */
