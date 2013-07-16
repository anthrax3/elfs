#ifndef UTILS_H
#define UTILS_H

#include "fs-structs.h"

char *elf_status_to_str(telf_status st);
int elf_status_to_errno(telf_status status);
telf_status binary_to_asm(char *path, char *start_addr, size_t bin_len, char **bufp, size_t *buf_lenp);

#endif /* UTILS_H */
