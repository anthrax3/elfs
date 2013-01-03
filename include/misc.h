#ifndef MISC_H
#define MISC_H

#include "elfs.h"

#define N_ELEMS(x) (sizeof x / sizeof x[0])

int memread(pid_t pid, unsigned long addr, void *outp, size_t len);

ElfW(Shdr) *elf_getnsection(telf_ctx *ctx, int n);
char *elf_getsectionname(telf_ctx *ctx, ElfW(Shdr) *shdr);
char *elf_getnsectionname(telf_ctx *ctx, int n);
ElfW(Shdr) *elf_getsectionbyname(telf_ctx *ctx, char *name);
ElfW(Shdr) * elf_getsectionbytype(telf_ctx *ctx, unsigned int type);

/** return thge name of a given symbol */
char *elf_getsymname(telf_ctx *ctx, ElfW(Sym) *sym);

/** return the name of a given dynamic symbol */
char *elf_getdsymname(telf_ctx *ctx, ElfW(Sym) *sym);

/**  get the n-th symbol (start at 0) */
ElfW(Sym) *elf_getnsym(telf_ctx *ctx, int n);

/**  get the n-th dynamic symbol (start at 0) */
ElfW(Sym) *elf_getndsym(telf_ctx *ctx, int n);

ElfW(Sym) *elf_getsymbyname(telf_ctx *ctx, char *name);
ElfW(Sym) *elf_getdsymbyname(telf_ctx *ctx, char *name);
char *sym_bind_to_str(ElfW(Sym) *sym);
char *sym_type_to_str(ElfW(Sym) *sym);


#endif /* MISC_H */
