#include "misc.h"



Elf64_Shdr *
elf_getnsection(telf_ctx *ctx,
                int n)
{
        if (n < 0 || n >= ctx->n_sections)
                return NULL;

        return ctx->shdr + n;
}

char *
elf_getsectionname(telf_ctx *ctx,
                   Elf64_Shdr *shdr)
{
        Elf64_Shdr *sh_strtab = ctx->shdr + ctx->ehdr->e_shstrndx;
        char *sh_strtab_p = ctx->addr + sh_strtab->sh_offset;

        return sh_strtab_p + shdr->sh_name;
}

char *
elf_getnsectionname(telf_ctx *ctx,
                    int n)
{
        if (n < 0 || n >= ctx->n_sections)
                return NULL;

        Elf64_Shdr *sh_strtab = ctx->shdr + ctx->ehdr->e_shstrndx;
        char *sh_strtab_p = ctx->addr + sh_strtab->sh_offset;

        return sh_strtab_p + ctx->shdr[n].sh_name;
}

Elf64_Shdr *
elf_getsectionbyname(telf_ctx *ctx,
                     char *name)
{
        int i;

        for (i = 0; i < ctx->n_sections; i++) {
                Elf64_Shdr *shdr = ctx->shdr + i;
                char *i_name = elf_getsectionname(ctx, shdr);

                if (0 == strcmp(i_name, name))
                        return shdr;
        }

        return NULL;
}

char *
elf_getsymname(telf_ctx *ctx,
            Elf64_Sym *sym)
{
        return &ctx->strtab[sym->st_name];
}

char *
elf_getdsymname(telf_ctx *ctx,
             Elf64_Sym *sym)
{
        return &ctx->dstrtab[sym->st_name];
}

Elf64_Sym *
elf_getnsym(telf_ctx *ctx,
            int n)
{
        if (n < 0 || n >= ctx->n_syms)
                return NULL;

        return ctx->symtab + n;
}

Elf64_Sym *
elf_getndsym(telf_ctx *ctx,
             int n)
{
        if (n < 0 || n >= ctx->n_dsyms)
                return NULL;

        return ctx->dsymtab + n;
}

Elf64_Sym *
elf_getsymbyname(telf_ctx *ctx,
                 char *name)
{
        int i;
        Elf64_Sym *sym = NULL;

        for (i = 0; i < ctx->n_syms; i++) {
                sym = elf_getnsym(ctx, i);
                if (0 == strcmp(name, elf_getsymname(ctx, sym)))
                        goto end;
        }

        sym = NULL;
  end:
        return sym;
}

Elf64_Sym *
elf_getdsymbyname(telf_ctx *ctx,
                  char *name)
{
        int i;

        for (i = 0; i < ctx->n_dsyms; i++) {
                Elf64_Sym *sym = elf_getndsym(ctx, i);
                if (0 == strcmp(name, elf_getdsymname(ctx, sym)))
                        return sym;
        }

        return NULL;
}

char *
sym_bind_to_str(Elf64_Sym *sym)
{
        if (! sym)
                return "unknown";

        unsigned char b = ELF64_ST_BIND(sym->st_info);

        switch (b) {
#define MAP(x) case x: return #x
                MAP(STB_LOCAL);
                MAP(STB_GLOBAL);
                MAP(STB_WEAK);
                MAP(STB_LOPROC);
                MAP(STB_HIPROC);
#undef MAP
        }

        return "impossible";
}

char *
sym_type_to_str(Elf64_Sym *sym)
{
        if (! sym)
                return "unknown";

        unsigned char t = ELF64_ST_TYPE(sym->st_info);

        switch (t) {
#define MAP(x) case x: return #x
                MAP(STT_NOTYPE);
                MAP(STT_OBJECT);
                MAP(STT_FUNC);
                MAP(STT_SECTION);
                MAP(STT_FILE);
                MAP(STT_LOPROC);
                MAP(STT_HIPROC);
#undef MAP
        }

        return "impossible";
}

