#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <inttypes.h>

#include "symbolfs.h"
#include "symentryfs.h"
#include "misc.h"
#include "log.h"
#include "defaultfs.h"
#include "fsapi.h"


static telf_status
symbolfs_symtab_build(telf_ctx *ctx)
{
        telf_status ret;
        telf_status rc;
        int i;
        telf_obj *symtab_obj = NULL;
        telf_obj *obj = NULL;
        char *name = NULL;
        ElfW(Shdr) *shdr = NULL;

        rc = elf_namei(ctx, "/sections/symtab", &symtab_obj);
        if (ELF_SUCCESS != rc) {
                ERR("can't find '/sections/symtab': %s", elf_status_to_str(rc));
                ret = ELF_ENOENT;
                goto end;
        }

        shdr = elf_getsectionbytype(ctx, SHT_SYMTAB);
        if (shdr) {
                ctx->n_syms = shdr->sh_size / sizeof (ElfW(Sym));
                ctx->symtab = (ElfW(Sym) *) (ctx->addr + shdr->sh_offset);
                ctx->strtab = (char *) ctx->addr + ctx->shdr[shdr->sh_link].sh_offset;
        }

        if (! ctx->n_syms) {
                ret = ELF_SUCCESS;
                goto end;
        }

        ElfW(Sym) *sym = NULL;
        for (i = 0; i < ctx->n_syms; i++) {
                char *path = NULL;
                sym = elf_getnsym(ctx, i);
                assert(NULL != sym);

                name = elf_getsymname(ctx, sym);
                assert(NULL != name);

                if ('\0' == *name) {
                        if (asprintf(&path, "noname.%p", (void *) sym) < 0) {
                                ERR("asprintf: %s", strerror(errno));
                                ret = ELF_ENOMEM;
                                goto end;
                        }
                } else {
                        path = strdup(name);
                        if (! path) {
                                ERR("strdup: %s", strerror(errno));
                                ret = ELF_ENOMEM;
                                goto end;
                        }
                }

                obj = elf_obj_new(ctx, path, symtab_obj,
                                  ELF_SYMBOL,
                                  ELF_S_IFDIR);
                if (! obj) {
                        ERR("object creation '%s' failed", path);
                        free(path);
                        ret = ELF_FAILURE;
                        goto end;
                }

                rc = symentryfs_build(ctx, obj);
                if (ELF_SUCCESS != rc) {
                        ERR("symentryfs creation failed: %s",
                            elf_status_to_str(rc));
                        free(path);
                        ret = rc;
                        goto end;
                }

                obj->data = sym;

                DEBUG("adding to symtab: %s", path);
                list_add(symtab_obj->entries, obj);
                free(path);
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}

static telf_status
symbolfs_dynsym_build(telf_ctx *ctx)
{
        telf_status ret;
        telf_status rc;
        int i;
        telf_obj *obj = NULL;
        telf_obj *dynsym_obj = NULL;
        char *name = NULL;
        ElfW(Shdr) *shdr = NULL;

        rc = elf_namei(ctx, "/sections/dynsym", &dynsym_obj);
        if (ELF_SUCCESS != rc) {
                ERR("can not find '/sections/dynsym': %s",
                    elf_status_to_str(rc));
                ret = ELF_ENOENT;
                goto end;
        }

        shdr = elf_getsectionbytype(ctx, SHT_DYNSYM);
        if (shdr) {
                ctx->n_dsyms = shdr->sh_size / sizeof (ElfW(Sym));
                ctx->dsymtab = (ElfW(Sym) *) (ctx->addr + shdr->sh_offset);
                ctx->dstrtab = (char *) ctx->addr +
                        ctx->shdr[shdr->sh_link].sh_offset;
        }

        if (! ctx->n_dsyms) {
                ret = ELF_SUCCESS;
                goto end;
        }

        ElfW(Sym) *sym = NULL;
        for (i = 0; i < ctx->n_dsyms; i++) {
                char *path = NULL;
                sym = elf_getndsym(ctx, i);
                assert(NULL != sym);

                name = elf_getdsymname(ctx, sym);
                assert(NULL != name);

                if ('\0' == *name) {
                        if (asprintf(&path, "noname.%p", (void *) sym) < 0) {
                                ERR("asprintf: %s", strerror(errno));
                                ret = ELF_ENOMEM;
                                goto end;
                        }
                } else {
                        path = strdup(name);
                        if (! path) {
                                ERR("strdup: %s", strerror(errno));
                                ret = ELF_ENOMEM;
                                goto end;
                        }
                }

                obj = elf_obj_new(ctx, path, dynsym_obj,
                                  ELF_SYMBOL,
                                  ELF_S_IFDIR);
                if (! obj) {
                        free(path);
                        ERR("object creation '%s' failed", path);
                        ret = ELF_FAILURE;
                        goto end;
                }

                free(path);

                rc = symentryfs_build(ctx, obj);
                if (ELF_SUCCESS != rc) {
                        ERR("symentryfs creation failed: %s",
                            elf_status_to_str(rc));
                        ret = rc;
                        goto end;
                }

                obj->data = sym;

                list_add(dynsym_obj->entries, obj);
                DEBUG("adding to dynsym: %s", path);
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}

telf_status
symbolfs_build(telf_ctx *ctx)
{
        telf_status rc;
        telf_status ret;

        rc = symbolfs_dynsym_build(ctx);
        if (ELF_SUCCESS != rc) {
                ERR("can't build dynsym driver: %s", elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        rc = symbolfs_symtab_build(ctx);
        if (ELF_SUCCESS != rc) {
                ERR("can't build symtab driver: %s", elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}
