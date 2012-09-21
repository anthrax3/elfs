#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "headerfs.h"
#include "fs-structs.h"
#include "log.h"
#include "elfs.h"
#include "defaultfs.h"
#include "misc.h"


static void
headerfs_freecontent(void *data)
{
        telf_default_content *content = data;

        if (! content)
                return;

        if (content->buf)
                free(content->buf);

        free(content);
}

static char *
headerfs_type_to_str(unsigned type)
{
        switch (type) {
        case ET_NONE:   return "NONE (No file type)";
        case ET_REL:    return "REL (Relocatable file)";
        case ET_EXEC:   return "EXEC (Executable file)";
        case ET_DYN:    return "DYN (Shared object file)";
        case ET_CORE:   return "CORE (Core file)";
        case ET_LOPROC: return "LOPROC (Processor-specific)";
        case ET_HIPROC: return "HIPROC (Processor-specific)";
        default:        return "Unknown type";
        }
}

static telf_status
headerfs_fillcontent_info(void *obj_hdl,
                          char **bufp,
                          size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        size_t size;
        size_t off = 0;
        int i;
        char ident_str[128] = "";
        telf_status ret;
        char *buf = NULL;
        size_t buf_len = 0;
        FILE *out = NULL;
        Elf64_Ehdr *ehdr = obj->ctx->ehdr;

        for (i = 0; i < EI_NIDENT; i++)
                off += sprintf(ident_str + off, "%.2x ", ehdr->e_ident[i]);

        out = open_memstream(&buf, &buf_len);
        if (! out) {
                ERR("open_memstream: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        fprintf(out,
                "Ident:                             %s\n"
                "Version:                           %d\n"
                "Class:                             %d\n"
                "Type:                              %s\n"
                "ELF Header size:                   %d bytes\n"
                "Entry point:                       %p\n"
                "Program Header offset:             %lu bytes\n"
                "Program Header entry size:         %d bytes\n"
                "Number of Program Header entries:  %d\n"
                "Section Header offset:             %lu bytes\n"
                "Section Header entry size:         %d bytes\n"
                "Number of Section Header entries:  %d\n"
                "SH string table index:             %d\n",
                ident_str,
                ehdr->e_ident[EI_VERSION],
                ehdr->e_ident[EI_CLASS] == ELFCLASS64 ? 64 : 32,
                headerfs_type_to_str(ehdr->e_type),
                ehdr->e_ehsize,
                (void *) ehdr->e_entry,
                ehdr->e_phoff,
                ehdr->e_phentsize,
                ehdr->e_phnum,
                ehdr->e_shoff,
                ehdr->e_shentsize,
                ehdr->e_shnum,
                ehdr->e_shstrndx);

        ret = ELF_SUCCESS;
  end:
        if (out)
                fclose(out);

        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}


static telf_status
headerfs_fillcontent_version(void *obj_hdl,
                             char **bufp,
                             size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        size_t size;
        telf_status ret;
        char *buf = NULL;
        size_t buf_len = 0;
        FILE *out = NULL;

        out = open_memstream(&buf, &buf_len);
        if (! out) {
                ERR("open_memstream: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        fprintf(out, "%d\n", obj->ctx->ehdr->e_version);

        ret = ELF_SUCCESS;
  end:
        if (out)
                fclose(out);

        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}


static telf_status
headerfs_fillcontent_entrypoint(void *obj_hdl,
                                char **bufp,
                                size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        size_t size;
        telf_status ret;
        char *buf = NULL;
        size_t buf_len = 0;
        FILE *out = NULL;

        out = open_memstream(&buf, &buf_len);
        if (! out) {
                ERR("open_memstream: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        fprintf(out, "%p\n", (void *) obj->ctx->ehdr->e_entry);

        ret = ELF_SUCCESS;
  end:
        if (out)
                fclose(out);

        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}

static telf_fcb headerfs_fcb[] = {
        { "info",       headerfs_fillcontent_info,       headerfs_freecontent },
        { "version",    headerfs_fillcontent_version,    headerfs_freecontent },
        { "entrypoint", headerfs_fillcontent_entrypoint, headerfs_freecontent },
};


telf_status
headerfs_build(telf_ctx *ctx)
{
        telf_obj *header_obj = NULL;
        telf_obj *section = NULL;
        telf_status ret;
        telf_status rc;
        int i;

        rc = elf_namei(ctx, "/header", &header_obj);
        if (ELF_SUCCESS != rc) {
                ERR("can't find '/header' object: %s",
                    elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        /* now add the pseudo files */
        for (i = 0; i < N_ELEMS(headerfs_fcb); i++) {
                telf_obj *entry = NULL;

                telf_fcb *fcb = headerfs_fcb + i;

                entry = elf_obj_new(ctx, fcb->str, header_obj,
                                    ELF_HEADER_ENTRY,
                                    ELF_S_IFREG);
                if (! entry) {
                        ERR("can't build entry '%s'", fcb->str);
                        continue;
                }

                entry->free_func = fcb->freecontent_func;
                entry->fill_func = fcb->fillcontent_func;

                list_add(header_obj->entries, entry);
        }

  end:
        return ret;
}
