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
headerfs_read_info(void *obj_hdl,
                   char **bufp,
                   size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
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
headerfs_read_version(void *obj_hdl,
                      char **bufp,
                      size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
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
headerfs_read_entrypoint(void *obj_hdl,
                         char **bufp,
                         size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
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

static telf_status
headerfs_read_ident(void *obj_hdl,
                    char **bufp,
                    size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        char *buf = NULL;
        size_t buf_len = 0;
        FILE *out = NULL;
        int i;

        out = open_memstream(&buf, &buf_len);
        if (! out) {
                ERR("open_memstream: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        for (i = 0; i < EI_NIDENT; i++)
                fprintf(out, "%.2x", obj->ctx->ehdr->e_ident[i]);

        fprintf(out, "\n");

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
headerfs_release_version(void *obj_hdl)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_default_content *cont = NULL;

        DEBUG("name:%s data=%p", obj->name, obj->data);

        cont = obj->data;
        if (cont) {
                unsigned char v = atoi(cont->buf);
                ERR("new version: %d", v);
                obj->ctx->ehdr->e_version = v;
        }

        ret = ELF_SUCCESS;
  end:

        return ret;
}

static telf_status
headerfs_release_entrypoint(void *obj_hdl)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_default_content *cont = NULL;

        DEBUG("name:%s data=%p", obj->name, obj->data);

        cont = obj->data;
        if (cont) {
                Elf64_Addr addr = (Elf64_Addr) strtoull(cont->buf, NULL, 0);
                ERR("new version: %llx", (unsigned long long) addr);
                obj->ctx->ehdr->e_entry = addr;
        }

        ret = ELF_SUCCESS;
  end:

        return ret;
}

static telf_status
headerfs_release_ident(void *obj_hdl)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_default_content *cont = NULL;
        Elf64_Ehdr *ehdr = obj->ctx->ehdr;

        DEBUG("name:%s data=%p", obj->name, obj->data);

        cont = obj->data;
        if (cont) {
                int i;

                for (i = 0; i < EI_NIDENT; i++) {
                        char tmp[3] = { cont->buf[2*i], cont->buf[2*i+1], 0 };
                        ehdr->e_ident[i] = (uint8_t) strtoul(tmp, NULL, 16);
                }
        }

        ret = ELF_SUCCESS;
  end:

        return ret;
}

static telf_fcb headerfs_fcb[] = {
        {
                "info",
                headerfs_read_info,
                headerfs_freecontent,
                NULL
        },
        {
                "version",
                headerfs_read_version,
                headerfs_freecontent,
                headerfs_release_version
        },
        {
                "entrypoint",
                headerfs_read_entrypoint,
                headerfs_freecontent,
                headerfs_release_entrypoint
        },
        {
                "ident",
                headerfs_read_ident,
                headerfs_freecontent,
                headerfs_release_ident
        },
};

static telf_status
headerfs_release(void *obj_hdl)
{
        telf_obj *obj = obj_hdl;
        telf_fcb *fcb = NULL;
        telf_status ret;
        telf_status rc;

        elf_obj_lock(obj);

        DEBUG("name:%s data=%p", obj->name, obj->data);

        fcb = elf_get_fcb(headerfs_fcb, N_ELEMS(headerfs_fcb), obj->name);
        if (! fcb) {
                ERR("no fcb matching obj '%s'", obj->name);
                ret = ELF_ENOENT;
                goto end;
        }

        if (fcb->release_func) {
                rc = fcb->release_func(obj);
                if (ELF_SUCCESS != rc) {
                        ERR("release ('%s') failed: %s",
                            obj->name, elf_status_to_str(rc));
                        ret = rc;
                        goto end;
                }
        }

        ret = ELF_SUCCESS;
  end:

        if (obj->free_func) {
                obj->free_func(obj->data);
                obj->data = NULL;
        }

        elf_obj_unlock(obj);

        return ret;
}

static void
headerfs_override_driver(telf_fs_driver *driver)
{
        driver->release = headerfs_release;
}

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

                headerfs_override_driver(entry->driver);
                entry->free_func = fcb->freecontent_func;
                entry->fill_func = fcb->fillcontent_func;

                list_add(header_obj->entries, entry);
        }

  end:
        return ret;
}
