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
headerfs_gen_info(Elf64_Ehdr *ehdr,
                  char **bufp,
                  size_t *buf_lenp)
{
        size_t size;
        size_t off = 0;
        int i;
        char ident_str[128] = "";
        char tmpbuf[1024];
        telf_status ret;
        char *buf = NULL;
        size_t buf_len = 0;
        FILE *out = NULL;

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
headerfs_info_getsize(void *obj_hdl,
                      size_t *sizep)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;

        rc = headerfs_gen_info(obj->ctx->ehdr, NULL, sizep);
        if (ELF_SUCCESS != rc) {
                ERR("Can't generate header info");
                ret = rc;
                goto end;
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}

static telf_status
headerfs_info_setcontent(void *obj_hdl,
                         char **bufp,
                         size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;

        rc = headerfs_gen_info(obj->ctx->ehdr, bufp, buf_lenp);
        if (ELF_SUCCESS != rc) {
                ERR("Can't generate header info");
                ret = rc;
                goto end;
        }

        ret = ELF_SUCCESS;
  end:
        DEBUG("ret=%s (%d)", elf_status_to_str(ret), ret);
        return ret;
}


typedef struct {
        char *str;
        tobj_getsize_func getsize_func;
        tobj_setcontent_func setcontent_func;
        tobj_freecontent_func freecontent_func;
} telf_fcb;

static telf_fcb headerfs_fcb[] = {
        {
                "info",
                headerfs_info_getsize,
                headerfs_info_setcontent,
                headerfs_freecontent
        },
};

static telf_status
headerfs_getattr(void *obj_hdl,
                 telf_stat *stp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;
        telf_stat st;
        int i;

        elf_obj_lock(obj);

        DEBUG("name:%s data=%p", obj->name, obj->data);

        memset(&st, 0, sizeof st);
        st.st_mode |= ELF_S_IFREG;

        for (i = 0; i < N_ELEMS(headerfs_fcb); i++) {
                telf_fcb *fcb = headerfs_fcb + i;

                if (0 == strcmp(obj->name, fcb->str)) {
                        rc = fcb->getsize_func(obj, &st.st_size);
                        if (ELF_SUCCESS != rc) {
                                ERR("can't get size of '%s'", obj->name);
                                ret = rc;
                                goto end;
                        }
                        break;
                }
        }

        ret = ELF_SUCCESS;
  end:

        elf_obj_unlock(obj);

        if (stp)
                *stp = st;

        DEBUG("ret=%s (%d)", elf_status_to_str(ret), ret);
        return ret;
}

static void
headerfs_override_driver(telf_fs_driver *driver)
{
        driver->getattr = headerfs_getattr;
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
                entry->fill_func = fcb->setcontent_func;

                list_add(header_obj->entries, entry);
        }

  end:
        return ret;
}
