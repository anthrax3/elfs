#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <inttypes.h>

#include "log.h"
#include "misc.h"
#include "elfs.h"
#include "defaultfs.h"
#include "programfs.h"
#include "fsapi.h"


static void
programfs_freecontent(void *data)
{
        telf_default_content *content = data;

        if (! content)
                return;

        free(content->buf);
        free(content);
}

static telf_status
programfs_read_asmcode(void *obj_hdl,
                       char **bufp,
                       size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;
        ElfW(Shdr) *shdr = NULL;
        char *buf = NULL;
        size_t buf_len = 0;
        char realname[128];

        sprintf(realname, ".%s", obj->parent->name);

        shdr = elf_getsectionbyname(obj->ctx, realname);
        if (! shdr) {
                ERR("section '%s' not found", realname);
                ret = ELF_FAILURE;
                goto end;
        }

        rc = binary_to_asm(obj->ctx->binpath,
                           (char *) obj->ctx->base_vaddr + shdr->sh_offset,
                           shdr->sh_size,
                           &buf,
                           &buf_len);
        if (ELF_SUCCESS != rc) {
                ERR("can't extract asm code from binary");
                ret = rc;
                goto end;
        }

        ret = ELF_SUCCESS;
  end:
        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}

static telf_status
programfs_read_bincode(void *obj_hdl,
                       char **bufp,
                       size_t *buf_lenp)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        char realname[128];
        ElfW(Shdr) *shdr = NULL;
        char *buf = NULL;
        size_t buf_len = 0;

        sprintf(realname, ".%s", obj->parent->name);
        shdr = elf_getsectionbyname(obj->ctx, realname);

        buf_len = shdr->sh_size;

        if (buf_len) {
                buf = malloc(buf_len);
                if (! buf) {
                        ERR("malloc: %s", strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }

                memcpy(buf, obj->ctx->addr + shdr->sh_offset, buf_len);
        }

        ret = ELF_SUCCESS;
  end:
        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}

static telf_fcb programfs_fcb[] = {
        { "code",     programfs_read_bincode, programfs_freecontent },
        { "code.asm", programfs_read_asmcode, programfs_freecontent },
};


static void
section_ctor_cb(void *obj_hdl,
                void *to_ignore)
{
        int i;
        telf_obj *obj = obj_hdl;
        telf_obj *entry = NULL;
        telf_status rc;
        ElfW(Shdr) *shdr = NULL;
        char realname[128];

        sprintf(realname, ".%s", obj->name);
        shdr = elf_getsectionbyname(obj->ctx, realname);
        if (! shdr) {
                ERR("can't find any section with name '%s'", realname);
                return;
        }

        if (ELF_SECTION_PROGBITS != obj->type)
                return;

        if (! (SHF_EXECINSTR & shdr->sh_flags))
                return;

        for (i = 0; i < N_ELEMS(programfs_fcb); i++) {
                telf_fcb *fcb = programfs_fcb + i;

                entry = elf_obj_new(obj->ctx, fcb->str, obj,
                                    ELF_SECTION_PROGBITS_CODE,
                                    ELF_S_IFREG);
                if (! entry) {
                        ERR("can't build entry '%s'", fcb->str);
                        continue;
                }

                entry->free_func = fcb->freecontent_func;
                entry->fill_func = fcb->fillcontent_func;

                list_add(obj->entries, entry);
        }

}

telf_status
programfs_build(telf_ctx *ctx)
{
        telf_obj *obj_sections = NULL;
        telf_obj *section = NULL;
        telf_status ret;
        telf_status rc;
        int i;

        rc = elf_namei(ctx, "/sections", &obj_sections);
        if (ELF_SUCCESS != rc) {
                ERR("can't find '/sections' object: %s",
                    elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        list_map(obj_sections->entries, section_ctor_cb, NULL);

        ret = ELF_SUCCESS;
  end:
        return ret;

}
