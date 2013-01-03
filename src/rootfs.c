#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "rootfs.h"
#include "fs-structs.h"
#include "log.h"
#include "elfs.h"
#include "defaultfs.h"
#include "misc.h"



/* root directory object creation */

telf_status
rootfs_build(telf_ctx *ctx)
{
        telf_status rc;
        telf_status ret;
        telf_obj *root_obj = NULL;
        telf_obj *sections_obj = NULL;
        telf_obj *libs_obj = NULL;
        telf_obj *header_obj = NULL;
        telf_obj *entry = NULL;
        int i;

        root_obj = elf_obj_new(ctx, "/", NULL,
                               ELF_ROOTDIR,
                               ELF_S_IFDIR);
        if (! root_obj) {
                ERR("root obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        sections_obj = elf_obj_new(ctx, "sections", root_obj,
                                   ELF_SECTION,
                                   ELF_S_IFDIR);
        if (! sections_obj) {
                ERR("section obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        libs_obj = elf_obj_new(ctx, "libs", root_obj,
                               ELF_LIBS,
                               ELF_S_IFDIR);
        if (! libs_obj) {
                ERR("libs obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        header_obj = elf_obj_new(ctx, "header", root_obj,
                                 ELF_HEADER,
                                 ELF_S_IFDIR);
        if (! header_obj) {
                ERR("header obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        list_add(root_obj->entries, sections_obj);
        list_add(root_obj->entries, libs_obj);
        list_add(root_obj->entries, header_obj);

        /* and finally... */
        ctx->root = root_obj;

        ret = ELF_SUCCESS;
  err:
        return ret;
}

