#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "rootfs.h"
#include "fs-structs.h"
#include "log.h"
#include "elfs.h"
#include "defaultfs.h"

extern telf_ctx *ctx;


/* root directory object creation */

telf_status
rootfs_build(telf_ctx *ctx)
{
        telf_status rc, ret;
        telf_obj *root_obj = NULL;
        telf_obj *sections_obj = NULL;

        root_obj = elf_obj_new(ctx, "/", NULL, ELF_ROOTDIR);
        if (! root_obj) {
                LOG(LOG_ERR, 0, "root obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        rc = elf_obj_list_new(root_obj);
        if (ELF_SUCCESS != rc) {
                LOG(LOG_ERR, 0, "list failed: %s", elf_status_to_str(rc));
                ret = ELF_FAILURE;
                goto err;
        }

        sections_obj = elf_obj_new(ctx, "sections", root_obj, ELF_SECTION);
        if (! sections_obj) {
                LOG(LOG_ERR, 0, "section obj creation failed");
                ret = ELF_FAILURE;
                goto err;
        }

        list_add(root_obj->entries, sections_obj);

        /* set the fs callbacks related to the root directory */
        root_obj->driver = *defaultfs_driver_new();
        /* root_obj->driver = rootfs_driver; */


        /* and finally... */
        ctx->root = root_obj;

        return ELF_SUCCESS;
  err:
        if (sections_obj)
                elf_obj_free(sections_obj);

        if (root_obj)
                elf_obj_free(root_obj);

        return ret;
}

