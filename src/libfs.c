#include <string.h>
#include <stdlib.h>
#include <stddef.h>

#include "elfs.h"
#include "log.h"
#include "misc.h"
#include "libfs.h"
#include "fsapi.h"

typedef struct {
        char *l_name;
        char *l_path;
} telf_libpath;

static int
elf_libpath_cmp(void *key_,
                void *value_)
{
        char *key = key_;
        telf_libpath *value = value_;

        return strcmp(key, value->l_name);
}

static void
elf_libpath_free(void *lp_)
{
        telf_libpath *lp = lp_;

        if (lp) {
                free(lp->l_name);
                free(lp->l_path);
                free(lp);
        }
}

static telf_libpath *
elf_libpath_new(char *name,
                char *path)
{
        telf_libpath *lp = NULL;

        lp = malloc(sizeof *lp);
        if (! lp) {
                ERR("malloc: %s", strerror(errno));
                goto err;
        }

        lp->l_name = strdup(name);
        if (! lp->l_name) {
                ERR("strdup: %s", strerror(errno));
                goto err;
        }

        lp->l_path = strdup(path);
        if (! lp->l_path) {
                ERR("strdup: %s", strerror(errno));
                goto err;
        }

        return lp;

  err:
        elf_libpath_free(lp);
        return NULL;
}

static telf_status
libfs_open(void *ctx_hdl,
           const char *path,
           void **objp)
{
        (void) ctx_hdl;
        (void) path;
        (void) objp;

        return ELF_FAILURE;
}


static telf_status
libfs_getattr(void *ctx_hdl,
              const char *path,
              telf_stat *stp)
{
        telf_ctx *ctx = ctx_hdl;
        telf_obj *obj = NULL;
        telf_status ret;
        telf_status rc;
        telf_stat st;
        telf_libpath *lp;
        int locked = 0;

        elf_ctx_lock(ctx);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ERR("namei(%s) failed: %d", path, rc);
                ret = -ENOENT;
                goto end;
        }

        elf_obj_lock(obj);
        locked = 1;

        memset(&st, 0, sizeof st);
        st.mode |= ELF_S_IFLNK;
        st.mode |= ELF_S_IRWXU|ELF_S_IRWXG|ELF_S_IRWXO;

        lp = list_get(obj->ctx->libpath, obj->name);
        if (lp && lp->l_path[0] == '/')
                /* we don't the length of "foo => (0x424242)" to be 0
                 * since the destination doesn't exist on disk */
                st.size = strlen(lp->l_path);

        ret = ELF_SUCCESS;
  end:

        if (locked)
                elf_obj_unlock(obj);

        elf_ctx_unlock(ctx);

        if (stp)
                *stp = st;
        return ret;
}

telf_status
libfs_readlink(void *ctx_hdl,
               const char *path,
               char **bufp,
               size_t *buf_lenp)
{
        telf_ctx *ctx = ctx_hdl;
        telf_obj *obj = NULL;
        telf_status ret;
        telf_status rc;
        size_t buf_len = 0;
        char *buf = NULL;
        telf_libpath *lp = NULL;
        int iret;
        int locked = 0;

        elf_ctx_lock(ctx);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ret = -ENOENT;
                goto end;
        }

        elf_obj_lock(obj);

        lp = list_get(obj->ctx->libpath, obj->name);
        if (lp) {
                iret = access(lp->l_path, R_OK);
                if (-1 == iret) {
                        if (ENOENT != errno)
                                ERR("access: %s", strerror(errno));

                } else {
                        buf = strdup(lp->l_path);
                        if (! buf) {
                                ERR("malloc: %s", strerror(errno));
                                ret = ELF_ENOMEM;
                                goto end;
                        }

                        buf_len = strlen(buf);
                }
        }

        ret = ELF_SUCCESS;
  end:

        if (locked)
                elf_obj_unlock(obj);

        elf_ctx_unlock(ctx);

        if (bufp)
                *bufp = buf;
        else
                free(buf);

        if (buf_lenp)
                *buf_lenp = buf_len;

        return ret;
}

static void
libfs_override_driver(telf_fs_driver *driver)
{
        driver->getattr  = libfs_getattr;
        driver->open     = libfs_open;
        driver->readlink = libfs_readlink;
}

static telf_status
elf_libpath_ctor(telf_ctx *ctx)
{
        telf_status ret;
        telf_status rc;
        FILE *ldd = NULL;
        telf_obj *libfs_obj = NULL;
        telf_obj *entry = NULL;

        rc = elf_namei(ctx, "/libs", &libfs_obj);
        if (ELF_SUCCESS != rc) {
                ERR("can't find '/libfs' object: %s", elf_status_to_str(rc));
                ret = rc;
                goto end;
        }

        ctx->libpath = list_new();
        if (! ctx->libpath) {
                ERR("can't create libpath list");
                ret = ELF_FAILURE;
                goto end;
        }

        list_set_cmp_func(ctx->libpath, elf_libpath_cmp);
        list_set_free_func(ctx->libpath, elf_libpath_free);

	do {
		char cmd[1024] = "";

		snprintf(cmd, sizeof cmd - 1, "ldd %s", ctx->binpath);

                ldd = popen(cmd, "r");
                if (! ldd) {
                        ERR("popen(%s): %s", cmd, strerror(errno));
                        ret = ELF_FAILURE;
                        goto end;
                }

		while (fgets(cmd, sizeof cmd - 1, ldd)) {
			unsigned int x;
			char path[PATH_MAX] = "";
                        char name[1024] = "";
                        telf_libpath *lp = NULL;

                        if (! strstr(cmd, " => "))
                                continue;

			sscanf(cmd, "%1023s => %1023s (%x)", name, path, &x);

                        if (0 == path[0])
                                continue;

                        lp = elf_libpath_new(name, path);
                        if (! lp) {
                                ERR("allocation issue");
                                ret = ELF_ENOMEM;
                                goto end;
                        }

                        entry = elf_obj_new(ctx, name, libfs_obj,
                                            ELF_LIBS_ENTRY,
                                            ELF_S_IFLNK);
                        if (! entry) {
                                ERR("can't build entry '%s'", name);
                                elf_libpath_free(lp);
                                continue;
                        }

                        list_add(ctx->libpath, lp);

                        libfs_override_driver(entry->driver);
                        list_add(libfs_obj->entries, entry);
		}

	} while (0);

        ret = ELF_SUCCESS;
  end:
	if (ldd)
		pclose(ldd);

        return ret;
}


telf_status
libfs_build(telf_ctx *ctx)
{
        telf_status ret;
        telf_status rc;

        rc = elf_libpath_ctor(ctx);
        if (ELF_SUCCESS != rc) {
                ERR("Can't set libpath list");
                ret = rc;
                goto end;
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}
