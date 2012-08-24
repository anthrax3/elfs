#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "defaultfs.h"
#include "elfs.h"

telf_ctx *ctx;


/* file */

telf_status
defaultfs_getattr(void *obj_hdl,
                  telf_stat *st)
{
        telf_status ret;
        telf_status rc;
        telf_obj *obj = obj_hdl;
        size_t size;
        telf_default_content *content;

        if (ELF_S_ISDIR(obj->ftype)) {
                st->st_nlink = 1;
                st->st_mode = ELF_S_IFDIR | ELF_S_IXUSR | ELF_S_IRUSR;
                st->st_size = 0;
        } else {
                content = malloc(sizeof *content);
                assert(NULL != content);

                memset(content, 0, sizeof *content);

                obj->data = content;

                /* we compute the content on-the-fly, in order to set the
                 * correct file size: not very efficient but who care? */
                rc = obj->fill_func(obj, NULL, &size);
                if (ELF_SUCCESS != rc) {
                        ret = rc;
                        goto end;
                }

                st->st_nlink = 1;
                st->st_mode = ELF_S_IFREG | ELF_S_IRUSR;
                st->st_size = size;
        }

        ret = ELF_SUCCESS;
  end:
        return ret;
}

telf_status
defaultfs_open(char *path,
               telf_open_flags flags,
               void **objp)
{
        telf_status ret;
        telf_status rc;
        telf_obj *obj;
        char *buf;
        size_t buf_len;
        telf_default_content *content;

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ret = rc;
                goto end;
        }

        content = malloc(sizeof *content);
        if (! content) {
                LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        rc = obj->fill_func(obj, &content->buf, &content->buf_len);
        if (ELF_SUCCESS != rc) {
                ret = rc;
                goto end;
        }

        if (obj->data)
                obj->free_func(obj->data);

        obj->data = content;

        ret = ELF_SUCCESS;
  end:

        if (objp)
                *objp = obj;

        return ret;
}

telf_status
defaultfs_release(void *obj_hdl)
{
        telf_obj *obj = obj_hdl;

        if (obj->free_func) {
                obj->free_func(obj->data);
                obj->data = NULL;
        }

        return ELF_SUCCESS;
}

telf_status
defaultfs_read(void *obj_hdl,
               char *buf,
               size_t size,
               off_t offset,
               ssize_t *sizep)
{
        telf_obj *obj = obj_hdl;
        telf_default_content *content = obj->data;
        telf_status ret;

        if (size > content->buf_len)
                size = content->buf_len;

        memcpy(buf, content->buf + offset, size);

        if (sizep)
                *sizep = size;

        return ELF_SUCCESS;
}

telf_status
defaultfs_write(void *obj,
                const char *buf,
                size_t size,
                off_t offset,
                ssize_t *sizep)
{
        return ELF_SUCCESS;
}


/* directory */


telf_status
defaultfs_opendir(char *path,
                  void **objp)
{
        return ELF_SUCCESS;
}

typedef struct {
        char name[128]; /* section/segment name */
} telf_dirent;

typedef struct elf_dir_hdl {
        void *(*get_entryname_func)(struct elf_dir_hdl *, char **);

        telf_ctx *ctx;
        telf_obj *obj;
        int cursor;
        int n_entries;
} telf_dir_hdl;

static void *
direntname(telf_dir_hdl *dir_hdl,
           char **namep)
{
        char *name = NULL;
        telf_obj *entry = NULL;
        static char *dots[] = { ".", ".." };

        switch (dir_hdl->cursor) {
        case 0: /* handle "." */
                entry = dir_hdl->obj;
                name = dots[dir_hdl->cursor];
                break;
        case 1: /* handle ".." */
                entry = dir_hdl->obj->parent;
                name = dots[dir_hdl->cursor];
                break;
        default: /* handle ordinary entry... */
                entry = list_get_nth(dir_hdl->obj->entries, dir_hdl->cursor - 2);
                if (! entry)
                        goto end;

                name = entry->name;
        }

  end:
        if (namep)
                *namep = name;

        return entry;
}

static int
dir_ctor(telf_ctx *ctx,
         telf_obj *obj,
         telf_dir_hdl *dir)
{
        dir->ctx = ctx;
        dir->cursor = 0;
        dir->obj = obj;
        dir->n_entries = list_get_size(obj->entries) + 2; // for "." and ".."
        dir->get_entryname_func = direntname;
}

static int
readdir_getdirent(void *hdl,
                  telf_dirent *dirent)
{
        telf_dir_hdl *dir_hdl = hdl;
        char *name = NULL;
        void *addr =  NULL;

        if (dir_hdl->cursor >= dir_hdl->n_entries + 2)
                return -1;

        addr = dir_hdl->get_entryname_func(dir_hdl, &name);
        if (! name)
                return -1;

        if (*name)
                sprintf(dirent->name, "%s", name);
        else
                sprintf(dirent->name, "noname.%p", addr);

        dir_hdl->cursor++;

        return ELF_SUCCESS;
}

telf_status
defaultfs_readdir(void *obj_hdl,
                  void *data,
                  fuse_fill_dir_t fill)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        int rc;
        telf_dir_hdl *dir_hdl = NULL;
        telf_dirent dirent;

        dir_hdl = alloca(sizeof *dir_hdl);
        if (! dir_hdl) {
                LOG(LOG_ERR, 0, "alloca: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto err;
        }

        memset(&dirent, 0, sizeof dirent);

        dir_ctor(ctx, obj, dir_hdl);

        while (0 == readdir_getdirent(dir_hdl, &dirent)) {
                if (fill(data, dirent.name, NULL, 0))
                        break;
        }

        ret = ELF_SUCCESS;
  err:
        return ret;
}

telf_status
defaultfs_releasedir(void *obj)
{
        return ELF_SUCCESS;
}


telf_fs_driver *
defaultfs_driver_new(void)
{
        telf_fs_driver *driver = NULL;

        driver = malloc(sizeof *driver);
        if (! driver) {
                LOG(LOG_ERR, 0, "malloc: %s", strerror(errno));
                return NULL;
        }

        driver->data = NULL;

        driver->getattr    = defaultfs_getattr;
        driver->open       = defaultfs_open;
        driver->release    = defaultfs_release;
        driver->read       = defaultfs_read;
        driver->write      = defaultfs_write;
        driver->opendir    = defaultfs_opendir;
        driver->readdir    = defaultfs_readdir;
        driver->releasedir = defaultfs_releasedir;

        return driver;
}
