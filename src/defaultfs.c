#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "defaultfs.h"
#include "elfs.h"

telf_ctx *ctx;


/* file */

static telf_status
defaultfs_getattr(void *ctx_hdl,
                  const char *path,
                  telf_stat *st)
{
        telf_ctx *ctx = ctx_hdl;
        telf_status ret;
        telf_status rc;
        telf_obj *obj = NULL;
        int locked = 0;

        DEBUG("path=%s", path);

        elf_ctx_lock(ctx);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ERR("namei(%s) failed: %d", path, rc);
                ret = -ENOENT;
                goto end;
        }

        elf_obj_lock(obj);
        locked = 1;

        DEBUG("name:%s data=%p", obj->name, obj->data);

        memcpy(st, &obj->st, sizeof *st);
        st->mode |= ELF_S_IRUSR|ELF_S_IWUSR | ELF_S_IRGRP | ELF_S_IROTH;
        st->nlink = 1;
        st->atime = st->mtime = st->ctime = time(NULL);

        if (ELF_S_ISREG(obj->st.mode)) {
                if (obj->fill_func) {
                        rc = obj->fill_func(obj, NULL, &st->size);
                        if (ELF_SUCCESS != rc) {
                                ret = rc;
                                goto end;
                        }
                }
        }

        ret = ELF_SUCCESS;
  end:

        if (locked)
                elf_obj_unlock(obj);

        elf_ctx_unlock(ctx);

        DEBUG("path=%s, ret=%s (%d)", path, elf_status_to_str(ret), ret);
        return ret;
}

static telf_status
defaultfs_open(void *ctx_hdl,
               const char *path,
               void **obj_hdlp)
{
        telf_ctx *ctx = ctx_hdl;
        telf_obj **objp = (telf_obj **) obj_hdlp;
        telf_obj *obj = NULL;
        telf_status ret;
        telf_status rc;
        char *buf;
        size_t buf_len;
        telf_default_content *content;
        int locked = 0;

        DEBUG("path=%s", path);

        elf_ctx_lock(ctx);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ERR("namei(%s) failed: %d", path, rc);
                ret = -ENOENT;
                goto end;
        }

        elf_obj_lock(obj);
        locked = 1;

        elf_obj_ref_nolock(obj);

        content = malloc(sizeof *content);
        if (! content) {
                ERR("malloc: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        if (obj->fill_func) {
                rc = obj->fill_func(obj, &content->buf, &content->buf_len);
                if (ELF_SUCCESS != rc) {
                        ret = rc;
                        goto end;
                }
        }

        if (obj->data && obj->free_func)
                obj->free_func(obj->data);

        obj->data = content;

        ret = ELF_SUCCESS;
  end:
        if (obj_hdlp)
                *obj_hdlp = obj;

        if (locked)
                elf_obj_unlock(obj);

        elf_ctx_unlock(ctx);

        DEBUG("path=%s, ret=%s (%d)", path, elf_status_to_str(ret), ret);
        return ret;
}

static telf_status
defaultfs_release(void *ctx_hdl,
                  const char *path)
{
        telf_ctx *ctx = ctx_hdl;
        telf_obj *obj = NULL;
        telf_status ret;
        telf_status rc;
        int locked = 0;

        DEBUG("path=%s", path);

        elf_ctx_lock(ctx);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ERR("namei(%s) failed: %d", path, rc);
                ret = -ENOENT;
                goto end;
        }

        elf_obj_lock(obj);
        locked = 1;

        elf_obj_unref_nolock(obj);

        DEBUG("name:%s data=%p", obj->name, obj->data);

        if (0 == obj->refcount) {
                if (obj->free_func) {
                        obj->free_func(obj->data);
                        obj->data = NULL;
                }
        }

        ret = ELF_SUCCESS;
  end:

        if (locked)
                elf_obj_unlock(obj);

        elf_ctx_unlock(ctx);

        DEBUG("path=%s, ret=%s (%d)", path, elf_status_to_str(ret), ret);

        return ELF_SUCCESS;
}

static telf_status
defaultfs_read(void *ctx_hdl,
               const char *path,
               char *buf,
               size_t size,
               off_t offset,
               ssize_t *sizep)
{
        telf_ctx *ctx = ctx_hdl;
        telf_obj *obj = NULL;
        telf_default_content *content = NULL;
        telf_status ret;
        telf_status rc;
        int locked = 0;

        DEBUG("path=%s", path);

        elf_ctx_lock(ctx);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ERR("namei(%s) failed: %d", path, rc);
                ret = -ENOENT;
                goto end;
        }

        elf_obj_lock(obj);
        locked = 1;

        DEBUG("name:%s data=%p", obj->name, obj->data);

        content = obj->data;

        if (content->buf) {

                if (size > content->buf_len - offset)
                        size = content->buf_len - offset;

                memcpy(buf, content->buf + offset, size);
        }

        ret = ELF_SUCCESS;
  end:
        if (sizep)
                *sizep = size;

        if (locked)
                elf_obj_unlock(obj);

        elf_ctx_unlock(ctx);

        DEBUG("path=%s, ret=%s (%d)", path, elf_status_to_str(ret), ret);
        return ret;
}

static telf_status
defaultfs_write(void *ctx_hdl,
                const char *path,
                const char *buf,
                size_t size,
                off_t offset,
                ssize_t *sizep)
{
        telf_ctx *ctx = ctx_hdl;
        telf_obj *obj = NULL;
        telf_default_content *content = NULL;
        telf_status ret;
        telf_status rc;
        int locked = 0;

        DEBUG("path=%s", path);

        elf_ctx_lock(ctx);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ERR("namei(%s) failed: %d", path, rc);
                ret = -ENOENT;
                goto end;
        }

        elf_obj_lock(obj);
        locked = 1;

        content = obj->data;

        if (size > content->buf_len - offset)
                size = content->buf_len - offset;

        memcpy(content->buf + offset, buf, size);

        ret = ELF_SUCCESS;
  end:
        if (sizep)
                *sizep = size;

        if (locked)
                elf_obj_unlock(obj);

        elf_ctx_unlock(ctx);

        DEBUG("path=%s, ret=%s (%d)", path, elf_status_to_str(ret), ret);
        return ret;
}


/* directory */


static telf_status
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

static void
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

static telf_status
defaultfs_readdir(void *ctx_hdl,
                  const char *path,
                  void *data,
                  fuse_fill_dir_t fill)
{
        telf_ctx *ctx = ctx_hdl;
        telf_obj *obj = NULL;
        telf_status ret;
        int rc;
        telf_dir_hdl *dir_hdl = NULL;
        telf_dirent dirent;
        int locked = 0;

        DEBUG("%s", path);

        elf_ctx_lock(ctx);

        rc = elf_namei(ctx, path, &obj);
        if (ELF_SUCCESS != rc) {
                ERR("can't find object with key '%s': %s",
                    path, elf_status_to_str(rc));
                ret = -ENOENT;
                goto end;
        }

        elf_obj_lock(obj);
        locked = 1;

        dir_hdl = alloca(sizeof *dir_hdl);
        if (! dir_hdl) {
                ERR("alloca: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        memset(&dirent, 0, sizeof dirent);

        dir_ctor(obj->ctx, obj, dir_hdl);

        while (0 == readdir_getdirent(dir_hdl, &dirent)) {
                if (fill(data, dirent.name, NULL, 0))
                        break;
        }

        ret = ELF_SUCCESS;

  end:
        if (locked)
                elf_obj_unlock(obj);

        elf_ctx_unlock(ctx);

        return ret;
}

static telf_status
defaultfs_releasedir(void *obj,
                     const char *path)
{
        return ELF_SUCCESS;
}

static telf_status
defaultfs_readlink(void *ctx_hdl,
                   const char *path,
                   char **bufp,
                   size_t *buf_lenp)
{
        return ELF_SUCCESS;
}

telf_fs_driver *
defaultfs_driver_new(void)
{
        telf_fs_driver *driver = NULL;

        driver = malloc(sizeof *driver);
        if (! driver) {
                ERR("malloc: %s", strerror(errno));
                return NULL;
        }

        driver->getattr    = defaultfs_getattr;
        driver->open       = defaultfs_open;
        driver->release    = defaultfs_release;
        driver->read       = defaultfs_read;
        driver->write      = defaultfs_write;
        driver->opendir    = defaultfs_opendir;
        driver->readdir    = defaultfs_readdir;
        driver->releasedir = defaultfs_releasedir;
        driver->readlink   = defaultfs_readlink;

        return driver;
}
