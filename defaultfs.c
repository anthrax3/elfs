#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "defaultfs.h"
#include "elfs.h"

telf_ctx *ctx;


/* file */

static telf_status
defaultfs_getattr(void *obj_hdl,
                  telf_stat *st)
{
        telf_status ret;
        telf_status rc;
        telf_obj *obj = obj_hdl;

        elf_obj_lock(obj);

        DEBUG("name:%s data=%p", obj->name, obj->data);

        memcpy(st, &obj->st, sizeof *st);
        st->st_mode |= ELF_S_IRUSR|ELF_S_IWUSR | ELF_S_IRGRP | ELF_S_IROTH;
        st->st_nlink = 1;

        if (ELF_S_ISREG(obj->st.st_mode)) {
                rc = obj->fill_func(obj, NULL, &st->st_size);
                if (ELF_SUCCESS != rc) {
                        ret = rc;
                        goto end;
                }
        }

        ret = ELF_SUCCESS;
  end:

        elf_obj_unlock(obj);

        DEBUG("ret=%s (%d)", elf_status_to_str(ret), ret);
        return ret;
}

static telf_status
defaultfs_open(void *obj_hdl)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        telf_status rc;
        char *buf;
        size_t buf_len;
        telf_default_content *content;
        int locked = 0;

        elf_obj_lock(obj);
        locked = 1;

        DEBUG("name:%s data=%p", obj->name, obj->data);

        content = malloc(sizeof *content);
        if (! content) {
                ERR("malloc: %s", strerror(errno));
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
        if (locked)
                elf_obj_unlock(obj);

        DEBUG("obj->data=%p, ret=%s (%d)",
            obj->data, elf_status_to_str(ret), ret);
        return ret;
}

static telf_status
defaultfs_release(void *obj_hdl)
{
        telf_obj *obj = obj_hdl;

        elf_obj_lock(obj);

        DEBUG("name:%s data=%p", obj->name, obj->data);

        if (obj->free_func) {
                obj->free_func(obj->data);
                obj->data = NULL;
        }

        elf_obj_unlock(obj);

        return ELF_SUCCESS;
}

static telf_status
defaultfs_read(void *obj_hdl,
               char *buf,
               size_t size,
               off_t offset,
               ssize_t *sizep)
{
        telf_obj *obj = obj_hdl;
        telf_default_content *cont = NULL;
        telf_status ret;
        telf_status rc;

        elf_obj_lock(obj);

        DEBUG("name:%s data=%p", obj->name, obj->data);

        cont = obj->data;

        /* FUSE might release() the object before read(), true story bro' */
        if (! cont) {
                cont = malloc(sizeof *cont);
                if (! cont) {
                        ERR("malloc: %s", strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }

                memset(cont, 0, sizeof *cont);

                rc = obj->fill_func(obj, &cont->buf, &cont->buf_len);
                if (ELF_SUCCESS != rc) {
                        ret = rc;
                        goto end;
                }

                obj->data = cont;
        }


        if (size > cont->buf_len)
                size = cont->buf_len;

        memcpy(buf, cont->buf + offset, size);

        ret = ELF_SUCCESS;
  end:
        if (sizep)
                *sizep = size;

        elf_obj_unlock(obj);

        DEBUG("ret=%s (%d)", elf_status_to_str(ret), ret);
        return ret;
}

static telf_status
defaultfs_write(void *obj_hdl,
                const char *buf,
                size_t size,
                off_t offset,
                ssize_t *sizep)
{
        telf_obj *obj = obj_hdl;
        telf_default_content *cont = NULL;
        telf_status ret;
        telf_status rc;

        elf_obj_lock(obj);

        DEBUG("name:%s data=%p", obj->name, obj->data);

        cont = obj->data;

        /* FUSE might release() the object before read(), true story bro' */
        if (! cont) {
                cont = malloc(sizeof *cont);
                if (! cont) {
                        ERR("malloc: %s", strerror(errno));
                        ret = ELF_ENOMEM;
                        goto end;
                }

                memset(cont, 0, sizeof *cont);

                rc = obj->fill_func(obj, &cont->buf, &cont->buf_len);
                if (ELF_SUCCESS != rc) {
                        ret = rc;
                        goto end;
                }

                obj->data = cont;
        }


        if (size > cont->buf_len)
                size = cont->buf_len;

        memcpy(cont->buf + offset, buf, size);

        ret = ELF_SUCCESS;
  end:
        if (sizep)
                *sizep = size;

        elf_obj_unlock(obj);

        DEBUG("ret=%s (%d)", elf_status_to_str(ret), ret);
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

static telf_status
defaultfs_readdir(void *obj_hdl,
                  void *data,
                  fuse_fill_dir_t fill)
{
        telf_obj *obj = obj_hdl;
        telf_status ret;
        int rc;
        telf_dir_hdl *dir_hdl = NULL;
        telf_dirent dirent;
        int locked = 0;

        DEBUG("%s", obj->name);

        dir_hdl = alloca(sizeof *dir_hdl);
        if (! dir_hdl) {
                ERR("alloca: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto err;
        }

        memset(&dirent, 0, sizeof dirent);

        elf_obj_lock(obj);
        locked = 1;

        dir_ctor(obj->ctx, obj, dir_hdl);

        while (0 == readdir_getdirent(dir_hdl, &dirent)) {
                if (fill(data, dirent.name, NULL, 0))
                        break;
        }

        ret = ELF_SUCCESS;
  err:
        if (locked)
                elf_obj_unlock(obj);

        return ret;
}

static telf_status
defaultfs_releasedir(void *obj)
{
        return ELF_SUCCESS;
}

static telf_status
defaultfs_readlink(void *obj,
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
