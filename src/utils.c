#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "utils.h"

#include "compat.h"

#define MAP(v) X(v, #v)
#define X(a, b) b,
char *elf_status_names[] = {
        ELF_STATUS_TABLE
};
#undef X
#undef MAP


char *
elf_status_to_str(telf_status status)
{
        return elf_status_names[status];
}

int
elf_status_to_errno(telf_status status)
{
        switch (status) {
        case ELF_ENOENT: return ENOENT;
        case ELF_ENOMEM: return ENOMEM;
        case ELF_EPERM: return EPERM;
        case ELF_EIO: return EIO;
        case ELF_SUCCESS: return 0;
        default: return EINVAL;
        }
}


telf_status
binary_to_asm(char *obj_path,
              char *start_addr,
              size_t bin_len,
              char **bufp,
              size_t *buf_lenp)
{
        telf_status ret;
        char *buf = NULL;
        size_t buf_len = 0;
        FILE *out = NULL;
        FILE *objdump = NULL;
        char cmd[256] = "";
        char line[128] = "";

        if (! bin_len || ! start_addr) {
                ret = ELF_SUCCESS;
                goto end;
        }

        out = open_memstream(&buf, &buf_len);
        if (! out) {
                ERR("open_memstream: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        (void) snprintf(cmd, sizeof cmd, "objdump -D "
                        "--start-address=%p "
                        "--stop-address=%p %s",
                        (void *) start_addr,
                        (void *) (start_addr + bin_len),
                        obj_path);

        objdump = popen(cmd, "r");
        if (! objdump) {
                ERR("popen(%s): %s", cmd, strerror(errno));
                ret = ELF_FAILURE;
                goto end;
        }

        while (fgets(line, sizeof line - 1, objdump))
                fprintf(out, "%s", line);

        ret = ELF_SUCCESS;
  end:

        if (objdump)
                pclose(objdump);

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
