#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <udis86.h>

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


telf_status
binary_to_asm(char *bin,
              size_t bin_len,
              char **bufp,
              size_t *buf_lenp)
{
        telf_status ret;
        char *buf = NULL;
        size_t buf_len = 0;
        ud_t ud_obj;
        FILE *out = NULL;

        ud_init(&ud_obj);
        ud_set_input_buffer(&ud_obj, bin, bin_len);
        ud_set_mode(&ud_obj, 64);
        ud_set_syntax(&ud_obj, UD_SYN_INTEL);

        if (! bin_len || ! bin) {
                ret = ELF_SUCCESS;
                goto end;
        }

        out = open_memstream(&buf, &buf_len);
        if (! out) {
                ERR("open_memstream: %s", strerror(errno));
                ret = ELF_ENOMEM;
                goto end;
        }

        while (ud_disassemble(&ud_obj)) {
                char line[64] = "";
                size_t len;

                fprintf(out, "%s\n", ud_insn_asm(&ud_obj));
        }

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
