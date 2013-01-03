/*-
 * Copyright (c) 2010 Advanced Computing Technologies LLC
 * Written by: John H. Baldwin <jhb@FreeBSD.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


/* Use funopen(3) to provide open_memstream(3) like functionality. */

#ifdef __FreeBSD_

#include <stdlib.h>
#include <string.h>
#include <errno.h>

struct memstream {
	char **cp;
	size_t *lenp;
	size_t offset;
};

static void
memstream_grow(struct memstream *ms, size_t newsize)
{
	char *buf;

	if (newsize > *ms->lenp) {
		buf = realloc(*ms->cp, newsize + 1);
		if (buf != NULL) {
#ifdef DEBUG
			fprintf(stderr, "MS: %p growing from %zd to %zd\n",
                                ms, *ms->lenp, newsize);
#endif
			memset(buf + *ms->lenp + 1, 0, newsize - *ms->lenp);
			*ms->cp = buf;
			*ms->lenp = newsize;
		}
	}
}

static int
memstream_read(void *cookie, char *buf, int len)
{
	struct memstream *ms;
	int tocopy;

	ms = cookie;
	memstream_grow(ms, ms->offset + len);
	tocopy = *ms->lenp - ms->offset;
	if (len < tocopy)
		tocopy = len;
	memcpy(buf, *ms->cp + ms->offset, tocopy);
	ms->offset += tocopy;
#ifdef DEBUG
	fprintf(stderr, "MS: read(%p, %d) = %d\n", ms, len, tocopy);
#endif
	return (tocopy);
}

static int
memstream_write(void *cookie, const char *buf, int len)
{
	struct memstream *ms;
	int tocopy;

	ms = cookie;
	memstream_grow(ms, ms->offset + len);
	tocopy = *ms->lenp - ms->offset;
	if (len < tocopy)
		tocopy = len;
	memcpy(*ms->cp + ms->offset, buf, tocopy);
	ms->offset += tocopy;
#ifdef DEBUG
	fprintf(stderr, "MS: write(%p, %d) = %d\n", ms, len, tocopy);
#endif
	return (tocopy);
}

static fpos_t
memstream_seek(void *cookie, fpos_t pos, int whence)
{
	struct memstream *ms;
#ifdef DEBUG
	size_t old;
#endif

	ms = cookie;
#ifdef DEBUG
	old = ms->offset;
#endif
	switch (whence) {
	case SEEK_SET:
		ms->offset = pos;
		break;
	case SEEK_CUR:
		ms->offset += pos;
		break;
	case SEEK_END:
		ms->offset = *ms->lenp + pos;
		break;
	}
#ifdef DEBUG
	fprintf(stderr, "MS: seek(%p, %zd, %d) %zd -> %zd\n", ms, pos, whence,
                old, ms->offset);
#endif
	return (ms->offset);
}

static int
memstream_close(void *cookie)
{

	free(cookie);
	return (0);
}

FILE *
open_memstream(char **cp, size_t *lenp)
{
	struct memstream *ms;
	int save_errno;
	FILE *fp;

	*cp = NULL;
	*lenp = 0;
	ms = malloc(sizeof(*ms));
	ms->cp = cp;
	ms->lenp = lenp;
	ms->offset = 0;
	fp = funopen(ms, memstream_read, memstream_write, memstream_seek,
                     memstream_close);
	if (fp == NULL) {
		save_errno = errno;
		free(ms);
		errno = save_errno;
	}
	return (fp);
}

#endif /* __FreeBSD__ */
