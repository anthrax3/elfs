#ifndef MEMSTREAM_H
#define MEMSTREAM_H

#ifdef __FreeBSD__
#include <stdio.h>

FILE *open_memstream(char **, size_t *);
#endif /* __FreeBSD__ */


#endif /* MEMSTREAM_H */
