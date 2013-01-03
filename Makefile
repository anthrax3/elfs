PROGNAME=elfs

CC?=gcc

DESTDIR=/usr/local
OBJDIR=objs
SRCDIR=src
INCDIR=include
BINDIR=bin
MANDIR=man

MANFILE=$(MANDIR)/${PROGNAME}.1
PROGFILE=$(BINDIR)/$(PROGNAME)

DESTMANDIR=$(DESTDIR)/man/man1
DESTBINDIR=$(DESTDIR)/bin

SRC=$(wildcard $(SRCDIR)/*.c)
OBJS=$(addprefix $(OBJDIR)/,$(patsubst %.c,%.o,$(notdir $(SRC))))

COMMON_CFLAGS=-D_FILE_OFFSET_BITS=64 -D_GNU_SOURCE -I$(INCDIR) -I/usr/local/include
COMMON_LDFLAGS=-lfuse -L /usr/local/lib

PROD_CFLAGS=-O3 $(COMMON_CFLAGS)
PROD_LDFLAGS=$(COMMON_LDFLAGS)

DEBUG_CFLAGS=-ggdb -g3 -O0 $(COMMON_CFLAGS)
DEBUG_LDFLAGS=$(COMMON_LDFLAGS)


prod: CFLAGS=$(PROD_CFLAGS)
prod: LDFLAGS=$(PROD_LDFLAGS)
prod: compile

debug: CFLAGS=$(DEBUG_CFLAGS)
debug: LDFLAGS=$(DEBUG_LDFLAGS)
debug: compile


compile: $(PROGNAME)

$(PROGNAME): $(OBJS)
	@echo objs: $(OBJS)
	$(CC) -o $(BINDIR)/$(PROGNAME) $(CFLAGS) $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(INCDIR)/%.h
	$(CC) $(CFLAGS) -o $@ -c $<

install:
	install -m755 bin/$(PROGNAME) $(DESTBINDIR)
	install -m644 $(MANFILE) $(DESTMANDIR)

uninstall:
	rm -f $(DESTBINDIR)/$(PROGNAME)
	rm -f $(DESTMANDIR)/$(MANFILE)

clean:
	rm -f objs/*.o $(BINDIR)/$(PROGNAME)
