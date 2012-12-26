A FUSE filesystem on top of ELF files!

This tool is mostly for educational purposes and allows the user to easily visualize
the structure of an ELF object.

0. INSTALLATION
===============

As a prerequisite, you need to have the tools ldd(1) and objdump(1) installed
on your system.

    $ git clone git://github.com/pozdnychev/elfs
    $ cd elfs

Then on Linux platforms:

    $ make

or on BSD platforms:

    $ make -f Makefile.BSD

And now, with root privileges:

    $ make install

1. USAGE
========

If you want to inspect the fdup(1) program, and mount its image into /tmp/elf:

    $ elfs `which fdup` /tmp/elf

    $ ls -l /tmp/elf/
    total 0
    drw-r--r-- 1 root root 0 Jan  1  1970 header
    drw-r--r-- 1 root root 0 Jan  1  1970 libs
    drw-r--r-- 1 root root 0 Jan  1  1970 sections

The 'info' file contains ELF header information (pretty much the same format provided by readelf -h):

    $ cat /tmp/elf/header/info
    Ident:                             7f 45 4c 46 02 01 01 00 00 00 00 00 00 00 00 00
    Version:                           1
    Class:                             64
    Type:                              EXEC (Executable file)
    ELF Header size:                   64 bytes
    Entry point:                       0x400f50
    Program Header offset:             64 bytes
    Program Header entry size:         56 bytes
    Number of Program Header entries:  9
    Section Header offset:             84552 bytes
    Section Header entry size:         64 bytes
    Number of Section Header entries:  38
    SH string table index:             35

Check the libraries: display the list and their path on the file system

    $ ls -l /tmp/elf/libs
    total 0
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libc.so.6 -> /lib/x86_64-linux-gnu/libc.so.6
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 linux-vdso.so.1 ->


If you want to inspect the sections:

    $ ls -l /tmp/elf/sections/
    total 0
    drw------- 1 root root 0 1970-01-01 01:00 bss
    d--------- 1 root root 0 1970-01-01 01:00 comment
    drw------- 1 root root 0 1970-01-01 01:00 ctors
    drw------- 1 root root 0 1970-01-01 01:00 data
    d--------- 1 root root 0 1970-01-01 01:00 debug_abbrev
    d--------- 1 root root 0 1970-01-01 01:00 debug_aranges
    d--------- 1 root root 0 1970-01-01 01:00 debug_info
    d--------- 1 root root 0 1970-01-01 01:00 debug_line
    d--------- 1 root root 0 1970-01-01 01:00 debug_loc
    d--------- 1 root root 0 1970-01-01 01:00 debug_macinfo
    d--------- 1 root root 0 1970-01-01 01:00 debug_pubnames
    d--------- 1 root root 0 1970-01-01 01:00 debug_pubtypes
    d--------- 1 root root 0 1970-01-01 01:00 debug_ranges
    d--------- 1 root root 0 1970-01-01 01:00 debug_str
    drw------- 1 root root 0 1970-01-01 01:00 dtors
    drw------- 1 root root 0 1970-01-01 01:00 dynamic
    dr-------- 1 root root 0 1970-01-01 01:00 dynstr
    dr-------- 1 root root 0 1970-01-01 01:00 dynsym
    dr-------- 1 root root 0 1970-01-01 01:00 eh_frame
    dr-------- 1 root root 0 1970-01-01 01:00 eh_frame_hdr
    dr-x------ 1 root root 0 1970-01-01 01:00 fini
    dr-------- 1 root root 0 1970-01-01 01:00 gnu.hash
    dr-------- 1 root root 0 1970-01-01 01:00 gnu.version
    dr-------- 1 root root 0 1970-01-01 01:00 gnu.version_r
    drw------- 1 root root 0 1970-01-01 01:00 got
    drw------- 1 root root 0 1970-01-01 01:00 got.plt
    dr-x------ 1 root root 0 1970-01-01 01:00 init
    dr-------- 1 root root 0 1970-01-01 01:00 interp
    drw------- 1 root root 0 1970-01-01 01:00 jcr
    d--------- 1 root root 0 1970-01-01 01:00 noname.0x7f14e3a863c0
    dr-------- 1 root root 0 1970-01-01 01:00 note.ABI-tag
    dr-------- 1 root root 0 1970-01-01 01:00 note.gnu.build-id
    dr-x------ 1 root root 0 1970-01-01 01:00 plt
    dr-------- 1 root root 0 1970-01-01 01:00 rela.dyn
    dr-------- 1 root root 0 1970-01-01 01:00 rela.plt
    dr-------- 1 root root 0 1970-01-01 01:00 rodata
    d--------- 1 root root 0 1970-01-01 01:00 shstrtab
    d--------- 1 root root 0 1970-01-01 01:00 strtab
    d--------- 1 root root 0 1970-01-01 01:00 symtab
    dr-x------ 1 root root 0 1970-01-01 01:00 text


We set the rwx bits, according to the Section Header flags:

   SHR_WRITE    : w bit
   SHR_ALLOC    : r bit
   SHR_EXECINSTR: x bit


You can read the whole program binary code (in assembler) with the following command:

    $ cat /tmp/elf/sections/text/code.asm


Check the bin/asm code of a function:

    $ ls -l /tmp/elf/sections/symtab/dup_cmp_gid/
    total 0
    -rw-r--r-- 1 root root 914 Jan  1  1970 code.asm
    -rw-r--r-- 1 root root  44 Jan  1  1970 code.bin
    -rw-r--r-- 1 root root  72 Jan  1  1970 info

    $ cat /tmp/elf/sections/symtab/dup_cmp_gid/info
    value: 0x401af0
    size: 44
    type: STT_FUNC
    bind: STB_LOCAL
    name: GLIBC_2.3.4

    $ od -t x1 /tmp/elf/sections/symtab/dup_cmp_gid/code.bin
    0000000 55 48 89 e5 48 89 7d f8 48 89 75 f0 48 8b 45 f8
    0000020 8b 50 20 48 8b 45 f0 8b 40 20 39 c2 75 07 b8 00
    0000040 00 00 00 eb 05 b8 ff ff ff ff c9 c3


Let's see the code associated with this symbol (it's ok, since it's a function,
type STT_FUNC):

    $ cat /tmp/elf/sections/symtab/dup_cmp_gid/code.asm

    /home/poz/code/fdup/fdup:     file format elf64-x86-64


    Disassembly of section .text:

    0000000000401af0 <dup_cmp_gid>:
      401af0:       55                      push   %rbp
      401af1:       48 89 e5                mov    %rsp,%rbp
      401af4:       48 89 7d f8             mov    %rdi,-0x8(%rbp)
      401af8:       48 89 75 f0             mov    %rsi,-0x10(%rbp)
      401afc:       48 8b 45 f8             mov    -0x8(%rbp),%rax
      401b00:       8b 50 20                mov    0x20(%rax),%edx
      401b03:       48 8b 45 f0             mov    -0x10(%rbp),%rax
      401b07:       8b 40 20                mov    0x20(%rax),%eax
      401b0a:       39 c2                   cmp    %eax,%edx
      401b0c:       75 07                   jne    401b15 <dup_cmp_gid+0x25>
      401b0e:       b8 00 00 00 00          mov    $0x0,%eax
      401b13:       eb 05                   jmp    401b1a <dup_cmp_gid+0x2a>
      401b15:       b8 ff ff ff ff          mov    $0xffffffff,%eax
      401b1a:       5d                      pop    %rbp
      401b1b:       c3                      retq

We can check that the code is correct just by taking a look at the binary:

    $ readelf -s /usr/local/bin/fdup | grep dup_cmp_gid
    60: 0000000000401af0    44 FUNC    LOCAL  DEFAULT   13 dup_cmp_gid

The code symbol is 44 bytes longs, so it ends at 0x401af0 + 0x2c (44 in hexa), which
is 0x401b1c.


    $ objdump -D --start-address=0x401af0 --stop-address=0x401b1c /usr/local/bin/fdup

    /usr/local/bin/fdup:     file format elf64-x86-64


    Disassembly of section .text:

    0000000000401af0 <dup_cmp_gid>:
      401af0:       55                      push   %rbp
      401af1:       48 89 e5                mov    %rsp,%rbp
      401af4:       48 89 7d f8             mov    %rdi,-0x8(%rbp)
      401af8:       48 89 75 f0             mov    %rsi,-0x10(%rbp)
      401afc:       48 8b 45 f8             mov    -0x8(%rbp),%rax
      401b00:       8b 50 20                mov    0x20(%rax),%edx
      401b03:       48 8b 45 f0             mov    -0x10(%rbp),%rax
      401b07:       8b 40 20                mov    0x20(%rax),%eax
      401b0a:       39 c2                   cmp    %eax,%edx
      401b0c:       75 07                   jne    401b15 <dup_cmp_gid+0x25>
      401b0e:       b8 00 00 00 00          mov    $0x0,%eax
      401b13:       eb 05                   jmp    401b1a <dup_cmp_gid+0x2a>
      401b15:       b8 ff ff ff ff          mov    $0xffffffff,%eax
      401b1a:       5d                      pop    %rbp
      401b1b:       c3                      retq


You can also attach a running process but the feature being pretty experimental,
use at your own risk as you might encounter strange/wrong behavior.  Here is a simple example:

    $ sudo elfs -p `pidof xclock` /tmp/elf
    $ sudo ls -l /tmp/elf/libs
    total 0
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libc.so.6 -> /lib/x86_64-linux-gnu/libc.so.6
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libdl.so.2 -> /lib/x86_64-linux-gnu/libdl.so.2
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libexpat.so.1 -> /lib/x86_64-linux-gnu/libexpat.so.1
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libfontconfig.so.1 -> /usr/lib/x86_64-linux-gnu/libfontconfig.so.1
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libfreetype.so.6 -> /usr/lib/x86_64-linux-gnu/libfreetype.so.6
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libICE.so.6 -> /usr/lib/x86_64-linux-gnu/libICE.so.6
    lrwxrwxrwx 0 root root 0 1970-01-01 01:00 libm.so.6 -> /lib/x86_64-linux-gnu/libm.so.6
    [...]


For more information, just type:

    $ elfs -h


2. UNINSTALL
============

With root privileges, in elfs source directory:

    $ make uninstall

3. ISSUES
=========

Please report bugs and comments to:

https://github.com/pozdnychev/elfs/issues
