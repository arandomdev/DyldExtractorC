/*
 * Copyright (c) 1999-2019 Apple Inc.  All Rights Reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */
#ifndef _MACHO_LOADER_H_
#define _MACHO_LOADER_H_

/*
 * This file describes the format of mach object files.
 */
#include <stdint.h>

/*
 * The 64-bit mach header appears at the very beginning of object files for
 * 64-bit architectures.
 */
struct mach_header_64 {
    uint32_t magic;      /* mach magic number identifier */
    uint32_t cputype;    /* cpu specifier */
    uint32_t cpusubtype; /* machine specifier */
    uint32_t filetype;   /* type of file */
    uint32_t ncmds;      /* number of load commands */
    uint32_t sizeofcmds; /* the size of all the load commands */
    uint32_t flags;      /* flags */
    uint32_t reserved;   /* reserved */
};

/* Constant for the magic field of the mach_header_64 (64-bit architectures) */
#define MH_MAGIC_64 0xfeedfacf /* the 64-bit mach magic number */
#define MH_CIGAM_64 0xcffaedfe /* NXSwapInt(MH_MAGIC_64) */

/*
 * The load commands directly follow the mach_header.  The total size of all
 * of the commands is given by the sizeofcmds field in the mach_header.  All
 * load commands must have as their first two fields cmd and cmdsize.  The cmd
 * field is filled in with a constant for that command type.  Each command type
 * has a structure specifically for it.  The cmdsize field is the size in bytes
 * of the particular load command structure plus anything that follows it that
 * is a part of the load command (i.e. section structures, strings, etc.).  To
 * advance to the next load command the cmdsize can be added to the offset or
 * pointer of the current load command.  The cmdsize for 32-bit architectures
 * MUST be a multiple of 4 bytes and for 64-bit architectures MUST be a multiple
 * of 8 bytes (these are forever the maximum alignment of any load commands).
 * The padded bytes must be zero.  All tables in the object file must also
 * follow these rules so the file can be memory mapped.  Otherwise the pointers
 * to these tables will not work well or at all on some machines.  With all
 * padding zeroed like objects will compare byte for byte.
 */
struct load_command {
    uint32_t cmd;     /* type of load command */
    uint32_t cmdsize; /* total size of command in bytes */

    using CMD_T = load_command;
    constexpr static uint32_t CMDS[] = {0x00, 0x00}; // magic value for all lcs
};

/*
 * After MacOS X 10.1 when a new load command is added that is required to be
 * understood by the dynamic linker for the image to execute properly the
 * LC_REQ_DYLD bit will be or'ed into the load command constant.  If the dynamic
 * linker sees such a load command it it does not understand will issue a
 * "unknown load command required for execution" error and refuse to use the
 * image.  Other load commands without this bit that are not understood will
 * simply be ignored.
 */
#define LC_REQ_DYLD 0x80000000

/* Constants for the cmd field of all load commands, the type */
// #define LC_SEGMENT 0x1       /* segment of this file to be mapped */
// #define LC_SYMTAB 0x2        /* link-edit stab symbol table info */
// #define LC_SYMSEG 0x3        /* link-edit gdb symbol table info (obsolete) */
// #define LC_THREAD 0x4        /* thread */
// #define LC_UNIXTHREAD 0x5    /* unix thread (includes a stack) */
// #define LC_LOADFVMLIB 0x6    /* load a specified fixed VM shared library */
// #define LC_IDFVMLIB 0x7      /* fixed VM shared library identification */
// #define LC_IDENT 0x8         /* object identification info (obsolete) */
// #define LC_FVMFILE 0x9       /* fixed VM file inclusion (internal use) */
// #define LC_PREPAGE 0xa       /* prepage command (internal use) */
// #define LC_DYSYMTAB 0xb      /* dynamic link-edit symbol table info */
// #define LC_LOAD_DYLIB 0xc    /* load a dynamically linked shared library */
// #define LC_ID_DYLIB 0xd      /* dynamically linked shared lib ident */
// #define LC_LOAD_DYLINKER 0xe /* load a dynamic linker */
// #define LC_ID_DYLINKER 0xf   /* dynamic linker identification */
// #define LC_PREBOUND_DYLIB
// 0x10                       /* modules prebound for a dynamically
/* linked shared library */
// #define LC_ROUTINES 0x11       /* image routines */
// #define LC_SUB_FRAMEWORK 0x12  /* sub framework */
// #define LC_SUB_UMBRELLA 0x13   /* sub umbrella */
// #define LC_SUB_CLIENT 0x14     /* sub client */
// #define LC_SUB_LIBRARY 0x15    /* sub library */
// #define LC_TWOLEVEL_HINTS 0x16 /* two-level namespace lookup hints */
// #define LC_PREBIND_CKSUM 0x17  /* prebind checksum */

/*
 * load a dynamically linked shared library that is allowed to be missing
 * (all symbols are weak imported).
 */
// #define LC_LOAD_WEAK_DYLIB (0x18 | LC_REQ_DYLD)

#define LC_SEGMENT_64 0x19 /* 64-bit segment of this file to be mapped */
// #define LC_ROUTINES_64 0x1a /* 64-bit image routines */
// #define LC_UUID 0x1b        /* the uuid */
// #define LC_RPATH (0x1c | LC_REQ_DYLD) /* runpath additions */
// #define LC_CODE_SIGNATURE 0x1d        /* local of code signature */
// #define LC_SEGMENT_SPLIT_INFO 0x1e    /* local of info to split segments */
// #define LC_REEXPORT_DYLIB (0x1f | LC_REQ_DYLD) /* load and re-export dylib */
// #define LC_LAZY_LOAD_DYLIB 0x20 /* delay load of dylib until first use */
// #define LC_ENCRYPTION_INFO 0x21 /* encrypted segment information */
// #define LC_DYLD_INFO 0x22       /* compressed dyld information */
// #define LC_DYLD_INFO_ONLY
// (0x22 | LC_REQ_DYLD) /* compressed dyld information only */
// #define LC_LOAD_UPWARD_DYLIB (0x23 | LC_REQ_DYLD) /* load upward dylib */
// #define LC_VERSION_MIN_MACOSX 0x24   /* build for MacOSX min OS version */
// #define LC_VERSION_MIN_IPHONEOS 0x25 /* build for iPhoneOS min OS version */
// #define LC_FUNCTION_STARTS
// 0x26 /* compressed table of function start addresses */
// #define LC_DYLD_ENVIRONMENT
// 0x27 /* string for dyld to treat like environment variable */
// #define LC_MAIN (0x28 | LC_REQ_DYLD) /* replacement for LC_UNIXTHREAD */
// #define LC_DATA_IN_CODE 0x29         /* table of non-instructions in __text
// */ #define LC_SOURCE_VERSION 0x2A       /* source version used to build
// binary */
// #define LC_DYLIB_CODE_SIGN_DRS
// 0x2B /* Code signing DRs copied from linked dylibs */
// #define LC_ENCRYPTION_INFO_64 0x2C /* 64-bit encrypted segment information */
// #define LC_LINKER_OPTION 0x2D      /* linker options in MH_OBJECT files */
// #define LC_LINKER_OPTIMIZATION_HINT
// 0x2E                            /* optimization hints in MH_OBJECT files */
// #define LC_VERSION_MIN_TVOS 0x2F    /* build for AppleTV min OS version */
// #define LC_VERSION_MIN_WATCHOS 0x30 /* build for Watch min OS version */
// #define LC_NOTE 0x31          /* arbitrary data included within a Mach-O file
// */ #define LC_BUILD_VERSION 0x32 /* build for platform min OS version */
// #define LC_DYLD_EXPORTS_TRIE
// (0x33 | LC_REQ_DYLD) /* used with linkedit_data_command, payload is trie
// * /
// #define LC_DYLD_CHAINED_FIXUPS
// (0x34 | LC_REQ_DYLD) /* used with linkedit_data_command */
// #define LC_FILESET_ENTRY
// (0x35 | LC_REQ_DYLD) /* used with fileset_entry_command */

/*
 * The 64-bit segment load command indicates that a part of this file is to
 * be mapped into a 64-bit task's address space.  If the 64-bit segment has
 * sections then section_64 structures directly follow the 64-bit segment
 * command and their size is reflected in cmdsize.
 */
struct segment_command_64 { /* for 64-bit architectures */
    uint32_t cmd;           /* LC_SEGMENT_64 */
    uint32_t cmdsize;       /* includes sizeof section_64 structs */
    char segname[16];       /* segment name */
    uint64_t vmaddr;        /* memory address of this segment */
    uint64_t vmsize;        /* memory size of this segment */
    uint64_t fileoff;       /* file offset of this segment */
    uint64_t filesize;      /* amount to map from the file */
    uint32_t maxprot;       /* maximum VM protection */
    uint32_t initprot;      /* initial VM protection */
    uint32_t nsects;        /* number of sections in segment */
    uint32_t flags;         /* flags */

    using CMD_T = segment_command_64;
    constexpr static uint32_t CMDS[] = {LC_SEGMENT_64};
};

/*
 * A segment is made up of zero or more sections.  Non-MH_OBJECT files have
 * all of their segments with the proper sections in each, and padded to the
 * specified segment alignment when produced by the link editor.  The first
 * segment of a MH_EXECUTE and MH_FVMLIB format file contains the mach_header
 * and load commands of the object file before its first section.  The zero
 * fill sections are always last in their segment (in all formats).  This
 * allows the zeroed segment padding to be mapped into memory where zero fill
 * sections might be. The gigabyte zero fill sections, those with the section
 * type S_GB_ZEROFILL, can only be in a segment with sections of this type.
 * These segments are then placed after all other segments.
 *
 * The MH_OBJECT format has all of its sections in one segment for
 * compactness.  There is no padding to a specified segment boundary and the
 * mach_header and load commands are not part of the segment.
 *
 * Sections with the same section name, sectname, going into the same segment,
 * segname, are combined by the link editor.  The resulting section is aligned
 * to the maximum alignment of the combined sections and is the new section's
 * alignment.  The combined sections are aligned to their original alignment in
 * the combined section.  Any padded bytes to get the specified alignment are
 * zeroed.
 *
 * The format of the relocation entries referenced by the reloff and nreloc
 * fields of the section structure for mach object files is described in the
 * header file <reloc.h>.
 */
struct section_64 {     /* for 64-bit architectures */
    char sectname[16];  /* name of this section */
    char segname[16];   /* segment this section goes in */
    uint64_t addr;      /* memory address of this section */
    uint64_t size;      /* size in bytes of this section */
    uint32_t offset;    /* file offset of this section */
    uint32_t align;     /* section alignment (power of 2) */
    uint32_t reloff;    /* file offset of relocation entries */
    uint32_t nreloc;    /* number of relocation entries */
    uint32_t flags;     /* flags (section type and attributes)*/
    uint32_t reserved1; /* reserved (for offset or index) */
    uint32_t reserved2; /* reserved (for count or sizeof) */
    uint32_t reserved3; /* reserved */
};

#endif /* _MACHO_LOADER_H_ */