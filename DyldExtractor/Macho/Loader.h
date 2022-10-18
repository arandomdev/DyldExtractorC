#ifndef __MACHO_LOADER__
#define __MACHO_LOADER__

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <Utils/Architectures.h>

#define CPU_SUBTYPE_MASK 0xff000000
#define CPU_SUBTYPE_ARM64E 2

namespace DyldExtractor::Macho::Loader {

template <class P> struct mach_header {};
template <> struct mach_header<Utils::Arch::Pointer32> : public ::mach_header {
  enum { MAGIC = MH_MAGIC, CIGAM = MH_CIGAM };
};
template <>
struct mach_header<Utils::Arch::Pointer64> : public ::mach_header_64 {
  enum { MAGIC = MH_MAGIC_64, CIGAM = MH_CIGAM_64 };
};

struct load_command : public ::load_command {
  constexpr static uint32_t CMDS[] = {0x00, 0x00}; // magic value for all lcs
};

template <class P> struct segment_command {};
template <>
struct segment_command<Utils::Arch::Pointer32> : public ::segment_command {
  constexpr static uint32_t CMDS[] = {LC_SEGMENT};
};
template <>
struct segment_command<Utils::Arch::Pointer64> : public ::segment_command_64 {
  constexpr static uint32_t CMDS[] = {LC_SEGMENT_64};
};

template <class P> struct section {};
template <> struct section<Utils::Arch::Pointer32> : public ::section {};
template <> struct section<Utils::Arch::Pointer64> : public ::section_64 {};

struct symtab_command : public ::symtab_command {
  constexpr static uint32_t CMDS[] = {LC_SYMTAB};
};

struct dysymtab_command : public ::dysymtab_command {
  constexpr static uint32_t CMDS[] = {LC_DYSYMTAB};
};

struct linkedit_data_command : public ::linkedit_data_command {
  constexpr static uint32_t CMDS[] = {
      LC_CODE_SIGNATURE,    LC_SEGMENT_SPLIT_INFO,  LC_FUNCTION_STARTS,
      LC_DATA_IN_CODE,      LC_DYLIB_CODE_SIGN_DRS, LC_LINKER_OPTIMIZATION_HINT,
      LC_DYLD_EXPORTS_TRIE, LC_DYLD_CHAINED_FIXUPS};
};

struct dyld_info_command : public ::dyld_info_command {
  constexpr static uint32_t CMDS[] = {LC_DYLD_INFO, LC_DYLD_INFO_ONLY};
};

template <class P> struct nlist {};
template <> struct nlist<Utils::Arch::Pointer32> : public ::nlist {};
template <> struct nlist<Utils::Arch::Pointer64> : public ::nlist_64 {};

struct dylib_command : public ::dylib_command {
  constexpr static uint32_t CMDS[] = {LC_ID_DYLIB,          LC_LOAD_DYLIB,
                                      LC_LOAD_WEAK_DYLIB,   LC_REEXPORT_DYLIB,
                                      LC_LOAD_UPWARD_DYLIB, LC_LAZY_LOAD_DYLIB};
};

}; // namespace DyldExtractor::Macho::Loader

#endif // __MACHO_LOADER__