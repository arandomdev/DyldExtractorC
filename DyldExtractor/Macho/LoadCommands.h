#ifndef __MACHO_LOADCOMMANDS__
#define __MACHO_LOADCOMMANDS__

#include <mach-o/loader.h>

namespace Macho {
namespace LC {

struct load_command {
    using CMD_T = ::load_command;
    constexpr static uint32_t CMDS[] = {0x00, 0x00}; // magic value for all lcs
};

struct segment_command_64 {
    using CMD_T = ::segment_command_64;
    constexpr static uint32_t CMDS[] = {LC_SEGMENT_64};
};

struct symtab_command {
    using CMD_T = ::symtab_command;
    constexpr static uint32_t CMDS[] = {LC_SYMTAB};
};

struct dysymtab_command {
    using CMD_T = ::dysymtab_command;
    constexpr static uint32_t CMDS[] = {LC_DYSYMTAB};
};

struct linkedit_data_command {
    using CMD_T = ::linkedit_data_command;
    constexpr static uint32_t CMDS[] = {
        LC_CODE_SIGNATURE,      LC_SEGMENT_SPLIT_INFO,
        LC_FUNCTION_STARTS,     LC_DATA_IN_CODE,
        LC_DYLIB_CODE_SIGN_DRS, LC_LINKER_OPTIMIZATION_HINT,
        LC_DYLD_EXPORTS_TRIE,   LC_DYLD_CHAINED_FIXUPS};
};

struct dyld_info_command {
    using CMD_T = ::dyld_info_command;
    constexpr static uint32_t CMDS[] = {LC_DYLD_INFO, LC_DYLD_INFO_ONLY};
};

}; // namespace LC
}; // namespace Macho

#endif // __MACHO_LOADCOMMANDS__