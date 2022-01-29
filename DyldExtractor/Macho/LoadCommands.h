#ifndef __MACHO_LOADCOMMANDS__
#define __MACHO_LOADCOMMANDS__

#include <mach-o/loader.h>

namespace Macho {
namespace LC {

struct load_command {
    using cmdT = ::load_command;
    constexpr static uint32_t cmds[] = {0x00, 0x00}; // magic value for all lcs
};

struct segment_command_64 {
    using cmdT = ::segment_command_64;
    constexpr static uint32_t cmds[] = {LC_SEGMENT_64};
};

}; // namespace LC
}; // namespace Macho

#endif // __MACHO_LOADCOMMANDS__