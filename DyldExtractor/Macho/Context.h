#ifndef __MACHO_CONTEXT__
#define __MACHO_CONTEXT__

#include <boost/iostreams/device/mapped_file.hpp>
#include <filesystem>

#include <dyld/dyld_cache_format.h>
#include <mach-o/loader.h>

namespace Macho {

namespace bio = boost::iostreams;
namespace fs = std::filesystem;

// Conditional const
template <bool _Test, class _T> struct c_const { using T = _T; };
template <class _T> struct c_const<true, _T> { using T = const _T; };

struct MappingInfo {
    uint64_t address;
    uint64_t size;
    uint64_t fileOffset;

    MappingInfo() = default;
    MappingInfo(const dyld_cache_mapping_info *);
};

template <bool _ro> class SegmentContext {
    using _SegmentCommandT = c_const<_ro, segment_command_64>::T;
    using _SectionT = c_const<_ro, section_64>::T;

  public:
    _SegmentCommandT *command;
    std::vector<_SectionT *> sections;

    SegmentContext(_SegmentCommandT *segment);
};

/// A wrapper around a MachO file in the DSC.
/// The template boolean determines if it is read only.
template <bool _ro> class Context {
    using _FileT = c_const<_ro, char>::T;
    using _HeaderT = c_const<_ro, mach_header_64>::T;
    using _LoadCommandT = c_const<_ro, load_command>::T;

  public:
    // The file containing the header
    _FileT *file;
    _HeaderT *header;

    std::vector<_LoadCommandT *> loadCommands;
    std::vector<typename SegmentContext<_ro>> segments;

    /// Create a wrapper around a MachO file.
    ///
    /// The access permissions is based on the main file provided. Calling this
    /// directly also implies that the context does not manage the file maps.
    ///
    /// @param fileOffset The file offset to the mach header.
    /// @param mainFile The memory map that contains the header.
    /// @param mainMapping The mapping info for mainFile
    /// @param subFiles A vector of tuples of all other memory maps and their
    ///   mapping info.
    Context(uint64_t fileOffset, bio::mapped_file mainFile,
            std::vector<MappingInfo> mainMappings,
            std::vector<std::tuple<bio::mapped_file, std::vector<MappingInfo>>>
                subFiles);
    /// Create a writable wrapper around a MachO file.
    ///
    /// The files will be opened with private (copy on write) access.
    ///
    /// @param fileOffset The file offset to the mach header.
    /// @param mainPath The file path of the file that contains the header.
    /// @param mainMapping The mapping info for mainFile
    /// @param subFiles A vector of tuples of all other file paths and their
    ///   mapping info.
    Context(
        uint64_t fileOffset, fs::path mainPath,
        std::vector<MappingInfo> mainMappings,
        std::vector<std::tuple<fs::path, std::vector<MappingInfo>>> subFiles);

    /// Convert a vmaddr to it's file offset.
    /// If the offset could not be found, a tuple with 0 and
    /// nullptr will be returned.
    ///
    /// @param addr The virtual address to convert.
    /// @returns A tuple of the file offset and its file.
    std::tuple<uint64_t, _FileT *> convertAddr(uint64_t addr) const;

    /// Get load commands
    ///
    /// Use the template to set if multiple load commands should be returned and
    /// the type of the load command. If multiple is false, the first match is
    /// returned.
    ///
    /// @returns A vector of load command pointers or a single load command
    ///     pointer.
    template <bool _m, class _c,
              class _ct = c_const<_ro, typename _c::CMD_T>::T>
    std::conditional<_m, std::vector<_ct *>, _ct *>::type
    getLoadCommand() const {
        auto ncmds = []<std::size_t _s>(const uint32_t(&)[_s]) constexpr {
            return _s;
        };

        if constexpr (_m) {
            return reinterpret_cast<std::vector<_ct *> &>(
                _getLoadCommands(_c::CMDS, ncmds(_c::CMDS)));
        } else {
            return (_ct *)_getLoadCommand(_c::CMDS, ncmds(_c::CMDS));
        }
    }

    /// Get load commands
    ///
    /// Use the template to set if multiple load commands should be returned and
    /// the type of the load command. If multiple is false, the first match is
    /// returned.
    ///
    /// @param cmds Overdrive the default set of command IDs associated with the
    ///     template command.
    /// @returns A vector of load command pointers or a single load command
    ///     pointer.
    template <bool _m, class _c,
              class _ct = c_const<_ro, typename _c::CMD_T>::T, std::size_t _s>
    std::conditional<_m, std::vector<_ct *>, _ct *>::type
    getLoadCommand(const uint32_t (&cmds)[_s]) const {
        if constexpr (_m) {
            return reinterpret_cast<std::vector<_ct *> &>(
                _getLoadCommands(cmds, _s));
        } else {
            return (_ct *)_getLoadCommand(cmds, _s);
        }
    }

    ~Context();
    Context(const Context &other) = delete;
    Context(Context &&other);
    Context &operator=(const Context &other) = delete;
    Context &operator=(Context &&other);

  private:
    // Determines if the file need to be closed during destruction.
    bool _ownFiles = false;
    // Indicates if the files are open, false if _ownFiles is false.
    bool _filesOpen = false;

    // Contains all file maps
    std::vector<bio::mapped_file> _fileMaps;
    // Contains all files and mappings
    std::vector<std::tuple<_FileT *, std::vector<MappingInfo>>> _files;

    std::vector<_LoadCommandT *>
    _getLoadCommands(const uint32_t (&targetCmds)[], std::size_t ncmds) const;
    _LoadCommandT *_getLoadCommand(const uint32_t (&targetCmds)[],
                                   std::size_t ncmds) const;

    // Convenience method to open files with private access.
    static bio::mapped_file openFile(fs::path path);
    static std::vector<std::tuple<bio::mapped_file, std::vector<MappingInfo>>>
    openFiles(
        std::vector<std::tuple<fs::path, std::vector<MappingInfo>>> paths);
};

}; // namespace Macho

#endif // __MACHO_CONTEXT__