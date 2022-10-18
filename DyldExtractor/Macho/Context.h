#ifndef __MACHO_CONTEXT__
#define __MACHO_CONTEXT__

#include <boost/iostreams/device/mapped_file.hpp>
#include <filesystem>

#include "Loader.h"
#include <dyld/dyld_cache_format.h>
#include <mach-o/loader.h>

namespace DyldExtractor::Macho {

namespace bio = boost::iostreams;
namespace fs = std::filesystem;

// Conditional const
template <bool _Test, class _T> struct c_const {
  using T = _T;
};
template <class _T> struct c_const<true, _T> {
  using T = const _T;
};

struct MappingInfo {
  uint64_t address;
  uint64_t size;
  uint64_t fileOffset;

  MappingInfo() = default;
  MappingInfo(const dyld_cache_mapping_info *);
};

template <bool ro, class P> class SegmentContext {
public:
  using SegmentCommandT = c_const<ro, Loader::segment_command<P>>::T;
  using SectionT = c_const<ro, Loader::section<P>>::T;

  SegmentCommandT *command;
  std::vector<SectionT *> sections;

  SegmentContext(SegmentCommandT *segment);
};

/// A wrapper around a MachO file in the DSC.
/// The template boolean determines if it is read only.
template <bool ro, class P> class Context {
public:
  using FileT = c_const<ro, uint8_t>::T;
  using LoadCommandT = c_const<ro, Loader::load_command>::T;
  using HeaderT = c_const<ro, Loader::mach_header<P>>::T;
  using SegmentT = SegmentContext<ro, P>;
  using EnumerationCallback =
      std::function<bool(SegmentT &, typename SegmentT::SectionT *)>;

  // The file containing the header
  FileT *file;
  HeaderT *header;

  std::vector<LoadCommandT *> loadCommands;
  std::vector<SegmentT> segments;

  /// @brief A wrapper around a MachO file.
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
  /// @brief A writable wrapper around a MachO file.
  ///
  /// The files will be opened with private (copy on write) access.
  ///
  /// @param fileOffset The file offset to the mach header.
  /// @param mainPath The file path of the file that contains the header.
  /// @param mainMapping The mapping info for mainFile
  /// @param subFiles A vector of tuples of all other file paths and their
  ///   mapping info.
  Context(uint64_t fileOffset, fs::path mainPath,
          std::vector<MappingInfo> mainMappings,
          std::vector<std::tuple<fs::path, std::vector<MappingInfo>>> subFiles);

  /// @brief Reload the header and load commands
  void reloadHeader();

  /// @brief Convert a vmaddr to it's file offset.
  ///
  /// If the offset could not be found, a pair with 0 and
  /// nullptr will be returned.
  ///
  /// @param addr The virtual address to convert.
  /// @returns A pair of the file offset and its file.
  std::pair<uint64_t, FileT *> convertAddr(uint64_t addr) const;

  /// @brief Convert a vmaddr to it's file offset.
  ///
  /// If the offset could not be found, nullptr will be
  /// returned.
  ///
  /// @param addr The virtual address to convert.
  /// @returns A file based pointer to the address
  FileT *convertAddrP(uint64_t addr) const;

  /// @brief Get the first load command with a custom filter
  /// @tparam lc The type of load command
  /// @param cmds The custom ID filter
  /// @return A pointer to the load command, nullptr if not found
  template <class lc, std::size_t _s>
  inline c_const<ro, lc>::T *getFirstLC(const uint32_t (&cmds)[_s]) const {
    return reinterpret_cast<c_const<ro, lc>::T *>(_getFirstLC(cmds, _s));
  }

  /// @brief Get the first load command
  /// @tparam lc The type of load command
  /// @return A pointer to the load command, nullptr if not found
  template <class lc> inline c_const<ro, lc>::T *getFirstLC() const {
    return getFirstLC<lc>(lc::CMDS);
  }

  /// @brief Get all load commands with a custom filter
  /// @tparam lc The type of load command
  /// @param cmds The custom ID filter
  /// @return A list of pointers to load commands
  template <class lc, std::size_t _s>
  inline std::vector<typename c_const<ro, lc>::T *>
  getAllLCs(const uint32_t (&cmds)[_s]) const {
    return reinterpret_cast<std::vector<typename c_const<ro, lc>::T *> &>(
        _getAllLCs(cmds, _s));
  }

  /// @brief Get all load commands
  /// @tparam lc The type of load command
  /// @return A list of pointer to load commands
  template <class lc>
  inline std::vector<typename c_const<ro, lc>::T *> getAllLCs() const {
    return getAllLCs<lc>(lc::CMDS);
  }

  /// @brief Search for a segment
  ///
  /// @param segName The name of the segment.
  /// @returns The segment context. nullptr if not found.
  const SegmentT *getSegment(const char *segName) const;

  /// @brief Search for a section
  /// @param segName The name of the segment, or nullptr.
  /// @param sectName The name of the section.
  /// @returns The segment and the section
  std::pair<const SegmentT *, const typename SegmentT::SectionT *>
  getSection(const char *segName, const char *sectName) const;

  /// @brief Enumerate all segments
  /// @param pred The predicate used to filter.
  /// @param callback The function to call for each section. Return false to
  ///     stop.
  void enumerateSections(EnumerationCallback pred,
                         EnumerationCallback callback);

  /// @brief Enumerate all segments
  /// @param callback The function to call for each section. Return false to
  ///     stop.
  void enumerateSections(EnumerationCallback callback);

  /// @brief Check if the address is in the macho file
  /// @param addr
  /// @returns If the file contains the address
  bool containsAddr(const uint64_t addr) const;

  ~Context();
  Context(const Context &other) = delete;
  Context(Context &&other);
  Context &operator=(const Context &other) = delete;
  Context &operator=(Context &&other);

private:
  uint64_t headerOffset;
  // Determines if the file need to be closed during destruction.
  bool ownFiles = false;
  // Indicates if the files are open, false if ownFiles is false.
  bool filesOpen = false;

  // Contains all file maps
  std::vector<bio::mapped_file> fileMaps;
  // Contains all files and mappings
  std::vector<std::tuple<FileT *, std::vector<MappingInfo>>> files;

  std::vector<LoadCommandT *> _getAllLCs(const uint32_t (&targetCmds)[],
                                         std::size_t ncmds) const;
  LoadCommandT *_getFirstLC(const uint32_t (&targetCmds)[],
                            std::size_t ncmds) const;

  // Convenience method to open files with private access.
  static bio::mapped_file openFile(fs::path path);
  static std::vector<std::tuple<bio::mapped_file, std::vector<MappingInfo>>>
  openFiles(std::vector<std::tuple<fs::path, std::vector<MappingInfo>>> paths);
};

}; // namespace DyldExtractor::Macho

#endif // __MACHO_CONTEXT__