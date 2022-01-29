#ifndef __DYLD_CONTEXT__
#define __DYLD_CONTEXT__

#include <boost/iostreams/device/mapped_file.hpp>
#include <filesystem>

#include <Macho/Context.h>
#include <dyld/dyld_cache_format.h>

namespace Dyld {

namespace bio = boost::iostreams;
namespace fs = std::filesystem;

class Context {
  public:
    const char *file;
    const dyld_cache_header *header;
    std::vector<const dyld_cache_image_info *> images;

    Context(fs::path sharedCachePath);
    ~Context();
    Context(const Context &other) = delete;
    Context(Context &&other);
    Context &operator=(const Context &other) = delete;
    Context &operator=(Context &&other);

    /// Convert a vmaddr to it's file offset.
    /// If the offset could not be found, a tuple with 0 and
    /// nullptr will be returned.
    ///
    /// @param addr The virtual address to convert.
    /// @returns A tuple of the file offset and its Context.
    std::tuple<uint64_t, const Context *> convertAddr(uint64_t addr) const;

    /// Determine if a member is contained in the header
    ///
    /// @param memberOffset The offset to the member.
    /// @returns A boolean on whether the header contains the member.
    bool headerContainsMember(std::size_t memberOffset) const;

    /// Create a macho context
    ///
    /// Use the template boolean to set if the macho has readonly access or
    /// private access.
    ///
    /// @param imageInfo The image info of the MachO file.
    template <bool _readonly>
    Macho::Context<_readonly>
    createMachoCtx(const dyld_cache_image_info *imageInfo) const;

  private:
    bio::mapped_file _cacheFile;
    fs::path _cachePath;
    // False when the cacheFile is not constructed, closed, or moved.
    bool _cacheOpen = false;

    std::vector<Context> _subcaches;
    std::vector<const dyld_cache_mapping_info *> _mappings;
};

}; // namespace Dyld

#endif // __DYLD_CONTEXT__