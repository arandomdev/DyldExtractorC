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
    const uint8_t *file;
    const dyld_cache_header *header;
    std::vector<const dyld_cache_image_info *> images;
    std::vector<Context> subcaches;

    Context(fs::path sharedCachePath, const uint8_t *subCacheUUID = nullptr);
    ~Context();
    Context(const Context &other) = delete;
    Context(Context &&other);
    Context &operator=(const Context &other) = delete;
    Context &operator=(Context &&other);

    /// Convert a vmaddr to it's file offset.
    /// If the offset could not be found, a pair with 0 and
    /// nullptr will be returned.
    ///
    /// @param addr The virtual address to convert.
    /// @returns A pair of the file offset and its Context.
    std::pair<uint64_t, const Context *> convertAddr(uint64_t addr) const;

    /// Convert a vmaddr to it's file offset.
    /// If the offset could not be found, nullptr will be
    /// returned.
    ///
    /// @param addr The virtual address to convert.
    /// @returns A file based pointer to the address
    const uint8_t *convertAddrP(uint64_t addr) const;

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
    template <bool ro, class P>
    Macho::Context<ro, P>
    createMachoCtx(const dyld_cache_image_info *imageInfo) const;

    /// Get the cache file for local symbols
    const Context *getSymbolsCache() const;

  private:
    bio::mapped_file _cacheFile;
    fs::path _cachePath;
    // False when the cacheFile is not constructed, closed, or moved.
    bool _cacheOpen = false;

    std::vector<const dyld_cache_mapping_info *> _mappings;

    void _preflightCache(const uint8_t *subCacheUUID = nullptr);
};

}; // namespace Dyld

#endif // __DYLD_CONTEXT__