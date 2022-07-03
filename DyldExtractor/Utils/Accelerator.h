#ifndef __UTILS_ACCELERATOR__
#define __UTILS_ACCELERATOR__

#include <dyld/dyld_cache_format.h>
#include <map>
#include <set>
#include <string>
#include <unordered_set>

#pragma warning(push)
#pragma warning(disable : 4267)
#include <dyld/Trie.hpp>
#pragma warning(pop)

namespace Utils {

namespace AcceleratorTypes {

/// Intermediate representation of a export, should not be used.
struct SymbolizerExportEntry {
  uint64_t address;
  ExportInfoTrie::Entry entry;

  /// This constructor should only be used for searching
  SymbolizerExportEntry(std::string n) : address(0), entry(n, ExportInfo()) {}
  SymbolizerExportEntry(uint64_t a, ExportInfoTrie::Entry e)
      : address(a), entry(e) {}
};
const static inline auto SymbolizerExportEntryHash =
    [](const SymbolizerExportEntry &e) {
      return std::hash<std::string>{}(e.entry.name);
    };
const static inline auto SymbolizerExportEntryEqual =
    [](const SymbolizerExportEntry &a, const SymbolizerExportEntry &b) {
      return a.entry.name == b.entry.name;
    };
using SymbolizerExportEntryMapT =
    std::unordered_multiset<SymbolizerExportEntry,
                            decltype(SymbolizerExportEntryHash),
                            decltype(SymbolizerExportEntryEqual)>;

}; // namespace AcceleratorTypes

/// Accelerate modules when processing more than one image. Single threaded.
template <class P> class Accelerator {
public:
  // Symbolizer
  std::map<std::string, const dyld_cache_image_info *> pathToImage;
  std::map<std::string, AcceleratorTypes::SymbolizerExportEntryMapT>
      exportsCache;

  // Arm64Utils
  std::map<uint64_t, uint64_t> arm64ResolvedChains;

  // StubFixer
  struct CodeRegion {
    uint64_t start;
    uint64_t end;
    auto operator<=>(const auto &o) const { return start <=> o.start; }
  };
  std::set<CodeRegion> codeRegions;

  Accelerator() = default;
  Accelerator(const Accelerator &) = delete;
  Accelerator(Accelerator &&other) = default;
  Accelerator &operator=(const Accelerator &) = delete;
  Accelerator &operator=(Accelerator &&other) = default;
};

}; // namespace Utils

#endif // __UTILS_ACCELERATOR__