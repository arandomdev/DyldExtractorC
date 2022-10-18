#ifndef __PROVIDER_ACCELERATOR__
#define __PROVIDER_ACCELERATOR__

#include <dyld/dyld_cache_format.h>
#include <map>
#include <set>
#include <string>
#include <unordered_set>

#pragma warning(push)
#pragma warning(disable : 4267)
#include <dyld/Trie.hpp>
#pragma warning(pop)

namespace DyldExtractor::Provider {

namespace AcceleratorTypes {

/// Intermediate representation of a export, should not be used.
struct SymbolizerExportEntry {
  uint64_t address;
  ExportInfoTrie::Entry entry;

  /// @brief This constructor should only be used for searching
  SymbolizerExportEntry(std::string n) : address(0), entry(n, ExportInfo()) {}
  SymbolizerExportEntry(uint64_t a, ExportInfoTrie::Entry e)
      : address(a), entry(e) {}

  struct Hash {
    std::size_t operator()(const SymbolizerExportEntry &e) const {
      return std::hash<std::string>{}(e.entry.name);
    }
  };

  struct KeyEqual {
    bool operator()(const SymbolizerExportEntry &a,
                    const SymbolizerExportEntry &b) const {
      return a.entry.name == b.entry.name;
    }
  };
};

using SymbolizerExportEntryMapT =
    std::unordered_multiset<SymbolizerExportEntry, SymbolizerExportEntry::Hash,
                            SymbolizerExportEntry::KeyEqual>;

}; // namespace AcceleratorTypes

/// Accelerate modules when processing more than one image. Single threaded.
template <class P> class Accelerator {
  using PtrT = P::PtrT;

public:
  // Provider::Symbolizer
  std::map<std::string, const dyld_cache_image_info *> pathToImage;
  std::map<std::string, AcceleratorTypes::SymbolizerExportEntryMapT>
      exportsCache;

  // Converter::Stubs::Arm64Utils, Converter::Stubs::ArmUtils
  std::map<PtrT, PtrT> arm64ResolvedChains;
  std::map<PtrT, PtrT> armResolvedChains;

  // Converter::Stubs::Fixer
  struct CodeRegion {
    PtrT start;
    PtrT end;
    auto operator<=>(const auto &o) const { return start <=> o.start; }
  };
  std::set<CodeRegion> codeRegions;

  Accelerator() = default;
  Accelerator(const Accelerator &) = delete;
  Accelerator &operator=(const Accelerator &) = delete;
};

}; // namespace DyldExtractor::Provider

#endif // __PROVIDER_ACCELERATOR__