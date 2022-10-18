#include "Symbolizer.h"

#include <ranges>
#include <spdlog/spdlog.h>

using namespace DyldExtractor;
using namespace Provider;

#pragma region SymbolicInfo
bool SymbolicInfo::Symbol::isReExport() const {
  if (exportFlags && *exportFlags & EXPORT_SYMBOL_FLAGS_REEXPORT) {
    return true;
  }

  return false;
}

std::strong_ordering
SymbolicInfo::Symbol::operator<=>(const Symbol &rhs) const {
  if (auto cmp = this->isReExport() <=> rhs.isReExport(); cmp != 0) {
    return cmp; // ReExports are better
  } else if (cmp = rhs.name <=> this->name; cmp != 0) {
    return cmp; // reverse names to avoid private symbols, A > _A
  } else if (cmp = this->ordinal <=> rhs.ordinal; cmp != 0) {
    return cmp; // smaller ordinals
  } else {
    return std::strong_ordering::equal;
  }
}

SymbolicInfo::SymbolicInfo(Symbol first, Encoding encoding)
    : symbols{first}, encoding(encoding) {}

SymbolicInfo::SymbolicInfo(std::set<Symbol> &symbols, Encoding encoding)
    : symbols(symbols), encoding(encoding) {
  assert(!symbols.empty() && "Constructed with empty set");
}
SymbolicInfo::SymbolicInfo(std::set<Symbol> &&symbols, Encoding encoding)
    : symbols(symbols), encoding(encoding) {
  assert(!symbols.empty() && "Constructed with empty set");
}

void SymbolicInfo::addSymbol(Symbol sym) { symbols.insert(sym); }

const SymbolicInfo::Symbol &SymbolicInfo::preferredSymbol() const {
  /**
   * There are 3 comparisons, in the following order, Normal or ReExport, name,
   * And ordinal. Normal is preferred, names are reverse compared, and highest
   * ordinal is preferred.
   */

  const Symbol *current = &(*symbols.begin());

  for (const auto &sym : symbols | std::views::drop(1)) {
    if (!current->isReExport() && sym.isReExport()) {
      current = &sym;
      continue;
    }

    if (current->name < sym.name) {
      current = &sym;
      continue;
    }

    // uniqueness is guaranteed by set
    if (current->ordinal < sym.ordinal) {
      current = &sym;
    }
  }

  return *current;
}
#pragma endregion SymbolicInfo

#pragma region Symbolizer
template <class A>
Symbolizer<A>::Symbolizer(const Dyld::Context &dCtx,
                          Macho::Context<false, P> &mCtx,
                          Logger::Activity &activity,
                          std::shared_ptr<spdlog::logger> logger,
                          Provider::Accelerator<P> &accelerator)
    : dCtx(&dCtx), mCtx(&mCtx), activity(&activity), logger(logger),
      accelerator(&accelerator) {}

template <class A> void Symbolizer<A>::enumerate() {
  activity->update(std::nullopt, "Enumerating Symbols");
  enumerateExports();
  enumerateSymbols();
}

template <class A>
const SymbolicInfo *Symbolizer<A>::symbolizeAddr(PtrT addr) const {
  if (symbols.contains(addr)) {
    return symbols.at(addr).get();
  } else {
    return nullptr;
  }
}

template <class A> bool Symbolizer<A>::containsAddr(PtrT addr) const {
  return symbols.contains(addr);
}

template <class A>
std::shared_ptr<SymbolicInfo> Symbolizer<A>::shareInfo(PtrT addr) const {
  return symbols.at(addr);
}

template <class A> void Symbolizer<A>::enumerateExports() {
  // Populate accelerator's pathToImage if needed
  if (accelerator->pathToImage.empty()) {
    for (auto image : dCtx->images) {
      std::string path((char *)(dCtx->file + image->pathFileOffset));
      accelerator->pathToImage[path] = image;
    }
  }

  // Process all dylibs including itself.
  auto dylibs = mCtx->getAllLCs<Macho::Loader::dylib_command>();
  for (uint64_t i = 0; i < dylibs.size(); i++) {
    const auto &exports = processDylibCmd(dylibs[i]);
    for (const auto &e : exports) {
      PtrT addr = e.address & -4;

      if (symbols.contains(addr)) {
        symbols.at(addr)->addSymbol({e.entry.name, i, e.entry.info.flags});
      } else {
        SymbolicInfo::Encoding enc;
        if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
          enc = static_cast<SymbolicInfo::Encoding>(e.address & 3);
        } else {
          enc = SymbolicInfo::Encoding::None;
        }

        symbols.emplace(
            addr, std::make_shared<SymbolicInfo>(
                      SymbolicInfo::Symbol{e.entry.name, i, e.entry.info.flags},
                      enc));
      }
    }
  }
}

template <class A> void Symbolizer<A>::enumerateSymbols() {
  auto linkeditFile =
      mCtx->convertAddr(mCtx->getSegment(SEG_LINKEDIT)->command->vmaddr).second;
  auto symtab = mCtx->getFirstLC<Macho::Loader::symtab_command>();
  auto symbolEntries =
      (Macho::Loader::nlist<P> *)(linkeditFile + symtab->symoff);
  auto strings = (char *)(linkeditFile + symtab->stroff);

  for (uint32_t i = 0; i < symtab->nsyms; i++) {
    auto symbol = symbolEntries + i;
    if ((symbol->n_type & N_TYPE) == N_SECT) {
      auto addr = symbol->n_value;
      if (symbols.contains(addr)) {
        symbols.at(addr)->addSymbol({strings + symbol->n_un.n_strx,
                                     SELF_LIBRARY_ORDINAL, std::nullopt});
      } else {
        SymbolicInfo::Encoding enc;
        if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
          enc = static_cast<SymbolicInfo::Encoding>(addr & 3);
        } else {
          enc = SymbolicInfo::Encoding::None;
        }

        symbols.emplace(
            addr, std::make_shared<SymbolicInfo>(
                      SymbolicInfo::Symbol{strings + symbol->n_un.n_strx,
                                           SELF_LIBRARY_ORDINAL, std::nullopt},
                      enc));
      }
    }
  }
}

template <class A>
Symbolizer<A>::EntryMapT &Symbolizer<A>::processDylibCmd(
    const Macho::Loader::dylib_command *dylibCmd) const {
  const std::string dylibPath(
      (char *)((uint8_t *)dylibCmd + dylibCmd->dylib.name.offset));
  if (accelerator->exportsCache.contains(dylibPath)) {
    return accelerator->exportsCache[dylibPath];
  }
  if (!accelerator->pathToImage.contains(dylibPath)) {
    /// It may refer to images outside the cache, but it doesn't seem to affect
    /// anything
    SPDLOG_LOGGER_DEBUG(logger, "Unable to find image with path {}", dylibPath);
    return accelerator->exportsCache[dylibPath]; // Empty map
  }

  // dequeue empty map to fill
  auto &exportsMap = accelerator->exportsCache[dylibPath];

  // process exports
  const auto imageInfo = accelerator->pathToImage.at(dylibPath);
  const auto dylibCtx = dCtx->createMachoCtx<true, P>(imageInfo);
  const auto rawExports = readExports(dylibPath, dylibCtx);
  std::map<uint64_t, std::vector<ExportInfoTrie::Entry>> reExports;
  for (const auto &e : rawExports) {
    if (e.info.flags & EXPORT_SYMBOL_FLAGS_REEXPORT) {
      reExports[e.info.other].push_back(e);
      continue;
    } else if (!e.info.address) {
      // Some exports like __objc_empty_vtable don't have an address?
      continue;
    }

    const auto eAddr = imageInfo->address + e.info.address;
    exportsMap.emplace(eAddr, e);

    if (e.info.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) {
      // The address points to the stub, while "other" points
      // to the function itself. Add the function as well.
      const auto fAddr = imageInfo->address + e.info.other;
      exportsMap.emplace(fAddr, e);
    }
  }

  // Process ReExports
  auto dylibDeps = dylibCtx.getAllLCs<Macho::Loader::dylib_command>();
  dylibDeps.erase(std::remove_if(dylibDeps.begin(), dylibDeps.end(),
                                 [](auto d) { return d->cmd == LC_ID_DYLIB; }),
                  dylibDeps.end());
  for (const auto &[ordinal, exports] : reExports) {
    const auto ordinalCmd = dylibDeps[ordinal - 1];
    const auto &ordinalExports = processDylibCmd(ordinalCmd);
    if (!ordinalExports.size()) {
      // In case the image was not found or if it didn't have any exports.
      continue;
    }

    for (const auto &e : exports) {
      // importName has the old symbol, otherwise it
      // is reexported under the same name.
      const auto importName =
          e.info.importName.length() ? e.info.importName : e.name;

      const auto it = ordinalExports.find(ExportEntry(importName));
      if (it != ordinalExports.end()) {
        exportsMap.emplace((*it).address, e);
      } else {
        SPDLOG_LOGGER_DEBUG(logger,
                            "Unable to find parent export with name {}, for "
                            "ReExport with name {}",
                            importName, e.name);
      }
    }
  }

  // Process ReExports dylibs
  for (const auto &dep : dylibDeps) {
    if (dep->cmd == LC_REEXPORT_DYLIB) {
      // Use parent ordinal because symbols are reexported.
      const auto reExports = processDylibCmd(dep);
      exportsMap.insert(reExports.begin(), reExports.end());
    }
  }

  return exportsMap;
}

template <class A>
std::vector<ExportInfoTrie::Entry>
Symbolizer<A>::readExports(const std::string &dylibPath,
                           const Macho::Context<true, P> &dylibCtx) const {
  // read exports
  std::vector<ExportInfoTrie::Entry> exports;
  const uint8_t *exportsStart;
  const uint8_t *exportsEnd;
  const auto linkeditFile =
      dylibCtx.convertAddr(dylibCtx.getSegment(SEG_LINKEDIT)->command->vmaddr)
          .second;
  const auto exportTrieCmd =
      dylibCtx.getFirstLC<Macho::Loader::linkedit_data_command>(
          {LC_DYLD_EXPORTS_TRIE});
  const auto dyldInfo = dylibCtx.getFirstLC<Macho::Loader::dyld_info_command>();
  if (exportTrieCmd) {
    exportsStart = linkeditFile + exportTrieCmd->dataoff;
    exportsEnd = exportsStart + exportTrieCmd->datasize;
  } else if (dyldInfo) {
    exportsStart = linkeditFile + dyldInfo->export_off;
    exportsEnd = exportsStart + dyldInfo->export_size;
  } else {
    SPDLOG_LOGGER_ERROR(logger, "Unable to get exports for '{}'", dylibPath);
    return exports;
  }

  if (exportsStart == exportsEnd) {
    // Some images like UIKIT don't have exports.
  } else if (!ExportInfoTrie::parseTrie(exportsStart, exportsEnd, exports)) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to read exports for '{}'", dylibPath);
  }

  return exports;
}

template class Symbolizer<Utils::Arch::x86_64>;
template class Symbolizer<Utils::Arch::arm>;
template class Symbolizer<Utils::Arch::arm64>;
template class Symbolizer<Utils::Arch::arm64_32>;
#pragma endregion Symbolizer