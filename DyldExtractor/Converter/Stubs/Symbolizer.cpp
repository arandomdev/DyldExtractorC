#include "Symbolizer.h"

#include <spdlog/spdlog.h>

using namespace Converter;

template <class A>
Symbolizer<A>::Symbolizer(const Utils::ExtractionContext<A> &eCtx)
    : dCtx(eCtx.dCtx), mCtx(eCtx.mCtx), activity(eCtx.activity),
      logger(eCtx.logger), accelerator(eCtx.accelerator) {}

template <class A> void Symbolizer<A>::enumerate() {
  activity.update(std::nullopt, "Enumerating Symbols");
  enumerateExports();
  enumerateSymbols();
}

template <class A>
const SymbolicInfo *Symbolizer<A>::symbolizeAddr(uint64_t addr) const {
  if (symbols.contains(addr)) {
    return &symbols.at(addr);
  } else {
    return nullptr;
  }
}

template <class A> void Symbolizer<A>::enumerateExports() {
  // Populate accelerator's pathToImage if needed
  if (accelerator.pathToImage.empty()) {
    for (auto image : dCtx.images) {
      std::string path((char *)(dCtx.file + image->pathFileOffset));
      accelerator.pathToImage[path] = image;
    }
  }

  // Process all dylibs including itself.
  auto dylibs = mCtx.getLoadCommand<true, Macho::Loader::dylib_command>();
  for (uint64_t i = 0; i < dylibs.size(); i++) {
    const auto &exports = processDylibCmd(dylibs[i]);
    for (const auto &e : exports) {
      if (symbols.contains(e.address)) {
        symbols.at(e.address).addSymbol({e.entry.name, i, e.entry.info.flags});
      } else {
        symbols.insert({e.address, SymbolicInfo::Symbol{e.entry.name, i,
                                                        e.entry.info.flags}});
      }
    }
  }
}

template <class A> void Symbolizer<A>::enumerateSymbols() {
  auto linkeditFile =
      mCtx.convertAddr(mCtx.getSegment("__LINKEDIT")->command->vmaddr).second;
  auto symtab = mCtx.getLoadCommand<false, Macho::Loader::symtab_command>();
  auto symbolEntries =
      (Macho::Loader::nlist<P> *)(linkeditFile + symtab->symoff);
  auto strings = (char *)(linkeditFile + symtab->stroff);

  for (uint32_t i = 0; i < symtab->nsyms; i++) {
    auto symbol = symbolEntries + i;
    if ((symbol->n_type & N_TYPE) == N_SECT) {
      auto addr = symbol->n_value;
      if (symbols.contains(addr)) {
        symbols.at(addr).addSymbol(
            {strings + symbol->n_un.n_strx, 0, std::nullopt});
      } else {
        symbols.insert(
            {addr, SymbolicInfo::Symbol{strings + symbol->n_un.n_strx, 0,
                                        std::nullopt}});
      }
    }
  }
}

template <class A>
Symbolizer<A>::EntryMapT &Symbolizer<A>::processDylibCmd(
    const Macho::Loader::dylib_command *dylibCmd) const {
  const std::string dylibPath(
      (char *)((uint8_t *)dylibCmd + dylibCmd->dylib.name.offset));
  if (accelerator.exportsCache.contains(dylibPath)) {
    return accelerator.exportsCache[dylibPath];
  }
  if (!accelerator.pathToImage.contains(dylibPath)) {
    SPDLOG_LOGGER_DEBUG(logger, "Unable to find image with path {}", dylibPath);
    return accelerator.exportsCache[dylibPath]; // Empty map
  }

  // dequeue empty map to fill
  auto &exportsMap = accelerator.exportsCache[dylibPath];

  // process exports
  const auto imageInfo = accelerator.pathToImage.at(dylibPath);
  const auto dylibCtx = dCtx.createMachoCtx<true, P>(imageInfo);
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
  auto dylibDeps =
      dylibCtx.getLoadCommand<true, Macho::Loader::dylib_command>();
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
        SPDLOG_LOGGER_WARN(logger,
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
std::vector<ExportInfoTrie::Entry> Symbolizer<A>::readExports(
    const std::string &dylibPath,
    const Macho::Context<true, typename A::P> &dylibCtx) const {
  // read exports
  std::vector<ExportInfoTrie::Entry> exports;
  const uint8_t *exportsStart;
  const uint8_t *exportsEnd;
  const auto linkeditFile =
      dylibCtx.convertAddr(dylibCtx.getSegment("__LINKEDIT")->command->vmaddr)
          .second;
  const auto exportTrieCmd =
      dylibCtx.getLoadCommand<false, Macho::Loader::linkedit_data_command>(
          {LC_DYLD_EXPORTS_TRIE});
  const auto dyldInfo =
      dylibCtx.getLoadCommand<false, Macho::Loader::dyld_info_command>();
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
