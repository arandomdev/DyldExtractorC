#include "Optimizer.h"
#include <Provider/LinkeditTracker.h>
#include <Provider/SymbolTableTracker.h>
#include <Utils/Utils.h>

#include <map>
#include <spdlog/spdlog.h>
#include <string_view>

using namespace DyldExtractor;
using namespace Converter;

#pragma region LinkeditOptimizer
template <class A> class LinkeditOptimizer {
  using P = A::P;
  using PtrT = P::PtrT;
  using LETrackerTag = Provider::LinkeditTracker<P>::Tag;
  using STSymbolType = Provider::SymbolTableTracker<P>::SymbolType;

public:
  LinkeditOptimizer(Utils::ExtractionContext<A> &eCtx);
  void run();

private:
  void addData(uint8_t *data, uint32_t size, LETrackerTag tag,
               Macho::Loader::load_command *lc);

  void copyBindingInfo();
  void copyWeakBindingInfo();
  void copyLazyBindingInfo();
  void copyExportInfo();

  void copyFunctionStarts();
  void copyDataInCode();

  void copyLocalSymbols();
  void copyExportedSymbols();
  void copyImportedSymbols();
  void copyIndirectSymbolTable();

  void commitData();

  /// Finds the start of the local symbols and how many there are.
  std::tuple<Macho::Loader::nlist<P> *, Macho::Loader::nlist<P> *>
  findLocalSymbolEntries(dyld_cache_local_symbols_info *symbolsInfo);
  void copyPublicLocalSymbols();
  void copyRedactedLocalSymbols();

  Utils::ExtractionContext<A> &eCtx;
  const Dyld::Context &dCtx;
  Macho::Context<false, P> &mCtx;
  Provider::ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;

  std::vector<typename Provider::LinkeditTracker<P>::Metadata> trackedData;

  Provider::SymbolTableTracker<P> stTracker;
  // map of old symbol indicies to new ones in the tracker
  std::map<uint32_t, std::pair<STSymbolType, uint32_t>> newSymbolIndicies;

  std::vector<uint8_t> newLeData; // data storage for new linkedit region
  uint32_t newLeSize = 0;         // current size of new linkedit data
  uint8_t *leFile;       // pointer to file containing old linkedit data
  uint32_t leFileOffset; // offset in leFile to start of old linkedit data
  uint8_t *leData;       // pointer to start of old linkedit data

  Macho::Loader::symtab_command *symtab;            // guaranteed available
  Macho::Loader::dysymtab_command *dysymtab;        // guaranteed available
  Macho::Loader::dyld_info_command *dyldInfo;       // optional
  Macho::Loader::linkedit_data_command *exportTrie; // optional
};

template <class A>
LinkeditOptimizer<A>::LinkeditOptimizer(Utils::ExtractionContext<A> &eCtx)
    : eCtx(eCtx), dCtx(*eCtx.dCtx), mCtx(*eCtx.mCtx), activity(*eCtx.activity),
      logger(eCtx.logger) {
  auto [off, file] =
      mCtx.convertAddr(mCtx.getSegment(SEG_LINKEDIT)->command->vmaddr);
  leFile = file;
  leFileOffset = (uint32_t)off;
  leData = leFile + leFileOffset;

  symtab = mCtx.getFirstLC<Macho::Loader::symtab_command>();
  dysymtab = mCtx.getFirstLC<Macho::Loader::dysymtab_command>();
  dyldInfo = mCtx.getFirstLC<Macho::Loader::dyld_info_command>();
  exportTrie = mCtx.getFirstLC<Macho::Loader::linkedit_data_command>(
      {LC_DYLD_EXPORTS_TRIE});
}

template <class A> void LinkeditOptimizer<A>::run() {
  if (dyldInfo) {
    copyBindingInfo();
    copyWeakBindingInfo();
    copyLazyBindingInfo();
  }
  copyExportInfo();

  copyFunctionStarts();
  copyDataInCode();

  copyLocalSymbols();
  copyExportedSymbols();
  copyImportedSymbols();
  copyIndirectSymbolTable();

  commitData();
}

template <class A>
void LinkeditOptimizer<A>::addData(uint8_t *data, uint32_t size,
                                   LETrackerTag tag,
                                   Macho::Loader::load_command *lc) {
  auto alignedSize = Utils::align(size, sizeof(PtrT));
  trackedData.emplace_back(tag, leData + newLeSize, alignedSize, lc);

  newLeData.insert(newLeData.end(), data, data + size);
  newLeData.resize(newLeSize + alignedSize);
  newLeSize = (uint32_t)newLeData.size();
}

template <class A> void LinkeditOptimizer<A>::copyBindingInfo() {
  if (!dyldInfo->bind_size) {
    dyldInfo->bind_off = 0;
    return;
  }

  activity.update(std::nullopt, "Copying binding info");
  addData(leFile + dyldInfo->bind_off, dyldInfo->bind_size,
          LETrackerTag::binding,
          reinterpret_cast<Macho::Loader::load_command *>(dyldInfo));
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::copyWeakBindingInfo() {
  if (!dyldInfo->weak_bind_size) {
    dyldInfo->weak_bind_off = 0;
    return;
  }

  activity.update(std::nullopt, "Copying weak binding info");
  addData(leFile + dyldInfo->weak_bind_off, dyldInfo->weak_bind_size,
          LETrackerTag::weakBinding,
          reinterpret_cast<Macho::Loader::load_command *>(dyldInfo));
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::copyLazyBindingInfo() {
  if (!dyldInfo->lazy_bind_size) {
    dyldInfo->lazy_bind_off = 0;
    return;
  }

  activity.update(std::nullopt, "Copying lazy binding info");
  addData(leFile + dyldInfo->lazy_bind_off, dyldInfo->lazy_bind_size,
          LETrackerTag::lazyBinding,
          reinterpret_cast<Macho::Loader::load_command *>(dyldInfo));
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::copyExportInfo() {
  if (!exportTrie && !dyldInfo) {
    return;
  }

  uint8_t *data;
  uint32_t size;
  LETrackerTag tag;
  Macho::Loader::load_command *lc;

  if (exportTrie) {
    data = leFile + exportTrie->dataoff;
    size = exportTrie->datasize;
    tag = LETrackerTag::detachedExportTrie;
    lc = reinterpret_cast<Macho::Loader::load_command *>(exportTrie);
  } else {
    data = leFile + dyldInfo->export_off;
    size = dyldInfo->export_size;
    tag = LETrackerTag::exportTrie;
    lc = reinterpret_cast<Macho::Loader::load_command *>(dyldInfo);
  }

  activity.update(std::nullopt, "Copying export info");
  addData(data, size, tag, lc);
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::copyFunctionStarts() {
  auto functionStarts = mCtx.getFirstLC<Macho::Loader::linkedit_data_command>(
      {LC_FUNCTION_STARTS});
  if (!functionStarts) {
    return;
  }

  activity.update(std::nullopt, "Copying function starts");
  addData(leFile + functionStarts->dataoff, functionStarts->datasize,
          LETrackerTag::functionStarts,
          reinterpret_cast<Macho::Loader::load_command *>(functionStarts));
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::copyDataInCode() {
  auto dataInCode =
      mCtx.getFirstLC<Macho::Loader::linkedit_data_command>({LC_DATA_IN_CODE});
  if (!dataInCode) {
    return;
  }

  // Most data in code is zero sized but still track it
  activity.update(std::nullopt, "Copying data in code");
  addData(leFile + dataInCode->dataoff, dataInCode->datasize,
          LETrackerTag::dataInCode,
          reinterpret_cast<Macho::Loader::load_command *>(dataInCode));
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::copyLocalSymbols() {
  activity.update(std::nullopt, "Finding local symbols");

  copyPublicLocalSymbols();
  copyRedactedLocalSymbols();
}

template <class A> void LinkeditOptimizer<A>::copyExportedSymbols() {
  activity.update(std::nullopt, "Finding exported symbols");

  auto syms = (Macho::Loader::nlist<P> *)(leFile + symtab->symoff);
  uint32_t symsStart = dysymtab->iextdefsym;
  uint32_t symsEnd = symsStart + dysymtab->nextdefsym;
  auto stringsStart = leFile + symtab->stroff;

  for (auto symIndex = symsStart; symIndex < symsEnd; symIndex++) {
    auto symEntry = syms + symIndex;
    const char *string = (const char *)stringsStart + symEntry->n_un.n_strx;

    auto &str = stTracker.addString(string);
    auto newSymIndex = stTracker.addSym(STSymbolType::external, str, *symEntry);

    newSymbolIndicies[symIndex] = newSymIndex;
    activity.update();
  }
}

template <class A> void LinkeditOptimizer<A>::copyImportedSymbols() {
  activity.update(std::nullopt, "Finding imported symbols");

  auto syms = (Macho::Loader::nlist<P> *)(leFile + symtab->symoff);
  uint32_t symsStart = dysymtab->iundefsym;
  uint32_t symsEnd = symsStart + dysymtab->nundefsym;
  auto stringsStart = leFile + symtab->stroff;

  for (auto symIndex = symsStart; symIndex < symsEnd; symIndex++) {
    auto symEntry = syms + symIndex;
    const char *string = (const char *)stringsStart + symEntry->n_un.n_strx;

    auto &str = stTracker.addString(string);
    auto newSymIndex =
        stTracker.addSym(STSymbolType::undefined, str, *symEntry);

    newSymbolIndicies[symIndex] = newSymIndex;
    activity.update();
  }
}

template <class A> void LinkeditOptimizer<A>::copyIndirectSymbolTable() {
  activity.update(std::nullopt, "Copying indirect symbol table");

  auto entries = (uint32_t *)(leFile + dysymtab->indirectsymoff);
  for (uint32_t entryI = 0; entryI < dysymtab->nindirectsyms; entryI++) {
    uint32_t *entry = entries + entryI;
    if (isRedactedIndirect(*entry)) {
      stTracker.indirectSyms.push_back(stTracker.getOrMakeRedactedSymIndex());
    } else {
      stTracker.indirectSyms.push_back(newSymbolIndicies[*entry]);
    }

    activity.update();
  }
}

template <class A> void LinkeditOptimizer<A>::commitData() {
  // Write data
  memcpy(leData, newLeData.data(), newLeSize);

  // add metadata to tracking, use original linkedit size
  auto linkeditSeg = mCtx.getSegment(SEG_LINKEDIT)->command;
  eCtx.leTracker.emplace(mCtx, linkeditSeg->filesize, trackedData);

  // update segment with new size
  linkeditSeg->vmsize = newLeSize;
  linkeditSeg->filesize = newLeSize;

  // Zero out symtab and dysymtab, create string table tracker
  *symtab = {0};
  symtab->cmd = LC_SYMTAB;
  symtab->cmdsize = sizeof(Macho::Loader::symtab_command);
  *dysymtab = {0};
  dysymtab->cmd = LC_DYSYMTAB;
  dysymtab->cmdsize = sizeof(Macho::Loader::dysymtab_command);

  eCtx.stTracker = std::move(stTracker);
  eCtx.symbolizer.emplace(*eCtx.dCtx, *eCtx.mCtx, *eCtx.accelerator, activity,
                          logger, *eCtx.stTracker);
}

template <class A>
std::tuple<Macho::Loader::nlist<typename A::P> *,
           Macho::Loader::nlist<typename A::P> *>
LinkeditOptimizer<A>::findLocalSymbolEntries(
    dyld_cache_local_symbols_info *symbolsInfo) {
  // Search local symbol entries for the macho context.
  auto searchEntries =
      [&]<class T>(decltype(T::dylibOffset) machoOffset) -> T * {
    T *entriesStart =
        (T *)((uint8_t *)symbolsInfo + symbolsInfo->entriesOffset);
    T *entriesEnd = entriesStart + symbolsInfo->entriesCount;
    for (auto entry = entriesStart; entry < entriesEnd; entry++) {
      if (entry->dylibOffset == machoOffset) {
        return entry;
      }
    }

    return nullptr;
  };

  uint8_t *nlistStart = nullptr;
  uint32_t nlistCount = 0;
  if (dCtx.headerContainsMember(offsetof(dyld_cache_header, symbolFileUUID))) {
    // Newer caches, vm offset to mach header.
    uint64_t machoOffset = mCtx.getSegment(SEG_TEXT)->command->vmaddr -
                           dCtx.header->sharedRegionStart;
    auto entry = searchEntries.operator()<dyld_cache_local_symbols_entry_64>(
        machoOffset);
    if (entry) {
      nlistStart = (uint8_t *)symbolsInfo + symbolsInfo->nlistOffset +
                   sizeof(Macho::Loader::nlist<P>) * entry->nlistStartIndex;
      nlistCount = entry->nlistCount;
    }
  } else {
    // Older caches, file offset to mach header.
    uint64_t machoOffset =
        mCtx.convertAddr(mCtx.getSegment(SEG_TEXT)->command->vmaddr).first;
    auto entry = searchEntries.operator()<dyld_cache_local_symbols_entry>(
        (uint32_t)machoOffset);
    if (entry) {
      nlistStart = (uint8_t *)symbolsInfo + symbolsInfo->nlistOffset +
                   sizeof(Macho::Loader::nlist<P>) * entry->nlistStartIndex;
      nlistCount = entry->nlistCount;
    }
  }

  if (!nlistStart) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to find local symbol entries.");
    return std::make_tuple(nullptr, nullptr);
  }

  return std::make_tuple((Macho::Loader::nlist<P> *)nlistStart,
                         (Macho::Loader::nlist<P> *)nlistStart + nlistCount);
}

template <class A> void LinkeditOptimizer<A>::copyPublicLocalSymbols() {
  if (!dysymtab->nlocalsym) {
    return;
  }

  auto strings = (const char *)leFile + symtab->stroff;
  auto symsStart = (Macho::Loader::nlist<P> *)(leFile + symtab->symoff) +
                   dysymtab->ilocalsym;
  auto symsEnd = symsStart + dysymtab->nlocalsym;

  for (auto entry = symsStart; entry < symsEnd; entry++) {
    const char *string = strings + entry->n_un.n_strx;
    if (std::strcmp(string, "<redacted>") == 0) {
      continue;
    }

    // Local symbol indices are not tracked for indirect symbols
    auto &str = stTracker.addString(string);
    stTracker.addSym(STSymbolType::local, str, *entry);

    activity.update();
  }
}

template <class A> void LinkeditOptimizer<A>::copyRedactedLocalSymbols() {
  auto symbolsCache = dCtx.getSymbolsCache();
  if (!symbolsCache || !symbolsCache->header->localSymbolsOffset) {
    return;
  }

  auto localSymsInfo =
      (dyld_cache_local_symbols_info
           *)(symbolsCache->file + symbolsCache->header->localSymbolsOffset);
  auto [symsStart, symsEnd] = findLocalSymbolEntries(localSymsInfo);
  if (!symsStart) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to copy redacted local symbols.");
  }

  auto stringsStart = (uint8_t *)localSymsInfo + localSymsInfo->stringsOffset;
  for (auto symEntry = symsStart; symEntry < symsEnd; symEntry++) {
    const char *string = (const char *)stringsStart + symEntry->n_un.n_strx;

    // Local symbol indices are not tracked for indirect symbols
    auto &str = stTracker.addString(string);
    stTracker.addSym(STSymbolType::local, str, *symEntry);

    activity.update();
  }
}

#pragma endregion LinkeditOptimizer

/// Check all load commands for unknown load commands
template <class A> void checkLoadCommands(Utils::ExtractionContext<A> &eCtx) {
  for (auto lc : eCtx.mCtx->loadCommands) {
    switch (lc->cmd) {
    case LC_SEGMENT:    // segment_command
    case LC_SEGMENT_64: // segment_command_64
    case LC_IDFVMLIB:   // fvmlib_command
    case LC_LOADFVMLIB:
    case LC_ID_DYLIB:   // dylib_command
    case LC_LOAD_DYLIB:
    case LC_LOAD_WEAK_DYLIB:
    case LC_REEXPORT_DYLIB:
    case LC_LOAD_UPWARD_DYLIB:
    case LC_LAZY_LOAD_DYLIB:
    case LC_SUB_FRAMEWORK:  // sub_framework_command
    case LC_SUB_CLIENT:     // sub_client_command
    case LC_SUB_UMBRELLA:   // sub_umbrella_command
    case LC_SUB_LIBRARY:    // sub_library_command
    case LC_PREBOUND_DYLIB: // prebound_dylib_command
    case LC_ID_DYLINKER:    // dylinker_command
    case LC_LOAD_DYLINKER:
    case LC_DYLD_ENVIRONMENT:
    case LC_THREAD:             // thread_command
    case LC_UNIXTHREAD:
    case LC_ROUTINES:           // routines_command
    case LC_ROUTINES_64:        // routines_command_64
    case LC_PREBIND_CKSUM:      // prebind_cksum_command
    case LC_UUID:               // uuid_command
    case LC_RPATH:              // rpath_command
    case LC_FILESET_ENTRY:      // fileset_entry_command
    case LC_ENCRYPTION_INFO:    // encryption_info_command
    case LC_ENCRYPTION_INFO_64: // encryption_info_command_64
    case LC_VERSION_MIN_MACOSX: // version_min_command
    case LC_VERSION_MIN_IPHONEOS:
    case LC_VERSION_MIN_WATCHOS:
    case LC_VERSION_MIN_TVOS:
    case LC_BUILD_VERSION:  // build_version_command
    case LC_LINKER_OPTION:  // linker_option_command
    case LC_IDENT:          // ident_command
    case LC_FVMFILE:        // fvmfile_command
    case LC_MAIN:           // entry_point_command
    case LC_SOURCE_VERSION: // source_version_command
      /* Don't contain any data in the linkedit */
      break;

    case LC_DYSYMTAB: {
      // Check deprecated fields
      auto dysymtab = (Macho::Loader::dysymtab_command *)lc;
      if (dysymtab->ntoc) {
        SPDLOG_LOGGER_WARN(eCtx.logger,
                           "Dysymtab's table of contents not processed.");
      }
      if (dysymtab->nmodtab) {
        SPDLOG_LOGGER_WARN(eCtx.logger,
                           "Dysymtab's module table not processed.");
      }
      if (dysymtab->nextrefsyms) {
        SPDLOG_LOGGER_WARN(eCtx.logger,
                           "Dysymtab's referenced symbol table not processed.");
      }
      if (dysymtab->nextrel) {
        SPDLOG_LOGGER_WARN(
            eCtx.logger,
            "Dysymtab's external relocation entries not processed.");
      }
      if (dysymtab->nlocrel) {
        SPDLOG_LOGGER_WARN(
            eCtx.logger, "Dysymtab's local relocation entries not processed.");
      }
      break;
    }

    case LC_SYMTAB:            // symtab_command
    case LC_DYLD_EXPORTS_TRIE: // linkedit_data_command
    case LC_FUNCTION_STARTS:
    case LC_DATA_IN_CODE:
    case LC_DYLD_INFO: // dyld_info_command
    case LC_DYLD_INFO_ONLY:
      // Contains linkedit data, is properly handled.
      break;

    case LC_TWOLEVEL_HINTS: // twolevel_hints_command
    case LC_CODE_SIGNATURE: // linkedit_data_command
    case LC_SEGMENT_SPLIT_INFO:
    case LC_DYLIB_CODE_SIGN_DRS:
    case LC_LINKER_OPTIMIZATION_HINT:
    case LC_DYLD_CHAINED_FIXUPS:
    case LC_SYMSEG: // symseg_command, deprecated
    case LC_NOTE:   // note_command
      // May contain linkedit data, not handled.
      SPDLOG_LOGGER_WARN(
          eCtx.logger,
          "Unhandled load command: {:#x}, may contain linkedit data.", lc->cmd);
      break;
    default:
      SPDLOG_LOGGER_WARN(
          eCtx.logger,
          "Unknown load command: {:#x}, may contain linkedit data.", lc->cmd);
      break;
    }
  }
}

bool Converter::isRedactedIndirect(uint32_t entry) {
  return entry == 0 || entry & INDIRECT_SYMBOL_LOCAL ||
         entry & INDIRECT_SYMBOL_ABS;
}

template <class A>
void Converter::optimizeLinkedit(Utils::ExtractionContext<A> &eCtx) {
  eCtx.activity->update("Linkedit Optimizer", "Optimizing Linkedit");
  checkLoadCommands(eCtx);
  LinkeditOptimizer(eCtx).run();
  return;
}

#define X(T)                                                                   \
  template void Converter::optimizeLinkedit<T>(Utils::ExtractionContext<T> &   \
                                               eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X