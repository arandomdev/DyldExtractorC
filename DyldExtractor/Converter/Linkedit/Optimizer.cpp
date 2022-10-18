#include "Optimizer.h"
#include <Provider/LinkeditTracker.h>

#include <map>
#include <spdlog/spdlog.h>
#include <string_view>

using namespace DyldExtractor;
using namespace Converter;

#pragma region StringPool
class StringPool {
public:
  StringPool();

  /// @brief Add a string to the string pool.
  /// @param string The string to add.
  /// @returns The string index.
  uint32_t addString(const char *string);

  /// @brief Write strings
  /// @param dest Buffer to write to. Writes to the end.
  void writeStrings(std::vector<uint8_t> &buffer);

  /// @brief Get total size of strings
  uint32_t getSize() const;

private:
  struct cmpStr {
    bool operator()(char const *a, char const *b) const {
      return std::strcmp(a, b) < 0;
    }
  };
  std::map<const char *, uint32_t, cmpStr> _pool;

  uint32_t _stringsLength = 0;
};

StringPool::StringPool() {
  // first string is \x00 historically
  addString("\x00");
}

uint32_t StringPool::addString(const char *string) {
  if (_pool.contains(string)) {
    return _pool.at(string);
  }

  uint32_t index = _stringsLength;

  _pool[string] = index;
  _stringsLength += (uint32_t)strlen(string) + 1; // +1 for null terminator
  return index;
}

void StringPool::writeStrings(std::vector<uint8_t> &buffer) {
  // Sort all strings by their offset
  std::vector<std::pair<uint32_t, const char *>> strings;
  for (auto const &pair : _pool) {
    strings.emplace_back(pair.second, pair.first);
  }
  std::sort(strings.begin(), strings.end());

  auto oldBufferSize = buffer.size();
  buffer.reserve(oldBufferSize + _stringsLength);

  // Write first string
  auto lastIt = std::prev(strings.end());
  for (auto it = strings.begin(); it != lastIt; it++) {
    auto &[offset, str] = *it;

    // Calculate string length, includes null terminator
    auto stringLength = std::next(it)->first - offset;
    buffer.insert(buffer.end(), str, str + stringLength);
  }

  // Write last string
  auto lastString = lastIt->second;
  auto lastStringLength = _stringsLength - lastIt->first;
  buffer.insert(buffer.end(), lastString, lastString + lastStringLength);

  assert(oldBufferSize + _stringsLength == buffer.size());
}

uint32_t StringPool::getSize() const { return _stringsLength; }
#pragma endregion StringPool

#pragma region LinkeditOptimizer
template <class A> class LinkeditOptimizer {
  using P = A::P;
  using PtrT = P::PtrT;
  using LETrackerTag = Provider::LinkeditTracker<P>::Tag;

public:
  LinkeditOptimizer(Utils::ExtractionContext<A> &eCtx);
  void run();

private:
  void addData(uint8_t *data, uint32_t size, LETrackerTag tag, uint8_t *lc);
  template <class T> void addStruct(T *data) {
    uint8_t *dataLoc = reinterpret_cast<uint8_t *>(data);
    uint32_t size = (uint32_t)sizeof(T);
    newLeData.insert(newLeData.end(), dataLoc, dataLoc + size);
    newLeSize += size;
  }

  void copyBindingInfo();
  void copyWeakBindingInfo();
  void copyLazyBindingInfo();
  void copyExportInfo();

  void startSymbolEntries();
  void searchRedactedSymbol();
  void copyLocalSymbols();
  void copyExportedSymbols();
  void copyImportedSymbols();
  void endSymbolEntries();

  void copyFunctionStarts();
  void copyDataInCode();
  void copyIndirectSymbolTable();
  void copyStringPool();

  void commitData();

  /// Finds the start of the local symbols and how many there are.
  std::tuple<Macho::Loader::nlist<P> *, Macho::Loader::nlist<P> *>
  findLocalSymbolEntries(dyld_cache_local_symbols_info *symbolsInfo);
  uint32_t copyPublicLocalSymbols();
  uint32_t copyRedactedLocalSymbols();

  Utils::ExtractionContext<A> &eCtx;
  const Dyld::Context &dCtx;
  Macho::Context<false, P> &mCtx;
  Logger::Activity &activity;
  std::shared_ptr<spdlog::logger> logger;

  std::set<typename Provider::LinkeditTracker<P>::Metadata> trackedData;

  StringPool stringsPool;
  uint32_t symbolsCount = 0;
  // offset of new symbols from the start of new linkedit data
  uint32_t newSymbolEntriesOffset;
  // map of old symbol indicies to new ones
  std::map<uint32_t, uint32_t> newSymbolIndicies;

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
  copyBindingInfo();
  copyWeakBindingInfo();
  copyLazyBindingInfo();
  copyExportInfo();

  startSymbolEntries();
  searchRedactedSymbol();
  copyLocalSymbols();
  copyExportedSymbols();
  copyImportedSymbols();
  endSymbolEntries();

  copyFunctionStarts();
  copyDataInCode();
  copyIndirectSymbolTable();
  copyStringPool();

  commitData();
}

template <class A>
void LinkeditOptimizer<A>::addData(uint8_t *data, uint32_t size,
                                   LETrackerTag tag, uint8_t *lc) {
  auto alignedSize = Utils::align(size, sizeof(PtrT));
  trackedData.emplace(tag, leData + newLeSize, alignedSize, lc);

  newLeData.insert(newLeData.end(), data, data + size);
  newLeData.resize(newLeSize + alignedSize);
  newLeSize = (uint32_t)newLeData.size();
}

template <class A> void LinkeditOptimizer<A>::copyBindingInfo() {
  if (!dyldInfo || !dyldInfo->bind_size) {
    return;
  }

  activity.update(std::nullopt, "Copying binding info");
  addData(leFile + dyldInfo->bind_off, dyldInfo->bind_size,
          LETrackerTag::bindInfo, reinterpret_cast<uint8_t *>(dyldInfo));
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::copyWeakBindingInfo() {
  if (!dyldInfo || !dyldInfo->weak_bind_size) {
    return;
  }

  activity.update(std::nullopt, "Copying weak binding info");
  addData(leFile + dyldInfo->weak_bind_off, dyldInfo->weak_bind_size,
          LETrackerTag ::weakBindInfo, reinterpret_cast<uint8_t *>(dyldInfo));
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::copyLazyBindingInfo() {
  if (!dyldInfo || !dyldInfo->lazy_bind_size) {
    return;
  }

  activity.update(std::nullopt, "Copying lazy binding info");
  addData(leFile + dyldInfo->lazy_bind_off, dyldInfo->lazy_bind_size,
          LETrackerTag ::lazyBindInfo, reinterpret_cast<uint8_t *>(dyldInfo));
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::copyExportInfo() {
  if (!exportTrie && !dyldInfo) {
    return;
  }

  uint8_t *data;
  uint32_t size;
  LETrackerTag tag;
  uint8_t *lc;

  if (exportTrie) {
    data = leFile + exportTrie->dataoff;
    size = exportTrie->datasize;
    tag = LETrackerTag::exportTrie;
    lc = reinterpret_cast<uint8_t *>(exportTrie);
  } else {
    data = leFile + dyldInfo->export_off;
    size = dyldInfo->export_size;
    tag = LETrackerTag::exportInfo;
    lc = reinterpret_cast<uint8_t *>(dyldInfo);
  }

  if (!size) {
    return;
  }

  activity.update(std::nullopt, "Copying export info");
  addData(data, size, tag, lc);
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::startSymbolEntries() {
  newSymbolEntriesOffset = newLeSize;
}

template <class A> void LinkeditOptimizer<A>::searchRedactedSymbol() {
  activity.update(std::nullopt, "Searching for redacted symbols");

  uint8_t *indirectSymStart = leFile + dysymtab->indirectsymoff;
  for (std::size_t i = 0; i < dysymtab->nindirectsyms; i++) {
    auto symbolIndex = (uint32_t *)(indirectSymStart + i * sizeof(uint32_t));
    if (isRedactedIndirect(*symbolIndex)) {
      eCtx.hasRedactedIndirect = true;
      break;
    }
  }

  // Add a redacted symbol so that redacted symbols don't show a random one
  auto strIndex = stringsPool.addString("<redacted>");
  symbolsCount++;

  Macho::Loader::nlist<P> symbolEntry = {0};
  symbolEntry.n_un.n_strx = strIndex;
  symbolEntry.n_type = 1;
  addStruct(&symbolEntry);
}

template <class A> void LinkeditOptimizer<A>::copyLocalSymbols() {
  activity.update(std::nullopt, "Copying local symbols");

  uint32_t newLocalSymbolsStartIndex = symbolsCount;
  uint32_t newSymsCount = copyPublicLocalSymbols();
  newSymsCount += copyRedactedLocalSymbols();

  if (newSymsCount) {
    dysymtab->ilocalsym = newLocalSymbolsStartIndex;
    dysymtab->nlocalsym = newSymsCount;
  } else {
    dysymtab->ilocalsym = 0;
    dysymtab->nlocalsym = 0;
  }
}

template <class A> void LinkeditOptimizer<A>::copyExportedSymbols() {
  activity.update(std::nullopt, "Copying exported symbols");

  uint32_t newExportedSymbolsStartIndex = symbolsCount;
  uint32_t newExportedSymbolsCount = 0;
  auto syms = (Macho::Loader::nlist<P> *)(leFile + symtab->symoff);
  uint32_t symsStart = dysymtab->iextdefsym;
  uint32_t symsEnd = symsStart + dysymtab->nextdefsym;
  auto stringsStart = leFile + symtab->stroff;

  for (auto symIndex = symsStart; symIndex < symsEnd; symIndex++) {
    auto symEntry = syms + symIndex;
    const char *string = (const char *)stringsStart + symEntry->n_un.n_strx;

    Macho::Loader::nlist<P> newEntry = *symEntry;
    newEntry.n_un.n_strx = stringsPool.addString(string);
    addStruct(&newEntry);

    newSymbolIndicies[symIndex] = symbolsCount;

    newExportedSymbolsCount++;
    symbolsCount++;
    activity.update();
  }

  if (newExportedSymbolsCount) {
    dysymtab->iextdefsym = newExportedSymbolsStartIndex;
    dysymtab->nextdefsym = newExportedSymbolsCount;
  } else {
    dysymtab->iextdefsym = 0;
    dysymtab->nextdefsym = 0;
  }
}

template <class A> void LinkeditOptimizer<A>::copyImportedSymbols() {
  activity.update(std::nullopt, "Copying imported symbols");

  uint32_t newImportedSymbolsStartIndex = symbolsCount;
  uint32_t newImportedSymbolsCount = 0;
  auto syms = (Macho::Loader::nlist<P> *)(leFile + symtab->symoff);
  uint32_t symsStart = dysymtab->iundefsym;
  uint32_t symsEnd = symsStart + dysymtab->nundefsym;
  auto stringsStart = leFile + symtab->stroff;

  for (auto symIndex = symsStart; symIndex < symsEnd; symIndex++) {
    auto symEntry = syms + symIndex;
    const char *string = (const char *)stringsStart + symEntry->n_un.n_strx;

    Macho::Loader::nlist<P> newEntry = *symEntry;
    newEntry.n_un.n_strx = stringsPool.addString(string);
    addStruct(&newEntry);

    newSymbolIndicies[symIndex] = symbolsCount;

    newImportedSymbolsCount++;
    symbolsCount++;
    activity.update();
  }

  if (newImportedSymbolsCount) {
    dysymtab->iundefsym = newImportedSymbolsStartIndex;
    dysymtab->nundefsym = newImportedSymbolsCount;
  } else {
    dysymtab->iundefsym = 0;
    dysymtab->nundefsym = 0;
  }
}

template <class A> void LinkeditOptimizer<A>::endSymbolEntries() {
  auto symEntrySize = (uint32_t)(newLeSize - newSymbolEntriesOffset);
  if (!symEntrySize) {
    SPDLOG_LOGGER_WARN(logger, "No symbol entries were added");
    return;
  }
  symtab->nsyms = symbolsCount;

  trackedData.emplace(LETrackerTag::symbolEntries,
                      leData + newSymbolEntriesOffset,
                      Utils::align(symEntrySize, sizeof(PtrT)),
                      reinterpret_cast<uint8_t *>(symtab));

  // pointer align
  Utils::align(&newLeSize, sizeof(PtrT));
  newLeData.resize(newLeSize);
}

template <class A> void LinkeditOptimizer<A>::copyFunctionStarts() {
  auto functionStarts = mCtx.getFirstLC<Macho::Loader::linkedit_data_command>(
      {LC_FUNCTION_STARTS});
  if (!functionStarts || !functionStarts->datasize) {
    return;
  }

  activity.update(std::nullopt, "Copying function starts");
  addData(leFile + functionStarts->dataoff, functionStarts->datasize,
          LETrackerTag::functionStarts,
          reinterpret_cast<uint8_t *>(functionStarts));
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::copyDataInCode() {
  auto dataInCode =
      mCtx.getFirstLC<Macho::Loader::linkedit_data_command>({LC_DATA_IN_CODE});
  if (!dataInCode || !dataInCode->datasize) {
    return;
  }

  activity.update(std::nullopt, "Copying data in code");
  addData(leFile + dataInCode->dataoff, dataInCode->datasize,
          LETrackerTag::dataInCode, reinterpret_cast<uint8_t *>(dataInCode));
  activity.update();
}

template <class A> void LinkeditOptimizer<A>::copyIndirectSymbolTable() {
  activity.update(std::nullopt, "Copying indirect symbol table");

  std::vector<uint32_t> newEntries;
  newEntries.reserve(dysymtab->nindirectsyms);

  auto entries = (uint32_t *)(leFile + dysymtab->indirectsymoff);
  for (uint32_t entryIndex = 0; entryIndex < dysymtab->nindirectsyms;
       entryIndex++) {
    uint32_t *entry = entries + entryIndex;
    if (isRedactedIndirect(*entry)) {
      // just copy entry
      newEntries.push_back(*entry);
      continue;
    }

    newEntries.push_back(newSymbolIndicies[*entry]);
    activity.update();
  }

  uint32_t size = (uint32_t)newEntries.size() * sizeof(uint32_t);
  if (!size) {
    return;
  }

  addData((uint8_t *)newEntries.data(), size, LETrackerTag::indirectSymtab,
          reinterpret_cast<uint8_t *>(dysymtab));
}

template <class A> void LinkeditOptimizer<A>::copyStringPool() {
  activity.update(std::nullopt, "Copying string pool");

  auto newSize = stringsPool.getSize();
  stringsPool.writeStrings(newLeData);
  symtab->strsize = newSize;

  // Add metadata
  auto alignedSize = Utils::align(newSize, sizeof(PtrT));
  trackedData.emplace(LETrackerTag::stringPool, leData + newLeSize, alignedSize,
                      reinterpret_cast<uint8_t *>(symtab));
  newLeData.resize(newLeSize + alignedSize);
  newLeSize = (uint32_t)newLeData.size();

  activity.update();
}

template <class A> void LinkeditOptimizer<A>::commitData() {
  // Write data
  memcpy(leData, newLeData.data(), newLeSize);

  // add metadata to tracking, use original linkedit size
  auto linkeditSeg = mCtx.getSegment(SEG_LINKEDIT)->command;
  eCtx.leTracker =
      Provider::LinkeditTracker<A::P>(mCtx, linkeditSeg->filesize, trackedData);

  // update segment with new size
  linkeditSeg->vmsize = newLeSize;
  linkeditSeg->filesize = newLeSize;
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

template <class A> uint32_t LinkeditOptimizer<A>::copyPublicLocalSymbols() {
  if (!dysymtab->nlocalsym) {
    return 0;
  }

  uint32_t newLocalSymbolsCount = 0;
  auto strings = (const char *)leFile + symtab->stroff;
  auto symsStart = (Macho::Loader::nlist<P> *)(leFile + symtab->symoff) +
                   dysymtab->ilocalsym;
  auto symsEnd = symsStart + dysymtab->nlocalsym;

  for (auto entry = symsStart; entry < symsEnd; entry++) {
    const char *string = strings + entry->n_un.n_strx;
    if (std::strcmp(string, "<redacted>") == 0) {
      continue;
    }

    Macho::Loader::nlist<P> newEntry = *entry;
    newEntry.n_un.n_strx = stringsPool.addString(string);
    addStruct(&newEntry);

    newLocalSymbolsCount++;
    symbolsCount++;
    activity.update();
  }

  return newLocalSymbolsCount;
}

template <class A> uint32_t LinkeditOptimizer<A>::copyRedactedLocalSymbols() {
  auto symbolsCache = dCtx.getSymbolsCache();
  if (!symbolsCache || !symbolsCache->header->localSymbolsOffset) {
    return 0;
  }

  auto localSymsInfo =
      (dyld_cache_local_symbols_info
           *)(symbolsCache->file + symbolsCache->header->localSymbolsOffset);
  auto [symsStart, symsEnd] = findLocalSymbolEntries(localSymsInfo);
  if (!symsStart) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to copy redacted local symbols.");
  }

  uint32_t newLocalSymbolsCount = 0;
  auto stringsStart = (uint8_t *)localSymsInfo + localSymsInfo->stringsOffset;
  for (auto symEntry = symsStart; symEntry < symsEnd; symEntry++) {
    const char *string = (const char *)stringsStart + symEntry->n_un.n_strx;

    Macho::Loader::nlist<P> newEntry = *symEntry;
    newEntry.n_un.n_strx = stringsPool.addString(string);
    addStruct(&newEntry);

    newLocalSymbolsCount++;
    symbolsCount++;
    activity.update();
  }

  return newLocalSymbolsCount;
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
    case LC_ID_DYLIB: // dylib_command
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
    case LC_THREAD: // thread_command
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

    case LC_SYMTAB:            // symtab_command
    case LC_DYSYMTAB:          // dysymtab_command
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