#include "LinkeditOptimizer.h"

#include <map>
#include <spdlog/spdlog.h>
#include <string_view>

using namespace Converter;

#pragma region LinkeditTracker
template <class P> uint8_t *LinkeditTracker<P>::TrackedData::end() const {
  return data + dataSize;
}

template <class P>
auto LinkeditTracker<P>::TrackedData::operator<=>(const TrackedData &o) const {
  return this->data <=> o.data;
}

template <class P>
bool LinkeditTracker<P>::TrackedData::operator==(const TrackedData &o) const {
  return this->data == o.data;
}

template <class P>
LinkeditTracker<P>::LinkeditTracker(Macho::Context<false, P> &mCtx)
    : mCtx(mCtx), mCtxHeader(mCtx.header) {
  auto linkeditSegData = mCtx.getSegment("__LINKEDIT");
  if (!linkeditSegData) {
    throw std::invalid_argument("Unable to find __LINKEDIT segment");
  }
  linkeditSeg = linkeditSegData->command;

  linkeditStart = mCtx.convertAddrP(linkeditSeg->vmaddr);
  linkeditEnd = linkeditStart + linkeditSeg->vmsize;
  commandsStart =
      (uint8_t *)mCtxHeader + sizeof(Macho::Context<false, P>::HeaderT);
  commandsEnd = commandsStart + mCtxHeader->sizeofcmds;
}

template <class P> bool LinkeditTracker<P>::addTrackingData(TrackedData data) {
  if (!preflightData(data)) {
    return false;
  }

  // Check that it isn't overlapping with other data
  for (const auto &test : trackedData) {
    if (data.data >= test.data && data.data < test.data) {
      return false;
    }
  }

  insertDataIntoStore(data);
  return true;
}

template <class P>
bool LinkeditTracker<P>::insertData(TrackedData metadata, TrackedData *after,
                                    const uint8_t *data) {
  if (!preflightData(metadata)) {
    return false;
  }

  auto dataShiftStartIt = trackedData.end();
  uint8_t *dataShiftStart;
  if (!after) {
    dataShiftStart = linkeditStart;
  } else {
    dataShiftStart = after->end();

    auto afterIt = std::find(trackedData.begin(), trackedData.end(), *after);
    if (afterIt == trackedData.end()) {
      return false;
    }
    dataShiftStartIt = std::next(afterIt);
  }

  uint8_t *dataShiftEnd;
  if (trackedData.empty()) {
    dataShiftEnd = linkeditStart;
  } else {
    auto end = *trackedData.rbegin();
    dataShiftEnd = end.end();
  }

  // Check if we have enough space
  const auto dataShiftAmount = metadata.dataSize;
  if (dataShiftEnd + dataShiftAmount > linkeditEnd) {
    return false;
  }

  // Move the old data
  for (auto it = dataShiftStartIt; it != trackedData.end(); it++) {
    it->data += dataShiftAmount;
    *it->offsetField += dataShiftAmount;
  }
  linkeditSeg->vmsize += dataShiftAmount;
  linkeditSeg->filesize += dataShiftAmount;

  memmove(dataShiftStart + dataShiftAmount, dataShiftStart,
          dataShiftEnd - dataShiftStart);

  // Insert the new data
  memcpy(dataShiftStart, data, metadata.dataSize);
  metadata.data = dataShiftStart;
  insertDataIntoStore(metadata);
  return true;
}

template <class P>
bool LinkeditTracker<P>::resizeData(TrackedData *data, uint32_t newSize) {
  if (data->dataSize == newSize) {
    return true;
  }
  if (data->dataSize % 8 != 0) {
    return false;
  }

  auto dataIt = std::find(trackedData.begin(), trackedData.end(), *data);
  if (dataIt == trackedData.end()) {
    return false;
  }
  auto dataShiftStartIt = std::next(dataIt);
  uint8_t *dataShiftStart = nullptr;
  if (dataShiftStartIt != trackedData.end()) {
    dataShiftStart = dataShiftStartIt->data;
  }

  uint8_t *dataShiftEnd = trackedData.rbegin()->end();
  int32_t shiftDelta = newSize - data->dataSize;

  // Check if the new size will fit the linkedit
  if (dataShiftEnd + shiftDelta >= linkeditEnd) {
    return false;
  }

  // move all other data
  if (dataShiftStart == nullptr) {
    if (shiftDelta > 0) {
      // Zero out the new area
      memset(dataIt->end(), 0x0, shiftDelta);
    }
    // no shifting needed
    return true;
  }

  memmove(dataShiftStart + shiftDelta, dataShiftStart,
          dataShiftEnd - dataShiftStart);

  // Zero out new area after we move the old data
  if (shiftDelta > 0) {
    memset(dataIt->end(), 0x0, shiftDelta);
  }

  for (auto it = dataShiftStartIt; it != trackedData.end(); it++) {
    it->data += shiftDelta;
    *it->offsetField += shiftDelta;
  }
  linkeditSeg->vmsize += shiftDelta;
  linkeditSeg->filesize += shiftDelta;

  // Resize the data
  dataIt->dataSize = newSize;
  return true;
}

template <class P>
LinkeditTracker<P>::TrackedData *LinkeditTracker<P>::findTag(Tag tag) {
  for (auto &data : trackedData) {
    if (data.tag == tag) {
      return &data;
    }
  }

  return nullptr;
}

template <class P> bool LinkeditTracker<P>::preflightData(TrackedData &data) {
  // Check that data is within the linkedit
  if (data.data < linkeditStart || data.data + data.dataSize >= linkeditEnd) {
    return false;
  }

  // Check if offset field is within commands
  if ((uint8_t *)data.offsetField < commandsStart ||
      (uint8_t *)data.offsetField >= commandsEnd) {
    return false;
  }

  if (data.dataSize % 8 != 0) {
    return false;
  }

  return true;
}

template <class P>
std::vector<typename LinkeditTracker<P>::TrackedData>::iterator
LinkeditTracker<P>::insertDataIntoStore(const TrackedData &data) {
  return trackedData.insert(
      std::upper_bound(trackedData.begin(), trackedData.end(), data), data);
}

template class LinkeditTracker<Utils::Pointer32>;
template class LinkeditTracker<Utils::Pointer64>;
#pragma endregion LinkeditTracker

#pragma region StringPool
class StringPool {
public:
  StringPool();

  /// @brief Add a string to the string pool.
  /// @param string The string to add.
  /// @returns The string index.
  uint32_t addString(const char *string);

  /// @brief Write strings
  /// @param dest Buffer to write to.
  /// @returns The size of the strings written.
  uint32_t writeStrings(uint8_t *dest);

private:
  std::map<std::string_view, uint32_t> _pool;
  uint32_t _stringsLength = 0;
};

StringPool::StringPool() {
  // first string is \x00 historically
  addString("\x00");
}

uint32_t StringPool::addString(const char *string) {
  std::string_view strView(string);
  if (_pool.contains(strView)) {
    return _pool[strView];
  }

  uint32_t index = _stringsLength;

  _pool[strView] = index;
  _stringsLength += (uint32_t)strView.length() + 1;
  return index;
}

uint32_t StringPool::writeStrings(uint8_t *dest) {
  std::vector<std::pair<uint32_t, std::string_view>> strings;
  for (auto const &pair : _pool) {
    strings.emplace_back(pair.second, pair.first);
  }

  std::sort(strings.begin(), strings.end());

  for (auto &[offset, string] : strings) {
    memcpy(dest + offset, string.data(), string.length());
  }

  auto &[lastStringOff, lastString] = *strings.rbegin();
  return lastStringOff + (uint32_t)lastString.length() + 1;
}
#pragma endregion StringPool

#pragma region LinkeditOptimizer
template <class A> class LinkeditOptimizer {
  using P = A::P;
  using LinkeditTrackerTag = LinkeditTracker<P>::Tag;

public:
  LinkeditOptimizer(Utils::ExtractionContext<A> &eCtx);

  void copyBindingInfo(uint8_t *newLinkedit, uint32_t &offset);
  void copyWeakBindingInfo(uint8_t *newLinkedit, uint32_t &offset);
  void copyLazyBindingInfo(uint8_t *newLinkedit, uint32_t &offset);
  void copyExportInfo(uint8_t *newLinkedit, uint32_t &offset);

  void startSymbolEntries(uint8_t *newLinkedit, uint32_t &offset);
  void searchRedactedSymbol(uint8_t *newLinkedit, uint32_t &offset);
  void copyLocalSymbols(uint8_t *newLinkedit, uint32_t &offset);
  void copyExportedSymbols(uint8_t *newLinkedit, uint32_t &offset);
  void copyImportedSymbols(uint8_t *newLinkedit, uint32_t &offset);
  void endSymbolEntries(uint8_t *newLinkedit, uint32_t &offset);

  void copyFunctionStarts(uint8_t *newLinkedit, uint32_t &offset);
  void copyDataInCode(uint8_t *newLinkedit, uint32_t &offset);
  void copyIndirectSymbolTable(uint8_t *newLinkedit, uint32_t &offset);
  void copyStringPool(uint8_t *newLinkedit, uint32_t &offset);

  void updateLoadCommands(uint32_t &offset);

private:
  /// Finds the start of the local symbols and how many there are.
  std::tuple<Macho::Loader::nlist<P> *, Macho::Loader::nlist<P> *>
  findLocalSymbolEntries(const Dyld::Context *symbolsCache,
                         dyld_cache_local_symbols_info *symbolsInfo);

  uint32_t copyPublicLocalSymbols(uint8_t *newLinkedit, uint32_t &offset);
  uint32_t copyRedactedLocalSymbols(uint8_t *newLinkedit, uint32_t &offset);

  Utils::ExtractionContext<A> &eCtx;
  const Dyld::Context &dCtx;
  Macho::Context<false, P> &mCtx;
  ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
  LinkeditTracker<P> &linkeditTracker;

  StringPool stringsPool;
  uint32_t symbolsCount = 0;

  uint8_t *linkeditFile;
  uint32_t linkeditOffset;
  uint8_t *linkeditStart;
  Macho::Loader::dyld_info_command *dyldInfo;
  Macho::Loader::symtab_command *symTab;
  Macho::Loader::dysymtab_command *dySymTab;
  Macho::Loader::linkedit_data_command *exportTrieCmd;

  uint32_t newSymbolEntriesStart = 0;
  std::map<uint32_t, uint32_t> newSymbolIndicies;
};

template <class A>
LinkeditOptimizer<A>::LinkeditOptimizer(Utils::ExtractionContext<A> &eCtx)
    : eCtx(eCtx), dCtx(*eCtx.dCtx), mCtx(*eCtx.mCtx), activity(*eCtx.activity),
      logger(eCtx.logger), linkeditTracker(*eCtx.linkeditTracker) {
  auto &mCtx = *eCtx.mCtx;

  auto [offset, file] =
      mCtx.convertAddr(mCtx.getSegment("__LINKEDIT")->command->vmaddr);
  linkeditFile = file;
  linkeditOffset = (uint32_t)offset;
  linkeditStart = file + offset;

  dyldInfo = mCtx.getLoadCommand<false, Macho::Loader::dyld_info_command>();
  symTab = mCtx.getLoadCommand<false, Macho::Loader::symtab_command>();
  dySymTab = mCtx.getLoadCommand<false, Macho::Loader::dysymtab_command>();
  exportTrieCmd =
      mCtx.getLoadCommand<false, Macho::Loader::linkedit_data_command>(
          {LC_DYLD_EXPORTS_TRIE});
}

template <class A>
void LinkeditOptimizer<A>::copyBindingInfo(uint8_t *newLinkedit,
                                           uint32_t &offset) {
  if (!dyldInfo) {
    return;
  }

  if (auto size = dyldInfo->bind_size) {
    activity.update(std::nullopt, "Copying binding info");
    memcpy(newLinkedit + offset, linkeditFile + dyldInfo->bind_off, size);

    Utils::align(&size, 8);
    linkeditTracker.addTrackingData(
        {linkeditStart + offset,
         (uint32_t *)((uint8_t *)dyldInfo +
                      offsetof(Macho::Loader::dyld_info_command, bind_off)),
         size, LinkeditTrackerTag::bindInfo});
    dyldInfo->bind_off = linkeditOffset + offset;

    offset += size;
  }
  activity.update();
}

template <class A>
void LinkeditOptimizer<A>::copyWeakBindingInfo(uint8_t *newLinkedit,
                                               uint32_t &offset) {
  if (!dyldInfo) {
    return;
  }

  if (auto size = dyldInfo->weak_bind_size) {
    activity.update(std::nullopt, "Copying weak binding info");
    memcpy(newLinkedit + offset, linkeditFile + dyldInfo->weak_bind_off, size);

    Utils::align(&size, 8);
    linkeditTracker.addTrackingData(
        {linkeditStart + offset,
         (uint32_t *)((uint8_t *)dyldInfo +
                      offsetof(Macho::Loader::dyld_info_command,
                               weak_bind_off)),
         size, LinkeditTrackerTag::weakBindInfo});
    dyldInfo->weak_bind_off = linkeditOffset + offset;

    offset += size;
  }

  activity.update();
}

template <class A>
void LinkeditOptimizer<A>::copyLazyBindingInfo(uint8_t *newLinkedit,
                                               uint32_t &offset) {
  if (!dyldInfo) {
    return;
  }

  if (auto size = dyldInfo->lazy_bind_size) {
    activity.update(std::nullopt, "Copying lazy binding info");
    memcpy(newLinkedit + offset, linkeditFile + dyldInfo->lazy_bind_off, size);

    Utils::align(&size, 8);
    linkeditTracker.addTrackingData(
        {linkeditStart + offset,
         (uint32_t *)((uint8_t *)dyldInfo +
                      offsetof(Macho::Loader::dyld_info_command,
                               lazy_bind_off)),
         size, LinkeditTrackerTag::lazyBindInfo});
    dyldInfo->lazy_bind_off = linkeditOffset + offset;

    offset += size;
  }

  activity.update();
}

template <class A>
void LinkeditOptimizer<A>::copyExportInfo(uint8_t *newLinkedit,
                                          uint32_t &offset) {
  if (!exportTrieCmd && !dyldInfo) {
    return;
  }

  uint8_t *data;
  uint32_t dataSize;
  uint32_t *dataFieldOff;
  if (exportTrieCmd) {
    data = linkeditFile + exportTrieCmd->dataoff;
    dataSize = exportTrieCmd->datasize;
    dataFieldOff =
        (uint32_t *)((uint8_t *)exportTrieCmd +
                     offsetof(Macho::Loader::linkedit_data_command, dataoff));
  } else {
    data = linkeditFile + dyldInfo->export_off;
    dataSize = dyldInfo->export_size;
    dataFieldOff =
        (uint32_t *)((uint8_t *)dyldInfo +
                     offsetof(Macho::Loader::dyld_info_command, export_off));
  }

  if (dataSize) {
    activity.update(std::nullopt, "Copying export info");
    memcpy(newLinkedit + offset, data, dataSize);

    Utils::align(&dataSize, 8);
    linkeditTracker.addTrackingData({linkeditStart + offset, dataFieldOff,
                                     dataSize, LinkeditTrackerTag::exportInfo});
    *dataFieldOff = linkeditOffset + offset;

    offset += dataSize;
  }

  activity.update();
}

template <class A>
void LinkeditOptimizer<A>::startSymbolEntries(uint8_t *newLinkedit,
                                              uint32_t &offset) {
  newSymbolEntriesStart = offset;
}

template <class A>
void LinkeditOptimizer<A>::searchRedactedSymbol(uint8_t *newLinkedit,
                                                uint32_t &offset) {
  activity.update(std::nullopt, "Searching for redacted symbols");

  uint8_t *indirectSymStart = linkeditFile + dySymTab->indirectsymoff;
  for (std::size_t i = 0; i < dySymTab->nindirectsyms; i++) {
    auto symbolIndex = (uint32_t *)(indirectSymStart + i * sizeof(uint32_t));
    if (isRedactedIndirect(*symbolIndex)) {
      eCtx.hasRedactedIndirect = true;
      break;
    }
  }

  // Add a redacted symbol so that redacted symbols don't show a random one
  auto strIndex = stringsPool.addString("<redacted>");
  symbolsCount++;

  auto symbolEntry = (Macho::Loader::nlist<P> *)(newLinkedit + offset);
  symbolEntry->n_un.n_strx = strIndex;
  symbolEntry->n_type = 1;

  offset += sizeof(Macho::Loader::nlist<P>);
}

template <class A>
void LinkeditOptimizer<A>::copyLocalSymbols(uint8_t *newLinkedit,
                                            uint32_t &offset) {
  activity.update(std::nullopt, "Copying local symbols");

  uint32_t newLocalSymbolsStartIndex = symbolsCount;
  uint32_t newSymsCount = copyPublicLocalSymbols(newLinkedit, offset);
  newSymsCount += copyRedactedLocalSymbols(newLinkedit, offset);

  if (newSymsCount && dySymTab) {
    dySymTab->ilocalsym = newLocalSymbolsStartIndex;
    dySymTab->nlocalsym = newSymsCount;
  }
}

template <class A>
void LinkeditOptimizer<A>::copyExportedSymbols(uint8_t *newLinkedit,
                                               uint32_t &offset) {
  activity.update(std::nullopt, "Copying exported symbols");

  if (!dySymTab) {
    SPDLOG_LOGGER_WARN(logger, "Unable to copy exported symbols");
    return;
  }

  uint32_t newExportedSymbolsStartIndex = symbolsCount;
  uint32_t newExportedSymbolsCount = 0;
  auto syms = (Macho::Loader::nlist<P> *)(linkeditFile + symTab->symoff);
  uint32_t symsStart = dySymTab->iextdefsym;
  uint32_t symsEnd = symsStart + dySymTab->nextdefsym;
  auto stringsStart = linkeditFile + symTab->stroff;
  auto newEntriesHead = (Macho::Loader::nlist<P> *)(newLinkedit + offset);

  for (auto symIndex = symsStart; symIndex < symsEnd; symIndex++) {
    activity.update();
    auto symEntry = syms + symIndex;
    const char *string = (const char *)stringsStart + symEntry->n_un.n_strx;

    Macho::Loader::nlist<P> *newEntry = newEntriesHead;
    memcpy(newEntry, syms + symIndex, sizeof(Macho::Loader::nlist<P>));
    newEntry->n_un.n_strx = stringsPool.addString(string);
    newEntriesHead++;

    newSymbolIndicies[symIndex] = symbolsCount;

    newExportedSymbolsCount++;
    symbolsCount++;
  }

  if (newExportedSymbolsCount) {
    dySymTab->iextdefsym = newExportedSymbolsStartIndex;
    dySymTab->nextdefsym = newExportedSymbolsCount;
  }
  offset += sizeof(Macho::Loader::nlist<P>) * newExportedSymbolsCount;
}

template <class A>
void LinkeditOptimizer<A>::copyImportedSymbols(uint8_t *newLinkedit,
                                               uint32_t &offset) {
  activity.update(std::nullopt, "Copying imported symbols");

  if (!dySymTab) {
    SPDLOG_LOGGER_WARN(logger, "Unable to copy imported symbols");
    return;
  }

  uint32_t newImportedSymbolsStartIndex = symbolsCount;
  uint32_t newImportedSymbolsCount = 0;
  auto syms = (Macho::Loader::nlist<P> *)(linkeditFile + symTab->symoff);
  uint32_t symsStart = dySymTab->iundefsym;
  uint32_t symsEnd = symsStart + dySymTab->nundefsym;
  auto stringsStart = linkeditFile + symTab->stroff;
  auto newEntriesHead = (Macho::Loader::nlist<P> *)(newLinkedit + offset);

  for (auto symIndex = symsStart; symIndex < symsEnd; symIndex++) {
    activity.update();
    auto symEntry = syms + symIndex;
    const char *string = (const char *)stringsStart + symEntry->n_un.n_strx;

    Macho::Loader::nlist<P> *newEntry = newEntriesHead;
    memcpy(newEntry, syms + symIndex, sizeof(Macho::Loader::nlist<P>));
    newEntry->n_un.n_strx = stringsPool.addString(string);
    newEntriesHead++;

    newSymbolIndicies[symIndex] = symbolsCount;

    newImportedSymbolsCount++;
    symbolsCount++;
  }

  if (newImportedSymbolsCount) {
    dySymTab->iundefsym = newImportedSymbolsStartIndex;
    dySymTab->nundefsym = newImportedSymbolsCount;
  }
  offset += sizeof(Macho::Loader::nlist<P>) * newImportedSymbolsCount;
}

template <class A>
void LinkeditOptimizer<A>::endSymbolEntries(uint8_t *newLinkedit,
                                            uint32_t &offset) {
  if (!symTab) {
    return;
  }

  auto symEntrySize = (uint32_t)(offset - newSymbolEntriesStart);
  Utils::align(&symEntrySize, 8);

  linkeditTracker.addTrackingData(
      {linkeditStart + newSymbolEntriesStart,
       (uint32_t *)((uint8_t *)symTab +
                    offsetof(Macho::Loader::symtab_command, symoff)),
       symEntrySize, LinkeditTrackerTag::symbolEntries});
  symTab->symoff = linkeditOffset + newSymbolEntriesStart;
  symTab->nsyms = symbolsCount;
}

template <class A>
void LinkeditOptimizer<A>::copyFunctionStarts(uint8_t *newLinkedit,
                                              uint32_t &offset) {
  auto functionStarts =
      mCtx.getLoadCommand<false, Macho::Loader::linkedit_data_command>(
          {LC_FUNCTION_STARTS});
  if (!functionStarts) {
    return;
  }

  if (auto size = functionStarts->datasize) {
    activity.update(std::nullopt, "Copying function starts");
    memcpy(newLinkedit + offset, linkeditFile + functionStarts->dataoff, size);

    Utils::align(&size, 8);
    linkeditTracker.addTrackingData(
        {linkeditStart + offset,
         (uint32_t *)((uint8_t *)functionStarts +
                      offsetof(Macho::Loader::linkedit_data_command, dataoff)),
         size, LinkeditTrackerTag::functionStarts});
    functionStarts->dataoff = linkeditOffset + offset;

    offset += size;
  }

  activity.update();
}

template <class A>
void LinkeditOptimizer<A>::copyDataInCode(uint8_t *newLinkedit,
                                          uint32_t &offset) {
  auto dataInCode =
      mCtx.getLoadCommand<false, Macho::Loader::linkedit_data_command>(
          {LC_DATA_IN_CODE});
  if (!dataInCode) {
    return;
  }

  if (auto size = dataInCode->datasize) {
    activity.update(std::nullopt, "Copying data in code");
    memcpy(newLinkedit + offset, linkeditFile + dataInCode->dataoff, size);

    Utils::align(&size, 8);
    linkeditTracker.addTrackingData(
        {linkeditStart + offset,
         (uint32_t *)((uint8_t *)dataInCode +
                      offsetof(Macho::Loader::linkedit_data_command, dataoff)),
         size, LinkeditTrackerTag::dataInCode});
    dataInCode->dataoff = linkeditOffset + offset;

    offset += size;
  }

  activity.update();
}

template <class A>
void LinkeditOptimizer<A>::copyIndirectSymbolTable(uint8_t *newLinkedit,
                                                   uint32_t &offset) {
  if (!dySymTab) {
    return;
  }

  activity.update(std::nullopt, "Copying indirect symbol table");

  auto entries = (uint32_t *)(linkeditFile + dySymTab->indirectsymoff);
  auto newEntries = (uint32_t *)(newLinkedit + offset);
  for (uint32_t entryIndex = 0; entryIndex < dySymTab->nindirectsyms;
       entryIndex++) {
    uint32_t *entry = entries + entryIndex;
    if (isRedactedIndirect(*entry)) {
      // just copy entry
      *(newEntries + entryIndex) = *entry;
      continue;
    }

    *(newEntries + entryIndex) = newSymbolIndicies[*entry];
    activity.update();
  }

  uint32_t size = dySymTab->nindirectsyms * sizeof(uint32_t);
  Utils::align(&size, 8);
  linkeditTracker.addTrackingData(
      {linkeditStart + offset,
       (uint32_t *)((uint8_t *)dySymTab +
                    offsetof(Macho::Loader::dysymtab_command, indirectsymoff)),
       size, LinkeditTrackerTag::indirectSymtab});
  dySymTab->indirectsymoff = linkeditOffset + offset;

  offset += size;
}

template <class A>
void LinkeditOptimizer<A>::copyStringPool(uint8_t *newLinkedit,
                                          uint32_t &offset) {
  activity.update(std::nullopt, "Copying string pool");

  auto size = stringsPool.writeStrings(newLinkedit + offset);
  symTab->stroff = linkeditOffset + offset;
  symTab->strsize = size;

  Utils::align(&size, 8);
  linkeditTracker.addTrackingData(
      {linkeditStart + offset,
       (uint32_t *)((uint8_t *)symTab +
                    offsetof(Macho::Loader::symtab_command, stroff)),
       size, LinkeditTrackerTag::stringPool});

  activity.update();
  offset += size;
}

template <class A>
void LinkeditOptimizer<A>::updateLoadCommands(uint32_t &offset) {
  // update segment
  auto linkeditSeg = mCtx.getSegment("__LINKEDIT")->command;
  linkeditSeg->vmsize = offset;
  linkeditSeg->filesize = offset;
}

template <class A>
std::tuple<Macho::Loader::nlist<typename A::P> *,
           Macho::Loader::nlist<typename A::P> *>
LinkeditOptimizer<A>::findLocalSymbolEntries(
    const Dyld::Context *symbolsCache,
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
    uint64_t machoOffset = mCtx.getSegment("__TEXT")->command->vmaddr -
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
        mCtx.convertAddr(mCtx.getSegment("__TEXT")->command->vmaddr).first;
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

template <class A>
uint32_t LinkeditOptimizer<A>::copyPublicLocalSymbols(uint8_t *newLinkedit,
                                                      uint32_t &offset) {
  if (!dySymTab || !dySymTab->nlocalsym) {
    return 0;
  }

  uint32_t newLocalSymbolsCount = 0;
  auto strings = (const char *)linkeditFile + symTab->stroff;
  auto symsStart = (Macho::Loader::nlist<P> *)(linkeditFile + symTab->symoff) +
                   dySymTab->ilocalsym;
  auto symsEnd = symsStart + dySymTab->nlocalsym;
  auto newEntriesHead = (Macho::Loader::nlist<P> *)(newLinkedit + offset);

  for (auto entry = symsStart; entry < symsEnd; entry++) {
    const char *string = strings + entry->n_un.n_strx;
    if (std::strcmp(string, "<redacted>") == 0) {
      continue;
    }

    Macho::Loader::nlist<P> *newEntry = newEntriesHead;
    memcpy(newEntry, entry, sizeof(Macho::Loader::nlist<P>));
    newEntry->n_un.n_strx = stringsPool.addString(string);
    newEntriesHead++;

    newLocalSymbolsCount++;
    symbolsCount++;
    activity.update();
  }

  offset += sizeof(Macho::Loader::nlist<P>) * newLocalSymbolsCount;
  return newLocalSymbolsCount;
}

template <class A>
uint32_t LinkeditOptimizer<A>::copyRedactedLocalSymbols(uint8_t *newLinkedit,
                                                        uint32_t &offset) {
  auto symbolsCache = dCtx.getSymbolsCache();
  if (!symbolsCache || !symbolsCache->header->localSymbolsOffset) {
    return 0;
  }

  auto localSymsInfo =
      (dyld_cache_local_symbols_info
           *)(symbolsCache->file + symbolsCache->header->localSymbolsOffset);
  auto [symsStart, symsEnd] =
      findLocalSymbolEntries(symbolsCache, localSymsInfo);
  if (!symsStart) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to copy redacted local symbols.");
  }

  uint32_t newLocalSymbolsCount = 0;
  auto newEntriesHead = (Macho::Loader::nlist<P> *)(newLinkedit + offset);
  auto stringsStart = (uint8_t *)localSymsInfo + localSymsInfo->stringsOffset;
  for (auto symEntry = symsStart; symEntry < symsEnd; symEntry++) {
    activity.update();
    const char *string = (const char *)stringsStart + symEntry->n_un.n_strx;

    Macho::Loader::nlist<P> *newEntry = newEntriesHead;
    memcpy(newEntry, symEntry, sizeof(Macho::Loader::nlist<P>));
    newEntry->n_un.n_strx = stringsPool.addString(string);
    newEntriesHead++;

    newLocalSymbolsCount++;
    symbolsCount++;
  }

  offset += sizeof(Macho::Loader::nlist<P>) * newLocalSymbolsCount;
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
  eCtx.linkeditTracker = new LinkeditTracker<typename A::P>(*eCtx.mCtx);
  auto &mCtx = *eCtx.mCtx;

  auto linkeditSeg = mCtx.getSegment("__LINKEDIT");
  if (!linkeditSeg) {
    throw std::invalid_argument("Mach-o file doesn't have __LINKEDIT segment.");
  }

  uint32_t offset = 0;
  uint8_t *newLinkedit = (uint8_t *)calloc(linkeditSeg->command->vmsize, 1);

  LinkeditOptimizer<A> optimizer = LinkeditOptimizer<A>(eCtx);
  optimizer.copyBindingInfo(newLinkedit, offset);
  optimizer.copyWeakBindingInfo(newLinkedit, offset);
  optimizer.copyLazyBindingInfo(newLinkedit, offset);
  optimizer.copyExportInfo(newLinkedit, offset);

  optimizer.startSymbolEntries(newLinkedit, offset);
  optimizer.searchRedactedSymbol(newLinkedit, offset);
  optimizer.copyLocalSymbols(newLinkedit, offset);
  optimizer.copyExportedSymbols(newLinkedit, offset);
  optimizer.copyImportedSymbols(newLinkedit, offset);
  optimizer.endSymbolEntries(newLinkedit, offset);

  optimizer.copyFunctionStarts(newLinkedit, offset);
  optimizer.copyDataInCode(newLinkedit, offset);
  optimizer.copyIndirectSymbolTable(newLinkedit, offset);
  optimizer.copyStringPool(newLinkedit, offset);

  // Copy new linkedit
  auto oldLinkedit = mCtx.convertAddrP(linkeditSeg->command->vmaddr);
  memcpy(oldLinkedit, newLinkedit, offset);
  optimizer.updateLoadCommands(offset);

  free(newLinkedit);
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