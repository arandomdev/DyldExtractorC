#include "Chained.h"

#include <Objc/Abstraction.h>

using namespace DyldExtractor;
using namespace Converter;
using namespace Linkedit;
using namespace Encoder;

#pragma region ChainedFixupBinds
void ChainedFixupBinds::ensureTarget(const Atom *atom, bool authPtr,
                                     uint64_t addend) {
  if (addend == 0) {
    // special case normal case of addend==0 to use map to be fast
    if (_bindOrdinalsWithNoAddend.count(atom))
      return;
    _bindOrdinalsWithNoAddend[atom] = (unsigned int)_bindsTargets.size();
    _bindsTargets.push_back({atom, 0});
    return;
  }
  unsigned index = 0;
  for (const AtomAndAddend &entry : _bindsTargets) {
    if (entry.atom == atom && entry.addend == addend)
      return;
    ++index;
  }
  _bindsTargets.push_back({atom, addend});
  if (authPtr) {
    // arm64e auth-pointer binds have no bit for addend, so any addend means
    // wide import table
    if (addend > 0xFFFFFFFF)
      _hasHugeAddends = true;
    else if (addend != 0)
      _hasLargeAddends = true;
  } else {
    if (addend > 0xFFFFFFFF)
      _hasHugeAddends = true;
    else if (addend > 255)
      _hasLargeAddends = true;
  }
}

uint32_t ChainedFixupBinds::count() const {
  return (uint32_t)_bindsTargets.size();
}

bool ChainedFixupBinds::hasLargeAddends() const { return _hasLargeAddends; }

bool ChainedFixupBinds::hasHugeAddends() const { return _hasHugeAddends; }

bool ChainedFixupBinds::hasHugeSymbolStrings() const {
  // we need to see if total size of all imported symbols will be >= 8MB
  // 99.9% of binaries have less than 10,000 imports and easily fit in 8MB of
  // strings
  if (_bindsTargets.size() < 10000)
    return false;
  uint32_t totalStringSize = 0;
  for (const AtomAndAddend &entry : _bindsTargets) {
    totalStringSize += ((uint32_t)strlen(entry.atom->name) + 1);
  }
  return (totalStringSize >= 0x00800000);
}

uint32_t ChainedFixupBinds::ordinal(const Atom *atom, uint64_t addend) const {
  if (addend == 0) {
    auto it = _bindOrdinalsWithNoAddend.find(atom);
    assert(it != _bindOrdinalsWithNoAddend.end());
    return it->second;
  }
  unsigned index = 0;
  for (const AtomAndAddend &entry : _bindsTargets) {
    if (entry.atom == atom && entry.addend == addend)
      return index;
    ++index;
  }
  assert(0 && "bind ordinal missing");
  return MAX_LIBRARY_ORDINAL;
}

void ChainedFixupBinds::forEachBind(EnumerationCallback callback) {
  unsigned index = 0;
  for (const AtomAndAddend &entry : _bindsTargets) {
    callback(index, entry.atom, entry.addend);
    ++index;
  }
}
#pragma endregion ChainedFixupBinds

ChainedEncoder::ChainedEncoder(Utils::ExtractionContext<A> &eCtx)
    : mCtx(*eCtx.mCtx), activity(*eCtx.activity), logger(eCtx.logger),
      exObjc(eCtx.exObjc), leTracker(eCtx.leTracker),
      ptrTracker(eCtx.ptrTracker) {}

void ChainedEncoder::generateMetadata() {
  // create the chained fixup info and Fixup pointers
  buildChainedFixupInfo();
  fixupPointers();

  auto chainInfo = encodeChainedInfo();
  auto chainInfoSize = (uint32_t)chainInfo.size();

  // Add lc to header, placed after the last segment
  Macho::Loader::linkedit_data_command chainedFixupCmd;
  chainedFixupCmd.cmd = LC_DYLD_CHAINED_FIXUPS;
  chainedFixupCmd.cmdsize = sizeof(Macho::Loader::linkedit_data_command);
  chainedFixupCmd.dataoff = 0; // Updated by LinkeditTracker
  chainedFixupCmd.datasize = chainInfoSize;

  auto lastSeg = mCtx.segments.rbegin()->command;
  Macho::Loader::load_command *pos =
      reinterpret_cast<Macho::Loader::load_command *>((uint8_t *)lastSeg +
                                                      lastSeg->cmdsize);
  if (!leTracker
           .insertLC(pos, reinterpret_cast<Macho::Loader::load_command *>(
                              &chainedFixupCmd))
           .second) {
    SPDLOG_LOGGER_ERROR(
        logger, "Not enough header space to insert chained fixup info.");
    return;
  }

  // Add data to linkedit, placed in the beginning
  typename Provider::LinkeditTracker<P>::Metadata meta(
      Provider::LinkeditTracker<P>::Tag::chainedFixups, nullptr, chainInfoSize,
      (uint8_t *)pos);
  if (!leTracker
           .insertData(leTracker.metadataBegin(), meta, chainInfo.data(),
                       chainInfoSize)
           .second) {
    SPDLOG_LOGGER_ERROR(
        logger, "Not enough space in linkedit to insert chained fixup info.");
    return;
  }

  // Chain pointers
  applyChainedFixups();
}

void ChainedEncoder::fixupPointers() {
  activity.update(std::nullopt, "Fixing pointers");

  switch (chainedPointerFormat()) {
  case DYLD_CHAINED_PTR_64_OFFSET:
    fixup64();
    break;

  case DYLD_CHAINED_PTR_ARM64E:
    fixup64e();
    break;

  default:
    assert(!"Unknown chained pointer format");
    break;
  }
}

void ChainedEncoder::buildChainedFixupInfo() {
  const auto &ptrs = ptrTracker.getPointers();
  const auto &auths = ptrTracker.getAuths();
  const auto &binds = ptrTracker.getBinds();

  const auto pageSize = ptrTracker.getPageSize();

  for (const auto &segCtx : mCtx.segments) {
    activity.update();
    const auto segCmd = segCtx.command;

    // Create segment info
    ChainedFixupSegInfo seg;
    seg.name = &segCmd->segname[0];
    seg.startAddr = segCmd->vmaddr;
    seg.endAddr = segCmd->vmaddr + segCmd->vmsize;
    seg.fileOffset = (uint32_t)segCmd->fileoff;
    seg.pageSize = pageSize;
    seg.pointerFormat = chainedPointerFormat();

    // add all pointers
    auto beginPtrIt = ptrs.lower_bound((PtrT)segCmd->vmaddr);
    auto endPtrIt = ptrs.lower_bound((PtrT)segCmd->vmaddr + segCmd->vmsize);
    for (auto it = beginPtrIt; it != endPtrIt; it++) {
      uint64_t fixUpAddr = it->first;

      uint64_t pageIndex = (fixUpAddr - seg.startAddr) / pageSize;
      while (pageIndex >= seg.pages.size()) {
        ChainedFixupPageInfo emptyPage;
        seg.pages.push_back(emptyPage);
      }
      uint16_t pageOffset =
          (uint16_t)(fixUpAddr - (seg.startAddr + pageIndex * pageSize));
      seg.pages[pageIndex].fixupOffsets.push_back(pageOffset);
    }

    // Add all binds
    auto beginBindIt = binds.lower_bound((PtrT)segCmd->vmaddr);
    auto endBindIt = binds.lower_bound((PtrT)segCmd->vmaddr + segCmd->vmsize);
    for (auto it = beginBindIt; it != endBindIt; it++) {
      // Verify that the bind has a pointer
      uint64_t bindAddr = it->first;
      if (!ptrs.contains((PtrT)bindAddr)) {
        SPDLOG_LOGGER_ERROR(
            logger,
            "Bind pointer at {:X} does not have a corresponding pointer",
            bindAddr);
        continue;
      }

      const auto &sym = it->second->preferredSymbol();
      auto atom = &atomMap
                       .try_emplace(bindAddr, sym.name.c_str(),
                                    (uint32_t)sym.ordinal, false)
                       .first->second;
      chainedFixupBinds.ensureTarget(atom, auths.contains((PtrT)bindAddr), 0);
    }

    chainedFixupSegments.push_back(seg);
  }

  // sort all fixups on each page, so chain can be built
  for (ChainedFixupSegInfo &segInfo : chainedFixupSegments) {
    for (ChainedFixupPageInfo &pageInfo : segInfo.pages) {
      std::sort(pageInfo.fixupOffsets.begin(), pageInfo.fixupOffsets.end());
    }
  }

  // remember largest legal rebase target
  uint64_t baseAddress = 0;
  uint64_t maxRebaseAddress = 0;
  for (ChainedFixupSegInfo &segInfo : chainedFixupSegments) {
    if (strcmp(segInfo.name, "__TEXT") == 0) {
      baseAddress = segInfo.startAddr;
      if (baseAddress == 0x4000)
        // 32-bit main executables have rebase targets that are zero based
        baseAddress = 0;
    } else if (strcmp(segInfo.name, "__LINKEDIT") == 0)
      maxRebaseAddress = (segInfo.startAddr - baseAddress + 0x00100000 - 1) &
                         -0x00100000; // align to 1MB
  }
  chainedFixupBinds.setMaxRebase(maxRebaseAddress);
}

void padToSize(std::vector<uint8_t> &data, std::size_t size) {
  auto padSize = Utils::align(data.size(), size) - data.size();
  data.insert(data.end(), padSize, 0x0);
}

void appendMem(std::vector<uint8_t> &data, void *mem, std::size_t size) {
  data.insert(data.end(), (uint8_t *)mem, (uint8_t *)mem + size);
}

std::vector<uint8_t> ChainedEncoder::encodeChainedInfo() {
  activity.update(std::nullopt, "Generating chained pointer info");
  std::vector<uint8_t> encodedData;
  encodedData.reserve(1024);

  uint16_t format = DYLD_CHAINED_IMPORT;
  if (chainedFixupBinds.hasHugeSymbolStrings())
    format = DYLD_CHAINED_IMPORT_ADDEND64;
  else if (chainedFixupBinds.hasHugeAddends())
    format = DYLD_CHAINED_IMPORT_ADDEND64;
  else if (chainedFixupBinds.hasLargeAddends())
    format = DYLD_CHAINED_IMPORT_ADDEND;
  dyld_chained_fixups_header header;
  header.fixups_version = 0;
  header.starts_offset =
      (sizeof(dyld_chained_fixups_header) + 7 & -8); // 8-byte align
  header.imports_offset = 0;                         // fixed up later
  header.symbols_offset = 0;                         // fixed up later
  header.imports_count = chainedFixupBinds.count();
  header.imports_format = format;
  header.symbols_format = 0;
  appendMem(encodedData, &header, sizeof(dyld_chained_fixups_header));
  padToSize(encodedData, 8);
  const unsigned segsHeaderOffset = (unsigned int)encodedData.size();

  // write starts table
  dyld_chained_starts_in_image segs;
  segs.seg_count = (uint32_t)chainedFixupSegments.size();
  segs.seg_info_offset[0] = 0;
  appendMem(encodedData, &segs, sizeof(dyld_chained_starts_in_image));
  uint32_t emptyOffset = 0;
  for (unsigned i = 1; i < chainedFixupSegments.size(); ++i) {
    // fixed up later if segment used
    appendMem(encodedData, &emptyOffset, sizeof(uint32_t));
  }
  unsigned segIndex = 0;
  uint64_t textStartAddress = 0;
  uint64_t maxRebaseAddress = 0;
  for (ChainedFixupSegInfo &segInfo : chainedFixupSegments) {
    if (strcmp(segInfo.name, "__TEXT") == 0) {
      textStartAddress = segInfo.startAddr;
    } else if (strcmp(segInfo.name, "__LINKEDIT") == 0) {
      uint64_t baseAddress = textStartAddress;
      if ((segInfo.pointerFormat == DYLD_CHAINED_PTR_32) &&
          (baseAddress == 0x4000)) {
        // 32-bit main executables have rebase targets that are zero based
        baseAddress = 0;
      }
      maxRebaseAddress = (segInfo.startAddr - baseAddress + 0x00100000 - 1) &
                         -0x00100000; // align to 1MB
    }
  }
  chainedFixupBinds.setMaxRebase(maxRebaseAddress);
  for (ChainedFixupSegInfo &segInfo : chainedFixupSegments) {
    if (!segInfo.pages.empty()) {
      uint32_t startBytesPerPage = sizeof(uint16_t);
      if (segInfo.pointerFormat == DYLD_CHAINED_PTR_32) {
        startBytesPerPage = 40; // guesstimate 32-bit chains go ~0.5K before
                                // needing a new start
      }
      dyld_chained_starts_in_segment aSeg;
      aSeg.size = offsetof(dyld_chained_starts_in_segment, page_start) +
                  (uint32_t)segInfo.pages.size() * startBytesPerPage;
      aSeg.page_size = segInfo.pageSize;
      aSeg.pointer_format = segInfo.pointerFormat;
      aSeg.segment_offset = segInfo.startAddr - textStartAddress;
      aSeg.max_valid_pointer = (segInfo.pointerFormat == DYLD_CHAINED_PTR_32)
                                   ? (uint32_t)maxRebaseAddress
                                   : 0;
      aSeg.page_count = (uint16_t)segInfo.pages.size();
      // pad so that dyld_chained_starts_in_segment will be 64-bit aligned
      padToSize(encodedData, 8);
      dyld_chained_starts_in_image *segHeader =
          (dyld_chained_starts_in_image *)(encodedData.data() +
                                           segsHeaderOffset);
      segHeader->seg_info_offset[segIndex] =
          (uint32_t)encodedData.size() - segsHeaderOffset;
      appendMem(encodedData, &aSeg,
                offsetof(dyld_chained_starts_in_segment, page_start));
      std::vector<uint16_t> segChainOverflows;
      for (ChainedFixupPageInfo &pageInfo : segInfo.pages) {
        uint16_t startOffset = pageInfo.fixupOffsets.empty()
                                   ? DYLD_CHAINED_PTR_START_NONE
                                   : pageInfo.fixupOffsets.front();
        appendMem(encodedData, &startOffset, sizeof(startOffset));
      }
      if (segInfo.pointerFormat == DYLD_CHAINED_PTR_32) {
        // zero out chain overflow area
        long padBytes = (startBytesPerPage - 2) * (long)segInfo.pages.size();
        for (long i = 0; i < padBytes; ++i)
          encodedData.push_back(0);
      }
    }
    ++segIndex;
  }

  // build imports and symbol table
  std::vector<dyld_chained_import> imports;
  std::vector<dyld_chained_import_addend> importsAddend;
  std::vector<dyld_chained_import_addend64> importsAddend64;
  std::vector<char> stringPool;
  stringPool.push_back('\0');
  chainedFixupBinds.forEachBind(
      [&header, &imports, &importsAddend, &importsAddend64, &stringPool](
          unsigned int bindOrdinal, const Atom *importAtom, uint64_t addend) {
        uint32_t libOrdinal = importAtom->libOrdinal;

        const char *symName = importAtom->name;
        bool weakImport = importAtom->weakImport;

        uint32_t nameOffset = (uint32_t)stringPool.size();
        if (header.imports_format == DYLD_CHAINED_IMPORT) {
          dyld_chained_import anImport;
          anImport.lib_ordinal = libOrdinal;
          anImport.weak_import = weakImport;
          anImport.name_offset = nameOffset;
          assert(anImport.name_offset == nameOffset);
          imports.push_back(anImport);
        } else if (header.imports_format == DYLD_CHAINED_IMPORT_ADDEND) {
          dyld_chained_import_addend anImportA;
          anImportA.lib_ordinal = libOrdinal;
          anImportA.weak_import = weakImport;
          anImportA.name_offset = nameOffset;
          anImportA.addend = (int32_t)addend;
          assert((uint64_t)anImportA.addend == addend);
          assert(anImportA.name_offset == nameOffset);
          importsAddend.push_back(anImportA);
        } else {
          dyld_chained_import_addend64 anImportA64;
          anImportA64.lib_ordinal = libOrdinal;
          anImportA64.weak_import = weakImport;
          anImportA64.name_offset = nameOffset;
          anImportA64.addend = addend;
          importsAddend64.push_back(anImportA64);
        }
        stringPool.insert(stringPool.end(), symName,
                          &symName[strlen(symName) + 1]);
      });

  // write imports and symbol table
  dyld_chained_fixups_header *chainHeader =
      (dyld_chained_fixups_header *)(encodedData.data());
  switch (header.imports_format) {
  case DYLD_CHAINED_IMPORT:
    padToSize(encodedData, 4);
    chainHeader = (dyld_chained_fixups_header *)(encodedData.data());
    chainHeader->imports_offset = (uint32_t)encodedData.size();
    appendMem(encodedData, imports.data(),
              sizeof(dyld_chained_import) * imports.size());
    break;
  case DYLD_CHAINED_IMPORT_ADDEND:
    padToSize(encodedData, 4);
    chainHeader = (dyld_chained_fixups_header *)(encodedData.data());
    chainHeader->imports_offset = (uint32_t)encodedData.size();
    appendMem(encodedData, importsAddend.data(),
              sizeof(dyld_chained_import_addend) * importsAddend.size());
    break;
  case DYLD_CHAINED_IMPORT_ADDEND64:
    padToSize(encodedData, 8);
    chainHeader = (dyld_chained_fixups_header *)(encodedData.data());
    chainHeader->imports_offset = (uint32_t)encodedData.size();
    appendMem(encodedData, importsAddend64.data(),
              sizeof(dyld_chained_import_addend64) * importsAddend64.size());
    break;
  }
  chainHeader = (dyld_chained_fixups_header *)(encodedData.data());
  chainHeader->symbols_offset = (uint32_t)encodedData.size();
  appendMem(encodedData, stringPool.data(), stringPool.size());

  // align to pointer size
  padToSize(encodedData, sizeof(PtrT));
  return encodedData;
}

void ChainedEncoder::applyChainedFixups() {
  activity.update(std::nullopt, "Chaining pointers");
  // Firmware chains are not supported

  // chain together fixups
  uint32_t segIndex = 0;
  for (ChainedFixupSegInfo &segInfo : chainedFixupSegments) {
    activity.update();

    uint8_t *segBufferStart = mCtx.convertAddrP(segInfo.startAddr);
    uint8_t *pageBufferStart = segBufferStart;
    uint32_t pageIndex = 0;
    uint32_t nextOverflowSlot = (uint32_t)segInfo.pages.size();
    for (ChainedFixupPageInfo &pageInfo : segInfo.pages) {

      uint8_t *prevLoc = nullptr;
      for (uint16_t pageOffset : pageInfo.fixupOffsets) {
        uint8_t *loc = (uint8_t *)pageBufferStart + pageOffset;

        if (prevLoc != nullptr) {
          uint64_t delta = (uint8_t *)loc - (uint8_t *)prevLoc;
          switch (segInfo.pointerFormat) {
          case DYLD_CHAINED_PTR_ARM64E:
          case DYLD_CHAINED_PTR_ARM64E_USERLAND:
          case DYLD_CHAINED_PTR_ARM64E_USERLAND24:
            ((dyld_chained_ptr_arm64e_rebase *)prevLoc)->next = delta / 8;
            assert((((dyld_chained_ptr_arm64e_rebase *)prevLoc)->next * 8) ==
                       delta &&
                   "next out of range");
            break;
          case DYLD_CHAINED_PTR_ARM64E_KERNEL:
          case DYLD_CHAINED_PTR_ARM64E_FIRMWARE:
            ((dyld_chained_ptr_arm64e_rebase *)prevLoc)->next = delta / 4;
            assert((((dyld_chained_ptr_arm64e_rebase *)prevLoc)->next * 4) ==
                       delta &&
                   "next out of range");
            break;
          case DYLD_CHAINED_PTR_64:
          case DYLD_CHAINED_PTR_64_OFFSET:
            ((dyld_chained_ptr_64_rebase *)prevLoc)->next = delta / 4;
            assert((((dyld_chained_ptr_64_rebase *)prevLoc)->next * 4) ==
                       delta &&
                   "next out of range");
            break;
          case DYLD_CHAINED_PTR_32:
            // chain32bitPointers((dyld_chained_ptr_32_rebase *)prevLoc,
            //                    (dyld_chained_ptr_32_rebase *)loc, segInfo,
            //                    pageBufferStart, pageIndex);
            assert(!"32bit pointers are not supported");
            break;
          default:
            assert(0 && "unknown pointer format");
          }
        }
        prevLoc = loc;
      }
      if (!pageInfo.chainOverflows.empty()) {
        uint8_t *chainHeader = NULL;
        if (auto metaIt = leTracker.findTag(
                Provider::LinkeditTracker<P>::Tag::chainedFixups);
            metaIt != leTracker.metadataEnd()) {
          chainHeader = metaIt->data;
        } else {
          throw std::invalid_argument(
              "Chained data was not added to the linkedit.");
        }

        dyld_chained_fixups_header *header =
            (dyld_chained_fixups_header *)chainHeader;
        dyld_chained_starts_in_image *chains =
            (dyld_chained_starts_in_image *)((uint8_t *)header +
                                             header->starts_offset);
        dyld_chained_starts_in_segment *segChains =
            (dyld_chained_starts_in_segment
                 *)((uint8_t *)chains + chains->seg_info_offset[segIndex]);
        uint32_t maxOverFlowCount =
            (segChains->size - offsetof(dyld_chained_starts_in_segment,
                                        page_start[segChains->page_count])) /
            sizeof(uint16_t);
        for (uint16_t extraStart : pageInfo.chainOverflows) {
          if ((segChains->page_start[pageIndex] &
               DYLD_CHAINED_PTR_START_MULTI) == 0) {
            uint16_t first = segChains->page_start[pageIndex];
            segChains->page_start[pageIndex] =
                DYLD_CHAINED_PTR_START_MULTI | nextOverflowSlot;
            segChains->page_start[nextOverflowSlot++] = first;
          }
          if (extraStart == pageInfo.chainOverflows.back())
            segChains->page_start[nextOverflowSlot++] =
                extraStart | DYLD_CHAINED_PTR_START_LAST;
          else
            segChains->page_start[nextOverflowSlot++] = extraStart;
        }
        assert(nextOverflowSlot <= maxOverFlowCount);
      }
      pageBufferStart += segInfo.pageSize;
      ++pageIndex;
    }
    ++segIndex;
  }
}

uint16_t ChainedEncoder::chainedPointerFormat() const {
  /**
   * arm64 = DYLD_CHAINED_PTR_64_OFFSET
   * arm64e = DYLD_CHAINED_PTR_ARM64E
   */

  if constexpr (std::is_same_v<A, Utils::Arch::arm64>) {
    if ((mCtx.header->cpusubtype & ~CPU_SUBTYPE_MASK) == CPU_SUBTYPE_ARM64E) {
      return DYLD_CHAINED_PTR_ARM64E;
    } else {
      return DYLD_CHAINED_PTR_64_OFFSET;
    }
  } else {
    throw std::invalid_argument(
        "Unknown or unsupported architecture for chained fixups");
  }
}

void ChainedEncoder::fixup64() {
  const auto &ptrs = ptrTracker.getPointers();
  const auto &auths = ptrTracker.getAuths();
  const auto &binds = ptrTracker.getBinds();

  // get address of header
  uint64_t machHeaderAddr = mCtx.getSegment(SEG_TEXT)->command->vmaddr;

  for (const auto &segCtx : mCtx.segments) {
    activity.update();
    const auto segCmd = segCtx.command;

    // Get relevant pointers
    uint64_t segAddr = segCmd->vmaddr;
    uint8_t *segData;
    if (strcmp(segCmd->segname, SEG_OBJC_EXTRA) == 0) {
      segData = exObjc.get<uint8_t>(segCmd->vmaddr);
    } else {
      segData = mCtx.convertAddrP(segCmd->vmaddr);
    }

    auto beginIt = ptrs.lower_bound((PtrT)segAddr);
    auto endIt = ptrs.lower_bound((PtrT)segAddr + segCmd->vmsize);

    for (auto it = beginIt; it != endIt; it++) {
      auto ptrAddr = it->first;
      auto ptrTarget = it->second;

      if (!mCtx.containsAddr(ptrTarget)) {
        SPDLOG_LOGGER_ERROR(logger,
                            "Pointer target at {:X} is not within MachO file, "
                            "re-pointing to mach header.",
                            ptrAddr);
        ptrTarget = (PtrT)machHeaderAddr;
      }

      auto fixUpLocation = segData + (ptrAddr - segAddr);

      if (binds.contains(ptrAddr)) {
        auto bindOrdinal = chainedFixupBinds.ordinal(&atomMap.at(ptrAddr), 0);

        dyld_chained_ptr_64_bind *b = (dyld_chained_ptr_64_bind *)fixUpLocation;
        b->bind = 1;
        b->next =
            0; // chained fixed up later once all fixup locations are known
        b->reserved = 0;
        b->addend = 0;
        b->ordinal = bindOrdinal;
        assert(b->ordinal == bindOrdinal);
      } else {
        uint64_t vmOffset = (ptrTarget - machHeaderAddr);
        uint64_t high8 = vmOffset >> 56;
        vmOffset &= 0x00FFFFFFFFFFFFFFULL;
        dyld_chained_ptr_64_rebase *r =
            (dyld_chained_ptr_64_rebase *)fixUpLocation;
        r->bind = 0;
        r->next =
            0; // chained fixed up later once all fixup locations are known
        r->reserved = 0;
        r->high8 = high8;
        r->target = vmOffset;
        uint64_t reconstituted = (((uint64_t)(r->high8)) << 56) + r->target;
        assert(reconstituted == (ptrTarget - machHeaderAddr));
      }
    }
  }
}

void ChainedEncoder::fixup64e() {
  const auto &ptrs = ptrTracker.getPointers();
  const auto &auths = ptrTracker.getAuths();
  const auto &binds = ptrTracker.getBinds();

  // get address of header
  uint64_t machHeaderAddr = mCtx.getSegment(SEG_TEXT)->command->vmaddr;

  for (const auto &segCtx : mCtx.segments) {
    activity.update();
    const auto segCmd = segCtx.command;

    // Get relevant pointers
    uint64_t segAddr = segCmd->vmaddr;
    uint8_t *segData;
    if (strcmp(segCmd->segname, SEG_OBJC_EXTRA) == 0) {
      segData = exObjc.get<uint8_t>(segCmd->vmaddr);
    } else {
      segData = mCtx.convertAddrP(segCmd->vmaddr);
    }

    auto beginIt = ptrs.lower_bound((PtrT)segAddr);
    auto endIt = ptrs.lower_bound((PtrT)segAddr + segCmd->vmsize);

    for (auto it = beginIt; it != endIt; it++) {
      auto ptrAddr = it->first;
      auto ptrTarget = it->second;

      if (!mCtx.containsAddr(ptrTarget)) {
        SPDLOG_LOGGER_ERROR(logger,
                            "Pointer target at {:X} is not within MachO file,"
                            "re-pointing to mach header.",
                            ptrAddr);
        ptrTarget = (PtrT)machHeaderAddr;
      }

      auto fixUpLocation = segData + (ptrAddr - segAddr);
      bool isAuth = auths.contains(ptrAddr);
      bool isBind = binds.contains(ptrAddr);

      if (isAuth) {
        auto authData = auths.at(ptrAddr);

        if (isBind) {
          auto bindOrdinal = chainedFixupBinds.ordinal(&atomMap.at(ptrAddr), 0);

          dyld_chained_ptr_arm64e_auth_bind *b =
              (dyld_chained_ptr_arm64e_auth_bind *)fixUpLocation;
          b->auth = 1;
          b->bind = 1;
          b->next = 0;
          b->key = authData.key;
          b->addrDiv = authData.hasAddrDiv;
          b->diversity = authData.diversity;
          b->zero = 0;
          b->ordinal = bindOrdinal;
          assert(b->ordinal == bindOrdinal);
        } else {
          dyld_chained_ptr_arm64e_auth_rebase *r =
              (dyld_chained_ptr_arm64e_auth_rebase *)fixUpLocation;
          uint64_t vmOffset = (ptrTarget - machHeaderAddr);
          r->auth = 1;
          r->bind = 0;
          r->next = 0;
          r->key = authData.key;
          r->addrDiv = authData.hasAddrDiv;
          r->diversity = authData.diversity;
          r->target = vmOffset & 0xFFFFFFFF;
          assert(r->target == vmOffset);
        }
      } else {
        if (isBind) {
          auto bindOrdinal = chainedFixupBinds.ordinal(&atomMap.at(ptrAddr), 0);

          dyld_chained_ptr_arm64e_bind *b =
              (dyld_chained_ptr_arm64e_bind *)fixUpLocation;
          b->auth = 0;
          b->bind = 1;
          b->next =
              0; // chained fixed up later once all fixup locations are known
          b->addend = 0;
          b->zero = 0;
          b->ordinal = bindOrdinal;
          assert(b->ordinal == bindOrdinal);
        } else {
          dyld_chained_ptr_arm64e_rebase *r =
              (dyld_chained_ptr_arm64e_rebase *)fixUpLocation;
          r->auth = 0;
          r->bind = 0;
          r->next =
              0; // chained fixed up later once all fixup locations are known
          r->high8 = (ptrTarget >> 56);
          r->target = ptrTarget;
          uint64_t reconstituted = (((uint64_t)(r->high8)) << 56) + r->target;
          assert(reconstituted == ptrTarget);
        }
      }
    }
  }
}
