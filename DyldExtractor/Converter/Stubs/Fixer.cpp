#include "Fixer.h"
#include "Stubs.h"

#include <Converter/Linkedit/Linkedit.h>

using namespace DyldExtractor;
using namespace Converter;
using namespace Stubs;

template <class A>
Fixer<A>::Fixer(Utils::ExtractionContext<A> &eCtx)
    : eCtx(eCtx), dCtx(*eCtx.dCtx), mCtx(*eCtx.mCtx), activity(*eCtx.activity),
      logger(eCtx.logger), accelerator(*eCtx.accelerator),
      bindInfo(eCtx.bindInfo), disasm(eCtx.disassembler),
      leTracker(eCtx.leTracker), ptrTracker(eCtx.ptrTracker),
      symbolizer(eCtx.symbolizer),
      linkeditFile(
          mCtx.convertAddr(mCtx.getSegment(SEG_LINKEDIT)->command->vmaddr)
              .second),
      symtab(mCtx.getFirstLC<Macho::Loader::symtab_command>()),
      dysymtab(mCtx.getFirstLC<Macho::Loader::dysymtab_command>()),
      pointerCache(*this) {
  if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                std::is_same_v<A, Utils::Arch::arm64_32>) {
    arm64Utils.emplace(eCtx);
    arm64Fixer.emplace(*this);
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    armUtils.emplace(eCtx);
    armFixer.emplace(*this);
  } else if constexpr (std::is_same_v<A, Utils::Arch::x86_64>) {
    throw std::logic_error("Stub Fixer does not support x85_64");
  }
}

template <class A> void Fixer<A>::fix() {
  // fill out code regions
  if (accelerator.codeRegions.empty()) {
    for (auto imageInfo : dCtx.images) {
      auto ctx = dCtx.createMachoCtx<true, P>(imageInfo);
      ctx.enumerateSections(
          [](auto seg, auto sect) {
            return sect->flags & S_ATTR_SOME_INSTRUCTIONS;
          },
          [this](auto seg, auto sect) {
            accelerator.codeRegions.insert(Provider::Accelerator<P>::CodeRegion(
                sect->addr, sect->addr + sect->size));
            return true;
          });
    }
  }

  checkIndirectEntries();
  symbolizer.enumerate();
  pointerCache.scanPointers();

  if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                std::is_same_v<A, Utils::Arch::arm64_32>) {
    arm64Fixer->fix();
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    armFixer->fix();
  }

  fixIndirectEntries();
  bindPointers();
}

template <class A>
std::pair<const Macho::Loader::nlist<typename A::P> *, const char *>
Fixer<A>::lookupIndirectEntry(const uint32_t index) const {
  const auto indirectEntry =
      *((uint32_t *)(linkeditFile + dysymtab->indirectsymoff) + index);
  if (isRedactedIndirect(indirectEntry)) {
    return std::make_pair(nullptr, nullptr);
  }

  // Indirect entry is an index into the symbol entries
  const auto entry =
      (Macho::Loader::nlist<P> *)(linkeditFile + symtab->symoff) +
      indirectEntry;
  const auto string =
      (char *)(linkeditFile + symtab->stroff + entry->n_un.n_strx);
  return std::make_pair(entry, string);
}

template <class A> Fixer<A>::PtrT Fixer<A>::resolveStubChain(const PtrT addr) {
  if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                std::is_same_v<A, Utils::Arch::arm64_32>) {
    return arm64Utils->resolveStubChain(addr);
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    return armUtils->resolveStubChain(addr);
  }

  throw std::logic_error("Arch not supported");
}

template <class A> void Fixer<A>::checkIndirectEntries() {
  activity.update(std::nullopt, "Checking indirect entires");

  if (!dysymtab->indirectsymoff) {
    return;
  }

  bool changed = false;
  bool hasStubs = false;
  std::vector<uint32_t> newEntries;
  auto indirectEntires = (uint32_t *)(linkeditFile + dysymtab->indirectsymoff);

  mCtx.enumerateSections([&](auto seg, auto sect) {
    activity.update();
    uint32_t newStartIndex = (uint32_t)newEntries.size();

    // Normal case
    switch (sect->flags & SECTION_TYPE) {
    case S_NON_LAZY_SYMBOL_POINTERS:
    case S_LAZY_SYMBOL_POINTERS:
    case S_THREAD_LOCAL_VARIABLE_POINTERS:
    case S_LAZY_DYLIB_SYMBOL_POINTERS: {
      uint32_t n = (uint32_t)(sect->size / sizeof(PtrT));
      uint32_t *start = indirectEntires + sect->reserved1;
      newEntries.insert(newEntries.end(), start, start + n);

      if (sect->reserved1 != newStartIndex) {
        sect->reserved1 = newStartIndex;
        changed = true;
      }
      return true;
      break;
    }
    case S_SYMBOL_STUBS: {
      hasStubs = true;
      uint32_t n = (uint32_t)(sect->size / sect->reserved2);
      uint32_t *start = indirectEntires + sect->reserved1;
      newEntries.insert(newEntries.end(), start, start + n);

      if (sect->reserved1 != newStartIndex) {
        sect->reserved1 = newStartIndex;
        changed = true;
      }
      return true;
      break;
    }
    default:
      break;
    }

    if ((memcmp(sect->sectname, "__got", 6) == 0 ||
         memcmp(sect->sectname, "__auth_got", 11) == 0) &&
        ((sect->flags & SECTION_TYPE) == 0)) {
      sect->flags |= S_NON_LAZY_SYMBOL_POINTERS;

      if ((hasStubs && sect->reserved1 != 0) ||
          (!hasStubs && sect->reserved1 == 0)) {
        // section type was removed, but index is still valid
        uint32_t n = (uint32_t)(sect->size / sizeof(PtrT));
        uint32_t *start = indirectEntires + sect->reserved1;
        newEntries.insert(newEntries.end(), start, start + n);

        if (sect->reserved1 != newStartIndex) {
          sect->reserved1 = newStartIndex;
          changed = true;
        }
      } else {
        // need to add redacted entries
        eCtx.hasRedactedIndirect = true;
        changed = true;
        sect->reserved1 = newStartIndex;
        uint32_t n = (uint32_t)(sect->size / sizeof(PtrT));
        newEntries.insert(newEntries.end(), n, 0x0);
      }

      return true;
    }

    return true;
  });

  if (!changed) {
    return;
  }

  // Resize the data region
  auto entriesMetadata =
      leTracker.findTag(Provider::LinkeditTracker<P>::Tag::indirectSymtab);
  if (entriesMetadata == leTracker.metadataEnd()) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to find indirect entries data");
    return;
  }
  uint32_t sizeOfEntries = (uint32_t)newEntries.size() * sizeof(uint32_t);
  if (auto it =
          leTracker.resizeData(entriesMetadata, Utils::align(sizeOfEntries, 8));
      it != leTracker.metadataEnd()) {
    // overwrite data and update command
    memcpy(it->data, newEntries.data(), sizeOfEntries);
    dysymtab->nindirectsyms = (uint32_t)newEntries.size();
  } else {
    SPDLOG_LOGGER_ERROR(logger, "Unable to resize indirect entries data");
  }
}

template <class A> void Fixer<A>::fixIndirectEntries() {
  /**
   * Some files have indirect symbols that are redacted,
   * These are then pointed to the "redacted" symbol entry.
   * But disassemblers like Ghidra use these to symbolize
   * stubs and other pointers.
   */

  if (!eCtx.hasRedactedIndirect) {
    return;
  }

  /// TODO: Use string pool to better coalesce strings
  activity.update(std::nullopt, "Fixing Indirect Symbols");

  auto indirectEntries = (uint32_t *)(linkeditFile + dysymtab->indirectsymoff);
  std::vector<Macho::Loader::nlist<P>> newEntries;
  std::vector<std::string> newStrings;
  uint32_t entryIndex = dysymtab->iundefsym + dysymtab->nundefsym;
  uint32_t stringsIndex = symtab->strsize;

  mCtx.enumerateSections([&](auto seg, auto sect) {
    switch (sect->flags & SECTION_TYPE) {
    case S_NON_LAZY_SYMBOL_POINTERS:
    case S_LAZY_SYMBOL_POINTERS: {
      auto pType = pointerCache.getPointerType(sect);

      uint32_t indirectI = sect->reserved1;
      for (PtrT pAddr = sect->addr; pAddr < sect->addr + sect->size;
           pAddr += sizeof(PtrT), indirectI++) {
        auto indirectEntry = indirectEntries + indirectI;
        if (!isRedactedIndirect(*indirectEntry)) {
          continue;
        }

        auto pInfo = pointerCache.getPointerInfo(pType, pAddr);
        if (!pInfo) {
          if (!mCtx.containsAddr(ptrTracker.slideP(pAddr))) {
            SPDLOG_LOGGER_DEBUG(
                logger,
                "Unable to symbolize pointer at {:#x}, with target {:#x}, "
                "for redacted indirect symbol entry.",
                pAddr, resolveStubChain(ptrTracker.slideP(pAddr)));
          }
          continue;
        }
        const auto &preferredSym = pInfo->preferredSymbol();

        // Create new entry and add string
        Macho::Loader::nlist<P> entry{};
        entry.n_type = 1;
        SET_LIBRARY_ORDINAL(entry.n_desc, (uint16_t)preferredSym.ordinal);
        entry.n_un.n_strx = stringsIndex;

        newEntries.push_back(entry);
        newStrings.push_back(preferredSym.name);
        *indirectEntry = entryIndex;

        entryIndex++;
        stringsIndex += (uint32_t)preferredSym.name.length() + 1;
      }
      break;
    }

    case S_SYMBOL_STUBS: {
      uint32_t indirectI = sect->reserved1;
      for (PtrT sAddr = sect->addr; sAddr < sect->addr + sect->size;
           sAddr += sect->reserved2, indirectI++) {
        auto indirectEntry = indirectEntries + indirectI;
        if (!isRedactedIndirect(*indirectEntry)) {
          continue;
        }

        Provider::SymbolicInfo *sInfo = nullptr;
        if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                      std::is_same_v<A, Utils::Arch::arm64_32>) {
          if (arm64Fixer->stubMap.contains(sAddr)) {
            sInfo = &arm64Fixer->stubMap.at(sAddr);
          }
        } else {
          if (armFixer->stubMap.contains(sAddr)) {
            sInfo = &armFixer->stubMap.at(sAddr);
          }
        }
        if (!sInfo) {
          SPDLOG_LOGGER_DEBUG(logger,
                              "Unable to symbolize stub at {:#x} for redacted "
                              "indirect symbol entry.",
                              sAddr);
          continue;
        }
        const auto &preferredSym = sInfo->preferredSymbol();

        // Create new entry and add string
        Macho::Loader::nlist<P> entry{};
        entry.n_type = 1;
        SET_LIBRARY_ORDINAL(entry.n_desc, (uint16_t)preferredSym.ordinal);
        entry.n_un.n_strx = stringsIndex;

        newEntries.push_back(entry);
        newStrings.push_back(preferredSym.name);
        *indirectEntry = entryIndex;

        entryIndex++;
        stringsIndex += (uint32_t)preferredSym.name.length() + 1;
      }
      break;
    }

    case S_THREAD_LOCAL_VARIABLE_POINTERS: {
      // ignore
      break;
    }
    case S_LAZY_DYLIB_SYMBOL_POINTERS: {
      SPDLOG_LOGGER_WARN(logger, "Unable to handle indirect entries for "
                                 "S_LAZY_DYLIB_SYMBOL_POINTERS section.");
      break;
    }

    default:
      break;
    }

    return true;
  });

  // Extend the entries region and add the data
  auto entriesMetadata =
      leTracker.findTag(Provider::LinkeditTracker<P>::Tag::symbolEntries);
  if (entriesMetadata == leTracker.metadataEnd()) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to find symbol entries data");
    return;
  }
  uint8_t *newEntriesLoc =
      entriesMetadata->data + (symtab->nsyms * sizeof(Macho::Loader::nlist<P>));
  const uint32_t sizeOfNewEntries =
      (uint32_t)newEntries.size() * sizeof(Macho::Loader::nlist<P>);
  if (auto it = leTracker.resizeData(
          entriesMetadata,
          Utils::align(entriesMetadata->dataSize + sizeOfNewEntries, 8));
      it == leTracker.metadataEnd()) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to extend the symbol entries region");
    return;
  }

  memcpy(newEntriesLoc, newEntries.data(), sizeOfNewEntries);

  // Extend the strings region and add the data
  auto stringsMetadata =
      leTracker.findTag(Provider::LinkeditTracker<P>::Tag::stringPool);
  if (stringsMetadata == leTracker.metadataEnd()) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to find the strings data");
    return;
  }
  uint8_t *newStringsLoc = stringsMetadata->data + symtab->strsize;
  const uint32_t sizeOfNewStrings = stringsIndex - symtab->strsize;
  if (auto it = leTracker.resizeData(
          stringsMetadata,
          Utils::align(stringsMetadata->dataSize + sizeOfNewStrings, 8));
      it == leTracker.metadataEnd()) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to extend the strings region");
    return;
  }

  for (auto &string : newStrings) {
    memcpy(newStringsLoc, string.c_str(), string.length() + 1);
    newStringsLoc += string.length() + 1;
  }

  // update the commands
  symtab->nsyms += (uint32_t)newEntries.size();
  symtab->strsize += sizeOfNewStrings;
  dysymtab->nundefsym += (uint32_t)newEntries.size();
}

/// @brief Bind non lazy symbol pointers
template <class A> void Fixer<A>::bindPointers() {
  for (auto &[pAddr, info] : pointerCache.ptr.normal) {
    ptrTracker.add(pAddr, 0);
    ptrTracker.addBind(pAddr, info);
  }
  for (auto &[pAddr, info] : pointerCache.ptr.auth) {
    ptrTracker.add(pAddr, 0);
    ptrTracker.addBind(pAddr, info);
  }
}

template <class A> bool Fixer<A>::isInCodeRegions(PtrT addr) {
  if (accelerator.codeRegions.empty()) {
    return false;
  }

  auto upper = accelerator.codeRegions.upper_bound(
      Provider::Accelerator<P>::CodeRegion(addr, addr));
  if (upper == accelerator.codeRegions.begin()) {
    return false;
  }

  const auto &potentialRange = *--upper;
  return addr >= potentialRange.start && addr < potentialRange.end;
}

template class Fixer<Utils::Arch::arm>;
template class Fixer<Utils::Arch::arm64>;
template class Fixer<Utils::Arch::arm64_32>;

template <class A> void Converter::fixStubs(Utils::ExtractionContext<A> &eCtx) {
  if constexpr (std::is_same_v<A, Utils::Arch::arm> ||
                std::is_same_v<A, Utils::Arch::arm64> ||
                std::is_same_v<A, Utils::Arch::arm64_32>) {
    eCtx.disassembler.disasm();
    eCtx.activity->update("Stub Fixer", "Starting Up");
    Fixer<A>(eCtx).fix();
  }

  // No stub fixing needed for x86_64
}

#define X(T)                                                                   \
  template void Converter::fixStubs<T>(Utils::ExtractionContext<T> & eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X