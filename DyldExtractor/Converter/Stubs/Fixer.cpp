#include "Fixer.h"
#include "Stubs.h"

#include <Converter/Linkedit/Linkedit.h>

using namespace DyldExtractor;
using namespace Converter;
using namespace Stubs;

template <class A>
Fixer<A>::Fixer(Utils::ExtractionContext<A> &eCtx)
    : eCtx(eCtx), dCtx(*eCtx.dCtx), mCtx(*eCtx.mCtx),
      accelerator(*eCtx.accelerator), activity(*eCtx.activity),
      logger(eCtx.logger), bindInfo(eCtx.bindInfo), disasm(eCtx.disasm),
      leTracker(eCtx.leTracker.value()), stTracker(eCtx.stTracker.value()),
      ptrTracker(eCtx.ptrTracker), symbolizer(eCtx.symbolizer.value()),
      ptrCache(*eCtx.mCtx, *eCtx.activity, eCtx.logger, eCtx.ptrTracker,
               eCtx.symbolizer.value(), eCtx.stTracker.value(), arm64Utils,
               armUtils) {
  if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                std::is_same_v<A, Utils::Arch::arm64_32>) {
    arm64Utils.emplace(dCtx, accelerator, ptrTracker);
    arm64Fixer.emplace(*this);
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    armUtils.emplace(dCtx, accelerator, ptrTracker);
    armFixer.emplace(*this);
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
  ptrCache.scanPointers();

  if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                std::is_same_v<A, Utils::Arch::arm64_32>) {
    arm64Fixer->fix();
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    armFixer->fix();
  }

  fixIndirectEntries();
  bindPointers();
}

/**
 * This checks if all the sections that have indirect symbols entries are synced
 * with the tracked indicies. It also generates redacted indirect symbols for
 * sections that should have them but don't.
 */
template <class A> void Fixer<A>::checkIndirectEntries() {
  activity.update(std::nullopt, "Checking indirect entires");

  auto &indirectSyms = stTracker.indirectSyms;
  uint32_t currentI = 0;
  bool hasIndirectSyms = false;

  /// TODO: Verify adding new indirect sym indicies
  mCtx.enumerateSections([&](auto seg, auto sect) {
    activity.update();

    // Normal case
    switch (sect->flags & SECTION_TYPE) {
    case S_SYMBOL_STUBS: {
      hasIndirectSyms = true;
      if (sect->reserved1 != currentI) {
        sect->reserved1 = currentI;
      }
      currentI += (uint32_t)(sect->size / sect->reserved2);
      return true;
    }

    case S_NON_LAZY_SYMBOL_POINTERS:
    case S_LAZY_SYMBOL_POINTERS:
    case S_THREAD_LOCAL_VARIABLE_POINTERS:
    case S_LAZY_DYLIB_SYMBOL_POINTERS: {
      hasIndirectSyms = true;
      if (sect->reserved1 != currentI) {
        sect->reserved1 = currentI;
      }
      currentI += (uint32_t)(sect->size / sizeof(PtrT));
      return true;
    }

    default:
      break;
    }

    if ((memcmp(sect->sectname, "__got", 6) == 0 ||
         memcmp(sect->sectname, "__auth_got", 11) == 0) &&
        ((sect->flags & SECTION_TYPE) == 0)) {
      sect->flags |= S_NON_LAZY_SYMBOL_POINTERS; // set flag again

      if ((hasIndirectSyms && sect->reserved1 != 0) ||
          (!hasIndirectSyms && sect->reserved1 == 0)) {
        // section type was removed, but index is still valid
        if (sect->reserved1 != currentI) {
          sect->reserved1 = currentI;
        }
        currentI += (uint32_t)(sect->size / sizeof(PtrT));
      } else {
        // need to add redacted entries
        if (sect->reserved1 != currentI) {
          sect->reserved1 = currentI;
        }

        uint32_t n = (uint32_t)(sect->size / sizeof(PtrT));
        indirectSyms.insert(indirectSyms.begin() + currentI, n,
                            stTracker.getOrMakeRedactedSymIndex());
        currentI += n;
      }

      hasIndirectSyms = true;
    }

    return true;
  });
}

template <class A> void Fixer<A>::fixIndirectEntries() {
  /**
   * Some files have indirect symbols that are redacted,
   * These are then pointed to the "redacted" symbol entry.
   * But disassemblers like Ghidra use these to symbolize
   * stubs and other pointers.
   */

  if (!stTracker.getRedactedSymIndex()) {
    return;
  }

  activity.update(std::nullopt, "Fixing Indirect Symbols");

  mCtx.enumerateSections([&](auto seg, auto sect) {
    switch (sect->flags & SECTION_TYPE) {
    case S_NON_LAZY_SYMBOL_POINTERS:
    case S_LAZY_SYMBOL_POINTERS: {
      auto pType = ptrCache.getPointerType(sect);

      uint32_t indirectI = sect->reserved1;
      for (PtrT pAddr = sect->addr; pAddr < sect->addr + sect->size;
           pAddr += sizeof(PtrT), indirectI++) {
        auto &symIndex = stTracker.indirectSyms.at(indirectI);
        if (symIndex != stTracker.getRedactedSymIndex()) {
          continue;
        }

        // Symbolize the pointer
        auto pInfo = ptrCache.getPointerInfo(pType, pAddr);
        if (!pInfo) {
          if (!mCtx.containsAddr(ptrTracker.slideP(pAddr))) {
            PtrT target;
            if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                          std::is_same_v<A, Utils::Arch::arm64_32>) {
              target = arm64Utils->resolveStubChain(ptrTracker.slideP(pAddr));
            } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
              target = armUtils->resolveStubChain(ptrTracker.slideP(pAddr));
            }
            SPDLOG_LOGGER_DEBUG(
                logger,
                "Unable to symbolize pointer at {:#x}, with target {:#x}, "
                "for redacted indirect symbol entry.",
                pAddr, target);
          }

          // Might point to something internal, ignore
          continue;
        }
        const auto &preferredSym = pInfo->preferredSymbol();

        // Create new string and entry
        auto &str = stTracker.addString(preferredSym.name);
        /// TODO: Check if symbol types are correct
        Macho::Loader::nlist<P> sym{};
        sym.n_type = 1;
        SET_LIBRARY_ORDINAL(sym.n_desc, (uint16_t)preferredSym.ordinal);
        auto newSymIndex = stTracker.addSym(STSymbolType::undefined, str, sym);
        stTracker.indirectSyms[indirectI] = newSymIndex;
      }
      break;
    }

    case S_SYMBOL_STUBS: {
      uint32_t indirectI = sect->reserved1;
      for (PtrT sAddr = sect->addr; sAddr < sect->addr + sect->size;
           sAddr += sect->reserved2, indirectI++) {
        auto &symIndex = stTracker.indirectSyms.at(indirectI);
        if (symIndex != stTracker.getRedactedSymIndex()) {
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

        // Create new string and entry
        auto &str = stTracker.addString(preferredSym.name);
        /// TODO: Check if symbol types are correct
        Macho::Loader::nlist<P> sym{};
        sym.n_type = 1;
        SET_LIBRARY_ORDINAL(sym.n_desc, (uint16_t)preferredSym.ordinal);
        auto newSymIndex = stTracker.addSym(STSymbolType::undefined, str, sym);
        stTracker.indirectSyms[indirectI] = newSymIndex;
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
}

/// @brief Bind non lazy symbol pointers
template <class A> void Fixer<A>::bindPointers() {
  for (auto &[pAddr, info] : ptrCache.ptr.normal) {
    ptrTracker.add(pAddr, 0);
    ptrTracker.addBind(pAddr, info);
  }
  for (auto &[pAddr, info] : ptrCache.ptr.auth) {
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
    // Load providers
    eCtx.bindInfo.load();
    eCtx.disasm.load();

    eCtx.activity->update("Stub Fixer", "Starting Up");
    if (!eCtx.symbolizer || !eCtx.leTracker || !eCtx.stTracker) {
      SPDLOG_LOGGER_ERROR(eCtx.logger,
                          "StubFixer depends on Linkedit Optimizer.");
      return;
    }

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