#include "Arm64Fixer.h"

#include "Fixer.h"

using namespace DyldExtractor;
using namespace Converter;
using namespace Stubs;

template <class A>
Arm64Fixer<A>::Arm64Fixer(Fixer<A> &delegate)
    : delegate(delegate), mCtx(delegate.mCtx), activity(delegate.activity),
      logger(delegate.logger), bindInfo(delegate.bindInfo),
      ptrTracker(delegate.ptrTracker), symbolizer(delegate.symbolizer),
      pointerCache(delegate.pointerCache), arm64Utils(*delegate.arm64Utils) {}

template <class A> void Arm64Fixer<A>::fix() {
  fixStubHelpers();
  scanStubs();
  fixPass1();
  fixPass2();
  fixCallsites();
}

template <class A> void Arm64Fixer<A>::fixStubHelpers() {
  const PtrT REG_HELPER_SIZE = 0xC;

  const auto helperSect = mCtx.getSection(SEG_TEXT, "__stub_helper").second;
  if (!helperSect) {
    return;
  }

  const bool canFixReg = bindInfo.hasLazyBinds();

  const PtrT helperEnd = helperSect->addr + helperSect->size;
  PtrT helperAddr = helperSect->addr;
  if (arm64Utils.isStubBinder(helperAddr)) {
    helperAddr += 0x18; // Size of binder;
  }

  while (helperAddr < helperEnd) {
    activity.update();

    if (const auto bindInfoOff = arm64Utils.getStubHelperData(helperAddr);
        bindInfoOff) {
      if (canFixReg) {
        const auto bindRecord = bindInfo.getLazyBind(*bindInfoOff);
        if (!bindRecord) {
          SPDLOG_LOGGER_ERROR(
              logger, "Unable to read bind info for stub helper at {:#x}.",
              helperAddr);
        }

        // Point the pointer to the stub helper
        PtrT pAddr = (PtrT)bindRecord->address;
        ptrTracker.add(pAddr, helperAddr);
      } else {
        SPDLOG_LOGGER_WARN(
            logger, "Unable to fix stub helper at {:#x} without bind info.",
            helperAddr);
      }
      helperAddr += REG_HELPER_SIZE;
      continue;
    }

    // It may be a resolver
    if (const auto resolverInfo = arm64Utils.getResolverData(helperAddr);
        resolverInfo) {
      // shouldn't need fixing but check just in case
      if (!mCtx.containsAddr(resolverInfo->targetFunc)) {
        SPDLOG_LOGGER_WARN(logger,
                           "Stub resolver at 0x{:x} points outside of image.",
                           helperAddr);
      }

      // Point the pointer to the helper
      ptrTracker.add(resolverInfo->targetPtr, helperAddr);

      helperAddr += resolverInfo->size;
      continue;
    }

    SPDLOG_LOGGER_ERROR(logger, "Unknown stub helper format at 0x{:x}",
                        helperAddr);
    helperAddr += REG_HELPER_SIZE; // Try to recover, will probably fail
  }
}

template <class A> void Arm64Fixer<A>::scanStubs() {
  activity.update(std::nullopt, "Scanning Stubs");

  mCtx.enumerateSections(
      [](auto seg, auto sect) {
        return (sect->flags & SECTION_TYPE) == S_SYMBOL_STUBS;
      },
      [this](auto seg, auto sect) {
        auto sAddr = sect->addr;
        auto sLoc = mCtx.convertAddrP(sAddr);
        auto indirectI = sect->reserved1;

        const auto stubSize = sect->reserved2;
        for (; sAddr < sect->addr + sect->size;
             sAddr += stubSize, sLoc += stubSize, indirectI++) {
          activity.update();

          const auto sDataPair = arm64Utils.resolveStub(sAddr);
          if (!sDataPair) {
            SPDLOG_LOGGER_ERROR(logger, "Unknown Arm64 stub format at {:#x}",
                                sAddr);
            continue;
          }
          const auto [sTarget, sFormat] = *sDataPair;

          // First symbolize the stub
          std::set<Provider::SymbolicInfo::Symbol> symbols;

          // Though indirect entries
          if (const auto [entry, string] =
                  delegate.lookupIndirectEntry(indirectI);
              entry) {
            uint64_t ordinal = GET_LIBRARY_ORDINAL(entry->n_desc);
            symbols.insert({std::string(string), ordinal, std::nullopt});
          }

          // Though its pointer if not optimized
          if (sFormat == AStubFormat::StubNormal) {
            if (const auto pAddr = *arm64Utils.getStubLdrAddr(sAddr);
                mCtx.containsAddr(pAddr)) {
              if (pointerCache.ptr.lazy.contains(pAddr)) {
                const auto &info = pointerCache.ptr.lazy.at(pAddr);
                symbols.insert(info->symbols.begin(), info->symbols.end());
              } else if (pointerCache.ptr.normal.contains(pAddr)) {
                const auto &info = pointerCache.ptr.normal.at(pAddr);
                symbols.insert(info->symbols.begin(), info->symbols.end());
              }
            }
          }

          if (sFormat == AStubFormat::AuthStubNormal) {
            if (const auto pAddr = *arm64Utils.getAuthStubLdrAddr(sAddr);
                mCtx.containsAddr(pAddr) &&
                pointerCache.ptr.auth.contains(pAddr)) {
              const auto &info = pointerCache.ptr.auth.at(pAddr);
              symbols.insert(info->symbols.begin(), info->symbols.end());
            }
          }

          // Though its target function
          const auto sTargetFunc = arm64Utils.resolveStubChain(sAddr);
          if (const auto info = symbolizer.symbolizeAddr(sTargetFunc); info) {
            symbols.insert(info->symbols.begin(), info->symbols.end());
          }

          if (!symbols.empty()) {
            addStubInfo(sAddr,
                        {symbols, Provider::SymbolicInfo::Encoding::None});
            brokenStubs.emplace_back(sFormat, sTargetFunc, sAddr, sLoc,
                                     stubSize);
          } else {
            SPDLOG_LOGGER_WARN(logger, "Unable to symbolize stub at {:#x}",
                               sAddr);
          }
        }

        return true;
      });
}

template <class A>
void Arm64Fixer<A>::addStubInfo(PtrT addr, Provider::SymbolicInfo info) {
  Provider::SymbolicInfo *newInfo;
  if (stubMap.contains(addr)) {
    newInfo = &stubMap.at(addr);
    newInfo->symbols.insert(info.symbols.begin(), info.symbols.end());
  } else {
    newInfo = &stubMap.insert({addr, info}).first->second;
  }

  for (auto &sym : newInfo->symbols) {
    reverseStubMap[sym.name].insert(addr);
  }
}

/// @brief Fix stubs, first pass
///
/// The first pass tries to remove non broken stubs, or trivially fixable stubs.
template <class A> void Arm64Fixer<A>::fixPass1() {
  activity.update(std::nullopt, "Fixing Stubs: Pass 1");

  for (auto it = brokenStubs.begin(); it != brokenStubs.end();) {
    activity.update();

    const auto &sInfo = *it;
    const auto sAddr = sInfo.addr;
    const auto &sSymbols = stubMap.at(sInfo.addr);

    bool fixed = false;
    switch (sInfo.format) {
    case AStubFormat::StubNormal: {
      if (const auto pAddr = *arm64Utils.getStubLdrAddr(sAddr);
          mCtx.containsAddr(pAddr)) {
        if (pointerCache.isAvailable(SPointerType::lazy, pAddr)) {
          // Mark the pointer as used
          pointerCache.used.lazy.insert(pAddr);
          fixed = true;
        } else if (pointerCache.isAvailable(SPointerType::normal, pAddr)) {
          // Mark the pointer as used
          pointerCache.used.normal.insert(pAddr);
          ptrTracker.add(pAddr, 0);
          fixed = true;
        } else if (pointerCache.unnamed.lazy.contains(pAddr)) {
          // Name the pointer and mark as used
          pointerCache.namePointer(SPointerType::lazy, pAddr, sSymbols);
          pointerCache.used.lazy.insert(pAddr);
          fixed = true;
        } else if (pointerCache.unnamed.normal.contains(pAddr)) {
          // Name the pointer and mark as used
          pointerCache.namePointer(SPointerType::normal, pAddr, sSymbols);
          pointerCache.used.normal.insert(pAddr);
          ptrTracker.add(pAddr, 0);
          fixed = true;
        } else {
          SPDLOG_LOGGER_WARN(
              logger, "Unable to find the pointer a normal stub at {:#x} uses.",
              sAddr);
        }
      }
      break;
    }

    case AStubFormat::AuthStubNormal: {
      if (const auto pAddr = *arm64Utils.getAuthStubLdrAddr(sAddr);
          mCtx.containsAddr(pAddr)) {
        if (pointerCache.isAvailable(SPointerType::auth, pAddr)) {
          // Mark the pointer as used, zero out pointer
          pointerCache.used.auth.insert(pAddr);
          ptrTracker.add(pAddr, 0);
          fixed = true;
        } else if (pointerCache.isAvailable(SPointerType::normal, pAddr)) {
          // Mark the pointer as used, zero out pointer
          pointerCache.used.normal.insert(pAddr);
          ptrTracker.add(pAddr, 0);
          fixed = true;
        } else if (pointerCache.unnamed.auth.contains(pAddr)) {
          // Name the pointer and mark as used, zero out pointer
          pointerCache.namePointer(SPointerType::auth, pAddr, sSymbols);
          pointerCache.used.auth.insert(pAddr);
          ptrTracker.add(pAddr, 0);
          fixed = true;
        } else if (pointerCache.unnamed.normal.contains(pAddr)) {
          // Name the pointer and mark as used, zero out pointer
          pointerCache.namePointer(SPointerType::normal, pAddr, sSymbols);
          pointerCache.used.normal.insert(pAddr);
          ptrTracker.add(pAddr, 0);
          fixed = true;
        } else {
          SPDLOG_LOGGER_WARN(
              logger,
              "Unable to find the pointer a normal auth stub at {:#x} uses.",
              sAddr);
        }
      }
      break;
    }

    case AStubFormat::StubOptimized: {
      if (sInfo.size == 0x10 && !pointerCache.ptr.auth.empty()) {
        // In older caches, optimized auth stubs resemble regular optimized
        // stubs
        it = brokenStubs.emplace(it, AStubFormat::AuthStubOptimized,
                                 sInfo.target, sAddr, sInfo.loc, sInfo.size);
        it++;
        fixed = true;
      }
      break;
    }

    case AStubFormat::AuthStubResolver:
    case AStubFormat::Resolver: {
      if (mCtx.containsAddr(sInfo.target)) {
        fixed = true;
      }
      break;
    }

    default:
      assert(!"Unknown stub format");
      break;
    }

    if (fixed) {
      it = brokenStubs.erase(it);
    } else {
      it++;
    }
  }
}

/// @brief Fix stub, second pass
///
/// The second pass converts optimized stubs.
template <class A> void Arm64Fixer<A>::fixPass2() {
  activity.update(std::nullopt, "Fixing Stubs: Pass 2");

  for (auto &sInfo : brokenStubs) {
    activity.update();

    const auto sAddr = sInfo.addr;
    const auto sLoc = sInfo.loc;
    const auto &sSymbols = stubMap.at(sInfo.addr);

    switch (sInfo.format) {
    case AStubFormat::StubNormal:
    case AStubFormat::StubOptimized: {
      // Try to find an unused named lazy pointer
      PtrT pAddr = 0;
      for (const auto &sym : sSymbols.symbols) {
        if (pointerCache.reverse.lazy.contains(sym.name)) {
          for (const auto ptr : pointerCache.reverse.lazy[sym.name]) {
            if (!pointerCache.used.lazy.contains(ptr)) {
              pAddr = ptr;
              pointerCache.used.lazy.insert(ptr);
              break;
            }
          }
          if (pAddr) {
            break;
          }
        }
      }

      // Try to find an unused named normal pointer
      if (!pAddr) {
        for (const auto &sym : sSymbols.symbols) {
          if (pointerCache.reverse.normal.contains(sym.name)) {
            for (const auto ptr : pointerCache.reverse.normal[sym.name]) {
              if (!pointerCache.used.normal.contains(ptr)) {
                pAddr = ptr;
                pointerCache.used.normal.insert(ptr);
                ptrTracker.add(pAddr, 0);
                break;
              }
            }
            if (pAddr) {
              break;
            }
          }
        }
      }

      if (!pAddr && !pointerCache.unnamed.lazy.empty()) {
        // Use an unnamed lazy pointer
        pAddr = *pointerCache.unnamed.lazy.begin();
        pointerCache.namePointer(SPointerType::lazy, pAddr, sSymbols);
        pointerCache.used.lazy.insert(pAddr);
      }

      if (!pAddr && !pointerCache.unnamed.normal.empty()) {
        // Use an unnamed normal pointer
        pAddr = *pointerCache.unnamed.normal.begin();
        pointerCache.namePointer(SPointerType::normal, pAddr, sSymbols);
        pointerCache.used.normal.insert(pAddr);
        ptrTracker.add(pAddr, 0);
      }

      if (!pAddr) {
        SPDLOG_LOGGER_WARN(logger, "Unable to fix optimized stub at {:#x}",
                           sAddr);
        break;
      }

      // Fix the stub
      arm64Utils.writeNormalStub(sLoc, sAddr, pAddr);
      break;
    }

    case AStubFormat::AuthStubNormal:
    case AStubFormat::AuthStubOptimized: {
      // Try to find an unused named pointer
      PtrT pAddr = 0;
      for (const auto &sym : sSymbols.symbols) {
        if (pointerCache.reverse.auth.contains(sym.name)) {
          for (const auto ptr : pointerCache.reverse.auth[sym.name]) {
            if (!pointerCache.used.auth.contains(ptr)) {
              pAddr = ptr;
              break;
            }
          }
          if (pAddr) {
            break;
          }
        }
      }

      if (!pAddr && !pointerCache.unnamed.auth.empty()) {
        // Use an unnamed pointer
        pAddr = *pointerCache.unnamed.auth.begin();
        pointerCache.namePointer(SPointerType::auth, pAddr, sSymbols);
      }

      if (!pAddr) {
        SPDLOG_LOGGER_WARN(logger, "Unable to fix optimized auth stub at {:#x}",
                           sAddr);
        break;
      }

      // Fix stub and zero out pointer
      arm64Utils.writeNormalAuthStub(sLoc, sAddr, pAddr);
      pointerCache.used.auth.insert(pAddr);
      ptrTracker.add(pAddr, 0);
      break;
    }

    case AStubFormat::AuthStubResolver: {
      SPDLOG_LOGGER_ERROR(logger, "Unable to fix auth stub resolver at {:#x}",
                          sAddr);
    }

    case AStubFormat::Resolver: {
      SPDLOG_LOGGER_ERROR(logger, "Unable to fix stub resolver at {:#x}",
                          sAddr);
      break;
    }

    default:
      assert(!"Unknown stub format");
      break;
    }
  }
}

template <class A> void Arm64Fixer<A>::fixCallsites() {
  activity.update(std::nullopt, "Fixing Callsites");
  const auto textSect = mCtx.getSection(SEG_TEXT, SECT_TEXT).second;

  auto iAddr = textSect->addr;
  auto iLoc = mCtx.convertAddrP(iAddr);
  for (; iAddr < textSect->addr + textSect->size; iAddr += 4, iLoc += 4) {
    /**
     * We are only looking for bl and b instructions only.
     * Theses instructions are only identical by their top
     * most byte. By only looking at the top byte, we can
     * save a lot of time.
     */
    const uint32_t instrTop = *(iLoc + 3) & 0xFC;
    if (instrTop != 0x94 && instrTop != 0x14) {
      continue;
    }

    const auto brInstr = (uint32_t *)iLoc;
    const SPtrT brOff =
        arm64Utils.signExtend<SPtrT, 28>((*brInstr & 0x3FFFFFF) << 2);
    const auto brTarget = iAddr + brOff;

    // Check if it needs fixing
    if (mCtx.containsAddr(brTarget)) {
      continue;
    }

    const auto brTargetFunc = arm64Utils.resolveStubChain(brTarget);
    auto names = symbolizer.symbolizeAddr(brTargetFunc);

    if (!names) {
      // There might be a stub hiding the export name, walk up the chain to try
      // to recover
      auto chain = arm64Utils.resolveStubChainExtended(brTarget);
      if (chain.size()) {
        for (auto it = std::next(chain.crbegin()); it != chain.crend(); it++) {
          names = symbolizer.symbolizeAddr(it->first);
          if (names) {
            break;
          }
        }
        if (!names) {
          names = symbolizer.symbolizeAddr(brTarget); // Try very first stub
        }
      }
    }

    if (!names) {
      /**
       * Sometimes there are bytes of data in the text section
       * that match the bl and b filter, these seem to follow a
       * BR or other branch, skip these.
       */
      const auto lastInstrTop = *(iLoc - 1) & 0xFC;
      if (lastInstrTop == 0x94 || lastInstrTop == 0x14 ||
          lastInstrTop == 0xD4) {
        continue;
      }

      if (brTarget == brTargetFunc) {
        // it probably isn't a branch if it didn't go though any stubs...
        continue;
      }

      if (!delegate.isInCodeRegions(brTargetFunc)) {
        continue;
      }

      SPDLOG_LOGGER_WARN(logger,
                         "Unable to symbolize branch at {:#x} with target "
                         "{:#x} and destination {:#x}",
                         iAddr, brTarget, brTargetFunc);
      continue;
    }

    // Try to find a stub
    bool fixed = false;
    for (const auto &name : names->symbols) {
      if (reverseStubMap.contains(name.name)) {
        const auto stubAddr = *reverseStubMap[name.name].begin();
        const auto imm26 = ((SPtrT)stubAddr - iAddr) >> 2;
        *brInstr = (*brInstr & 0xFC000000) | (uint32_t)imm26;
        fixed = true;
        break;
      }
    }
    if (fixed) {
      activity.update();
      continue;
    } else {
      SPDLOG_LOGGER_WARN(logger,
                         "Unable to find stub for branch at {:#x}, with target "
                         "{:#x}, with symbols {}.",
                         iAddr, brTarget, fmt::join(names->symbols, ", "));
    }
  }
}

template class Arm64Fixer<Utils::Arch::arm64>;
template class Arm64Fixer<Utils::Arch::arm64_32>;
