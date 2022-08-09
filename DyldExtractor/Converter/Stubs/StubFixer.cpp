#include "StubFixer.h"

#include <spdlog/spdlog.h>

using namespace Converter;

#pragma region SymbolPointerCache
template <class A>
SymbolPointerCache<A>::SymbolPointerCache(StubFixer<A> &delegate)
    : delegate(delegate), mCtx(delegate.mCtx), activity(delegate.activity),
      logger(delegate.logger) {}

template <class A>
SymbolPointerCache<A>::PointerType
SymbolPointerCache<A>::getPointerType(const auto sect) const {
  const auto sectType = sect->flags & SECTION_TYPE;
  const bool isAuth =
      strstr(sect->segname, "AUTH") || strstr(sect->sectname, "auth");

  if (sectType == S_LAZY_SYMBOL_POINTERS) {
    if (isAuth) {
      SPDLOG_LOGGER_ERROR(logger, "Unknown section type combination");
    } else {
      return PointerType::lazy;
    }
  } else if (sectType == S_NON_LAZY_SYMBOL_POINTERS) {
    if (isAuth) {
      return PointerType::auth;
    } else {
      return PointerType::normal;
    }
  } else {
    SPDLOG_LOGGER_ERROR(logger, "Unexpected section type {:#x}", sectType);
  }

  return PointerType::normal;
}

template <class A> void SymbolPointerCache<A>::scanPointers() {
  activity.update(std::nullopt, "Scanning Symbol Pointers");
  const auto bindRecords = getBindRecords();

  mCtx.enumerateSections(
      [](auto seg, auto sect) {
        return (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS ||
               (sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS;
      },
      [this, &bindRecords](auto seg, auto sect) {
        auto pType = getPointerType(sect);

        uint32_t indirectI = sect->reserved1;
        for (PtrT pAddr = sect->addr; pAddr < sect->addr + sect->size;
             pAddr += sizeof(PtrT), indirectI++) {
          activity.update();

          std::set<Provider::SymbolicInfo::Symbol> symbols;

          // Bind records
          if (bindRecords.contains(pAddr)) {
            auto &record = bindRecords.at(pAddr);
            symbols.insert({std::string(record.symbolName),
                            (uint64_t)record.libOrdinal, std::nullopt});
          }

          // Check indirect entry
          if (const auto [entry, string] =
                  delegate.lookupIndirectEntry(indirectI);
              entry) {
            uint64_t ordinal = GET_LIBRARY_ORDINAL(entry->n_desc);
            symbols.insert({std::string(string), ordinal, std::nullopt});
          }

          // The pointer's target function
          if (const auto pTarget = delegate.pointerTracker.slideP(pAddr);
              pTarget) {
            const auto pFunc = delegate.resolveStubChain(pTarget);
            if (const auto set = delegate.symbolizer.symbolizeAddr(pFunc);
                set) {
              symbols.insert(set->symbols.begin(), set->symbols.end());
            }
          }

          if (!symbols.empty()) {
            addPointerInfo(pType, pAddr,
                           Provider::SymbolicInfo(std::move(symbols)));
          } else {
            // Add to unnamed
            switch (pType) {
            case PointerType::normal:
              unnamed.normal.insert(pAddr);
              break;

            case PointerType::lazy:
              unnamed.lazy.insert(pAddr);
              break;

            case PointerType::auth:
              unnamed.auth.insert(pAddr);
              break;

            default:
              break;
            }
          }
        }

        return true;
      });
}

template <class A>
bool SymbolPointerCache<A>::isAvailable(PointerType pType, PtrT addr) {
  switch (pType) {
  case PointerType::normal:
    return ptr.normal.contains(addr) && !used.normal.contains(addr);
    break;

  case PointerType::lazy:
    return ptr.lazy.contains(addr) && !used.lazy.contains(addr);
    break;

  case PointerType::auth:
    return ptr.auth.contains(addr) && !used.auth.contains(addr);
    break;

  default:
    return false;
    break;
  }
}

template <class A>
void SymbolPointerCache<A>::namePointer(PointerType pType, PtrT addr,
                                        Provider::SymbolicInfo info) {
  switch (pType) {
  case PointerType::normal:
    unnamed.normal.erase(addr);
    break;
  case PointerType::lazy:
    unnamed.lazy.erase(addr);
    break;
  case PointerType::auth:
    unnamed.auth.erase(addr);
    break;

  default:
    return;
    break;
  }

  addPointerInfo(pType, addr, info);
}

template <class A>
Provider::SymbolicInfo *SymbolPointerCache<A>::getPointerInfo(PointerType pType,
                                                              PtrT addr) {
  switch (pType) {
  case PointerType::normal:
    if (ptr.normal.contains(addr)) {
      return &ptr.normal.at(addr);
    } else {
      return nullptr;
    }
    break;

  case PointerType::lazy:
    if (ptr.lazy.contains(addr)) {
      return &ptr.lazy.at(addr);
    } else {
      return nullptr;
    }
    break;

  case PointerType::auth:
    if (ptr.auth.contains(addr)) {
      return &ptr.auth.at(addr);
    } else {
      return nullptr;
    }
    break;

  default:
    return nullptr;
    break;
  }
}

template <class A>
std::map<typename SymbolPointerCache<A>::PtrT, Macho::BindRecord>
SymbolPointerCache<A>::getBindRecords() {
  std::map<PtrT, Macho::BindRecord> bindRecords;

  if (!delegate.dyldInfo) {
    return bindRecords;
  }

  auto linkeditFile = delegate.linkeditFile;
  auto dyldInfo = delegate.dyldInfo;

  std::vector<Macho::BindRecord> records;
  try {
    if (dyldInfo->bind_size) {
      std::vector<Macho::BindRecord> r;
      const auto start = linkeditFile + dyldInfo->bind_off;
      auto reader =
          Macho::BindInfoReader<P>(start, start + dyldInfo->bind_size);
      while (reader) {
        r.push_back(reader());
      }

      records.insert(records.end(), r.begin(), r.end());
    }
  } catch (const std::invalid_argument &e) {
    // In some caches the bind info points to what looks like an export trie??
    SPDLOG_LOGGER_DEBUG(logger, "Error while parsing bind info, {}", e.what());
  }

  try {
    if (dyldInfo->weak_bind_size) {
      std::vector<Macho::BindRecord> r;
      const auto start = linkeditFile + dyldInfo->weak_bind_off;
      auto reader =
          Macho::BindInfoReader<P>(start, start + dyldInfo->weak_bind_size);
      while (reader) {
        records.push_back(reader());
      }

      records.insert(records.end(), r.begin(), r.end());
    }
  } catch (const std::invalid_argument &e) {
    SPDLOG_LOGGER_DEBUG(logger, "Error while parsing weak bind info, {}",
                        e.what());
  }

  try {
    if (dyldInfo->lazy_bind_size) {
      std::vector<Macho::BindRecord> r;
      const auto start = linkeditFile + dyldInfo->lazy_bind_off;
      auto reader =
          Macho::BindInfoReader<P>(start, start + dyldInfo->lazy_bind_size);
      while (reader) {
        records.push_back(reader());
      }

      records.insert(records.end(), r.begin(), r.end());
    }
  } catch (const std::invalid_argument &e) {
    SPDLOG_LOGGER_DEBUG(logger, "Error while parsing lazy bind info, {}",
                        e.what());
  }

  for (auto &r : records) {
    const auto bindAddr =
        mCtx.segments[r.segIndex].command->vmaddr + r.segOffset;
    bindRecords[(unsigned int)bindAddr] = r;
  }

  return bindRecords;
}

template <class A>
void SymbolPointerCache<A>::addPointerInfo(PointerType pType, PtrT pAddr,
                                           Provider::SymbolicInfo info) {
  PtrMapT *pointers;
  ReverseMapT *reversePtrs;
  switch (pType) {
  case PointerType::normal:
    pointers = &ptr.normal;
    reversePtrs = &reverse.normal;
    break;

  case PointerType::lazy:
    pointers = &ptr.lazy;
    reversePtrs = &reverse.lazy;
    break;

  case PointerType::auth:
    pointers = &ptr.auth;
    reversePtrs = &reverse.auth;
    break;

  default:
    throw std::logic_error("Unknown Pointer Type");
    break;
  }

  // Add to normal cache
  Provider::SymbolicInfo *newInfo;
  if (pointers->contains(pAddr)) {
    newInfo = &pointers->at(pAddr);
    newInfo->symbols.insert(info.symbols.begin(), info.symbols.end());
  } else {
    newInfo = &pointers->insert({pAddr, info}).first->second;
  }

  // add to reverse cache
  for (auto &sym : newInfo->symbols) {
    (*reversePtrs)[std::cref(sym.name)].insert(pAddr);
  }
}
#pragma endregion SymbolPointerCache

#pragma region Arm64Fixer
template <class A>
Arm64Fixer<A>::Arm64Fixer(StubFixer<A> &delegate)
    : delegate(delegate), mCtx(delegate.mCtx), activity(delegate.activity),
      logger(delegate.logger), ptrTracker(delegate.pointerTracker),
      symbolizer(delegate.symbolizer), pointerCache(delegate.pointerCache),
      arm64Utils(*delegate.arm64Utils) {
  if constexpr (!std::is_same_v<A, Utils::Arch::arm64> &&
                !std::is_same_v<A, Utils::Arch::arm64_32>) {
    assert(!"Arm64Fixer only supports arches arm64 and arm64_32");
  }
}

template <class A> void Arm64Fixer<A>::fix() {
  fixStubHelpers();
  scanStubs();
  fixPass1();
  fixPass2();
  fixCallsites();
}

template <class A> void Arm64Fixer<A>::fixStubHelpers() {
  static const PtrT REG_HELPER_SIZE = 0xC;

  const auto helperSect = mCtx.getSection("__TEXT", "__stub_helper").second;
  if (!helperSect) {
    return;
  }

  const auto linkeditFile = delegate.linkeditFile;
  const auto dyldInfo = delegate.dyldInfo;
  const bool canFixReg = dyldInfo != nullptr && dyldInfo->lazy_bind_size != 0;
  const auto bindInfoStart =
      canFixReg ? (const uint8_t *)(linkeditFile + dyldInfo->lazy_bind_off)
                : nullptr;
  const auto bindInfoEnd =
      canFixReg ? bindInfoStart + dyldInfo->lazy_bind_size : nullptr;

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
        auto bindRecord = Macho::BindInfoReader<P>(bindInfoStart + *bindInfoOff,
                                                   bindInfoEnd)();

        // Point the pointer to the stub helper
        PtrT pAddr = mCtx.segments[bindRecord.segIndex].command->vmaddr +
                     (PtrT)bindRecord.segOffset;
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
                symbols.insert(info.symbols.begin(), info.symbols.end());
              } else if (pointerCache.ptr.normal.contains(pAddr)) {
                const auto &info = pointerCache.ptr.normal.at(pAddr);
                symbols.insert(info.symbols.begin(), info.symbols.end());
              }
            }
          }

          if (sFormat == AStubFormat::AuthStubNormal) {
            if (const auto pAddr = *arm64Utils.getAuthStubLdrAddr(sAddr);
                mCtx.containsAddr(pAddr) &&
                pointerCache.ptr.auth.contains(pAddr)) {
              const auto &info = pointerCache.ptr.auth.at(pAddr);
              symbols.insert(info.symbols.begin(), info.symbols.end());
            }
          }

          // Though its target function
          const auto sTargetFunc = arm64Utils.resolveStubChain(sAddr);
          if (const auto info = symbolizer.symbolizeAddr(sTargetFunc); info) {
            symbols.insert(info->symbols.begin(), info->symbols.end());
          }

          if (!symbols.empty()) {
            addStubInfo(sAddr, {symbols});
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
          *(PtrT *)mCtx.convertAddrP(pAddr) = 0;
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
          *(PtrT *)mCtx.convertAddrP(pAddr) = 0;
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
          *(PtrT *)mCtx.convertAddrP(pAddr) = 0;
          fixed = true;
        } else if (pointerCache.unnamed.auth.contains(pAddr)) {
          // Name the pointer and mark as used, zero out pointer
          pointerCache.namePointer(SPointerType::auth, pAddr, sSymbols);
          pointerCache.used.auth.insert(pAddr);
          *(PtrT *)mCtx.convertAddrP(pAddr) = 0;
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
        brokenStubs.emplace_back(AStubFormat::AuthStubOptimized, sInfo.target,
                                 sAddr, sInfo.loc, sInfo.size);
        fixed = true;
      }
      break;
    }

    case AStubFormat::Resolver: {
      if (mCtx.containsAddr(sInfo.target)) {
        fixed = true;
      }
      break;
    }

    default:
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
                *(PtrT *)mCtx.convertAddrP(ptr) = 0;
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
        *(PtrT *)mCtx.convertAddrP(pAddr) = 0;
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
      *(PtrT *)mCtx.convertAddrP(pAddr) = 0;
      break;
    }

    case AStubFormat::Resolver: {
      SPDLOG_LOGGER_ERROR(logger, "Unable to fix auth stub resolver at {:#x}",
                          sAddr);
      break;
    }

    default:
      break;
    }
  }
}

template <class A> void Arm64Fixer<A>::fixCallsites() {
  activity.update(std::nullopt, "Fixing Callsites");

  const auto textSect = mCtx.getSection("__TEXT", "__text").second;
  if (textSect == nullptr) {
    SPDLOG_LOGGER_WARN(logger, "Unable to find text section");
    return;
  }

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
    const auto names = symbolizer.symbolizeAddr(brTargetFunc);
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

      SPDLOG_LOGGER_WARN(
          logger, "Unable to symbolize branch at {:#x} with target {:#x}",
          iAddr, brTarget);
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
#pragma endregion Arm64Fixer

#pragma region ArmFixer
ArmFixer::ArmFixer(StubFixer<A> &delegate)
    : delegate(delegate), mCtx(delegate.mCtx), activity(delegate.activity),
      logger(delegate.logger), disasm(delegate.disasm),
      symbolizer(delegate.symbolizer), pointerCache(delegate.pointerCache),
      armUtils(*delegate.armUtils) {}

void ArmFixer::fix() {
  fixStubHelpers();
  scanStubs();
  fixPass1();
  fixPass2();
  fixCallsites();
}

void ArmFixer::fixStubHelpers() {
  static const PtrT REG_HELPER_SIZE = 0xC;

  const auto helperSect = mCtx.getSection("__TEXT", "__stub_helper").second;
  if (!helperSect) {
    return;
  }

  const auto linkeditFile = delegate.linkeditFile;
  const auto dyldInfo = delegate.dyldInfo;
  const bool canFixReg = dyldInfo != nullptr && dyldInfo->lazy_bind_size != 0;
  const auto bindInfoStart =
      canFixReg ? (const uint8_t *)(linkeditFile + dyldInfo->lazy_bind_off)
                : nullptr;
  const auto bindInfoEnd =
      canFixReg ? bindInfoStart + dyldInfo->lazy_bind_size : nullptr;

  const PtrT helperEnd = helperSect->addr + helperSect->size;
  PtrT helperAddr = helperSect->addr;
  if (auto info = armUtils.isStubBinder(helperAddr); info) {
    helperAddr += info->size;

    // may need to add private pointer to cache
    if (pointerCache.unnamed.normal.contains(info->privatePtr)) {
      pointerCache.namePointer(SPointerType::normal, info->privatePtr,
                               {{"__dyld_private", SELF_LIBRARY_ORDINAL}});
    }
  }

  while (helperAddr < helperEnd) {
    activity.update();

    if (const auto bindInfoOff = armUtils.getStubHelperData(helperAddr);
        bindInfoOff) {
      if (canFixReg) {
        auto bindRecord = Macho::BindInfoReader<P>(bindInfoStart + *bindInfoOff,
                                                   bindInfoEnd)();

        //  Point the pointer to the stub helper
        PtrT pAddr = mCtx.segments[bindRecord.segIndex].command->vmaddr +
                     (PtrT)bindRecord.segOffset;
        *(PtrT *)mCtx.convertAddrP(pAddr) = helperAddr;
      } else {
        SPDLOG_LOGGER_WARN(
            logger, "Unable to fix stub helper at {:#x} without bind info.",
            helperAddr);
      }
      helperAddr += REG_HELPER_SIZE;
      continue;
    }

    // It may be a resolver
    if (const auto resolverInfo = armUtils.getResolverData(helperAddr);
        resolverInfo) {
      // Shouldn't need fixing but check just in case
      if (!mCtx.containsAddr(resolverInfo->targetFunc)) {
        SPDLOG_LOGGER_WARN(logger,
                           "Stub resolver at 0x{:x} points outside of image.",
                           helperAddr);
      }

      // Point the pointer to the helper
      *(PtrT *)mCtx.convertAddrP(resolverInfo->targetPtr) = helperAddr;

      helperAddr += resolverInfo->size;
      continue;
    }

    SPDLOG_LOGGER_ERROR(logger, "Unknown stub helper format at 0x{:x}",
                        helperAddr);
    helperAddr += REG_HELPER_SIZE; // Try to recover, will probably fail
  }
}

void ArmFixer::scanStubs() {
  activity.update(std::nullopt, "Scanning Stubs");

  mCtx.enumerateSections(
      [](auto seg, auto sect) {
        return (sect->flags & SECTION_TYPE) == S_SYMBOL_STUBS;
      },
      [this](auto seg, auto sect) {
        const auto sSize = sect->reserved2;
        auto sLoc = mCtx.convertAddrP(sect->addr);
        uint32_t indirectI = sect->reserved1;
        for (PtrT sAddr = sect->addr; sAddr < sect->addr + sect->size;
             sAddr += sSize, sLoc += sSize, indirectI++) {
          activity.update();

          const auto sDataPair = armUtils.resolveStub(sAddr);
          if (!sDataPair) {
            SPDLOG_LOGGER_ERROR(logger, "Unknown Arm stub at {:#x}", sAddr);
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
          if (sFormat == AStubFormat::normalV4) {
            if (const auto pAddr = *armUtils.getNormalV4LdrAddr(sAddr);
                mCtx.containsAddr(pAddr)) {
              if (pointerCache.ptr.lazy.contains(pAddr)) {
                const auto &info = pointerCache.ptr.lazy.at(pAddr);
                symbols.insert(info.symbols.begin(), info.symbols.end());
              } else if (pointerCache.ptr.normal.contains(pAddr)) {
                const auto &info = pointerCache.ptr.normal.at(pAddr);
                symbols.insert(info.symbols.begin(), info.symbols.end());
              }
            }
          }

          // Through its target function
          const auto sTargetFunc = armUtils.resolveStubChain(sAddr);
          if (const auto info = symbolizeAddr(sTargetFunc); info) {
            symbols.insert(info->symbols.begin(), info->symbols.end());
          }

          if (!symbols.empty()) {
            addStubInfo(sAddr, {symbols});
            brokenStubs.emplace_back(sFormat, sTargetFunc, sAddr, sLoc);
          } else {
            SPDLOG_LOGGER_WARN(logger, "Unable to symbolize stub at {:#x}",
                               sAddr);
          }
        }
        return true;
      });
}

/// @brief Fix stubs, first pass
///
/// The first pass tries to remove non broken stubs, or trivially fixable stubs.
void ArmFixer::fixPass1() {
  activity.update(std::nullopt, "Fixing Stubs: Pass 1");

  for (auto it = brokenStubs.begin(); it != brokenStubs.end();) {
    activity.update();

    const auto &sInfo = *it;
    const auto sAddr = sInfo.addr;
    const auto &sSymbols = stubMap.at(sInfo.addr);

    bool fixed = false;
    switch (sInfo.format) {
    case AStubFormat::normalV4: {
      if (const auto pAddr = *armUtils.getNormalV4LdrAddr(sAddr);
          mCtx.containsAddr(pAddr)) {
        if (pointerCache.isAvailable(SPointerType::lazy, pAddr)) {
          // Mark the pointer as used
          pointerCache.used.lazy.insert(pAddr);
          fixed = true;
        } else if (pointerCache.isAvailable(SPointerType::normal, pAddr)) {
          // Mark the pointer as used
          pointerCache.used.normal.insert(pAddr);
          *(PtrT *)mCtx.convertAddrP(pAddr) = 0;
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
          *(PtrT *)mCtx.convertAddrP(pAddr) = 0;
          fixed = true;
        } else {
          SPDLOG_LOGGER_WARN(
              logger, "Unable to find the pointer a normal stub at {:#x} uses.",
              sAddr);
        }
      }
      break;
    }

    default:
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
void ArmFixer::fixPass2() {
  activity.update(std::nullopt, "Fixing Stubs: Pass 2");
  for (auto &sInfo : brokenStubs) {
    activity.update();

    const auto sAddr = sInfo.addr;
    const auto sLoc = sInfo.loc;
    const auto &sSymbols = stubMap.at(sInfo.addr);

    switch (sInfo.format) {
    case AStubFormat::normalV4:
    case AStubFormat::optimizedV5: {
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
                *(PtrT *)mCtx.convertAddrP(ptr) = 0;
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
        *(PtrT *)mCtx.convertAddrP(pAddr) = 0;
      }

      if (!pAddr) {
        SPDLOG_LOGGER_WARN(logger, "Unable to fix optimized stub at {:#x}",
                           sAddr);
        break;
      }

      // Fix the stub
      armUtils.writeNormalV4Stub(sLoc, sAddr, pAddr);
      break;
    }

    default:
      break;
    }
  }
}

void ArmFixer::fixCallsites() {
  activity.update(std::nullopt, "Fixing Callsites");

  const auto textSect = mCtx.getSection("__TEXT", "__text").second;
  if (textSect == nullptr) {
    SPDLOG_LOGGER_WARN(logger, "Unable to find text section");
    return;
  }

  auto textAddr = textSect->addr;
  auto textData = mCtx.convertAddrP(textAddr);

  for (const auto &inst : disasm.instructions) {
    // only look for arm immediate branch instructions
    const bool isBL = inst.id == ARM_INS_BL;
    const bool isBLX = inst.id == ARM_INS_BLX;
    const bool isB = inst.id == ARM_INS_B;
    if (isBL || isBLX || isB) {
      if (inst.size != 4) {
        continue;
      }

      // get the branch target
      if (inst.opStr.find(",") != std::string::npos || inst.opStr[0] != '#') {
        // only want direct branches with imm, no registers
        continue;
      }

      uint32_t brTarget;
      try {
        brTarget = std::stoi(inst.opStr.substr(1), nullptr, 16);
      } catch (std::invalid_argument const &) {
        continue;
      }

      if (mCtx.containsAddr(brTarget)) {
        continue;
      }

      auto iAddr = (uint32_t)inst.address;
      auto iLoc = (uint32_t *)(textData + (iAddr - textAddr));
      auto iLocAligned = (uint32_t *)(textData + (iAddr - 2 - textAddr));

      auto fTarget = delegate.resolveStubChain(brTarget);
      auto names = symbolizeAddr(fTarget);
      if (!names) {
        // Too many edge cases for meaningful diagnostics
        // SPDLOG_LOGGER_DEBUG(
        //     logger, "Unable to symbolize branch at {:#x} with target {:#x}",
        //     iAddr, brTarget);
        continue;
      }

      // Try to find a stub
      bool fixed = false;
      for (const auto &name : names->symbols) {
        if (reverseStubMap.contains(name.name)) {
          const auto stubAddr = *reverseStubMap[name.name].begin();

          uint32_t newInstruction;
          int32_t displacement = stubAddr - (iAddr + 4);
          if (isBL || isBLX) {
            newInstruction = 0xC000F000;
            if (iAddr & 0x2) {
              displacement += 2;
            }
          } else {
            newInstruction = 0x9000F000;
          }

          uint32_t s = (uint32_t)(displacement >> 24) & 0x1;
          uint32_t i1 = (uint32_t)(displacement >> 23) & 0x1;
          uint32_t i2 = (uint32_t)(displacement >> 22) & 0x1;
          uint32_t imm10 = (uint32_t)(displacement >> 12) & 0x3FF;
          uint32_t imm11 = (uint32_t)(displacement >> 1) & 0x7FF;
          uint32_t j1 = (i1 == s);
          uint32_t j2 = (i2 == s);
          uint32_t nextDisp = (j1 << 13) | (j2 << 11) | imm11;
          uint32_t firstDisp = (s << 10) | imm10;
          newInstruction |= (nextDisp << 16) | firstDisp;

          *iLoc = newInstruction;
          fixed = true;
        }
      }
      if (fixed) {
        activity.update();
        continue;
      } else {
        SPDLOG_LOGGER_DEBUG(
            logger,
            "Unable to find stub for branch at {:#x}, with target "
            "{:#x}, with symbols {}.",
            iAddr, brTarget, fmt::join(names->symbols, ", "));
      }
    }
  }
}

void ArmFixer::addStubInfo(PtrT addr, Provider::SymbolicInfo info) {
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

const Provider::SymbolicInfo *ArmFixer::symbolizeAddr(PtrT addr) const {
  if (auto res = symbolizer.symbolizeAddr(addr); res) {
    return res;
  } else {
    if (addr & 1) {
      return symbolizer.symbolizeAddr(addr & -4);
    } else {
      return symbolizer.symbolizeAddr(addr | 1);
    }
  }
}
#pragma endregion ArmFixer

#pragma region StubFixer
template <class A>
StubFixer<A>::StubFixer(Utils::ExtractionContext<A> &eCtx)
    : eCtx(eCtx), dCtx(*eCtx.dCtx), mCtx(*eCtx.mCtx), activity(*eCtx.activity),
      logger(eCtx.logger), accelerator(*eCtx.accelerator),
      pointerTracker(eCtx.pointerTracker), disasm(eCtx.disassembler),
      symbolizer(eCtx.symbolizer), linkeditTracker(eCtx.linkeditTracker),
      linkeditFile(
          mCtx.convertAddr(mCtx.getSegment("__LINKEDIT")->command->vmaddr)
              .second),
      dyldInfo(mCtx.getLoadCommand<false, Macho::Loader::dyld_info_command>()),
      symtab(mCtx.getLoadCommand<false, Macho::Loader::symtab_command>()),
      dysymtab(mCtx.getLoadCommand<false, Macho::Loader::dysymtab_command>()),
      pointerCache(*this) {
  if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                std::is_same_v<A, Utils::Arch::arm64_32>) {
    arm64Utils.emplace(eCtx);
    arm64Fixer.emplace(*this);
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    armUtils.emplace(eCtx);
    armFixer.emplace(*this);
  }
}

template <class A> void StubFixer<A>::fix() {
  // Check if we have necessary data
  if (!linkeditFile) {
    SPDLOG_LOGGER_WARN(logger,
                       "Unable to fix stubs without __LINKEDIT segment");
    return;
  } else if (!symtab) {
    SPDLOG_LOGGER_WARN(logger, "Unable to fix stubs without symtab");
    return;
  } else if (!dysymtab) {
    SPDLOG_LOGGER_WARN(logger, "Unable to fix stubs without dysymtab");
    return;
  }

  // fill out code regions
  if (accelerator.codeRegions.empty()) {
    for (auto imageInfo : dCtx.images) {
      auto ctx = dCtx.createMachoCtx<true, P>(imageInfo);
      ctx.enumerateSections(
          [](auto seg, auto sect) {
            return sect->flags & S_ATTR_SOME_INSTRUCTIONS;
          },
          [this](auto seg, auto sect) {
            accelerator.codeRegions.insert(Utils::Accelerator<P>::CodeRegion(
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
}

template <class A>
std::pair<const Macho::Loader::nlist<typename A::P> *, const char *>
StubFixer<A>::lookupIndirectEntry(const uint32_t index) const {
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

template <class A>
StubFixer<A>::PtrT StubFixer<A>::resolveStubChain(const PtrT addr) {
  if constexpr (std::is_same_v<A, Utils::Arch::arm64> ||
                std::is_same_v<A, Utils::Arch::arm64_32>) {
    return arm64Utils->resolveStubChain(addr);
  } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
    return armUtils->resolveStubChain(addr);
  }

  throw std::logic_error("Arch not supported");
}

template <class A> void StubFixer<A>::checkIndirectEntries() {
  activity.update(std::nullopt, "Checking indirect entires");

  if (!dysymtab->indirectsymoff) {
    SPDLOG_LOGGER_WARN(logger, "Image does not contain indirect entires");
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
      linkeditTracker->findTag(LinkeditTracker<P>::Tag::indirectSymtab);
  if (!entriesMetadata) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to find indirect entries data");
    return;
  }
  uint32_t sizeOfEntries = (uint32_t)newEntries.size() * sizeof(uint32_t);
  if (!linkeditTracker->resizeData(entriesMetadata,
                                   Utils::align(sizeOfEntries, 8))) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to resize indirect entries data");
    return;
  }

  // overwrite data and update command
  memcpy(entriesMetadata->data, newEntries.data(), sizeOfEntries);
  dysymtab->nindirectsyms = (uint32_t)newEntries.size();
}

template <class A> void StubFixer<A>::fixIndirectEntries() {
  /**
   * Some files have indirect symbols that are redacted,
   * These are then pointed to the "redacted" symbol entry.
   * But disassemblers like Ghidra use these to symbolize
   * stubs and other pointers.
   */

  if (!eCtx.hasRedactedIndirect) {
    return;
  }

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

        Provider::SymbolicInfo *pInfo =
            pointerCache.getPointerInfo(pType, pAddr);
        if (!pInfo) {
          if (!mCtx.containsAddr(pointerTracker.slideP(pAddr))) {
            SPDLOG_LOGGER_DEBUG(
                logger,
                "Unable to symbolize pointer at {:#x}, with target {:#x}, "
                "for redacted indirect symbol entry.",
                pAddr, resolveStubChain(pointerTracker.slideP(pAddr)));
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
        } else if constexpr (std::is_same_v<A, Utils::Arch::arm>) {
          if (armFixer->stubMap.contains(sAddr)) {
            sInfo = &armFixer->stubMap.at(sAddr);
          }
        } else {
          throw std::logic_error("Arch not implemented");
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
      linkeditTracker->findTag(LinkeditTracker<P>::Tag::symbolEntries);
  if (!entriesMetadata) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to find symbol entries data");
    return;
  }
  uint8_t *newEntriesLoc = entriesMetadata->end();
  const uint32_t sizeOfNewEntries =
      (uint32_t)newEntries.size() * sizeof(Macho::Loader::nlist<P>);
  if (!linkeditTracker->resizeData(
          entriesMetadata,
          Utils::align(entriesMetadata->dataSize + sizeOfNewEntries, 8))) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to extend the symbol entries region");
    return;
  }

  memcpy(newEntriesLoc, newEntries.data(), sizeOfNewEntries);

  // Extend the strings region and add the data
  auto stringsMetadata =
      linkeditTracker->findTag(LinkeditTracker<P>::Tag::stringPool);
  if (!stringsMetadata) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to find the strings data");
    return;
  }
  uint8_t *newStringsLoc = stringsMetadata->end();
  const uint32_t sizeOfNewStrings = stringsIndex - symtab->strsize;
  if (!linkeditTracker->resizeData(
          stringsMetadata,
          Utils::align(stringsMetadata->dataSize + sizeOfNewStrings, 8))) {
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

template <class A> bool StubFixer<A>::isInCodeRegions(PtrT addr) {
  if (accelerator.codeRegions.empty()) {
    return false;
  }

  auto upper = accelerator.codeRegions.upper_bound(
      Utils::Accelerator<P>::CodeRegion(addr, addr));
  if (upper == accelerator.codeRegions.begin()) {
    return false;
  }

  const auto &potentialRange = *--upper;
  return addr >= potentialRange.start && addr < potentialRange.end;
}
#pragma endregion StubFixer

template <class A> void Converter::fixStubs(Utils::ExtractionContext<A> &eCtx) {
  eCtx.disassembler.disasm();

  eCtx.activity->update("Stub Fixer", "Starting Up");

  if constexpr (std::is_same_v<A, Utils::Arch::arm> ||
                std::is_same_v<A, Utils::Arch::arm64> ||
                std::is_same_v<A, Utils::Arch::arm64_32>) {
    StubFixer<A>(eCtx).fix();
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