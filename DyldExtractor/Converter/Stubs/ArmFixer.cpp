#include "ArmFixer.h"

#include "Fixer.h"

using namespace DyldExtractor;
using namespace Converter;
using namespace Stubs;

ArmFixer::ArmFixer(Fixer<A> &delegate)
    : delegate(delegate), mCtx(delegate.mCtx), activity(delegate.activity),
      logger(delegate.logger), bindInfo(delegate.bindInfo),
      disasm(delegate.disasm), ptrTracker(delegate.ptrTracker),
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

  const auto helperSect = mCtx.getSection(SEG_TEXT, "__stub_helper").second;
  if (!helperSect) {
    return;
  }

  const bool canFixReg = bindInfo.hasLazyBinds();

  const PtrT helperEnd = helperSect->addr + helperSect->size;
  PtrT helperAddr = helperSect->addr;
  if (auto info = armUtils.isStubBinder(helperAddr); info) {
    helperAddr += info->size;

    // may need to add private pointer to cache
    if (pointerCache.unnamed.normal.contains(info->privatePtr)) {
      pointerCache.namePointer(SPointerType::normal, info->privatePtr,
                               {{"__dyld_private", SELF_LIBRARY_ORDINAL},
                                Provider::SymbolicInfo::Encoding::None});
    }
  }

  while (helperAddr < helperEnd) {
    activity.update();

    if (const auto bindInfoOff = armUtils.getStubHelperData(helperAddr);
        bindInfoOff) {
      if (canFixReg) {
        const auto bindRecord = bindInfo.getLazyBind(*bindInfoOff);
        if (!bindRecord) {
          SPDLOG_LOGGER_ERROR(
              logger, "Unable to read bind info for stub helper at {:#x}.",
              helperAddr);
        }

        //  Point the pointer to the stub helper
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
    if (const auto resolverInfo = armUtils.getResolverData(helperAddr);
        resolverInfo) {
      // Shouldn't need fixing but check just in case
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
                symbols.insert(info->symbols.begin(), info->symbols.end());
              } else if (pointerCache.ptr.normal.contains(pAddr)) {
                const auto &info = pointerCache.ptr.normal.at(pAddr);
                symbols.insert(info->symbols.begin(), info->symbols.end());
              }
            }
          }

          // Through its target function
          const auto sTargetFunc = armUtils.resolveStubChain(sAddr);
          if (const auto info = symbolizer.symbolizeAddr(sTargetFunc & -4);
              info) {
            symbols.insert(info->symbols.begin(), info->symbols.end());
          }

          if (!symbols.empty()) {
            addStubInfo(sAddr,
                        {symbols, Provider::SymbolicInfo::Encoding::None});
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
                ptrTracker.add(ptr, 0);
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
  const auto textSect = mCtx.getSection(SEG_TEXT, SECT_TEXT).second;

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
      auto names = symbolizer.symbolizeAddr(fTarget & -4);
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
            "{:#x}, with symbols {}",
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
