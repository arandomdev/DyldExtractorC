#include "SymbolPointerCache.h"

#include "Fixer.h"

using namespace DyldExtractor;
using namespace Converter::Stubs;

template <class A>
SymbolPointerCache<A>::SymbolPointerCache(Fixer<A> &delegate)
    : delegate(delegate), mCtx(delegate.mCtx), activity(delegate.activity),
      logger(delegate.logger), bindInfo(delegate.bindInfo) {}

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
          if (const auto pTarget = delegate.ptrTracker.slideP(pAddr); pTarget) {
            const auto pFunc = delegate.resolveStubChain(pTarget);
            if (const auto set = delegate.symbolizer.symbolizeAddr(pFunc & -4);
                set) {
              symbols.insert(set->symbols.begin(), set->symbols.end());
            }
          }

          if (!symbols.empty()) {
            addPointerInfo(
                pType, pAddr,
                Provider::SymbolicInfo(std::move(symbols),
                                       Provider::SymbolicInfo::Encoding::None));
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
                                        const Provider::SymbolicInfo &info) {
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
    assert(!"Unknown pointer type");
    return;
  }

  addPointerInfo(pType, addr, info);
}

template <class A>
const Provider::SymbolicInfo *
SymbolPointerCache<A>::getPointerInfo(PointerType pType, PtrT addr) const {
  switch (pType) {
  case PointerType::normal:
    if (ptr.normal.contains(addr)) {
      return ptr.normal.at(addr).get();
    } else {
      return nullptr;
    }

  case PointerType::lazy:
    if (ptr.lazy.contains(addr)) {
      return ptr.lazy.at(addr).get();
    } else {
      return nullptr;
    }

  case PointerType::auth:
    if (ptr.auth.contains(addr)) {
      return ptr.auth.at(addr).get();
    } else {
      return nullptr;
    }

  default:
    assert(!"Unknown pointer type");
    return nullptr;
  }
}

template <class A>
std::map<typename SymbolPointerCache<A>::PtrT, Provider::BindRecord>
SymbolPointerCache<A>::getBindRecords() {
  std::map<PtrT, Provider::BindRecord> bindRecords;
  for (const auto &record : bindInfo.getBinds()) {
    bindRecords[(PtrT)record.address] = record;
  }
  for (const auto &record : bindInfo.getLazyBinds()) {
    bindRecords[(PtrT)record.second.address] = record.second;
  }
  for (const auto &record : bindInfo.getWeakBinds()) {
    bindRecords[(PtrT)record.address] = record;
  }

  return bindRecords;
}

template <class A>
void SymbolPointerCache<A>::addPointerInfo(PointerType pType, PtrT pAddr,
                                           const Provider::SymbolicInfo &info) {
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
    assert(!"Unknown Pointer Type");
    break;
  }

  // Add to normal cache
  Provider::SymbolicInfo *newInfo;
  if (pointers->contains(pAddr)) {
    newInfo = pointers->at(pAddr).get();
    newInfo->symbols.insert(info.symbols.begin(), info.symbols.end());
  } else {
    newInfo =
        pointers->emplace(pAddr, std::make_shared<Provider::SymbolicInfo>(info))
            .first->second.get();
  }

  // add to reverse cache
  for (auto &sym : newInfo->symbols) {
    (*reversePtrs)[sym.name].insert(pAddr);
  }
}

template class SymbolPointerCache<Utils::Arch::arm>;
template class SymbolPointerCache<Utils::Arch::arm64>;
template class SymbolPointerCache<Utils::Arch::arm64_32>;
