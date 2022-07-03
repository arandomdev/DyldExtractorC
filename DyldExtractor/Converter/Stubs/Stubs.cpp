#include "../Stubs.h"

#include <functional>
#include <spdlog/spdlog.h>

#include "../LinkeditOptimizer.h"
#include "Arm64Utils.h"
#include <Macho/BindInfo.h>
#include <Provider/PointerTracker.h>
#include <Utils/Accelerator.h>

#pragma warning(push)
#pragma warning(disable : 4267)
#include <dyld/Trie.hpp>
#pragma warning(pop)

using namespace Converter;

template <class A> class StubFixer;

#pragma region SymbolPointerCache
template <class A> class SymbolPointerCache {
public:
  SymbolPointerCache(StubFixer<A> &delegate);

  enum class PointerType {
    normal, // Commonly in __got
    lazy,   // Commonly in __la_symbol_ptr
    auth    // Commonly in __auth_got
  };

  std::set<uint64_t> unnamedNormal;
  std::set<uint64_t> unnamedLazy;
  std::set<uint64_t> unnamedAuth;

  // TODO: Should contain ordinal info
  std::map<uint64_t, std::set<std::string>> normal;
  std::map<uint64_t, std::set<std::string>> lazy;
  std::map<uint64_t, std::set<std::string>> auth;

  std::map<std::string, std::set<uint64_t>> reverseNormal;
  std::map<std::string, std::set<uint64_t>> reverseLazy;
  std::map<std::string, std::set<uint64_t>> reverseAuth;

  std::set<uint64_t> usedNormal;
  std::set<uint64_t> usedLazy;
  std::set<uint64_t> usedAuth;

  void scanPointers();
  PointerType getPointerType(auto sect);

private:
  using ptrT = A::P::ptr_t;

  StubFixer<A> &delegate;
  Macho::Context<false, P> &mCtx;
  ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;

  std::map<uint64_t, Macho::BindRecord> readBindRecords();
  void addPointer(PointerType pType, uint64_t addr, std::string name);
};

template <class A>
SymbolPointerCache<A>::SymbolPointerCache(StubFixer<A> &delegate)
    : delegate(delegate), mCtx(delegate.mCtx), activity(delegate.activity) {}

template <class A> void SymbolPointerCache<A>::scanPointers() {
  const auto bindRecords = readBindRecords();

  mCtx.enumerateSections(
      [](auto seg, auto sect) {
        return (sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS ||
               (sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS
      },
      [&bindRecords](auto seg, auto sect) {
        auto pType = getPointerType(sect);

        const auto pSize = sizeof(ptrT);
        ptrT pAddr = sect->Addr;
        uint32_t indirectI = sect->reserved1;
        for (ptrT i = 0; i < sect->size / pSize;
             i++, pAddr += pSize, indirectI++) {
          activity.update();

          bool symbolized = false;

          // bind records
          if (bindRecords.contains(pAddr)) {
            addPointer(pType, pAddr, bindRecords.at(pAddr).symbolName);
            symbolized = true;
          }

          // indirect symbol entires
          if (const auto sym = delegate->lookupIndirectEntry(indirectI); sym) {
            addPointer(pType, pAddr, sym);
            symbolized = true;
          }

          // Though pointer's target function
          const auto ptrTargetFunc =
              *delegate->resolveStubChain(delegate.ptrTracker.slideP(pAddr));
          if (const auto set = symbolizer->symbolizeAddr(ptrTargetFunc); set) {
            for (const auto &sym : set->symbols) {
              addPointer(pType, pAddr, sym.name);
            }
            symbolized = true;
          }

          // Skip special cases like __csbitmaps in CoreFoundation
          if (mCtx.containsAddr(ptrTargetFunc)) {
            continue;
          }

          // Add to unnamed
          switch (pType) {
          case PointerType::normal:
            unnamedNormal.insert(pAddr);
            break;

          case PointerType::lazy:
            unnamedLazy.insert(pAddr);
            break;

          case PointerType::auth:
            unnamedAuth.insert(pAddr);
            break;

          default:
            break;
          }
        }
      });
}

template <class A>
SymbolPointerCache<A>::PointerType getPointerType(auto sect) {
  const auto sectType = sect->flags & SECTION_TYPE;
  const bool isAuth = strstr(sect->sectname, "auth");

  if (sectType == S_LAZY_SYMBOL_POINTERS) {
    if (isAuth) {
      SPDLOG_LOGGER_ERROR(logger, "Unknown section type combination");
      return PointerType::normal;
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
    return PointerType::normal;
  }
}

template <class A>
std::map<uint64_t, Macho::BindRecord> SymbolPointerCache<A>::readBindRecords() {
  std::map<uint64_t, Macho::BindRecord> bindRecords;

  auto linkeditFile = delegate.linkeditFile;
  auto dyldInfo = delegate.dyldInfo;

  if (dyldInfo) {
    try {
      std::vector<Macho::BindRecord> records;
      if (dyldInfo->weak_bind_size) {
        const auto start = linkeditFile + dyldInfo->weak_bind_off;
        auto reader =
            Macho::BindInfoReader<P>(start, start + dyldInfo->weak_bind_size);
        while (reader) {
          records.push_back(reader());
        }
      }

      if (dyldInfo->lazy_bind_size) {
        const auto start = linkeditFile + dyldInfo->lazy_bind_off;
        auto reader =
            Macho::BindInfoReader<P>(start, start + dyldInfo->lazy_bind_size);
        while (reader) {
          records.push_back(reader());
        }
      }

      for (auto &r : records) {
        const auto bindAddr =
            mCtx.segments[r.segIndex].command->vmaddr + r.segOffset;
        bindRecords[bindAddr] = r;
      }
    } catch (const std::invalid_argument &e) {
      SPDLOG_LOGGER_ERROR(logger, "Error while parsing bind info, ", e.what());
    }
  }

  return bindRecords;
}

template <class A>
void SymbolPointerCache<A>::addPointer(PointerType pType, uint64_t addr,
                                       std::string name) {
  switch (pType) {
  case PointerType::normal:
    normal[addr].insert(name);
    reverseNormal[name].insert(addr);
    break;

  case PointerType::lazy:
    lazy[addr].insert(name);
    reverseLazy[name].insert(addr);
    break;

  case PointerType::auth:
    auth[addr].insert(name);
    reverseAuth[name].insert(addr);
    break;

  default:
    break;
  }
}
#pragma endregion SymbolPointerCache

template <class A> class StubFixer {
  using P = typename A::P;
  using ptr_t = typename P::ptr_t;

public:
  StubFixer(Utils::ExtractionContext<P> &eCtx);
  void run();

private:
  friend class SymbolPointerCache<A>;

  Utils::ExtractionContext<P> &eCtx;
  Dyld::Context &dCtx;
  Macho::Context<false, P> &mCtx;
  std::shared_ptr<spdlog::logger> logger;
  ActivityLogger &activity;
  Provider::PointerTracker<P> ptrTracker;
  LinkeditTracker<P> *linkeditTracker;

  Symbolizer<P> *symbolizer;
  std::optional<Arm64Utils> arm64Utils;

  enum class SymbolPointerType {
    normal, // Commonly in __got
    lazy,   // Commonly in __la_symbol_ptr
    auth    // Commonly in __auth_got
  };
  struct {
    std::set<uint64_t> normalUnnamed;
    std::set<uint64_t> lazyUnnamed;
    std::set<uint64_t> authUnnamed;

    std::multimap<uint64_t, std::string> normal;
    std::multimap<uint64_t, std::string> lazy;
    std::multimap<uint64_t, std::string> auth;
    std::multimap<std::string, uint64_t> normalReverse;
    std::multimap<std::string, uint64_t> lazyReverse;
    std::multimap<std::string, uint64_t> authReverse;

    std::set<uint64_t> normalUsed;
    std::set<uint64_t> lazyUsed;
    std::set<uint64_t> authUsed;
  } symPtrs;

  // A map of stub names and their address
  std::multimap<std::string, uint64_t> stubMap;
  std::multimap<uint64_t, std::string> reverseStubMap;

  uint8_t *linkeditFile;
  Macho::Loader::dyld_info_command *dyldInfo;
  Macho::Loader::symtab_command *symtab;
  Macho::Loader::dysymtab_command *dysymtab;

  std::optional<uint64_t> resolveStubChain(const uint64_t addr);
  char *lookupIndirectEntry(const uint64_t index);

  void preflightSections();
  void scanSymbolPointers();

  struct Arm64DeferredStubFixInfo {
    Arm64Utils::StubFormat format;
    uint64_t addr;
    uint8_t *loc;
    std::string name;
    uint32_t indirectIndex;
  };
  void arm64FixStubHelpers();
  std::vector<Arm64DeferredStubFixInfo> arm64ScanStubs();
  void arm64FixStubs(std::vector<Arm64DeferredStubFixInfo> brokenStubs);
  void arm64FixCallsites();
};

template <class A>
StubFixer<A>::StubFixer(Utils::ExtractionContext<P> &eCtx)
    : eCtx(eCtx), dCtx(eCtx.dCtx), mCtx(eCtx.mCtx), logger(eCtx.logger),
      activity(eCtx.activity), linkeditTracker(eCtx.linkeditTracker),
      ptrTracker(eCtx.pointerTracker), symbolizer(new Symbolizer<A::P>(eCtx)) {
  if constexpr (std::is_same_v<A, Utils::Arch::arm64>) {
    arm64Utils.emplace(eCtx);
  }
}

template <class A> void StubFixer<A>::run() {
  symbolizer->enumerate();
  eCtx.symbolizer = symbolizer;

  linkeditFile =
      mCtx.convertAddr(mCtx.getSegment("__LINKEDIT")->command->vmaddr).second;
  dyldInfo = mCtx.getLoadCommand<false, Macho::Loader::dyld_info_command>();
  symtab = mCtx.getLoadCommand<false, Macho::Loader::symtab_command>();
  dysymtab = mCtx.getLoadCommand<false, Macho::Loader::dysymtab_command>();

  preflightSections();
  scanSymbolPointers();

  if constexpr (std::is_same_v<A, Utils::Arch::arm64>) {
    arm64FixStubHelpers();
    auto brokenStubs = arm64ScanStubs();
    arm64FixStubs(brokenStubs);
    arm64FixCallsites();
  }
}

template <class A>
std::optional<uint64_t> StubFixer<A>::resolveStubChain(const uint64_t addr) {
  if constexpr (std::is_same_v<A, Utils::Arch::arm64>) {
    return arm64Utils->resolveStubChain(addr);
  }

  return std::nullopt;
}

template <class A>
char *StubFixer<A>::lookupIndirectEntry(const uint64_t index) {
  const auto indirectEntry =
      *((uint32_t *)(linkeditFile + dysymtab->indirectsymoff) + index);
  if (isRedactedIndirect(indirectEntry)) {
    return nullptr;
  }

  // Indirect entry is an index into the symbol entries
  const auto symbolEntry =
      (Macho::Loader::nlist<P> *)(linkeditFile + symtab->symoff) +
      indirectEntry;
  return (char *)(linkeditFile + symtab->stroff + symbolEntry->n_un.n_strx);
}

template <class A> void StubFixer<A>::preflightSections() {
  mCtx.enumerateSections(
      [](auto seg, auto sect) {
        return (memcmp(sect->sectname, "__got", 6) == 0 ||
                memcmp(sect->sectname, "__auth_got", 11) == 0) &&
               ((sect->flags & SECTION_TYPE) == 0);
      },
      [](auto seg, auto sect) {
        // Starting around iOS 16, S_NON_LAZY_SYMBOL_POINTERS is no longer
        // set, only set it reserved1 is not zeroed, or the edge case where
        // there isn't stubs
        if (mCtx.getSection("__TEXT", "__stubs") == nullptr ||
            sect->reserved1 != 0) {
          sect->flags |= S_NON_LAZY_SYMBOL_POINTERS;
        } else {
          // TODO: Maybe add the entries?
          SPDLOG_LOGGER_WARN(logger,
                             "Found symbol pointer section without it's "
                             "section type set flag and it's indirect symbol "
                             "index offset zeroed. Results might be worse.");
        }
        return true;
      });
}

template <class A> void StubFixer<A>::scanSymbolPointers() {
  activity.update(std::nullopt, "Scanning Symbol Pointers");
  const auto bindRecords = readBindRecords();

  for (const auto &seg : mCtx.segments) {
    for (const auto &sect : seg.sections) {
      if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS ||
          (sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {
        auto sectType = _getSectPtrType(sect);
        auto addToCache = [this, sectType](const std::string sym,
                                           const uint64_t addr) {
          switch (sectType) {
          case SymbolPointerType::normal:
            symPtrs.normal.emplace(addr, sym);
            symPtrs.normalReverse.emplace(sym, addr);
            break;
          case SymbolPointerType::lazy:
            symPtrs.lazy.emplace(addr, sym);
            symPtrs.lazyReverse.emplace(sym, addr);
            break;
          case SymbolPointerType::auth:
            symPtrs.auth.emplace(addr, sym);
            symPtrs.authReverse.emplace(sym, addr);
            break;
          default:
            break;
          }
        };

        ptr_t pAddr = sect->addr;
        for (ptr_t i = 0; i < sect->size / sizeof(ptr_t);
             i++, pAddr += sizeof(ptr_t)) {
          activity.update();

          // Try bind records
          if (bindRecords.contains(pAddr)) {
            addToCache(bindRecords.at(pAddr).symbolName, pAddr);
            continue;
          }

          // Try with indirect symbol entries
          // reserved1 contains the starting index
          if (const auto sym = lookupIndirectEntry(sect->reserved1 + i); sym) {
            addToCache(sym, pAddr);
            continue;
          }

          // Though the pointer's target function
          const auto ptrTargetFunc =
              *resolveStubChain(ptrTracker.slideP(pAddr));
          if (const auto set = symbolizer->symbolizeAddr(ptrTargetFunc); set) {
            for (const auto &sym : set->symbols) {
              addToCache(sym.name, pAddr);
            }
            continue;
          }

          // Skip special cases like __csbitmaps in CoreFoundation
          if (mCtx.containsAddr(ptrTargetFunc)) {
            continue;
          }

          // Add to unnamed
          switch (sectType) {
          case SymbolPointerType::normal:
            symPtrs.normalUnnamed.insert(pAddr);
            break;
          case SymbolPointerType::lazy:
            symPtrs.lazyUnnamed.insert(pAddr);
            break;
          case SymbolPointerType::auth:
            symPtrs.authUnnamed.insert(pAddr);
            break;
          default:
            break;
          }
        }
      }
    }
  }
}

#pragma region arm64
template <class A> void StubFixer<A>::arm64FixStubHelpers() {
  static const uint64_t STUB_BINDER_SIZE = 0x18;
  static const uint64_t REG_HELPER_SIZE = 0xc;

  const auto helperSect = mCtx.getSection("__TEXT", "__stub_helper");
  if (!helperSect || !dyldInfo) {
    return;
  } else if (!dyldInfo->lazy_bind_size) {
    SPDLOG_LOGGER_WARN(logger,
                       "Unable to fix stub helpers without lazy bind info");
    return;
  }

  activity.update(std::nullopt, "Fixing Stub Helpers");

  const auto bindInfoStart =
      (const uint8_t *)(linkeditFile + dyldInfo->lazy_bind_off);
  const auto bindInfoEnd = bindInfoStart + dyldInfo->lazy_bind_size;

  // The stub helper sect starts with a binder, skip it
  uint64_t helperAddr = helperSect->addr + STUB_BINDER_SIZE;
  const uint64_t helperEnd = helperSect->addr + helperSect->size;
  while (helperAddr < helperEnd) {
    activity.update();

    if (const auto bindInfoOff = arm64Utils->getStubHelperData(helperAddr);
        bindInfoOff) {
      auto bindRecord =
          Macho::BindInfoReader<P>(bindInfoStart + *bindInfoOff, bindInfoEnd)();

      // Point the pointer to the stub helper
      uint64_t pAddr = mCtx.segments[bindRecord.segIndex].command->vmaddr +
                       bindRecord.segOffset;
      *(uint64_t *)mCtx.convertAddrP(pAddr) = helperAddr;

      helperAddr += REG_HELPER_SIZE;
      continue;
    }

    // It may be a resolver
    if (const auto resolverInfo = arm64Utils->getResolverData(helperAddr);
        resolverInfo) {
      // shouldn't need fixing but check just in case
      if (!mCtx.containsAddr(resolverInfo->first)) {
        SPDLOG_LOGGER_WARN(logger,
                           "Stub resolver at 0x{:x} points outside of image.",
                           helperAddr);
      }

      helperAddr += resolverInfo->second;
      continue;
    }

    SPDLOG_LOGGER_ERROR(logger, "Unknown stub helper format at 0x{:x}",
                        helperAddr);
    helperAddr += REG_HELPER_SIZE; // Try to recover, will probably fail
  }
}

template <class A>
std::vector<typename StubFixer<A>::Arm64DeferredStubFixInfo>
StubFixer<A>::arm64ScanStubs() {
  activity.update(std::nullopt, "Scanning Stubs");

  std::vector<Arm64DeferredStubFixInfo> brokenStubs;
  for (const auto &seg : mCtx.segments) {
    for (const auto &sect : seg.sections) {
      if ((sect->flags & SECTION_TYPE) == S_SYMBOL_STUBS) {
        auto stubLoc = mCtx.convertAddrP(sect->addr);
        auto stubAddr = sect->addr;
        auto indirectI = sect->reserved1;

        // reserved2 contains the size of the stub
        for (uint64_t i = 0; i < (sect->size / sect->reserved2); i++,
                      stubLoc += sect->reserved2, stubAddr += sect->reserved2,
                      indirectI++) {
          activity.update();

          const auto stubDataPair = arm64Utils->resolveStub(stubAddr);
          if (!stubDataPair) {
            SPDLOG_LOGGER_ERROR(logger, "Unknown arm64 stub format at 0x{:x}",
                                stubAddr);
            continue;
          }
          const auto [stubTarget, stubFormat] = *stubDataPair;

          // First symbolize the stub
          std::string name;

          // Though indirect entries
          if (const auto sym = lookupIndirectEntry(indirectI); sym) {
            name = sym;
          }

          // Though its pointer if not optimized
          if (name.empty() &&
              stubFormat == Arm64Utils::StubFormat::StubNormal) {
            if (const auto pAddr = *arm64Utils->getStubLdrAddr(stubAddr);
                mCtx.containsAddr(pAddr)) {
              if (const auto names = symPtrs.lazy.find(pAddr);
                  names != symPtrs.lazy.end()) {
                name = names->second;
              }
              // else if (const auto names =
              //                _symPtrs.normal.find(pAddr);
              //            names != _symPtrs.normal.end()) {
              //     name == names->second;
              // }
            }
          }

          if (name.empty() &&
              stubFormat == Arm64Utils::StubFormat::AuthStubNormal) {
            if (const auto pAddr = *arm64Utils->getAuthStubLdrAddr(stubAddr);
                mCtx.containsAddr(pAddr)) {
              if (const auto names = symPtrs.auth.find(pAddr);
                  names != symPtrs.auth.end()) {
                name = names->second;
              }
            }
          }

          // Though its target
          if (name.empty()) {
            const auto targetFunc = arm64Utils->resolveStubChain(stubAddr);
            const auto names = symbolizer->symbolizeAddr(targetFunc);
            if (names) {
              name = names->preferredSymbol().name;
            }
          }

          if (name.empty()) {
            SPDLOG_LOGGER_WARN(logger, "Unable to symbolize stub at 0x{:x}",
                               stubAddr);
            continue;
          }

          // Add to stub map
          stubMap.emplace(name, stubAddr);
          reverseStubMap.emplace(stubAddr, name);

          switch (stubFormat) {
          case Arm64Utils::StubFormat::StubNormal: {
            if (const auto pAddr = *arm64Utils->getStubLdrAddr(stubAddr);
                mCtx.containsAddr(pAddr)) {
              // mark its pointer as used
              if (symPtrs.lazy.contains(pAddr)) {
                symPtrs.lazyUsed.insert(pAddr);
              }
              // else if (_symPtrs.normal.contains(pAddr)) {
              //     _symPtrs.normalUsed.insert(pAddr);
              // }
              else if (symPtrs.lazyUnnamed.contains(pAddr)) {
                // convert unnamed to named, and mark used
                symPtrs.lazy.emplace(pAddr, name);
                symPtrs.lazyReverse.emplace(name, pAddr);
                symPtrs.lazyUnnamed.erase(pAddr);
                symPtrs.lazyUsed.insert(pAddr);
              }
              // else if (_symPtrs.normalUnnamed.contains(pAddr))
              else {
                SPDLOG_LOGGER_WARN(logger,
                                   "Unable to find the pointer a normal stub "
                                   "at {:#x} uses.",
                                   stubAddr);
              }
            } else {
              // Fix the stub later
              brokenStubs.push_back(
                  {stubFormat, stubAddr, stubLoc, name, indirectI});
            }
            break;
          }

          case Arm64Utils::StubFormat::AuthStubNormal: {
            if (const auto pAddr = *arm64Utils->getAuthStubLdrAddr(stubAddr);
                mCtx.containsAddr(pAddr)) {
              // mark its pointer as used
              if (symPtrs.auth.contains(pAddr)) {
                symPtrs.authUsed.insert(pAddr);

                // Zero out the pointer
                // TODO: Shouldn't this be in PointerTracker?
                *(uint64_t *)mCtx.convertAddrP(pAddr) = 0;
              } else if (symPtrs.authUnnamed.contains(pAddr)) {
                // convert unnamed to named, and mark used
                symPtrs.auth.emplace(pAddr, name);
                symPtrs.authReverse.emplace(name, pAddr);
                symPtrs.authUnnamed.erase(pAddr);
                symPtrs.authUsed.insert(pAddr);

                // Zero out the pointer
                // TODO: Shouldn't this be in PointerTracker?
                *(uint64_t *)mCtx.convertAddrP(pAddr) = 0;
              } else {
                SPDLOG_LOGGER_WARN(logger,
                                   "Unable to find the pointer a normal auth "
                                   "stub at {:#x} uses.",
                                   stubAddr);
              }
            } else {
              // Fix the stub later
              brokenStubs.push_back(
                  {stubFormat, stubAddr, stubLoc, name, indirectI});
            }
            break;
          }

          case Arm64Utils::StubFormat::StubOptimized: {
            if (sect->reserved2 == 0x10) {
              // In older caches, optimized auth stubs resemble
              // regular optimized stubs
              brokenStubs.push_back({Arm64Utils::StubFormat::AuthStubOptimized,
                                     stubAddr, stubLoc, name, indirectI});
            } else {
              brokenStubs.push_back(
                  {stubFormat, stubAddr, stubLoc, name, indirectI});
            }
            break;
          }

          case Arm64Utils::StubFormat::AuthStubOptimized: {
            brokenStubs.push_back(
                {stubFormat, stubAddr, stubLoc, name, indirectI});
            break;
          }

          case Arm64Utils::StubFormat::Resolver: {
            // Shouldn't need to fix but check just in case
            if (!mCtx.containsAddr(stubTarget)) {
              brokenStubs.push_back(
                  {stubFormat, stubAddr, stubLoc, name, indirectI});
            }
            break;
          }
          default:
            break;
          }
        }
      }
    }
  }

  return brokenStubs;
}

template <class A>
void StubFixer<A>::arm64FixStubs(
    std::vector<Arm64DeferredStubFixInfo> brokenStubs) {
  activity.update(std::nullopt, "Fixing Stubs");

  for (auto &info : brokenStubs) {
    activity.update();

    switch (info.format) {
    case Arm64Utils::StubFormat::StubNormal: {
      SPDLOG_LOGGER_ERROR(logger, "Unable to fix normal stub at {:#x}",
                          info.addr);
      break;
    }

    case Arm64Utils::StubFormat::StubOptimized: {
      // Try to find an unused named pointer
      bool fixed = false;
      auto [beginIt, endIt] = symPtrs.lazyReverse.equal_range(info.name);
      for (auto it = beginIt; it != endIt; it++) {
        const auto pAddr = it->second;
        if (symPtrs.lazyUsed.contains(pAddr)) {
          continue;
        }

        arm64Utils->writeNormalStub(info.loc, info.addr, pAddr);
        symPtrs.lazyUsed.insert(pAddr);
        fixed = true;
        break;
      }
      if (fixed) {
        break;
      }

      // Use an unnamed pointer
      if (symPtrs.lazyUnnamed.size()) {
        const auto pAddr = *symPtrs.lazyUnnamed.begin();
        arm64Utils->writeNormalStub(info.loc, info.addr, pAddr);

        symPtrs.lazy.emplace(pAddr, info.name);
        symPtrs.lazyReverse.emplace(info.name, pAddr);
        symPtrs.lazyUsed.insert(pAddr);
        symPtrs.lazyUnnamed.erase(pAddr);
        break;
      }

      SPDLOG_LOGGER_WARN(logger, "Unable to fix optimized stub at {:#x}",
                         info.addr);
      break;
    }

    case Arm64Utils::StubFormat::AuthStubNormal:
    case Arm64Utils::StubFormat::AuthStubOptimized: {
      // Try to find an unused named pointer
      bool fixed = false;
      auto [beginIt, endIt] = symPtrs.authReverse.equal_range(info.name);
      for (auto it = beginIt; it != endIt; it++) {
        const auto pAddr = it->second;
        if (symPtrs.authUsed.contains(pAddr)) {
          continue;
        }

        arm64Utils->writeNormalAuthStub(info.loc, info.addr, pAddr);
        symPtrs.authUsed.insert(pAddr);

        // Zero out ptr
        *(uint64_t *)mCtx.convertAddrP(pAddr) = 0;
        fixed = true;
        break;
      }
      if (fixed) {
        break;
      }

      // Use an unnamed pointer
      if (symPtrs.authUnnamed.size()) {
        const auto pAddr = *symPtrs.authUnnamed.begin();
        arm64Utils->writeNormalAuthStub(info.loc, info.addr, pAddr);

        symPtrs.auth.emplace(pAddr, info.name);
        symPtrs.authReverse.emplace(info.name, pAddr);
        symPtrs.authUsed.insert(pAddr);
        symPtrs.authUnnamed.erase(pAddr);

        // Zero out ptr
        *(uint64_t *)mCtx.convertAddrP(pAddr) = 0;
      }

      SPDLOG_LOGGER_WARN(logger, "Unable to fix auth stub at {:#x}", info.addr);
    }

    case Arm64Utils::StubFormat::Resolver: {
      SPDLOG_LOGGER_ERROR(logger, "Unable to fix auth stub resolver");
      break;
    }

    default:
      break;
    }
  }
}

template <class A> void StubFixer<A>::arm64FixCallsites() {
  activity.update(std::nullopt, "Fixing Callsites");

  const auto textSect = mCtx.getSection("__TEXT", "__text");
  if (textSect == nullptr) {
    SPDLOG_LOGGER_WARN(logger, "Unable to find text section");
    return;
  }

  const auto textAddr = textSect->addr;
  const auto textData = mCtx.convertAddrP(textAddr);
  for (uint64_t sectOff = 0; sectOff < textSect->size; sectOff += 4) {
    /**
     * We are only looking for bl and b instructions only.
     * Theses instructions are only identical by their top
     * most byte. By only looking at the top byte, we can
     * save a lot of time.
     */
    const uint32_t instrTop = *(textData + sectOff + 3) & 0xFC;
    if (instrTop != 0x94 && instrTop != 0x14) {
      continue;
    }

    const auto brInstr = (uint32_t *)(textData + sectOff);
    const int64_t brOff =
        arm64Utils->signExtend<int64_t, 28>((*brInstr & 0x3FFFFFF) << 2);
    const auto brTarget = textAddr + sectOff + brOff;

    // Check if it needs fixing
    if (mCtx.containsAddr(brTarget)) {
      continue;
    }

    const auto brAddr = textAddr + sectOff;

    // Find a stub for the branch
    bool fixed = false;
    const auto names =
        symbolizer->symbolizeAddr(arm64Utils->resolveStubChain(brTarget));
    for (auto name : names->symbols) {
      if (stubMap.contains(name.name)) {
        const auto stubAddr = stubMap.find(name.name)->second;
        const auto imm26 = ((int64_t)stubAddr - brAddr) >> 2;
        *brInstr = instrTop | (uint32_t)imm26;
        fixed = true;
      }
    }
    if (fixed) {
      activity.update();
      continue;
    }

    /**
     * Sometimes there are bytes of data in the text section
     * that match the bl and b filter, these seem to follow a
     * BR or other branch, skip these.
     */
    const auto lastInstrTop = *(textData + sectOff - 1) & 0xFC;
    if (lastInstrTop == 0x94 || lastInstrTop == 0x14 || lastInstrTop == 0xD6) {
      SPDLOG_LOGGER_DEBUG(logger, "Found data in code at {:#x}", brAddr);
      continue;
    }

    SPDLOG_LOGGER_WARN(logger,
                       "Unable to fix branch at 0x{:x}, targeting 0x{:x}",
                       brAddr, brTarget);
  }
}
#pragma endregion arm64

template <class A>
void Converter::fixStubs(Utils::ExtractionContext<typename A::P> &eCtx) {
  eCtx.activity.update("Stub Fixer", "Starting Up");

  if (!eCtx.pointerTracker) {
    SPDLOG_LOGGER_ERROR(eCtx.logger,
                        "Fixing stubs requires PointerTracker from "
                        "processing slide info.");
    return;
  }

  if constexpr (std::is_same<A, Utils::Arch::arm>::value ||
                std::is_same<A, Utils::Arch::arm64>::value ||
                std::is_same<A, Utils::Arch::arm64_32>::value) {
    StubFixer<A>(eCtx).run();
  }

  // No stub fixing needed for x86_64
}

#define X(T)                                                                   \
  template void Converter::fixStubs<T>(Utils::ExtractionContext<T::P> & eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X
