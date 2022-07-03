#ifndef __CONVERTER_STUBS_FIXER__
#define __CONVERTER_STUBS_FIXER__

#include "../LinkeditOptimizer.h"
#include "Arm64Utils.h"
#include "Symbolizer.h"
#include <Macho/BindInfo.h>
#include <Utils/ExtractionContext.h>

namespace Converter {

template <class A> class StubFixer;

template <class A> class SymbolPointerCache {
  using P = A::P;
  using ptrT = P::ptr_t;

public:
  enum class PointerType {
    normal, // Commonly in __got
    lazy,   // Commonly in __la_symbol_ptr
    auth    // Commonly in __auth_got
  };

  SymbolPointerCache(StubFixer<A> &delegate);
  PointerType getPointerType(const auto sect) const;
  void scanPointers();

  /// Check if a pointer is free to use
  bool isAvailable(PointerType pType, uint64_t addr);
  /// Provide symbolic info for a unnamed pointer
  void namePointer(PointerType pType, uint64_t addr, SymbolicInfo info);
  SymbolicInfo *getPointerInfo(PointerType pType, uint64_t addr);

  using PtrMapT = std::map<uint64_t, SymbolicInfo>;
  struct {
    // TODO: Shouldn't this be ptrT
    PtrMapT normal;
    PtrMapT lazy;
    PtrMapT auth;
  } ptr;

  using ReverseMapT =
      std::map<std::reference_wrapper<const std::string>, std::set<uint64_t>,
               std::less<const std::string>>;
  struct {
    ReverseMapT normal;
    ReverseMapT lazy;
    ReverseMapT auth;
  } reverse;

  struct {
    std::set<uint64_t> normal;
    std::set<uint64_t> lazy;
    std::set<uint64_t> auth;
  } unnamed;

  struct {
    std::set<uint64_t> normal;
    std::set<uint64_t> lazy;
    std::set<uint64_t> auth;
  } used;

private:
  std::map<uint64_t, Macho::BindRecord> getBindRecords();
  void addPointerInfo(PointerType pType, uint64_t pAddr, SymbolicInfo info);

  StubFixer<A> &delegate;
  Macho::Context<false, P> &mCtx;
  ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
};

class Arm64Fixer {
  using A = Utils::Arch::arm64;
  using P = A::P;

  using SPointerType = SymbolPointerCache<A>::PointerType;

public:
  Arm64Fixer(StubFixer<A> &delegate);
  void fix();

  std::map<uint64_t, SymbolicInfo> stubMap;

private:
  struct StubInfo {
    Arm64Utils::StubFormat format;
    uint64_t target; // The target function of the stub
    uint64_t addr;
    uint8_t *loc;  // Writable location of the stub
    uint32_t size; // Size in bytes of the stub
  };

  void fixStubHelpers();
  void scanStubs();
  void fixPass1();
  void fixPass2();
  void fixCallsites();

  void addStubInfo(uint64_t sAddr, SymbolicInfo info);

  StubFixer<A> &delegate;
  Macho::Context<false, P> &mCtx;
  ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
  Symbolizer<P> *symbolizer;

  SymbolPointerCache<A> &pointerCache;
  Arm64Utils &arm64Utils;

  std::map<std::reference_wrapper<const std::string>, std::set<uint64_t>,
           std::less<const std::string>>
      reverseStubMap;

  std::list<StubInfo> brokenStubs;
};

template <class A> class StubFixer {
  friend class SymbolPointerCache<A>;
  friend class Arm64Fixer;
  using P = A::P;
  using PtrT = P::ptr_t;

public:
  StubFixer(Utils::ExtractionContext<P> &eCtx);
  void fix();

private:
  std::pair<const Macho::Loader::nlist<P> *, const char *>
  lookupIndirectEntry(const uint32_t index) const;
  uint64_t resolveStubChain(const uint64_t addr);
  void checkIndirectEntries();
  void fixIndirectEntries();
  bool isInCodeRegions(uint64_t addr);

  Utils::ExtractionContext<P> &eCtx;
  Dyld::Context &dCtx;
  Macho::Context<false, P> &mCtx;
  ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
  Utils::Accelerator<P> &accelerator;
  Provider::PointerTracker<P> pointerTracker;
  Converter::LinkeditTracker<P> *linkeditTracker;
  Symbolizer<P> *symbolizer;

  uint8_t *linkeditFile;
  Macho::Loader::dyld_info_command *dyldInfo;
  Macho::Loader::symtab_command *symtab;
  Macho::Loader::dysymtab_command *dysymtab;

  SymbolPointerCache<A> pointerCache;

  std::optional<Arm64Utils> arm64Utils;
  std::optional<Arm64Fixer> arm64Fixer;
};

template <class A> void fixStubs(Utils::ExtractionContext<typename A::P> &eCtx);

} // namespace Converter

#endif // __CONVERTER_STUBS_FIXER__