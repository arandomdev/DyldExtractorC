#ifndef __CONVERTER_STUBS_FIXER__
#define __CONVERTER_STUBS_FIXER__

#include "../LinkeditOptimizer.h"
#include "Arm64Utils.h"
#include "ArmUtils.h"
#include "Symbolizer.h"
#include <Macho/BindInfo.h>
#include <Utils/ExtractionContext.h>

namespace Converter {

template <class A> class StubFixer;

template <class A> class SymbolPointerCache {
  using P = A::P;
  using PtrT = P::PtrT;

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
  bool isAvailable(PointerType pType, PtrT addr);
  /// Provide symbolic info for a unnamed pointer
  void namePointer(PointerType pType, PtrT addr, SymbolicInfo info);
  SymbolicInfo *getPointerInfo(PointerType pType, PtrT addr);

  using PtrMapT = std::map<PtrT, SymbolicInfo>;
  struct {
    PtrMapT normal;
    PtrMapT lazy;
    PtrMapT auth;
  } ptr;

  using ReverseMapT = std::map<std::reference_wrapper<const std::string>,
                               std::set<PtrT>, std::less<const std::string>>;
  struct {
    ReverseMapT normal;
    ReverseMapT lazy;
    ReverseMapT auth;
  } reverse;

  struct {
    std::set<PtrT> normal;
    std::set<PtrT> lazy;
    std::set<PtrT> auth;
  } unnamed;

  struct {
    std::set<PtrT> normal;
    std::set<PtrT> lazy;
    std::set<PtrT> auth;
  } used;

private:
  std::map<PtrT, Macho::BindRecord> getBindRecords();
  void addPointerInfo(PointerType pType, PtrT pAddr, SymbolicInfo info);

  StubFixer<A> &delegate;
  Macho::Context<false, P> &mCtx;
  ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
};

template <class A> class Arm64Fixer {
  using P = A::P;
  using PtrT = P::PtrT;
  using SPtrT = P::SPtrT;

  using SPointerType = SymbolPointerCache<A>::PointerType;
  using AStubFormat = Arm64Utils<A>::StubFormat;

public:
  Arm64Fixer(StubFixer<A> &delegate);
  void fix();

  std::map<PtrT, SymbolicInfo> stubMap;

private:
  struct StubInfo {
    AStubFormat format;
    PtrT target; // The target function of the stub
    PtrT addr;
    uint8_t *loc;  // Writable location of the stub
    uint32_t size; // Size in bytes of the stub
  };

  void fixStubHelpers();
  void scanStubs();
  void fixPass1();
  void fixPass2();
  void fixCallsites();

  void addStubInfo(PtrT sAddr, SymbolicInfo info);

  StubFixer<A> &delegate;
  Macho::Context<false, P> &mCtx;
  ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
  Symbolizer<A> *symbolizer;

  SymbolPointerCache<A> &pointerCache;
  Arm64Utils<A> &arm64Utils;

  std::map<std::reference_wrapper<const std::string>, std::set<PtrT>,
           std::less<const std::string>>
      reverseStubMap;

  std::list<StubInfo> brokenStubs;
};

class ArmFixer {
  using A = Utils::Arch::arm;
  using P = A::P;
  using PtrT = P::PtrT;

  using SPointerType = SymbolPointerCache<A>::PointerType;
  using AStubFormat = ArmUtils::StubFormat;

public:
  ArmFixer(StubFixer<A> &delegate);

  void fix();

  std::map<PtrT, SymbolicInfo> stubMap;

private:
  struct StubInfo {
    AStubFormat format;
    PtrT target; // The target function of the stub
    PtrT addr;
    uint8_t *loc; // Writable location of the stub
  };

  void fixStubHelpers();
  void scanStubs();
  void fixPass1();
  void fixPass2();
  void fixCallsites();

  void addStubInfo(PtrT sAddr, SymbolicInfo info);

  /// Encoding independent lookup
  const SymbolicInfo *symbolizeAddr(PtrT addr) const;

  StubFixer<A> &delegate;
  Macho::Context<false, P> &mCtx;
  ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
  Provider::Disassembler<A> &disasm;
  Symbolizer<A> *symbolizer;

  SymbolPointerCache<A> &pointerCache;
  ArmUtils &armUtils;

  std::map<std::reference_wrapper<const std::string>, std::set<PtrT>,
           std::less<const std::string>>
      reverseStubMap;

  std::list<StubInfo> brokenStubs;
};

template <class A> class StubFixer {
  friend class SymbolPointerCache<A>;
  friend class Arm64Fixer<A>;
  friend class ArmFixer;
  using P = A::P;
  using PtrT = P::PtrT;

public:
  StubFixer(Utils::ExtractionContext<A> &eCtx);
  void fix();

private:
  std::pair<const Macho::Loader::nlist<P> *, const char *>
  lookupIndirectEntry(const uint32_t index) const;
  PtrT resolveStubChain(const PtrT addr);
  void checkIndirectEntries();
  void fixIndirectEntries();
  bool isInCodeRegions(PtrT addr);

  Utils::ExtractionContext<A> &eCtx;
  Dyld::Context &dCtx;
  Macho::Context<false, P> &mCtx;
  ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
  Utils::Accelerator<P> &accelerator;
  Provider::PointerTracker<P> &pointerTracker;
  Provider::Disassembler<A> &disasm;
  Converter::LinkeditTracker<P> *linkeditTracker;
  Symbolizer<A> *symbolizer;

  uint8_t *linkeditFile;
  Macho::Loader::dyld_info_command *dyldInfo;
  Macho::Loader::symtab_command *symtab;
  Macho::Loader::dysymtab_command *dysymtab;

  SymbolPointerCache<A> pointerCache;

  std::optional<Arm64Utils<A>> arm64Utils;
  std::optional<Arm64Fixer<A>> arm64Fixer;

  std::optional<ArmUtils> armUtils;
  std::optional<ArmFixer> armFixer;
};

template <class A> void fixStubs(Utils::ExtractionContext<A> &eCtx);

} // namespace Converter

#endif // __CONVERTER_STUBS_FIXER__