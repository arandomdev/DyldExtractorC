#ifndef __CONVERTER_STUBS_ARMFIXER__
#define __CONVERTER_STUBS_ARMFIXER__

#include "ArmUtils.h"
#include "SymbolPointerCache.h"

namespace DyldExtractor::Converter::Stubs {

template <class A> class Fixer;

class ArmFixer {
  using A = Utils::Arch::arm;
  using P = A::P;
  using PtrT = P::PtrT;

  using SPointerType = SymbolPointerCache<A>::PointerType;
  using AStubFormat = ArmUtils::StubFormat;

public:
  ArmFixer(Fixer<A> &delegate);

  void fix();

  std::map<PtrT, Provider::SymbolicInfo> stubMap;

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

  void addStubInfo(PtrT sAddr, Provider::SymbolicInfo info);

  Fixer<A> &delegate;
  Macho::Context<false, P> &mCtx;
  Provider::ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
  Provider::BindInfo<P> &bindInfo;
  Provider::Disassembler<A> &disasm;
  Provider::PointerTracker<P> &ptrTracker;
  Provider::Symbolizer<A> &symbolizer;
  Provider::SymbolTableTracker<P> &stTracker;

  SymbolPointerCache<A> &pointerCache;
  ArmUtils &armUtils;

  std::map<std::reference_wrapper<const std::string>, std::set<PtrT>,
           std::less<const std::string>>
      reverseStubMap;

  std::list<StubInfo> brokenStubs;
};

} // namespace DyldExtractor::Converter::Stubs

#endif // __CONVERTER_STUBS_ARMFIXER__