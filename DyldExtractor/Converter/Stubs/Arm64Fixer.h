#ifndef __CONVERTER_STUBS_ARM64FIXER__
#define __CONVERTER_STUBS_ARM64FIXER__

#include "Arm64Utils.h"
#include "SymbolPointerCache.h"

namespace DyldExtractor::Converter::Stubs {

template <class A> class Fixer;

template <class A> class Arm64Fixer {
  using P = A::P;
  using PtrT = P::PtrT;
  using SPtrT = P::SPtrT;

  using SPointerType = SymbolPointerCache<A>::PointerType;
  using AStubFormat = Arm64Utils<A>::StubFormat;

public:
  Arm64Fixer(Fixer<A> &delegate);
  void fix();

  std::map<PtrT, Provider::SymbolicInfo> stubMap;

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
  Arm64Utils<A> &arm64Utils;

  std::map<std::reference_wrapper<const std::string>, std::set<PtrT>,
           std::less<const std::string>>
      reverseStubMap;

  std::list<StubInfo> brokenStubs;
};

} // namespace DyldExtractor::Converter::Stubs

#endif // __CONVERTER_STUBS_ARM64FIXER__