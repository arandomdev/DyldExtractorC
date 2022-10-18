#ifndef __CONVERTER_STUBS_FIXER__
#define __CONVERTER_STUBS_FIXER__

#include "Arm64Fixer.h"
#include "ArmFixer.h"
#include "SymbolPointerCache.h"
#include <Utils/ExtractionContext.h>

namespace DyldExtractor::Converter::Stubs {

template <class A> class Fixer {
  friend class SymbolPointerCache<A>;
  friend class Arm64Fixer<A>;
  friend class ArmFixer;
  using P = A::P;
  using PtrT = P::PtrT;

public:
  Fixer(Utils::ExtractionContext<A> &eCtx);
  void fix();

private:
  std::pair<const Macho::Loader::nlist<P> *, const char *>
  lookupIndirectEntry(const uint32_t index) const;
  PtrT resolveStubChain(const PtrT addr);
  void checkIndirectEntries();
  void fixIndirectEntries();
  void bindPointers();

  bool isInCodeRegions(PtrT addr);

  Utils::ExtractionContext<A> &eCtx;
  const Dyld::Context &dCtx;
  Macho::Context<false, P> &mCtx;
  Logger::Activity &activity;
  std::shared_ptr<spdlog::logger> logger;
  Provider::Accelerator<P> &accelerator;
  Provider::BindInfo<P> &bindInfo;
  Provider::Disassembler<A> &disasm;
  Provider::LinkeditTracker<P> &leTracker;
  Provider::PointerTracker<P> &ptrTracker;
  Provider::Symbolizer<A> &symbolizer;

  uint8_t *linkeditFile;
  Macho::Loader::symtab_command *symtab;
  Macho::Loader::dysymtab_command *dysymtab;

  SymbolPointerCache<A> pointerCache;

  std::optional<Arm64Utils<A>> arm64Utils;
  std::optional<Arm64Fixer<A>> arm64Fixer;

  std::optional<ArmUtils> armUtils;
  std::optional<ArmFixer> armFixer;
};

} // namespace DyldExtractor::Converter::Stubs

#endif // __CONVERTER_STUBS_FIXER__