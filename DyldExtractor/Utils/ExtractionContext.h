#ifndef __UTILS_EXTRACTIONCONTEXT__
#define __UTILS_EXTRACTIONCONTEXT__

#include <Dyld/Context.h>
#include <Macho/Context.h>
#include <Provider/Accelerator.h>
#include <Provider/ActivityLogger.h>
#include <Provider/BindInfo.h>
#include <Provider/Disassembler.h>
#include <Provider/ExtraData.h>
#include <Provider/FunctionTracker.h>
#include <Provider/LinkeditTracker.h>
#include <Provider/PointerTracker.h>
#include <Provider/SymbolTableTracker.h>
#include <Provider/Symbolizer.h>
#include <spdlog/logger.h>

namespace DyldExtractor::Utils {

template <class A> class ExtractionContext {
  using P = A::P;

public:
  const Dyld::Context *dCtx;
  Macho::Context<false, P> *mCtx;
  Provider::Accelerator<P> *accelerator;
  Provider::ActivityLogger *activity;
  std::shared_ptr<spdlog::logger> logger;

  Provider::BindInfo<P> bindInfo;
  Provider::Disassembler<A> disasm;
  Provider::FunctionTracker<P> funcTracker;
  Provider::PointerTracker<P> ptrTracker;

  std::optional<Provider::Symbolizer<A>> symbolizer;
  std::optional<Provider::LinkeditTracker<P>> leTracker;
  std::optional<Provider::SymbolTableTracker<P>> stTracker;
  std::optional<Provider::ExtraData<P>> exObjc;

  ExtractionContext(const Dyld::Context &dCtx, Macho::Context<false, P> &mCtx,
                    Provider::Accelerator<P> &accelerator,
                    Provider::ActivityLogger &activity);
  ExtractionContext(const ExtractionContext<A> &other) = delete;
  ExtractionContext &operator=(const ExtractionContext<A> &other) = delete;
  ExtractionContext(ExtractionContext<A> &&other) = delete;
  ExtractionContext &operator=(ExtractionContext<A> &&other) = delete;
};

};     // namespace DyldExtractor::Utils

#endif // __UTILS_EXTRACTIONCONTEXT__