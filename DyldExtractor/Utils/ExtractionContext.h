#ifndef __UTILS_EXTRACTIONCONTEXT__
#define __UTILS_EXTRACTIONCONTEXT__

#include <Dyld/Context.h>
#include <Logger/Activity.h>
#include <Macho/Context.h>
#include <Provider/Accelerator.h>
#include <Provider/BindInfo.h>
#include <Provider/Disassembler.h>
#include <Provider/ExtraData.h>
#include <Provider/LinkeditTracker.h>
#include <Provider/PointerTracker.h>
#include <Provider/Symbolizer.h>
#include <spdlog/logger.h>

namespace DyldExtractor::Utils {

template <class A> class ExtractionContext {
  using P = A::P;

public:
  const Dyld::Context *dCtx;
  Macho::Context<false, P> *mCtx;
  Logger::Activity *activity;
  std::shared_ptr<spdlog::logger> logger;
  Provider::Accelerator<P> *accelerator;

  Provider::BindInfo<P> bindInfo;
  Provider::Disassembler<A> disassembler;
  Provider::ExtraData<P> exObjc;
  Provider::LinkeditTracker<P> leTracker;
  Provider::PointerTracker<P> ptrTracker;
  Provider::Symbolizer<A> symbolizer;

  // Linkedit optimizer guarantees that undefined symbols are added last in the
  // symtab.
  bool hasRedactedIndirect = false;

  ExtractionContext(const Dyld::Context &dCtx, Macho::Context<false, P> &mCtx,
                    Logger::Activity &activity,
                    Provider::Accelerator<P> &accelerator);
  ExtractionContext(const ExtractionContext<A> &other) = delete;
  ExtractionContext &operator=(const ExtractionContext<A> &other) = delete;
};

}; // namespace DyldExtractor::Utils

#endif // __UTILS_EXTRACTIONCONTEXT__