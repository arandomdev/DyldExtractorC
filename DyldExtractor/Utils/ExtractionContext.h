#ifndef __UTILS_EXTRACTIONCONTEXT__
#define __UTILS_EXTRACTIONCONTEXT__

#include "Accelerator.h"
#include <Dyld/Context.h>
#include <Logger/ActivityLogger.h>
#include <Macho/Context.h>
#include <Provider/Disassembler.h>
#include <Provider/PointerTracker.h>
#include <spdlog/logger.h>

namespace Converter {
template <class P> class LinkeditTracker;
template <class P> class Symbolizer;
}; // namespace Converter

namespace Utils {
template <class P> class Accelerator;

template <class A> class ExtractionContext {
  using P = A::P;

public:
  std::reference_wrapper<Dyld::Context> dCtx;
  std::reference_wrapper<Macho::Context<false, P>> mCtx;
  std::reference_wrapper<ActivityLogger> activity;
  std::shared_ptr<spdlog::logger> logger;
  std::reference_wrapper<Accelerator<P>> accelerator;

  Provider::PointerTracker<P> pointerTracker;
  Provider::Disassembler<A> disassembler;

  Converter::LinkeditTracker<P> *linkeditTracker = nullptr;
  Converter::Symbolizer<A> *symbolizer = nullptr;

  // Linkedit optimizer guarantees that undefined symbols are added last in the
  // symtab.
  bool hasRedactedIndirect = false;

  ExtractionContext(Dyld::Context &dCtx, Macho::Context<false, P> &mCtx,
                    ActivityLogger &activity, Accelerator<P> &accelerator);
  ExtractionContext(const ExtractionContext<A> &other) = delete;
  ExtractionContext(ExtractionContext<A> &&other);
  ExtractionContext &operator=(const ExtractionContext<A> &other) = delete;
  ExtractionContext &operator=(ExtractionContext<A> &&other);
  ~ExtractionContext();
};

}; // namespace Utils

#endif // __UTILS_EXTRACTIONCONTEXT__