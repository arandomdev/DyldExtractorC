#ifndef __UTILS_EXTRACTIONCONTEXT__
#define __UTILS_EXTRACTIONCONTEXT__

#include "Accelerator.h"
#include <Dyld/Context.h>
#include <Logger/ActivityLogger.h>
#include <Macho/Context.h>
#include <Provider/PointerTracker.h>
#include <spdlog/logger.h>

namespace Converter {
template <class P> class LinkeditTracker;
template <class P> class Symbolizer;
}; // namespace Converter

namespace Utils {
template <class P> class Accelerator;

template <class P> class ExtractionContext {
public:
  std::reference_wrapper<Dyld::Context> dCtx;
  std::reference_wrapper<Macho::Context<false, P>> mCtx;
  std::reference_wrapper<ActivityLogger> activity;
  std::shared_ptr<spdlog::logger> logger;
  std::reference_wrapper<Accelerator<P>> accelerator;

  Provider::PointerTracker<P> pointerTracker;

  Converter::LinkeditTracker<P> *linkeditTracker = nullptr;
  Converter::Symbolizer<P> *symbolizer = nullptr;

  // Linkedit optimizer guarantees that undefined symbols are added last in the
  // symtab.
  bool hasRedactedIndirect = false;

  ExtractionContext(Dyld::Context &dCtx, Macho::Context<false, P> &mCtx,
                    ActivityLogger &activity, Accelerator<P> &accelerator);
  ExtractionContext(const ExtractionContext<P> &other) = delete;
  ExtractionContext(ExtractionContext<P> &&other);
  ExtractionContext &operator=(const ExtractionContext<P> &other) = delete;
  ExtractionContext &operator=(ExtractionContext<P> &&other);
  ~ExtractionContext();
};

}; // namespace Utils

#endif // __UTILS_EXTRACTIONCONTEXT__