#include "ExtractionContext.h"
#include "Architectures.h"

#include <Converter/LinkeditOptimizer.h>
#include <Converter/Slide.h>
#include <Converter/Stubs.h>

using namespace Utils;

template <class P>
ExtractionContext<P>::ExtractionContext(Dyld::Context &dCtx,
                                        Macho::Context<false, P> &mCtx,
                                        ActivityLogger &activity,
                                        Accelerator<P> &accelerator)
    : dCtx(dCtx), mCtx(mCtx), activity(activity), logger(activity.logger),
      accelerator(accelerator), pointerTracker(*this) {}

template <class P>
ExtractionContext<P>::ExtractionContext(ExtractionContext<P> &&other)
    : dCtx(std::move(other.dCtx)), mCtx(std::move(other.mCtx)),
      activity(std::move(other.activity)), logger(std::move(other.logger)),
      accelerator(std::move(other.accelerator)),
      pointerTracker(std::move(other.pointerTracker)),
      linkeditTracker(other.linkeditTracker), symbolizer(other.symbolizer),
      hasRedactedIndirect(other.hasRedactedIndirect) {
  other.hasRedactedIndirect = false;
  other.linkeditTracker = nullptr;
  other.symbolizer = nullptr;
}

template <class P>
ExtractionContext<P> &
ExtractionContext<P>::operator=(ExtractionContext<P> &&other) {
  this->dCtx = std::move(other.dCtx);
  this->mCtx = std::move(other.mCtx);
  this->activity = std::move(other.activity);
  this->logger = std::move(other.logger);
  this->accelerator = std::move(other.accelerator);
  this->pointerTracker = std::move(other.pointerTracker);

  this->linkeditTracker = other.linkeditTracker;
  this->symbolizer = other.symbolizer;
  other.linkeditTracker = nullptr;
  other.symbolizer = nullptr;

  this->hasRedactedIndirect = other.hasRedactedIndirect;
  other.hasRedactedIndirect = false;
  return *this;
}

template <class P> ExtractionContext<P>::~ExtractionContext() {
  if (linkeditTracker) {
    delete linkeditTracker;
  }
  if (symbolizer) {
    delete symbolizer;
  }
}

template class ExtractionContext<Utils::Pointer32>;
template class ExtractionContext<Utils::Pointer64>;