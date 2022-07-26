#include "ExtractionContext.h"
#include "Architectures.h"

#include <Converter/LinkeditOptimizer.h>
#include <Converter/Slide.h>
#include <Converter/Stubs.h>

using namespace Utils;

template <class A>
ExtractionContext<A>::ExtractionContext(Dyld::Context &dCtx,
                                        Macho::Context<false, P> &mCtx,
                                        ActivityLogger &activity,
                                        Accelerator<P> &accelerator)
    : dCtx(dCtx), mCtx(mCtx), activity(activity), logger(activity.logger),
      accelerator(accelerator), pointerTracker(dCtx, logger),
      disassembler(&mCtx, &activity, logger) {}

template <class A>
ExtractionContext<A>::ExtractionContext(ExtractionContext<A> &&other)
    : dCtx(std::move(other.dCtx)), mCtx(std::move(other.mCtx)),
      activity(std::move(other.activity)), logger(std::move(other.logger)),
      accelerator(std::move(other.accelerator)),
      pointerTracker(std::move(other.pointerTracker)),
      disassembler(std::move(other.disassembler)),
      linkeditTracker(other.linkeditTracker), symbolizer(other.symbolizer),
      hasRedactedIndirect(other.hasRedactedIndirect) {
  other.hasRedactedIndirect = false;
  other.linkeditTracker = nullptr;
  other.symbolizer = nullptr;
}

template <class A>
ExtractionContext<A> &
ExtractionContext<A>::operator=(ExtractionContext<A> &&other) {
  this->dCtx = std::move(other.dCtx);
  this->mCtx = std::move(other.mCtx);
  this->activity = std::move(other.activity);
  this->logger = std::move(other.logger);
  this->accelerator = std::move(other.accelerator);
  this->pointerTracker = std::move(other.pointerTracker);
  this->disassembler = std::move(other.disassembler);

  this->linkeditTracker = other.linkeditTracker;
  this->symbolizer = other.symbolizer;
  other.linkeditTracker = nullptr;
  other.symbolizer = nullptr;

  this->hasRedactedIndirect = other.hasRedactedIndirect;
  other.hasRedactedIndirect = false;
  return *this;
}

template <class A> ExtractionContext<A>::~ExtractionContext() {
  if (linkeditTracker) {
    delete linkeditTracker;
  }
  if (symbolizer) {
    delete symbolizer;
  }
}

template class ExtractionContext<Utils::Arch::x86_64>;
template class ExtractionContext<Utils::Arch::arm>;
template class ExtractionContext<Utils::Arch::arm64>;
template class ExtractionContext<Utils::Arch::arm64_32>;