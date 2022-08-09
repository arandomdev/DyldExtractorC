#include "ExtractionContext.h"
#include "Architectures.h"

#include <Converter/LinkeditOptimizer.h>

using namespace Utils;

template <class A>
ExtractionContext<A>::ExtractionContext(const Dyld::Context &dCtx,
                                        Macho::Context<false, P> &mCtx,
                                        ActivityLogger &activity,
                                        Accelerator<P> &accelerator)
    : dCtx(&dCtx), mCtx(&mCtx), activity(&activity), logger(activity.logger),
      accelerator(&accelerator), pointerTracker(dCtx, logger),
      disassembler(&mCtx, &activity, logger),
      symbolizer(dCtx, mCtx, activity, logger, accelerator) {}

template <class A>
ExtractionContext<A>::ExtractionContext(ExtractionContext<A> &&other)
    : dCtx(other.dCtx), mCtx(other.mCtx), activity(other.activity),
      logger(std::move(other.logger)), accelerator(other.accelerator),
      pointerTracker(std::move(other.pointerTracker)),
      disassembler(std::move(other.disassembler)),
      symbolizer(std::move(other.symbolizer)), exObjc(std::move(other.exObjc)),
      linkeditTracker(other.linkeditTracker),
      hasRedactedIndirect(other.hasRedactedIndirect) {
  other.dCtx = nullptr;
  other.mCtx = nullptr;
  other.activity = nullptr;
  other.accelerator = nullptr;
  other.hasRedactedIndirect = false;
  other.linkeditTracker = nullptr;
}

template <class A>
ExtractionContext<A> &
ExtractionContext<A>::operator=(ExtractionContext<A> &&other) {
  this->dCtx = other.dCtx;
  this->mCtx = other.mCtx;
  this->activity = other.activity;
  this->logger = std::move(other.logger);
  this->accelerator = other.accelerator;
  this->pointerTracker = std::move(other.pointerTracker);
  this->disassembler = std::move(other.disassembler);
  this->symbolizer = std::move(other.symbolizer);
  this->exObjc = std::move(other.exObjc);

  this->linkeditTracker = other.linkeditTracker;
  this->hasRedactedIndirect = other.hasRedactedIndirect;

  other.dCtx = nullptr;
  other.mCtx = nullptr;
  other.activity = nullptr;
  other.accelerator = nullptr;

  other.linkeditTracker = nullptr;
  other.hasRedactedIndirect = false;
  return *this;
}

template <class A> ExtractionContext<A>::~ExtractionContext() {
  if (linkeditTracker) {
    delete linkeditTracker;
  }
}

template class ExtractionContext<Utils::Arch::x86_64>;
template class ExtractionContext<Utils::Arch::arm>;
template class ExtractionContext<Utils::Arch::arm64>;
template class ExtractionContext<Utils::Arch::arm64_32>;