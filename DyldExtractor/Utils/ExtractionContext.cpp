#include "ExtractionContext.h"
#include "Architectures.h"

#include <Converter/LinkeditOptimizer.h>
#include <Converter/Slide.h>
#include <Converter/Stubs.h>

using namespace Utils;

template <class P>
ExtractionContext<P>::ExtractionContext(Dyld::Context &_dCtx,
                                        Macho::Context<false, P> &_mCtx,
                                        ActivityLogger *_activity)
    : dCtx(_dCtx), mCtx(_mCtx), activity(_activity), logger(_activity->logger) {
}

template <class P>
ExtractionContext<P>::ExtractionContext(ExtractionContext<P> &&other)
    : dCtx(other.dCtx), mCtx(other.mCtx), activity(other.activity),
      logger(other.logger), linkeditTracker(other.linkeditTracker),
      pointerTracker(other.pointerTracker), symbolizer(other.symbolizer),
      hasRedactedIndirect(other.hasRedactedIndirect) {
    other.activity = nullptr;
    other.hasRedactedIndirect = false;
    other.linkeditTracker = nullptr;
    other.pointerTracker = nullptr;
    other.symbolizer = nullptr;
}

template <class P>
ExtractionContext<P> &
ExtractionContext<P>::operator=(ExtractionContext<P> &&other) {
    this->dCtx = std::move(other.dCtx);
    this->mCtx = std::move(other.mCtx);
    this->activity = other.activity;
    other.activity = nullptr;
    this->logger = other.logger;

    this->linkeditTracker = other.linkeditTracker;
    this->pointerTracker = other.pointerTracker;
    this->symbolizer = other.symbolizer;
    other.linkeditTracker = nullptr;
    other.pointerTracker = nullptr;
    other.symbolizer = nullptr;

    this->hasRedactedIndirect = other.hasRedactedIndirect;
    other.hasRedactedIndirect = false;
    return *this;
}

template <class P> ExtractionContext<P>::~ExtractionContext() {
    if (linkeditTracker) {
        delete linkeditTracker;
    }
    if (pointerTracker) {
        delete pointerTracker;
    }
    if (symbolizer) {
        delete symbolizer;
    }
}

template class ExtractionContext<Utils::Pointer32>;
template class ExtractionContext<Utils::Pointer64>;