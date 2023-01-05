#include "ExtractionContext.h"
#include "Architectures.h"

using namespace DyldExtractor;
using namespace Utils;

template <class A>
ExtractionContext<A>::ExtractionContext(const Dyld::Context &dCtx,
                                        Macho::Context<false, P> &mCtx,
                                        Provider::Accelerator<P> &accelerator,
                                        Provider::ActivityLogger &activity)
    : dCtx(&dCtx), mCtx(&mCtx), accelerator(&accelerator), activity(&activity),
      logger(activity.getLogger()), bindInfo(mCtx, activity),
      disasm(mCtx, activity, logger, funcTracker),
      funcTracker(mCtx, logger), ptrTracker(dCtx, logger) {}

template class ExtractionContext<Arch::x86_64>;
template class ExtractionContext<Arch::arm>;
template class ExtractionContext<Arch::arm64>;
template class ExtractionContext<Arch::arm64_32>;