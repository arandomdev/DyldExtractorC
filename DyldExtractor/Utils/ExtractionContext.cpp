#include "ExtractionContext.h"
#include "Architectures.h"

using namespace DyldExtractor;
using namespace Utils;

template <class A>
ExtractionContext<A>::ExtractionContext(const Dyld::Context &dCtx,
                                        Macho::Context<false, P> &mCtx,
                                        Logger::Activity &activity,
                                        Provider::Accelerator<P> &accelerator)
    : dCtx(&dCtx), mCtx(&mCtx), activity(&activity), logger(activity.logger),
      accelerator(&accelerator), ptrTracker(dCtx, logger),
      disassembler(&mCtx, &activity, logger),
      symbolizer(dCtx, mCtx, activity, logger, accelerator), leTracker(mCtx),
      bindInfo(mCtx) {}

template class ExtractionContext<Arch::x86_64>;
template class ExtractionContext<Arch::arm>;
template class ExtractionContext<Arch::arm64>;
template class ExtractionContext<Arch::arm64_32>;