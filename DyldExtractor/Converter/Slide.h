#ifndef __CONVERTER_SLIDE__
#define __CONVERTER_SLIDE__

#include <Utils/ExtractionContext.h>
#include <map>

namespace DyldExtractor::Converter {

template <class A> void processSlideInfo(Utils::ExtractionContext<A> &eCtx);

} // namespace DyldExtractor::Converter

#endif // __CONVERTER_SLIDE__