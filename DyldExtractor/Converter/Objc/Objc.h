#ifndef __CONVERTER_OBJC_OBJC__
#define __CONVERTER_OBJC_OBJC__

#include <Utils/ExtractionContext.h>

namespace DyldExtractor::Converter {

template <class A> void fixObjc(Utils::ExtractionContext<A> &eCtx);

} // namespace DyldExtractor::Converter

#endif // __CONVERTER_OBJC_OBJC__