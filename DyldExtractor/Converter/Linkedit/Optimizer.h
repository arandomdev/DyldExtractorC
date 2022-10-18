#ifndef __CONVERTER_LINKEDIT_OPTIMIZER__
#define __CONVERTER_LINKEDIT_OPTIMIZER__

#include <Utils/ExtractionContext.h>

namespace DyldExtractor::Converter {

bool isRedactedIndirect(uint32_t entry);
template <class A> void optimizeLinkedit(Utils::ExtractionContext<A> &eCtx);

} // namespace DyldExtractor::Converter

#endif // __CONVERTER_LINKEDIT_OPTIMIZER__