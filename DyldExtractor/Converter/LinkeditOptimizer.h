#ifndef __CONVERTER_LINKEDITOPTIMIZER__
#define __CONVERTER_LINKEDITOPTIMIZER__

#include <Macho/Context.h>
#include <Utils/ExtractionContext.h>

namespace Converter {

template <class P>
void optimizeLinkedit(Utils::ExtractionContext<P> extractionCtx);

} // namespace Converter

#endif // __CONVERTER_LINKEDITOPTIMIZER__