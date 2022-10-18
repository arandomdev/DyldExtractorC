#ifndef __CONVERTER_LINKEDIT_METADATAGENERATOR__
#define __CONVERTER_LINKEDIT_METADATAGENERATOR__

#include <Utils/ExtractionContext.h>

namespace DyldExtractor::Converter {

template <class A> void generateMetadata(Utils::ExtractionContext<A> &eCtx);

} // namespace DyldExtractor::Converter

#endif // __CONVERTER_LINKEDIT_METADATAGENERATOR__