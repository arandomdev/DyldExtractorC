#ifndef __CONVERTER_LINKEDIT_LEGACYGENERATOR__
#define __CONVERTER_LINKEDIT_LEGACYGENERATOR__

#include <Utils/ExtractionContext.h>

namespace DyldExtractor::Converter::Linkedit::Encoder {

/// @brief Generate rebase and bind info using the legacy opcode method.
template <class A>
void generateLegacyMetadata(Utils::ExtractionContext<A> &eCtx);

} // namespace DyldExtractor::Converter::Linkedit::Encoder

#endif // __CONVERTER_LINKEDIT_LEGACYGENERATOR__