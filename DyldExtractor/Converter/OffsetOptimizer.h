#ifndef __CONVERTER_OFFSETOPTIMIZER__
#define __CONVERTER_OFFSETOPTIMIZER__

#include <Utils/Architectures.h>
#include <Utils/ExtractionContext.h>

#define SEGMENT_ALIGNMENT 0x4000

namespace DyldExtractor::Converter {

struct OffsetWriteProcedure {
  uint64_t writeOffset;
  const uint8_t *source;
  uint64_t size;
};

/// @brief Optimize a mach-o file's offsets for output.
/// @returns A vector of write procedures.
template <class A>
std::vector<OffsetWriteProcedure>
optimizeOffsets(Utils::ExtractionContext<A> &eCtx);

}; // namespace DyldExtractor::Converter

#endif // __CONVERTER_OFFSETOPTIMIZER__