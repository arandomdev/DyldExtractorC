#ifndef __CONVERTER_OFFSETOPTIMIZER__
#define __CONVERTER_OFFSETOPTIMIZER__

#include <Utils/Architectures.h>
#include <Utils/ExtractionContext.h>

namespace Converter {

struct WriteProcedure {
  uint64_t writeOffset;
  const uint8_t *source;
  uint64_t size;
};

/// @brief Optimize a mach-o file's offsets for output.
/// @returns A vector of write procedures.
template <class A>
std::vector<WriteProcedure> optimizeOffsets(Utils::ExtractionContext<A> &eCtx);

}; // namespace Converter

#endif // __CONVERTER_OFFSETOPTIMIZER__