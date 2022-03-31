#ifndef __CONVERTER_OFFSETOPTIMIZER__
#define __CONVERTER_OFFSETOPTIMIZER__

#include <Utils/ExtractionContext.h>

namespace Converter {

struct WriteProcedure {
    uint64_t writeOffset;
    const char *source;
    uint64_t size;
};

/// Optimize a mach-o file's offsets for output.
///
/// @returns A vector of write procedures.
std::vector<WriteProcedure>
optimizeOffsets(Utils::ExtractionContext extractionCtx);

}; // namespace Converter

#endif // __CONVERTER_OFFSETOPTIMIZER__