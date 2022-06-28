#ifndef __UTILS_EXTRACTIONCONTEXT__
#define __UTILS_EXTRACTIONCONTEXT__

#include <spdlog/logger.h>

#include <Dyld/Context.h>
#include <Logger/ActivityLogger.h>
#include <Macho/Context.h>

namespace Converter {
template <class P> class LinkeditTracker;
template <class P> class PointerTracker;
template <class P> class Symbolizer;
}; // namespace Converter

namespace Utils {
template <class P> class Accelerator;

template <class P> class ExtractionContext {
  public:
    Dyld::Context &dCtx;
    Macho::Context<false, P> &mCtx;
    ActivityLogger *activity;
    std::shared_ptr<spdlog::logger> logger;

    Converter::LinkeditTracker<P> *linkeditTracker = nullptr;
    Converter::PointerTracker<P> *pointerTracker = nullptr;
    Converter::Symbolizer<P> *symbolizer = nullptr;

    /// Accelerator cache when running multiple images.
    /// Is not destroyed in deconstructor.
    Accelerator<P> *accelerator = nullptr;

    /// If this variable is non zero, the following is true,
    /// * There are redacted indirect symbol entries.
    /// * Space was allocated for the redacted symbol entries.
    ///     * This space is placed at the end of the symbol table.
    /// * The string table to at the end of the LINKEDIT segment.
    ///
    uint32_t redactedIndirectCount = 0;

    ExtractionContext(Dyld::Context &dCtx, Macho::Context<false, P> &mCtx,
                      ActivityLogger *activity, Accelerator<P> *accelerator);
    ExtractionContext(const ExtractionContext<P> &other) = delete;
    ExtractionContext(ExtractionContext<P> &&other);
    ExtractionContext &operator=(const ExtractionContext<P> &other) = delete;
    ExtractionContext &operator=(ExtractionContext<P> &&other);
    ~ExtractionContext();
};

}; // namespace Utils

#endif // __UTILS_EXTRACTIONCONTEXT__