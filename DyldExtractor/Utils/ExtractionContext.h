#ifndef __UTILS_EXTRACTIONCONTEXT__
#define __UTILS_EXTRACTIONCONTEXT__

#include <spdlog/logger.h>

#include "HeaderTracker.h"
#include <Dyld/Context.h>
#include <Logger/ActivityLogger.h>
#include <Macho/Context.h>

namespace Utils {

template <class P> struct ExtractionContext {
    Dyld::Context &dCtx;
    Macho::Context<false, P> &mCtx;
    ActivityLogger &activity;
    std::shared_ptr<spdlog::logger> logger;
    HeaderTracker<P> &headerTracker;

    ///
    /// If this variable is true, the following is true,
    /// * There are redacted indirect symbol entries.
    /// * Space was allocated for the redacted symbol entries.
    ///     * This space is placed at the end of the symbol table.
    /// * The string table to at the end of the LINKEDIT segment.
    ///
    bool hasRedactedIndirect = false;
};

}; // namespace Utils

#endif // __UTILS_EXTRACTIONCONTEXT__