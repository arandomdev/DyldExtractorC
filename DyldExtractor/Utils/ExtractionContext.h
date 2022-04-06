#ifndef __UTILS_EXTRACTIONCONTEXT__
#define __UTILS_EXTRACTIONCONTEXT__

#include <spdlog/logger.h>

#include <Dyld/Context.h>
#include <Logger/ActivityLogger.h>
#include <Macho/Context.h>

namespace Utils {

template<class P>
struct ExtractionContext {
    Dyld::Context *dyldCtx;
    Macho::Context<false, P> *machoCtx;
    ActivityLogger *activity;
    std::shared_ptr<spdlog::logger> logger;
};

}; // namespace Utils

#endif // __UTILS_EXTRACTIONCONTEXT__