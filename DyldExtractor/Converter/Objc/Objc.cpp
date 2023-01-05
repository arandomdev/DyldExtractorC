#include "Objc.h"
#include "Placer.h"
#include "Walker.h"

using namespace DyldExtractor;
using namespace Converter;
using namespace ObjcFixer;

template <class A> void fix(Utils::ExtractionContext<A> &eCtx) {
  auto &mCtx = *eCtx.mCtx;
  Walker<A> objcWalker(eCtx);
  Placer<A> objcPlacer(eCtx, objcWalker);

  Objc::image_info *objcImageInfo;
  if (auto sect = mCtx.getSection(nullptr, "__objc_imageinfo").second; sect) {
    objcImageInfo = (Objc::image_info *)mCtx.convertAddrP(sect->addr);
    if (!(objcImageInfo->flags & Objc::image_info::OptimizedByDyld)) {
      return; // Image not optimized
    }
  } else {
    // no objc
    return;
  }

  // Walk classes
  if (!objcWalker.walkAll()) {
    return;
  }

  if (auto exData = objcPlacer.placeAll(); exData) {
    eCtx.exObjc.emplace(std::move(*exData));
  } else {
    return;
  }

  // clear optimized by Dyld flag
  objcImageInfo->flags &= ~Objc::image_info::OptimizedByDyld;
}

template <class A> void Converter::fixObjc(Utils::ExtractionContext<A> &eCtx) {
  // Load Providers
  eCtx.bindInfo.load();

  if (!eCtx.symbolizer || !eCtx.leTracker || !eCtx.stTracker) {
    SPDLOG_LOGGER_ERROR(eCtx.logger,
                        "ObjC Fixer depends on Linkedit Optimizer");
    return;
  }

  eCtx.activity->update("ObjC Fixer");
  fix(eCtx);
}

#define X(T)                                                                   \
  template void Converter::fixObjc<T>(Utils::ExtractionContext<T> & eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm) X(Utils::Arch::arm64) X(Utils::Arch::arm64_32)
#undef X