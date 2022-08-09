#ifndef __CONVERTER_OBJC_OBJCFIXER__
#define __CONVERTER_OBJC_OBJCFIXER__

#include <Utils/ExtractionContext.h>

namespace Converter {

template <class A> class ObjcFixer {
  using P = A::P;
  using PtrT = P::PtrT;

public:
  ObjcFixer(Utils::ExtractionContext<A> &eCtx);
  void fix();

private:
  bool detectMethodNameStorage();
  void allocateDataRegion();
  void processSections();

  std::pair<bool, PtrT> processClass(const PtrT cAddr,
                                     std::set<PtrT> processing_ = {});
  void processFutureClasses();

  const uint8_t *relMethodNameBaseLoc = nullptr;

  struct {
    using CacheT = std::map<PtrT, PtrT>;

    // processed class_t
    CacheT classes;

    /// A list of class pointers that need to be fixed after all classes are
    /// processed. The first of each pair is the address of the pointer, with
    /// the second being the original class target.
    CacheT futureClassFixes;
  } cache;

  const Dyld::Context &dCtx;
  Macho::Context<false, P> &mCtx;
  ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
  Provider::PointerTracker<P> &ptrTracker;
  Provider::Symbolizer<A> &symbolizer;
  Provider::ExtraData<P> &exObjc;
};

template <class A> void fixObjc(Utils::ExtractionContext<A> &eCtx);

} // namespace Converter

#endif // __CONVERTER_OBJC_OBJCFIXER__