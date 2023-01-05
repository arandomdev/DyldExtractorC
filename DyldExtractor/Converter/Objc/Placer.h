#ifndef __CONVERTER_OBJC_PLACER__
#define __CONVERTER_OBJC_PLACER__

#include "Walker.h"

namespace DyldExtractor::Converter::ObjcFixer {

template <class A> class Placer {
  using P = A::P;
  using PtrT = P::PtrT;

public:
  Placer(Utils::ExtractionContext<A> &eCtx, Walker<A> &walker);

  std::optional<Provider::ExtraData<P>> placeAll();

private:
  /// @brief Inserts a new segment for the extra data
  /// @return The name of the segment that the extra data extends and the
  ///   address of the extra data or 0 if it couldn't be allocated.
  std::pair<std::string, PtrT> allocateDataRegion();

  /// @brief Gives addresses to all atoms
  /// @returns The size of the extra data section
  PtrT placeAtoms(const PtrT exDataAddr);
  /// @brief Propagate all atoms
  void propagateAtoms();
  /// @brief Update data fields and write
  void writeAtoms(Provider::ExtraData<P> &exData);
  /// @brief Adds pointers to tracking
  void trackAtoms(Provider::ExtraData<P> &exData);

  /// @brief Checks if a bind has a symbol entry
  void checkBind(const std::shared_ptr<Provider::SymbolicInfo> &bind);

  Macho::Context<false, P> &mCtx;
  std::shared_ptr<spdlog::logger> logger;
  Provider::PointerTracker<P> &ptrTracker;
  Provider::LinkeditTracker<P> &leTracker;
  Provider::SymbolTableTracker<P> &stTracker;

  Walker<A> &walker;
};

} // namespace DyldExtractor::Converter::ObjcFixer

#endif // __CONVERTER_OBJC_PLACER__