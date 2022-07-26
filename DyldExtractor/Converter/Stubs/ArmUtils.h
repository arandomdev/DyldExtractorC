#ifndef __CONVERTER_STUBS_ARMUTILS__
#define __CONVERTER_STUBS_ARMUTILS__

#include <Dyld/Context.h>
#include <Utils/Architectures.h>
#include <Utils/ExtractionContext.h>

namespace Converter {

class ArmUtils {
  using A = Utils::Arch::arm;
  using P = Utils::Pointer32;
  using PtrT = P::PtrT;

public:
  enum class StubFormat {
    normalV4,    // __picsymbolstub4, not optimized
    optimizedV5, // __picsymbolstub5, optimized
    resolver     // __stub_helper
  };

  struct ResolverData {
    PtrT targetFunc;
    PtrT targetPtr;
    PtrT size;
  };

  struct StubBinderInfo {
    PtrT privatePtr;
    PtrT size;
  };

  ArmUtils(Utils::ExtractionContext<A> &eCtx);

  /// Sign extend a number
  ///
  /// @tparam T The type of the number
  /// @tparam B The number of bits
  /// @returns The number sign extended.
  template <typename T, unsigned B> static inline T signExtend(const T x) {
    struct {
      T x : B;
    } s;
    return s.x = x;
  };

  /// Check if it is a stub binder
  ///
  /// @param addr Address to the bind, usually start of the __stub_helper sect.
  /// @returns If it is or not.
  std::optional<StubBinderInfo> isStubBinder(PtrT addr) const;

  /// Get the stub helper data
  ///
  /// @param addr The address of the stub helper
  /// @returns The stub data, or nullopt if the format is incorrect.
  std::optional<PtrT> getStubHelperData(PtrT addr) const;

  /// Get resolver data
  ///
  /// Resolver data is a special helper that should branch to a function within
  /// its own image.
  /// @param addr the address of the stub helper
  /// @returns Optional resolver data
  std::optional<ResolverData> getResolverData(PtrT addr) const;

  /// Resolve a stub chain
  ///
  /// @param addr The address of the beginning of the chain
  /// @returns The last known node of the chain. Can fail to properly resolve
  ///   if the format is not known.
  PtrT resolveStubChain(const PtrT addr);

  /// Get a stub's target and its format
  ///
  /// @param addr The address of the stub
  /// @returns An optional pair of the stub's target and its format.
  std::optional<std::pair<PtrT, StubFormat>> resolveStub(const PtrT addr) const;

  /// Get the ldr address of a normal V4 stub
  ///
  /// @param addr The address of the stub
  /// @returns The target address or nullopt
  std::optional<PtrT> getNormalV4LdrAddr(PtrT addr) const;

  /// Write a normal V4 stub at the location.
  ///
  /// @param loc Where to write the stub
  /// @param stubAddr The address of the stub
  /// @param ldrAddr The address for the target load
  void writeNormalV4Stub(uint8_t *loc, const PtrT stubAddr,
                         const PtrT ldrAddr) const;

private:
  std::optional<PtrT> getNormalV4Target(PtrT addr) const;
  std::optional<PtrT> getOptimizedV5Target(PtrT addr) const;
  std::optional<PtrT> getResolverTarget(PtrT addr) const;

  Dyld::Context &dCtx;
  Utils::Accelerator<P> &accelerator;
  const Provider::PointerTracker<P> &ptrTracker;

  using ResolverT = typename std::function<std::optional<PtrT>(PtrT)>;
  std::map<StubFormat, ResolverT> stubResolvers;
};

} // namespace Converter

#endif // __CONVERTER_STUBS_ARMUTILS__