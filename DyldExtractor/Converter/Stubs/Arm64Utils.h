#ifndef __CONVERTER_STUBS_ARM64UTILS__
#define __CONVERTER_STUBS_ARM64UTILS__

#include <Provider/PointerTracker.h>
#include <Utils/ExtractionContext.h>

namespace Converter {

template <class A> class Arm64Utils {
  using P = A::P;
  using PtrT = P::PtrT;
  using SPtrT = P::SPtrT;

public:
  enum class StubFormat {
    // Non optimized stub with a symbol pointer and a stub helper.
    StubNormal,
    // Optimized stub with a symbol pointer and a stub helper.
    StubOptimized,
    // Non optimized auth stub with a symbol pointer.
    AuthStubNormal,
    // Optimized auth stub with a branch to a function.
    AuthStubOptimized,
    // Non optimized auth stub with a symbol pointer and a resolver.
    AuthStubResolver,
    // A special stub helper with a branch to a function.
    Resolver
  };

  struct ResolverData {
    PtrT targetFunc;
    PtrT targetPtr;
    PtrT size;
  };

  Arm64Utils(const Utils::ExtractionContext<A> &eCtx);

  /// Check if it is a stub binder
  ///
  /// @param addr Address to the bind, usually start of the __stub_helper sect.
  /// @returns If it is or not.
  bool isStubBinder(const PtrT addr) const;

  /// Get data for a stub resolver
  ///
  /// A stub resolver is a special helper that branches to a function that
  /// should be in the same image.
  ///
  /// @param addr The address of the resolver
  /// @returns Optional resolver data
  std::optional<ResolverData> getResolverData(const PtrT addr) const;

  /// Get a stub's target and its format
  ///
  /// @param addr The address of the stub
  /// @returns An optional pair of the stub's target and its format.
  std::optional<std::pair<PtrT, StubFormat>> resolveStub(const PtrT addr) const;

  /// Resolve a stub chain
  ///
  /// @param addr The address of the first stub.
  /// @returns The address to the final target, usually a function but can be
  ///     addr or an address to a stub if the format is not known.
  PtrT resolveStubChain(const PtrT addr);

  /// Get the offset data of a stub helper.
  ///
  /// @param addr The address of the stub helper
  /// @returns The offset data or nullopt if it's not a regular stub helper.
  std::optional<PtrT> getStubHelperData(const PtrT addr) const;

  /// Get the address of the symbol pointer for a normal stub.
  ///
  /// @param addr The address of the stub
  /// @returns The address of the pointer, or nullopt.
  std::optional<PtrT> getStubLdrAddr(const PtrT addr) const;

  /// Get the address of the symbol pointer for a normal auth stub.
  ///
  /// @param addr The address of the stub
  /// @returns The address of the pointer, or nullopt.
  std::optional<PtrT> getAuthStubLdrAddr(const PtrT addr) const;

  /// Write a normal stub at the location.
  ///
  /// @param loc Where to write the stub
  /// @param stubAddr The address of the stub
  /// @param ldrAddr The address for the target load
  void writeNormalStub(uint8_t *loc, const PtrT stubAddr,
                       const PtrT ldrAddr) const;

  /// Write a normal auth stub at the location.
  ///
  /// @param loc Where to write the stub
  /// @param stubAddr The address of the stub
  /// @param ldrAddr The address for the target load
  void writeNormalAuthStub(uint8_t *loc, const PtrT stubAddr,
                           const PtrT ldrAddr) const;

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

private:
  friend class Utils::Accelerator<P>;

  const Dyld::Context &dCtx;
  Utils::Accelerator<P> &accelerator;
  const Provider::PointerTracker<P> &ptrTracker;

  using ResolverT = typename std::function<std::optional<PtrT>(PtrT)>;
  std::map<StubFormat, ResolverT> stubResolvers;

  std::optional<PtrT> getStubNormalTarget(const PtrT addr) const;
  std::optional<PtrT> getStubOptimizedTarget(const PtrT addr) const;
  std::optional<PtrT> getAuthStubNormalTarget(const PtrT addr) const;
  std::optional<PtrT> getAuthStubOptimizedTarget(const PtrT addr) const;
  std::optional<PtrT> getAuthStubResolverTarget(const PtrT addr) const;
  std::optional<PtrT> getResolverTarget(const PtrT addr) const;

  static PtrT getLdrOffset(const uint32_t ldrI);
};

}; // namespace Converter

#endif // __CONVERTER_STUBS_ARM64UTILS__