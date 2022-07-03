#ifndef __CONVERTER_STUBS_ARM64UTILS__
#define __CONVERTER_STUBS_ARM64UTILS__

#include <Provider/PointerTracker.h>
#include <Utils/ExtractionContext.h>

namespace Converter {

class Arm64Utils {
  using P = typename Utils::Arch::arm64::P;

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
    uint64_t targetFunc;
    uint64_t targetPtr;
    uint64_t size;
  };

  Arm64Utils(const Utils::ExtractionContext<P> &eCtx);

  /// Check if it is a stub binder
  ///
  /// @param addr Address to the bind, usually start of the __stub_helper sect.
  /// @returns If it is or not.
  bool isStubBinder(const uint64_t addr) const;

  /// Get data for a stub resolver
  ///
  /// A stub resolver is a special helper that branches to a function that
  /// should be in the same image.
  ///
  /// @param addr The address of the resolver
  /// @returns An optional pair that contains the target of the resolver and
  ///     the size of the resolver in bytes.
  std::optional<ResolverData> getResolverData(const uint64_t addr) const;

  /// Get a stub's target and its format
  ///
  /// @param addr The address of the stub
  /// @returns An optional pair of the stub's target and its format.
  std::optional<std::pair<uint64_t, StubFormat>>
  resolveStub(const uint64_t addr) const;

  /// Resolve a stub chain
  ///
  /// @param addr The address of the first stub.
  /// @returns The address to the final target, usually a function but can be
  ///     addr or an address to a stub if the format is not known.
  uint64_t resolveStubChain(const uint64_t addr);

  /// Get the offset data of a stub helper.
  ///
  /// @param addr The address of the stub helper
  /// @returns The offset data or nullopt if it's not a regular stub helper.
  std::optional<uint64_t> getStubHelperData(const uint64_t addr) const;

  /// Get the address of the symbol pointer for a normal stub.
  ///
  /// @param addr The address of the stub
  /// @returns The address of the pointer, or nullopt.
  std::optional<uint64_t> getStubLdrAddr(const uint64_t addr) const;

  /// Get the address of the symbol pointer for a normal auth stub.
  ///
  /// @param addr The address of the stub
  /// @returns The address of the pointer, or nullopt.
  std::optional<uint64_t> getAuthStubLdrAddr(const uint64_t addr) const;

  /// Write a normal stub at the location.
  ///
  /// @param loc Where to write the stub
  /// @param stubAddr The address of the stub
  /// @param ldrAddr The address for the target load
  void writeNormalStub(uint8_t *loc, const uint64_t stubAddr,
                       const uint64_t ldrAddr) const;

  /// Write a normal auth stub at the location.
  ///
  /// @param loc Where to write the stub
  /// @param stubAddr The address of the stub
  /// @param ldrAddr The address for the target load
  void writeNormalAuthStub(uint8_t *loc, const uint64_t stubAddr,
                           const uint64_t ldrAddr) const;

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
  const Provider::PointerTracker<P> ptrTracker;

  using ResolverT = typename std::function<std::optional<uint64_t>(uint64_t)>;
  std::map<StubFormat, ResolverT> stubResolvers;
  std::map<uint64_t, uint64_t> resolvedChains;

  std::optional<uint64_t> getStubNormalTarget(const uint64_t addr) const;
  std::optional<uint64_t> getStubOptimizedTarget(const uint64_t addr) const;
  std::optional<uint64_t> getAuthStubNormalTarget(const uint64_t addr) const;
  std::optional<uint64_t> getAuthStubOptimizedTarget(const uint64_t addr) const;
  std::optional<uint64_t> getAuthStubResolverTarget(const uint64_t addr) const;
  std::optional<uint64_t> getResolverTarget(const uint64_t addr) const;
};

}; // namespace Converter

#endif // __CONVERTER_STUBS_ARM64UTILS__