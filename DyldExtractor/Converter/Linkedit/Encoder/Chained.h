#ifndef __CONVERTER_LINKEDIT_ENCODER_CHAINED__
#define __CONVERTER_LINKEDIT_ENCODER_CHAINED__

#include <Utils/ExtractionContext.h>
#include <functional>
#include <mach-o/fixup-chains.h>

namespace DyldExtractor::Converter::Linkedit::Encoder {

class Atom {
public:
  const char *name;
  uint32_t libOrdinal;
  bool weakImport;
};

class ChainedFixupBinds {
public:
  using EnumerationCallback = std::function<void(
      unsigned bindOrdinal, const Atom *importAtom, uint64_t addend)>;

  void ensureTarget(const Atom *atom, bool authPtr, uint64_t addend);
  uint32_t count() const;
  bool hasLargeAddends() const;
  bool hasHugeAddends() const;
  bool hasHugeSymbolStrings() const;
  void forEachBind(EnumerationCallback callback);
  uint32_t ordinal(const Atom *atom, uint64_t addend) const;
  void setMaxRebase(uint64_t max) { _maxRebase = max; }
  uint64_t maxRebase() const { return _maxRebase; }

private:
  struct AtomAndAddend {
    const Atom *atom;
    uint64_t addend;
  };
  std::unordered_map<const Atom *, uint32_t> _bindOrdinalsWithNoAddend;
  std::vector<AtomAndAddend> _bindsTargets;
  uint64_t _maxRebase = 0;
  bool _hasLargeAddends = false;
  bool _hasHugeAddends = false;
};

struct ChainedFixupPageInfo {
  std::vector<uint16_t> fixupOffsets;
  std::vector<uint16_t> chainOverflows;
};

struct ChainedFixupSegInfo {
  const char *name;
  uint64_t startAddr;
  uint64_t endAddr;
  uint32_t fileOffset;
  uint32_t pageSize;
  uint32_t pointerFormat;
  std::vector<ChainedFixupPageInfo> pages;
};

/// @brief Generated rebase and bind info using the new chained pointers method,
///   only supports arm64 and arm64e. This can not be used for arm and arm64_32
///   because pointers are too big to fit.
class ChainedEncoder {
  using A = Utils::Arch::arm64;
  using P = A::P;
  using PtrT = P::PtrT;

  using LETrackerTag = Provider::LinkeditTracker<P>::Tag;

public:
  ChainedEncoder(Utils::ExtractionContext<A> &eCtx);

  void generateMetadata();

private:
  /// @brief fixup pointers and set their targets
  void fixupPointers();

  /// @brief Builds chains info
  void buildChainedFixupInfo();

  /// @brief Encodes linkedit data.
  /// @return The linkedit data, pointer aligned
  std::vector<uint8_t> encodeChainedInfo();

  /// @brief applies and chains pointers together, must be ran after
  /// `encodeChainedInfo` and linkedit data is added.
  void applyChainedFixups();

  uint16_t chainedPointerFormat() const;
  void fixup64();
  void fixup64e();

  Macho::Context<false, P> &mCtx;
  Provider::ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
  Provider::PointerTracker<P> &ptrTracker;
  Provider::LinkeditTracker<P> &leTracker;
  Provider::SymbolTableTracker<P> &stTracker;
  std::optional<Provider::ExtraData<P>> &exObjc;

  ChainedFixupBinds chainedFixupBinds;
  std::vector<ChainedFixupSegInfo> chainedFixupSegments;

  // Map of symbolic info to atoms
  std::map<std::shared_ptr<Provider::SymbolicInfo>, Atom> atomMap;
  // Map of bind address to atoms
  std::map<PtrT, Atom *> bindToAtoms;
};

} // namespace DyldExtractor::Converter::Linkedit::Encoder

#endif // __CONVERTER_LINKEDIT_ENCODER_CHAINED__
