#ifndef __PROVIDER_SYMBOLIZER__
#define __PROVIDER_SYMBOLIZER__

#include <Dyld/Context.h>
#include <Logger/Activity.h>
#include <Macho/Context.h>
#include <Provider/Accelerator.h>
#include <fmt/format.h>

namespace DyldExtractor::Provider {

/// Provides symbolic info for a single address
class SymbolicInfo {
public:
  struct Symbol {
    /// The name of the symbol
    std::string name;
    /// The ordinal of the dylib the symbol comes from
    uint64_t ordinal;
    /// Export flags if the symbol was generated from export info
    std::optional<uint64_t> exportFlags;

    /// @brief If the symbol is a ReExport
    /// @returns false if exportFlags is not given
    bool isReExport() const;

    std::strong_ordering operator<=>(const Symbol &rhs) const;
  };

  enum class Encoding : uint8_t {
    None = 0b00,
    Arm = 0b00,
    Thumb = 0b01,
    Jazelle = 0b10,
    ThumbEE = 0b11
  };

  /// @brief Construct with one symbol
  SymbolicInfo(Symbol first, Encoding encoding);
  /// @brief Construct by copying symbols, must not be empty
  SymbolicInfo(std::set<Symbol> &symbols, Encoding encoding);
  /// @brief Construct by moving symbols, must not be empty
  SymbolicInfo(std::set<Symbol> &&symbols, Encoding encoding);

  void addSymbol(Symbol sym);

  /// @brief Get the preferred symbol
  const Symbol &preferredSymbol() const;

  std::set<Symbol> symbols;

  /// @brief The instruction set encoding. set by the first 2 LSBits. Only
  /// applies to ARMv7
  Encoding encoding;
};

template <class A> class Symbolizer {
  using P = A::P;
  using PtrT = P::PtrT;

public:
  Symbolizer(const Dyld::Context &dCtx, Macho::Context<false, P> &mCtx,
             Logger::Activity &activity, std::shared_ptr<spdlog::logger> logger,
             Provider::Accelerator<P> &accelerator);
  Symbolizer(const Symbolizer &) = delete;
  Symbolizer &operator=(const Symbolizer &) = delete;

  void enumerate();

  /// @brief Look for a symbol
  /// @param addr The address of the symbol. Without instruction bits.
  /// @return A pointer to the symbolic info or a nullptr
  const SymbolicInfo *symbolizeAddr(PtrT addr) const;

  /// @brief Check if an address has symbolic info
  /// @param addr The address without instruction bits
  /// @return If there is symbolic info
  bool containsAddr(PtrT addr) const;

  /// @brief Get a shared pointer for a symbolic info
  /// @param addr The address without instruction bits
  /// @return A new shared pointer
  std::shared_ptr<SymbolicInfo> shareInfo(PtrT addr) const;

private:
  void enumerateExports();
  void enumerateSymbols();

  using ExportEntry = Provider::AcceleratorTypes::SymbolizerExportEntry;
  using EntryMapT = Provider::AcceleratorTypes::SymbolizerExportEntryMapT;
  EntryMapT &
  processDylibCmd(const Macho::Loader::dylib_command *dylibCmd) const;
  std::vector<ExportInfoTrie::Entry>
  readExports(const std::string &dylibPath,
              const Macho::Context<true, P> &dylibCtx) const;

  const Dyld::Context *dCtx;
  Macho::Context<false, P> *mCtx;
  Logger::Activity *activity;
  std::shared_ptr<spdlog::logger> logger;
  Provider::Accelerator<P> *accelerator;

  std::map<PtrT, std::shared_ptr<SymbolicInfo>> symbols;
};

} // namespace DyldExtractor::Provider

template <>
struct fmt::formatter<DyldExtractor::Provider::SymbolicInfo::Symbol>
    : formatter<std::string> {
  template <typename FormatContext>
  auto format(DyldExtractor::Provider::SymbolicInfo::Symbol sym,
              FormatContext &ctx) {
    return formatter<std::string>::format(sym.name, ctx);
  }
};

#endif // __PROVIDER_SYMBOLIZER__