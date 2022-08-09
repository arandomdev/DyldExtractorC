#ifndef __PROVIDER_SYMBOLIZER__
#define __PROVIDER_SYMBOLIZER__

#include <Dyld/Context.h>
#include <Logger/ActivityLogger.h>
#include <Macho/Context.h>
#include <Utils/Accelerator.h>
#include <fmt/format.h>

namespace Provider {

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

  /// @brief Construct with one symbol
  SymbolicInfo(Symbol first);
  /// @brief Construct by copying symbols, must not be empty
  SymbolicInfo(std::set<Symbol> &symbols);
  /// @brief Construct by moving symbols, must not be empty
  SymbolicInfo(std::set<Symbol> &&symbols);

  void addSymbol(Symbol sym);

  /// @brief Get the preferred symbol
  const Symbol &preferredSymbol() const;

  std::set<Symbol> symbols;
};

template <class A> class Symbolizer {
  using P = A::P;

public:
  Symbolizer(const Dyld::Context &dCtx, Macho::Context<false, P> &mCtx,
             ActivityLogger &activity, std::shared_ptr<spdlog::logger> logger,
             Utils::Accelerator<P> &accelerator);
  Symbolizer(const Symbolizer &o) = delete;
  Symbolizer(Symbolizer &&o) = default;
  Symbolizer &operator=(const Symbolizer &o) = delete;
  Symbolizer &operator=(Symbolizer &&o) = default;
  ~Symbolizer() = default;

  void enumerate();
  const SymbolicInfo *symbolizeAddr(uint64_t addr) const;

private:
  void enumerateExports();
  void enumerateSymbols();

  using ExportEntry = Utils::AcceleratorTypes::SymbolizerExportEntry;
  using EntryMapT = Utils::AcceleratorTypes::SymbolizerExportEntryMapT;
  EntryMapT &
  processDylibCmd(const Macho::Loader::dylib_command *dylibCmd) const;
  std::vector<ExportInfoTrie::Entry>
  readExports(const std::string &dylibPath,
              const Macho::Context<true, typename A::P> &dylibCtx) const;

  const Dyld::Context *dCtx;
  Macho::Context<false, P> *mCtx;
  ActivityLogger *activity;
  std::shared_ptr<spdlog::logger> logger;
  Utils::Accelerator<P> *accelerator;

  std::map<uint64_t, SymbolicInfo> symbols;
};

} // namespace Provider

template <>
struct fmt::formatter<Provider::SymbolicInfo::Symbol> : formatter<std::string> {
  template <typename FormatContext>
  auto format(Provider::SymbolicInfo::Symbol sym, FormatContext &ctx) {
    return formatter<std::string>::format(sym.name, ctx);
  }
};

#endif // __PROVIDER_SYMBOLIZER__