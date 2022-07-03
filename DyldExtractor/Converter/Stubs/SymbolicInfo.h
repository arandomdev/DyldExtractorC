#ifndef __CONVERTER_STUBS_SYMBOLICINFO__
#define __CONVERTER_STUBS_SYMBOLICINFO__

#include <fmt/format.h>
#include <optional>
#include <set>
#include <string>

namespace Converter {

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

    /// If the symbol is a ReExport
    ///
    /// @returns false if exportFlags is not given
    bool isReExport() const;

    std::strong_ordering operator<=>(const Symbol &rhs) const;
  };

  /// Construct with one symbol
  SymbolicInfo(Symbol first);
  /// Construct by copying symbols, must not be empty
  SymbolicInfo(std::set<Symbol> &symbols);
  /// Construct by moving symbols, must not be empty
  SymbolicInfo(std::set<Symbol> &&symbols);

  void addSymbol(Symbol sym);

  /// Get the preferred symbol
  const Symbol &preferredSymbol() const;

  std::set<Symbol> symbols;
};

} // namespace Converter

template <>
struct fmt::formatter<Converter::SymbolicInfo::Symbol>
    : formatter<std::string> {
  template <typename FormatContext>
  auto format(Converter::SymbolicInfo::Symbol sym, FormatContext &ctx) {
    return formatter<std::string>::format(sym.name, ctx);
  }
};

#endif // __CONVERTER_STUBS_SYMBOLICINFO__