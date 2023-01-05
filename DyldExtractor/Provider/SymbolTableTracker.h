#ifndef __PROVIDER__SYMBOLTABLETRACKER__
#define __PROVIDER__SYMBOLTABLETRACKER__

#include <Macho/Loader.h>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace DyldExtractor::Provider {

/// @brief Represents a dynamic symbol table
template <class P> class SymbolTableTracker {
public:
  enum class SymbolType { other, local, external, undefined };
  using StringCache = std::set<std::string>;
  using SymbolIndex = std::pair<SymbolType, uint32_t>;

  struct SymbolCaches {
    using SymbolCacheT = std::vector<
        std::pair<StringCache::const_iterator, Macho::Loader::nlist<P>>>;
    SymbolCacheT other;
    SymbolCacheT local;
    SymbolCacheT external;
    SymbolCacheT undefined;
  };

  SymbolTableTracker() = default;
  SymbolTableTracker(const SymbolTableTracker &) = delete;
  SymbolTableTracker(SymbolTableTracker &&) = default;
  SymbolTableTracker &operator=(const SymbolTableTracker &) = delete;
  SymbolTableTracker &operator=(SymbolTableTracker &&) = default;

  /// @brief Add a string
  const std::string &addString(const std::string &str);

  /// @brief Add a symbol
  /// @param type The type of symbol, string index does not have to be valid
  /// @param str The string associated with the symbol, must already be added
  /// @param sym The symbol metadata
  /// @returns The symbol type and index pair.
  SymbolIndex addSym(SymbolType type, const std::string &str,
                     const Macho::Loader::nlist<P> &sym);

  const std::pair<StringCache::const_iterator, Macho::Loader::nlist<P>> &
  getSymbol(const SymbolIndex &index) const;

  /// @brief Get tracked strings
  const StringCache &getStrings() const;

  /// @brief Get tracked symbols
  const SymbolCaches &getSymbolCaches() const;

  /// @brief Get or create a "<redacted> symbol with n_type=1"
  /// @return The symbol index
  SymbolIndex &getOrMakeRedactedSymIndex();
  const std::optional<SymbolIndex> &getRedactedSymIndex() const;

  // indirect symbols, the second pair element is the index into that group of
  // symbols
  std::vector<SymbolIndex> indirectSyms;

private:
  StringCache strings;
  SymbolCaches syms;

  std::optional<SymbolIndex> redactedSymIndex;
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER__SYMBOLTABLETRACKER__