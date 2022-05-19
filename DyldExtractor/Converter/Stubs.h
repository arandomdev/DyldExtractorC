#ifndef __CONVERTER_STUBS__
#define __CONVERTER_STUBS__

#include <Utils/Accelerator.h>
#include <Utils/ExtractionContext.h>
#include <map>
#include <set>
#include <string_view>
#include <unordered_set>

#pragma warning(push)
#pragma warning(disable : 4267)
#include <dyld/Trie.hpp>
#pragma warning(pop)

namespace Converter {

struct SymbolicSet {
    struct Symbol {
        std::string name;

        std::optional<uint64_t> flags;
        std::optional<uint64_t> topLevelOrdinal;

        bool isReExport() const;

        /// Has a non trivial ordering
        ///
        /// Ordering is split into 4 groups, symtab1, symtab2, ReExport, and
        /// normal. In each group it is ordered by flags, ordinal and then
        /// name. Then any symbol with the same name are considered equal.
        /// The greater the symbol the more preferred it is.
        ///
        /// - symtab1 (no ordinal) -- flags, name
        /// - symtab2 (no flags) -- ordinal, name
        /// - ReExport (ReExport flag) -- flag, ordinal, name
        /// - Normal -- flag, ordinal, name
        ///
        /// @param rhs The symbol is compare against.
        bool operator<(const Symbol &rhs) const;
    };

    /// Symbols in the set, the last element is the most preferred. Should
    /// never be empty.
    std::set<Symbol> symbols;

    /// Add a symbol to the set
    ///
    /// @param sym The symbol to add
    void addSymbol(const Symbol sym);

    /// Get the current preferred symbol
    ///
    /// Preferred symbol might be changed if a symbol
    /// is added to the set.
    const Symbol preferredSymbol() const;
};

template <class P> class Symbolizer {
  public:
    Symbolizer(const Utils::ExtractionContext<P> &eCtx);

    void enumerate();
    const SymbolicSet *symbolizeAddr(uint64_t addr) const;

  private:
    friend class Utils::Accelerator<P>;

    /// Enumerate mCtx's symbols, I don't think this is too helpful though...
    void _enumerateSymbols();
    void _enumerateExports();

    static inline void _eraseIDCmd(auto &dylibs) {
        dylibs.erase(
            std::remove_if(dylibs.begin(), dylibs.end(),
                           [](auto d) { return d->cmd == LC_ID_DYLIB; }),
            dylibs.end());
    }

    struct _ExportEntry {
        uint64_t address;
        ExportInfoTrie::Entry entry;

        /// This constructor should only be used for searching
        _ExportEntry(std::string n) : address(0), entry(n, ExportInfo()) {}
        _ExportEntry(uint64_t a, ExportInfoTrie::Entry e)
            : address(a), entry(e) {}
    };

    const static inline auto _entryHash = [](const _ExportEntry &e) {
        return std::hash<std::string>{}(e.entry.name);
    };
    const static inline auto _entryEqual = [](const _ExportEntry &a,
                                              const _ExportEntry &b) {
        return a.entry.name == b.entry.name;
    };

    using _EntryMapT =
        std::unordered_multiset<_ExportEntry, decltype(_entryHash),
                                decltype(_entryEqual)>;
    using _PathToImagesT = std::map<std::string, const dyld_cache_image_info *>;
    using _ImagesProcessedT = std::map<std::string, _EntryMapT>;

    _EntryMapT &_processDylibCmd(const Macho::Loader::dylib_command *dylibCmd,
                                 const _PathToImagesT &pathToImages,
                                 _ImagesProcessedT &imagesProcessed) const;
    std::vector<ExportInfoTrie::Entry>
    _readExports(const std::string &dylibPath,
                 const Macho::Context<true, P> &dylibCtx) const;

    const Utils::ExtractionContext<P> &_eCtx;
    const Dyld::Context &_dCtx;
    Macho::Context<false, P> &_mCtx;
    std::shared_ptr<spdlog::logger> _logger;
    Utils::Accelerator<P> *_accelerator;

    std::map<uint64_t, SymbolicSet> _symbols;
};

template <class A> void fixStubs(Utils::ExtractionContext<typename A::P> &eCtx);

} // namespace Converter

#endif // __CONVERTER_STUBS__