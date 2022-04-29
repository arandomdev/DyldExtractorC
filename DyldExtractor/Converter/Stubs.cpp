#include "Stubs.h"

#include <spdlog/spdlog.h>

#pragma warning(push)
#pragma warning(disable : 4267)
#include <dyld/Trie.hpp>
#pragma warning(pop)

using namespace Converter;

bool SymbolicSet::Symbol::isReExport() const {
    // Check if has extended info
    if (flags && topLevelOrdinal) {
        return *flags & EXPORT_SYMBOL_FLAGS_REEXPORT;
    }

    return false;
}

bool SymbolicSet::Symbol::operator<(const SymbolicSet::Symbol &rhs) const {
    // Compare within the same group
    auto compGroup = [this, &rhs]() {
        if (flags != rhs.flags) {
            if (!flags || !rhs.flags) {
                // A flag is nullopt, use regular order
                return flags < rhs.flags;
            } else {
                // Reverse order flags, 0x0 (regular) is preferred
                return flags > rhs.flags;
            }
        } else if (topLevelOrdinal != rhs.topLevelOrdinal) {
            if (!topLevelOrdinal || !rhs.topLevelOrdinal) {
                // A ordinal is nullopt, use regular ordering
                return topLevelOrdinal < rhs.topLevelOrdinal;
            } else {
                // Reverse order ordinal, lowest preferred
                return topLevelOrdinal > rhs.topLevelOrdinal;
            }
        } else {
            return name < rhs.name;
        }
    };

    // rhs in symtab1 group
    if (!rhs.topLevelOrdinal) {
        if (topLevelOrdinal) {
            return false; // lhs in higher group
        } else {
            return compGroup();
        }
    }

    // rhs in symtab2 group
    if (!rhs.flags) {
        if (!topLevelOrdinal) {
            return true; // lhs in symtab1
        } else if (!flags) {
            return compGroup();
        } else {
            return false; // lhs in higher group
        }
    }

    // rhs in ReExport Group
    if (rhs.isReExport()) {
        if (!topLevelOrdinal || !flags) {
            return true; // lhs in lower group
        } else if (isReExport()) {
            return compGroup();
        } else {
            return false; // lhs in higher group
        }
    }

    // rhs in normal group
    if (!topLevelOrdinal || !flags || isReExport()) {
        return true; // lhs in lower group
    } else {
        return compGroup();
    }
}

void SymbolicSet::addSymbol(const Symbol sym) { symbols.insert(sym); }

const SymbolicSet::Symbol SymbolicSet::preferredSymbol() const {
    return *symbols.rbegin();
}

template <class P>
Symbolizer<P>::Symbolizer(const Utils::ExtractionContext<P> &eCtx)
    : _eCtx(eCtx), _dCtx(eCtx.dCtx), _mCtx(eCtx.mCtx), _logger(eCtx.logger) {}

template <class P> void Symbolizer<P>::enumerate() {
    _eCtx.activity->update(std::nullopt, "Enumerating Symbols");
    _enumerateSymbols();
    _enumerateExports();
}

template <class P> void Symbolizer<P>::_enumerateSymbols() {
    auto linkeditFile =
        _mCtx.convertAddr(_mCtx.getSegment("__LINKEDIT")->command->vmaddr)
            .second;

    auto symtab = _mCtx.getLoadCommand<false, Macho::Loader::symtab_command>();
    auto symbols = (Macho::Loader::nlist<P> *)(linkeditFile + symtab->symoff);
    auto symbolsEnd = symbols + symtab->nsyms;
    uint8_t *strings = linkeditFile + symtab->stroff;

    for (auto sym = symbols; sym < symbolsEnd; sym++) {
        _eCtx.activity->update();

        auto symAddr = sym->n_value;
        auto str = std::string((char *)(strings + sym->n_un.n_strx));

        if (symAddr == 0) {
            continue;
        } else if (!_mCtx.containsAddr(symAddr)) {
            SPDLOG_LOGGER_WARN(_eCtx.logger,
                               "Invalid address: {}, for string: {}", symAddr,
                               str);
        }

        _symbols[symAddr].addSymbol({str, std::nullopt, std::nullopt});
    }
};

template <class P> void Symbolizer<P>::_enumerateExports() {
    _ImagesProcessedT imagesProcessed;
    _PathToImagesT pathToImage;
    for (auto image : _dCtx.images) {
        std::string_view path((char *)(_dCtx.file + image->pathFileOffset));
        pathToImage[path] = image;
    }

    auto dylibs = _mCtx.getLoadCommand<true, Macho::Loader::dylib_command>();
    _eraseIDCmd(dylibs);
    for (int i = 0; i < dylibs.size(); i++) {
        const auto &exports =
            _processDylibCmd(dylibs[i], pathToImage, imagesProcessed);
        for (const auto &e : exports) {
            _symbols[e.address].addSymbol(
                {e.entry.name, e.entry.info.flags, i + 1});
        }
    }
}

template <class P>
Symbolizer<P>::_EntryMapT &
Symbolizer<P>::_processDylibCmd(const Macho::Loader::dylib_command *dylibCmd,
                                const _PathToImagesT &pathToImages,
                                _ImagesProcessedT &imagesProcessed) const {
    const std::string_view dylibPath(
        (char *)((uint8_t *)dylibCmd + dylibCmd->dylib.name.offset));
    if (imagesProcessed.contains(dylibPath)) {
        return imagesProcessed[dylibPath];
    }
    if (!pathToImages.contains(dylibPath)) {
        SPDLOG_LOGGER_WARN(_logger, "Unable to find image with path {}",
                           dylibPath);
        return imagesProcessed[dylibPath]; // Empty map
    }

    auto &exportsMap = imagesProcessed[dylibPath];

    // process exports
    const auto imageInfo = pathToImages.at(dylibPath);
    const auto dylibCtx = _dCtx.createMachoCtx<true, P>(imageInfo);
    const auto rawExports = _readExports(dylibPath, dylibCtx);
    std::map<uint64_t, std::vector<ExportInfoTrie::Entry>> reExports;
    for (const auto &e : rawExports) {
        if (e.info.flags & EXPORT_SYMBOL_FLAGS_REEXPORT) {
            reExports[e.info.other].push_back(e);
            continue;
        } else if (!e.info.address) {
            // Some exports like __objc_empty_vtable don't have an address?
            continue;
        }

        const auto eAddr = imageInfo->address + e.info.address;
        exportsMap.emplace(eAddr, e);

        if (e.info.flags & EXPORT_SYMBOL_FLAGS_STUB_AND_RESOLVER) {
            // The address points to the stub, while "other" points
            // to the function itself. Add the function as well.
            // TODO: We might need to add a reference to stub addr.
            const auto fAddr = imageInfo->address + e.info.other;
            exportsMap.emplace(fAddr, e);
        }
    }

    // Process ReExports
    auto dylibDeps =
        dylibCtx.getLoadCommand<true, Macho::Loader::dylib_command>();
    _eraseIDCmd(dylibDeps);
    for (const auto &[ordinal, exports] : reExports) {
        const auto ordinalCmd = dylibDeps[ordinal - 1];
        const auto &ordinalExports =
            _processDylibCmd(ordinalCmd, pathToImages, imagesProcessed);
        if (!ordinalExports.size()) {
            // In case the image was not found or if it didn't have any exports.
            continue;
        }

        for (const auto &e : exports) {
            // importName has the old symbol, otherwise it
            // is reexported under the same name.
            const auto importName =
                e.info.importName.length() ? e.info.importName : e.name;

            const auto it = ordinalExports.find(_ExportEntry(importName));
            if (it != ordinalExports.end()) {
                exportsMap.emplace((*it).address, e);
            } else {
                SPDLOG_LOGGER_WARN(
                    _logger,
                    "Unable to find parent export with name {}, for "
                    "ReExport with name {}",
                    importName, e.name);
            }
        }
    }

    // Process ReExports dylibs
    for (const auto &dep : dylibDeps) {
        if (dep->cmd == LC_REEXPORT_DYLIB) {
            // Use parent ordinal because symbols are reexported.
            const auto reExports =
                _processDylibCmd(dep, pathToImages, imagesProcessed);
            exportsMap.insert(reExports.begin(), reExports.end());
        }
    }

    return exportsMap;
}

template <class P>
std::vector<ExportInfoTrie::Entry>
Symbolizer<P>::_readExports(const std::string_view &dylibPath,
                            const Macho::Context<true, P> &dylibCtx) const {
    // read exports
    std::vector<ExportInfoTrie::Entry> exports;
    const uint8_t *exportsStart;
    const uint8_t *exportsEnd;
    const auto linkeditFile =
        dylibCtx.convertAddr(dylibCtx.getSegment("__LINKEDIT")->command->vmaddr)
            .second;
    const auto exportTrieCmd =
        dylibCtx.getLoadCommand<false, Macho::Loader::linkedit_data_command>(
            {LC_DYLD_EXPORTS_TRIE});
    const auto dyldInfo =
        dylibCtx.getLoadCommand<false, Macho::Loader::dyld_info_command>();
    if (exportTrieCmd) {
        exportsStart = linkeditFile + exportTrieCmd->dataoff;
        exportsEnd = exportsStart + exportTrieCmd->datasize;
    } else if (dyldInfo) {
        exportsStart = linkeditFile + dyldInfo->export_off;
        exportsEnd = exportsStart + dyldInfo->export_size;
    } else {
        SPDLOG_LOGGER_ERROR(_logger, "Unable to get exports for '{}'",
                            dylibPath);
        return exports;
    }

    if (exportsStart == exportsEnd) {
        // Some images like UIKIT don't have exports.
    } else if (!ExportInfoTrie::parseTrie(exportsStart, exportsEnd, exports)) {
        SPDLOG_LOGGER_ERROR(_logger, "Unable to read exports for '{}'",
                            dylibPath);
    }

    return exports;
}

template class Symbolizer<Utils::Pointer32>;
template class Symbolizer<Utils::Pointer64>;

template <class P> void Converter::fixStubs(Utils::ExtractionContext<P> &eCtx) {
    eCtx.activity->update("Stub Fixer", "Starting Up");
    eCtx.symbolizer = new Symbolizer<P>(eCtx);
    eCtx.symbolizer->enumerate();
}

template void Converter::fixStubs<Utils::Pointer32>(
    Utils::ExtractionContext<Utils::Pointer32> &eCtx);
template void Converter::fixStubs<Utils::Pointer64>(
    Utils::ExtractionContext<Utils::Pointer64> &eCtx);