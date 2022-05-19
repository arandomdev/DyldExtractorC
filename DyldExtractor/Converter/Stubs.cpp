#include "Stubs.h"

#include "LinkeditOptimizer.h"
#include "slide.h"
#include <Macho/BindInfo.h>
#include <Utils/Accelerator.h>
#include <functional>
#include <spdlog/spdlog.h>

#pragma warning(push)
#pragma warning(disable : 4267)
#include <dyld/Trie.hpp>
#pragma warning(pop)

using namespace Converter;

#pragma region SymbolicSet
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
#pragma endregion SymbolicSet

#pragma region Symbolizer
template <class P>
Symbolizer<P>::Symbolizer(const Utils::ExtractionContext<P> &eCtx)
    : _eCtx(eCtx), _dCtx(eCtx.dCtx), _mCtx(eCtx.mCtx), _logger(eCtx.logger),
      _accelerator(eCtx.accelerator) {}

template <class P> void Symbolizer<P>::enumerate() {
    _eCtx.activity->update(std::nullopt, "Enumerating Symbols");
    _enumerateSymbols();
    _enumerateExports();
}

template <class P>
const SymbolicSet *Symbolizer<P>::symbolizeAddr(uint64_t addr) const {
    if (_symbols.contains(addr)) {
        return &_symbols.at(addr);
    } else {
        return nullptr;
    }
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
        std::string path((char *)(_dCtx.file + image->pathFileOffset));
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
    const std::string dylibPath(
        (char *)((uint8_t *)dylibCmd + dylibCmd->dylib.name.offset));
    if (imagesProcessed.contains(dylibPath)) {
        return imagesProcessed[dylibPath];
    } else if (_accelerator && _accelerator->exportsCache.contains(dylibPath)) {
        return _accelerator->exportsCache[dylibPath];
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

    if (_accelerator) {
        _accelerator->exportsCache[dylibPath] = exportsMap;
    }

    return exportsMap;
}

template <class P>
std::vector<ExportInfoTrie::Entry>
Symbolizer<P>::_readExports(const std::string &dylibPath,
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
#pragma endregion Symbolizer

#pragma region Arm64Utils
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
    Arm64Utils(const Utils::ExtractionContext<P> &eCtx);

    /// Get data for a stub resolver
    ///
    /// A stub resolver is a special helper that branches to a function that
    /// should be in the same image.
    ///
    /// @param addr The address of the resolver
    /// @returns An optional pair that contains the target of the resolver and
    ///     the size of the resolver in bytes.
    std::optional<std::pair<uint64_t, uint64_t>>
    getResolverData(const uint64_t addr) const;

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

    const Dyld::Context &_dCtx;
    const Utils::ExtractionContext<P> &_eCtx;
    const Converter::PointerTracker<P> *_ptrTracker;
    Utils::Accelerator<P> *_accelerator;

    using ResolverT = typename std::function<std::optional<uint64_t>(uint64_t)>;
    std::map<StubFormat, ResolverT> _stubResolvers;
    std::map<uint64_t, uint64_t> _resolvedChains;

    std::optional<uint64_t> _getStubNormalTarget(const uint64_t addr) const;
    std::optional<uint64_t> _getStubOptimizedTarget(const uint64_t addr) const;
    std::optional<uint64_t> _getAuthStubNormalTarget(const uint64_t addr) const;
    std::optional<uint64_t>
    _getAuthStubOptimizedTarget(const uint64_t addr) const;
    std::optional<uint64_t>
    _getAuthStubResolverTarget(const uint64_t addr) const;
    std::optional<uint64_t> _getResolverTarget(const uint64_t addr) const;
};

Arm64Utils::Arm64Utils(const Utils::ExtractionContext<P> &eCtx)
    : _eCtx(eCtx), _dCtx(eCtx.dCtx), _ptrTracker(eCtx.pointerTracker),
      _accelerator(eCtx.accelerator) {

    _stubResolvers = {
        {StubFormat::StubNormal,
         [this](uint64_t a) { return _getStubNormalTarget(a); }},
        {StubFormat::StubOptimized,
         [this](uint64_t a) { return _getStubOptimizedTarget(a); }},
        {StubFormat::AuthStubNormal,
         [this](uint64_t a) { return _getAuthStubNormalTarget(a); }},
        {StubFormat::AuthStubOptimized,
         [this](uint64_t a) { return _getAuthStubOptimizedTarget(a); }},
        {StubFormat::AuthStubResolver,
         [this](uint64_t a) { return _getAuthStubResolverTarget(a); }},
        {StubFormat::Resolver,
         [this](uint64_t a) { return _getResolverTarget(a); }}};
}

std::optional<std::pair<uint64_t, uint64_t>>
Arm64Utils::getResolverData(const uint64_t addr) const {
    /**
     * fd 7b bf a9  stp     x29,x30,[sp, #local_10]!
     * fd 03 00 91  mov     x29,sp
     * e1 03 bf a9  stp     x1,x0,[sp, #local_20]!
     * e3 0b bf a9  stp     x3,x2,[sp, #local_30]!
     * e5 13 bf a9  stp     x5,x4,[sp, #local_40]!
     * e7 1b bf a9  stp     x7,x6,[sp, #local_50]!
     * e1 03 bf 6d  stp     d1,d0,[sp, #local_60]!
     * e3 0b bf 6d  stp     d3,d2,[sp, #local_70]!
     * e5 13 bf 6d  stp     d5,d4,[sp, #local_80]!
     * e7 1b bf 6d  stp     d7,d6,[sp, #local_90]!
     * 5f d4 fe 97  bl      _vDSP_vadd
     * 70 e6 26 90  adrp    x16,0x1e38ba000
     * 10 02 0f 91  add     x16,x16,#0x3c0
     * 00 02 00 f9  str     x0,[x16]
     * f0 03 00 aa  mov     x16,x0
     * e7 1b c1 6c  ldp     d7,d6,[sp], #0x10
     * e5 13 c1 6c  ldp     d5,d4,[sp], #0x10
     * e3 0b c1 6c  ldp     d3,d2,[sp], #0x10
     * e1 03 c1 6c  ldp     d1,d0,[sp], #0x10
     * e7 1b c1 a8  ldp     x7,x6,[sp], #0x10
     * e5 13 c1 a8  ldp     x5,x4,[sp], #0x10
     * e3 0b c1 a8  ldp     x3,x2,[sp], #0x10
     * e1 03 c1 a8  ldp     x1,x0,[sp], #0x10
     * fd 7b c1 a8  ldp     x29=>local_10,x30,[sp], #0x10
     * 1f 0a 1f d6  braaz   x16

     * Because the format is not the same across iOS versions,
     * the following conditions are used to verify it.
     * * Starts with stp and mov
     * * A branch within an arbitrary threshold
     * * bl is in the middle
     * * adrp is directly after bl
     * * ldp is directly before the branch
     */

    const auto p = (const uint32_t *)_dCtx.convertAddrP(addr);
    if (p == nullptr) {
        return std::nullopt;
    }

    // Test stp and mov
    const auto stp = p[0];
    const auto mov = p[1];
    if ((stp & 0x7FC00000) != 0x29800000 || (mov & 0x7F3FFC00) != 0x11000000) {
        return std::nullopt;
    }

    // Find braaz instruction
    static const uint64_t SEARCH_LIMIT = 50; // 50 instructions
    const uint32_t *braazInstr = nullptr;
    for (auto i = p + 2; i < p + SEARCH_LIMIT; i++) {
        if ((*i & 0xFE9FF000) == 0xD61F0000) {
            braazInstr = i;
            break;
        }
    }
    if (braazInstr == nullptr) {
        return std::nullopt;
    }

    // Find bl instruction
    const uint32_t *blInstr = nullptr;
    for (auto i = p + 2; i < braazInstr; i++) {
        if ((*i & 0xFC000000) == 0x94000000) {
            blInstr = i;
            break;
        }
    }
    if (blInstr == nullptr) {
        return std::nullopt;
    }

    // Test adrp after bl and ldp before braaz
    const auto adrp = *(blInstr + 1);
    const auto ldp = *(braazInstr - 1);
    if ((adrp & 0x9F00001F) != 0x90000010 || (ldp & 0x7FC00000) != 0x28C00000) {
        return std::nullopt;
    }

    // Hopefully it's a resolver
    const int64_t imm = signExtend<int64_t, 28>((*blInstr & 0x3FFFFFF) << 2);
    const uint64_t blResult = addr + ((blInstr - p) * 4) + imm;

    const uint64_t size = ((braazInstr - p) * 4) + 4;
    return std::make_pair(blResult, size);
}

std::optional<std::pair<uint64_t, Arm64Utils::StubFormat>>
Arm64Utils::resolveStub(const uint64_t addr) const {
    for (auto &[format, resolver] : _stubResolvers) {
        if (auto res = resolver(addr); res != std::nullopt) {
            return std::make_pair(*res, format);
        }
    }

    return std::nullopt;
}

uint64_t Arm64Utils::resolveStubChain(const uint64_t addr) {
    if (_resolvedChains.contains(addr)) {
        return _resolvedChains[addr];
    } else if (_accelerator &&
               _accelerator->arm64ResolvedChains.contains(addr)) {
        return _accelerator->arm64ResolvedChains[addr];
    }

    uint64_t target = addr;
    while (true) {
        if (auto stubData = resolveStub(target); stubData != std::nullopt) {
            target = stubData->first;
        } else {
            break;
        }
    }

    _resolvedChains[addr] = target;
    if (_accelerator) {
        _accelerator->arm64ResolvedChains[addr] = target;
    }

    return target;
}

std::optional<uint64_t>
Arm64Utils::getStubHelperData(const uint64_t addr) const {
    auto p = (const uint32_t *)_dCtx.convertAddrP(addr);
    if (p == nullptr) {
        return std::nullopt;
    }

    // Verify
    const auto ldr = p[0];
    const auto b = p[1];
    if ((ldr & 0xBF000000) != 0x18000000 || (b & 0xFC000000) != 0x14000000) {
        return std::nullopt;
    }

    return p[2];
}

std::optional<uint64_t> Arm64Utils::getStubLdrAddr(const uint64_t addr) const {
    const auto p = (const uint32_t *)_dCtx.convertAddrP(addr);
    if (p == nullptr) {
        return std::nullopt;
    }

    // Verify
    const auto adrp = p[0];
    const auto ldr = p[1];
    const auto br = p[2];
    if ((adrp & 0x9F00001F) != 0x90000010 || (ldr & 0xFFC003FF) != 0xF9400210 ||
        br != 0xD61F0200) {
        return std::nullopt;
    }

    // adrp
    const uint64_t immlo = (adrp & 0x60000000) >> 29;
    const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
    const int64_t imm = signExtend<int64_t, 33>((immhi | immlo) << 12);
    const uint64_t adrpResult = (addr & ~0xFFF) + imm;

    // ldr
    const uint64_t offset = (ldr & 0x3FFC00) >> 7;
    return adrpResult + offset;
}

std::optional<uint64_t>
Arm64Utils::getAuthStubLdrAddr(const uint64_t addr) const {
    const auto p = (const uint32_t *)_dCtx.convertAddrP(addr);
    if (p == nullptr) {
        return std::nullopt;
    }

    // Verify
    const auto adrp = p[0];
    const auto add = p[1];
    const auto ldr = p[2];
    const auto braa = p[3];
    if ((adrp & 0x9F000000) != 0x90000000 || (add & 0xFFC00000) != 0x91000000 ||
        (ldr & 0xFFC00000) != 0xF9400000 || (braa & 0xFEFFF800) != 0xD61F0800) {
        return std::nullopt;
    }

    // adrp
    const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
    const uint64_t immlo = (adrp & 0x60000000) >> 29;
    const int64_t adrpImm = signExtend<int64_t, 33>((immhi | immlo) << 12);
    const uint64_t adrpResult = (addr & ~0xFFF) + adrpImm;

    // add
    const uint64_t addImm = (add & 0x3FFC00) >> 10;
    const uint64_t addResult = adrpResult + addImm;

    // ldr
    const uint64_t ldrImm = (ldr & 0x3FFC00) >> 7;
    return addResult + ldrImm;
}

void Arm64Utils::writeNormalStub(uint8_t *loc, const uint64_t stubAddr,
                                 const uint64_t ldrAddr) const {
    auto instructions = (uint32_t *)loc;

    // ADRP X16, lp@page
    const uint64_t adrpDelta = (ldrAddr & -4096) - (stubAddr & -4096);
    const uint64_t immhi = (adrpDelta >> 9) & (0x00FFFFE0);
    const uint64_t immlo = (adrpDelta << 17) & (0x60000000);
    instructions[0] = (uint32_t)((0x90000010) | immlo | immhi);

    // LDR X16, [X16, lp@pageoff]
    const uint64_t ldrOffset = ldrAddr - (ldrAddr & -4096);
    const uint64_t imm12 = (ldrOffset << 7) & 0x3FFC00;
    instructions[1] = (uint32_t)(0xF9400210 | imm12);

    // BR X16
    instructions[2] = 0xD61F0200;
}

void Arm64Utils::writeNormalAuthStub(uint8_t *loc, const uint64_t stubAddr,
                                     const uint64_t ldrAddr) const {
    auto instructions = (uint32_t *)loc;

    // ADRP X17, sp@page
    const uint64_t adrpDelta = (ldrAddr & -4096) - (stubAddr & -4096);
    const uint64_t immhi = (adrpDelta >> 9) & (0x00FFFFE0);
    const uint64_t immlo = (adrpDelta << 17) & (0x60000000);
    instructions[0] = (uint32_t)((0x90000011) | immlo | immhi);

    // ADD X17, [X17, sp@pageoff]
    const uint64_t addOffset = ldrAddr - (ldrAddr & -4096);
    const uint64_t imm12 = (addOffset << 10) & 0x3FFC00;
    instructions[1] = (uint32_t)(0x91000231 | imm12);

    // LDR X16, [X17, 0]
    instructions[2] = 0xF9400230;

    // BRAA X16
    instructions[3] = 0xD71F0A11;
}

std::optional<uint64_t>
Arm64Utils::_getStubNormalTarget(const uint64_t addr) const {
    /**
     * ADRP x16, page
     * LDR x16, [x16, pageoff] -> [Symbol pointer]
     * BR x16
     */

    const auto p = (const uint32_t *)_dCtx.convertAddrP(addr);
    if (p == nullptr) {
        return std::nullopt;
    }

    // Verify
    const auto adrp = p[0];
    const auto ldr = p[1];
    const auto br = p[2];
    if ((adrp & 0x9F00001F) != 0x90000010 || (ldr & 0xFFC003FF) != 0xF9400210 ||
        br != 0xD61F0200) {
        return std::nullopt;
    }

    // adrp
    const uint64_t immlo = (adrp & 0x60000000) >> 29;
    const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
    const int64_t imm = signExtend<int64_t, 33>((immhi | immlo) << 12);
    const uint64_t adrpResult = (addr & ~0xFFF) + imm;

    // ldr
    const uint64_t offset = (ldr & 0x3FFC00) >> 7;
    const uint64_t ldrTarget = adrpResult + offset;
    return _ptrTracker->slideP(ldrTarget);
}

std::optional<uint64_t>
Arm64Utils::_getStubOptimizedTarget(const uint64_t addr) const {
    /**
     * ADRP x16, page
     * ADD x16, x16, offset
     * BR x16
     */

    const auto p = (const uint32_t *)_dCtx.convertAddrP(addr);
    if (p == nullptr) {
        return std::nullopt;
    }

    // Verify
    const auto adrp = p[0];
    const auto add = p[1];
    const auto br = p[2];
    if ((adrp & 0x9F00001F) != 0x90000010 || (add & 0xFFC003FF) != 0x91000210 ||
        br != 0xD61F0200) {
        return std::nullopt;
    }

    // adrp
    const uint64_t immlo = (adrp & 0x60000000) >> 29;
    const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
    const int64_t imm = signExtend<int64_t, 33>((immhi | immlo) << 12);
    const uint64_t adrpResult = (addr & ~0xFFF) + imm;

    // add
    const uint64_t imm12 = (add & 0x3FFC00) >> 10;
    return adrpResult + imm12;
}

std::optional<uint64_t>
Arm64Utils::_getAuthStubNormalTarget(const uint64_t addr) const {
    /**
     * 91 59 11 90  adrp    x17,0x1e27e5000
     * 31 22 0d 91  add     x17,x17,#0x348
     * 30 02 40 f9  ldr     x16,[x17]=>->__auth_stubs::_CCRandomCopyBytes
     * 11 0a 1f d7  braa    x16=>__auth_stubs::_CCRandomCopyBytes,x17
     */

    const auto p = (const uint32_t *)_dCtx.convertAddrP(addr);
    if (p == nullptr) {
        return std::nullopt;
    }

    // Verify
    const auto adrp = p[0];
    const auto add = p[1];
    const auto ldr = p[2];
    const auto braa = p[3];
    if ((adrp & 0x9F000000) != 0x90000000 || (add & 0xFFC00000) != 0x91000000 ||
        (ldr & 0xFFC00000) != 0xF9400000 || (braa & 0xFEFFF800) != 0xD61F0800) {
        return std::nullopt;
    }

    // adrp
    const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
    const uint64_t immlo = (adrp & 0x60000000) >> 29;
    const int64_t adrpImm = signExtend<int64_t, 33>((immhi | immlo) << 12);
    const uint64_t adrpResult = (addr & ~0xFFF) + adrpImm;

    // add
    const uint64_t addImm = (add & 0x3FFC00) >> 10;
    const uint64_t addResult = adrpResult + addImm;

    // ldr
    const uint64_t ldrImm = (ldr & 0x3FFC00) >> 7;
    const uint64_t ldrTarget = addResult + ldrImm;
    return _ptrTracker->slideP(ldrTarget);
}

std::optional<uint64_t>
Arm64Utils::_getAuthStubOptimizedTarget(const uint64_t addr) const {
    /**
     * 1bfcb5d20 30 47 e2 90  adrp  x16,0x184599000
     * 1bfcb5d24 10 62 30 91  add   x16,x16,#0xc18
     * 1bfcb5d28 00 02 1f d6  br    x16=>LAB_184599c18
     * 1bfcb5d2c 20 00 20 d4  trap
     */

    const auto p = (const uint32_t *)_dCtx.convertAddrP(addr);
    if (p == nullptr) {
        return std::nullopt;
    }

    // Verify
    const auto adrp = p[0];
    const auto add = p[1];
    const auto br = p[2];
    const auto trap = p[3];
    if ((adrp & 0x9F000000) != 0x90000000 || (add & 0xFFC00000) != 0x91000000 ||
        br != 0xD61F0200 || trap != 0xD4200020) {
        return std::nullopt;
    }

    // adrp
    const uint64_t immlo = (adrp & 0x60000000) >> 29;
    const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
    const int64_t imm = signExtend<int64_t, 33>((immhi | immlo) << 12);
    const uint64_t adrpResult = (addr & ~0xFFF) + imm;

    const uint64_t imm12 = (add & 0x3FFC00) >> 10;
    return adrpResult + imm12;
}

std::optional<uint64_t>
Arm64Utils::_getAuthStubResolverTarget(const uint64_t addr) const {
    /**
     * 70 e6 26 b0  adrp    x16,0x1e38ba000
     * 10 e6 41 f9  ldr     x16,[x16, #0x3c8]
     * 1f 0a 1f d6  braaz   x16=>FUN_195bee070
     */

    const auto p = (const uint32_t *)_dCtx.convertAddrP(addr);
    if (p == nullptr) {
        return std::nullopt;
    }

    // Verify
    const auto adrp = p[0];
    const auto ldr = p[1];
    const auto braaz = p[2];
    if ((adrp & 0x9F000000) != 0x90000000 || (ldr & 0xFFC00000) != 0xF9400000 ||
        (braaz & 0xFEFFF800) != 0xD61F0800) {
        return std::nullopt;
    }

    // adrp
    const uint64_t immlo = (adrp & 0x60000000) >> 29;
    const uint64_t immhi = (adrp & 0xFFFFE0) >> 3;
    const int64_t imm = signExtend<int64_t, 33>((immhi | immlo) << 12);
    const uint64_t adrpResult = (addr & ~0xFFF) + imm;

    // ldr
    const uint64_t ldrImm = (ldr & 0x3FFC00) >> 7;
    const uint64_t ldrTarget = adrpResult + ldrImm;
    return _ptrTracker->slideP(ldrTarget);
}

std::optional<uint64_t>
Arm64Utils::_getResolverTarget(const uint64_t addr) const {
    // get the resolver target and strip away the size
    if (auto res = getResolverData(addr); res != std::nullopt) {
        return res->first;
    } else {
        return std::nullopt;
    }
}
#pragma endregion Arm64Utils

#pragma region StubFixer
template <class A> class StubFixer {
    using P = typename A::P;
    using ptr_t = typename P::ptr_t;

  public:
    StubFixer(Utils::ExtractionContext<P> &eCtx);
    void run();

  private:
    enum class _PtrSectType { lazy, nonLazy, nonLazyAuth };

    Utils::ExtractionContext<P> &_eCtx;
    Dyld::Context &_dCtx;
    Macho::Context<false, P> &_mCtx;
    std::shared_ptr<spdlog::logger> _logger;
    ActivityLogger *_activity;
    LinkeditTracker<P> *_linkeditTracker;
    PointerTracker<P> *_ptrTracker;

    Symbolizer<P> *_symbolizer;
    std::optional<Arm64Utils> _arm64Utils;

    // A map of pointer names to a list of available pointers
    std::multimap<std::string, uint64_t> _lazySymPtrs;
    std::multimap<std::string, uint64_t> _nonLazySymPtrs;
    std::multimap<std::string, uint64_t> _nonLazyAuthSymPtrs;
    // A map of pointers to their names
    std::multimap<uint64_t, std::string> _reverseLazySymPtrs;
    std::multimap<uint64_t, std::string> _reverseNonLazySymPtrs;
    std::multimap<uint64_t, std::string> _reverseNonLazyAuthSymPtrs;

    // A map of stub names and their address
    std::multimap<std::string, uint64_t> _stubMap;
    std::multimap<uint64_t, std::string> _reverseStubMap;

    uint8_t *_linkeditFile;
    Macho::Loader::dyld_info_command *_dyldInfo;
    Macho::Loader::symtab_command *_symtab;
    Macho::Loader::dysymtab_command *_dysymtab;

    void _preflightSections();

    void _scanSymbolPointers();
    std::optional<uint64_t> _resolveStubChain(const uint64_t addr);
    char *_lookupIndirectEntry(const uint64_t index);
    _PtrSectType _getPtrSectType(const auto sect) const;

    void _arm64FixStubHelpers();
    void _arm64FixStubs();
    void _arm64FixCallsites();

    void _fixIndirectSymbols();
};

template <class A>
StubFixer<A>::StubFixer(Utils::ExtractionContext<P> &eCtx)
    : _eCtx(eCtx), _dCtx(eCtx.dCtx), _mCtx(eCtx.mCtx), _logger(eCtx.logger),
      _activity(eCtx.activity), _linkeditTracker(eCtx.linkeditTracker),
      _ptrTracker(eCtx.pointerTracker),
      _symbolizer(new Symbolizer<A::P>(eCtx)) {
    if constexpr (std::is_same_v<A, Utils::Arch::arm64>) {
        _arm64Utils.emplace(eCtx);
    }
}

template <class A> void StubFixer<A>::run() {
    _symbolizer->enumerate();
    _eCtx.symbolizer = _symbolizer;

    _linkeditFile =
        _mCtx.convertAddr(_mCtx.getSegment("__LINKEDIT")->command->vmaddr)
            .second;
    _dyldInfo = _mCtx.getLoadCommand<false, Macho::Loader::dyld_info_command>();
    _symtab = _mCtx.getLoadCommand<false, Macho::Loader::symtab_command>();
    _dysymtab = _mCtx.getLoadCommand<false, Macho::Loader::dysymtab_command>();

    _preflightSections();
    _scanSymbolPointers();

    if constexpr (std::is_same_v<A, Utils::Arch::arm64>) {
        _arm64FixStubHelpers();
        _arm64FixStubs();
    }

    _fixIndirectSymbols();
}

template <class A> void StubFixer<A>::_preflightSections() {
    for (auto seg : _mCtx.segments) {
        for (auto sect : seg.sections) {
            if ((memcmp(sect->sectname, "__got", 6) == 0 ||
                 memcmp(sect->sectname, "__auth_got", 11) == 0) &&
                ((sect->flags & SECTION_TYPE) == 0)) {
                // Starting around iOS 16, S_NON_LAZY_SYMBOL_POINTERS is no
                // longer set
                sect->flags |= S_NON_LAZY_SYMBOL_POINTERS;
            }
        }
    }
}

template <class A> void StubFixer<A>::_scanSymbolPointers() {
    _activity->update(std::nullopt, "Caching Symbol Pointers");

    // read all bind info
    std::map<uint64_t, Macho::BindRecord> bindRecords;
    if (_dyldInfo) {
        std::vector<Macho::BindRecord> records;
        try {
            if (_dyldInfo->weak_bind_size) {
                const auto start = _linkeditFile + _dyldInfo->weak_bind_off;
                auto reader = Macho::BindInfoReader<P>(
                    start, start + _dyldInfo->weak_bind_size);
                while (reader) {
                    records.push_back(reader());
                }
            }

            if (_dyldInfo->lazy_bind_size) {
                const auto start = _linkeditFile + _dyldInfo->lazy_bind_off;
                auto reader = Macho::BindInfoReader<P>(
                    start, start + _dyldInfo->lazy_bind_size);
                while (reader) {
                    records.push_back(reader());
                }
            }

            for (auto &r : records) {
                const auto bindAddr =
                    _mCtx.segments[r.segIndex].command->vmaddr + r.segOffset;
                bindRecords[bindAddr] = r;
            }
        } catch (const std::invalid_argument &e) {
            SPDLOG_LOGGER_ERROR(_logger, "Error while parsing bind info, ",
                                e.what());
        }
    }

    for (auto &seg : _mCtx.segments) {
        for (auto &sect : seg.sections) {
            const auto ptrSize = sizeof(ptr_t);
            if ((sect->flags & SECTION_TYPE) == S_NON_LAZY_SYMBOL_POINTERS ||
                (sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS) {

                auto _sectType = _getPtrSectType(sect);
                auto addToCache = [_sectType, this](const char *sym,
                                                    const uint64_t addr) {
                    switch (_sectType) {
                    case _PtrSectType::lazy:
                        _lazySymPtrs.emplace(sym, addr);
                        _reverseLazySymPtrs.emplace(addr, sym);
                        break;
                    case _PtrSectType::nonLazy:
                        _nonLazySymPtrs.emplace(sym, addr);
                        _reverseNonLazySymPtrs.emplace(addr, sym);
                        break;
                    case _PtrSectType::nonLazyAuth:
                        _nonLazyAuthSymPtrs.emplace(sym, addr);
                        _reverseNonLazyAuthSymPtrs.emplace(addr, sym);
                        break;
                    }
                };

                const uint8_t *sectData = _mCtx.convertAddrP(sect->addr);
                const uint64_t sectAddr = sect->addr;
                for (uint64_t i = 0; i < (sect->size / ptrSize); i++) {
                    _activity->update();

                    const ptr_t *p = (ptr_t *)(sectData + i * ptrSize);
                    const uint64_t pAddr = sectAddr + i * ptrSize;

                    // Try with bind records
                    if (bindRecords.contains(pAddr)) {
                        addToCache(bindRecords[pAddr].symbolName, pAddr);
                        continue;
                    }

                    // Try with indirect symbol entries
                    // reserved1 contains the starting index
                    if (auto sym = _lookupIndirectEntry(sect->reserved1 + i);
                        sym) {
                        addToCache(sym, pAddr);
                        continue;
                    }

                    // though the pointer's target
                    const auto ptrTarget =
                        _resolveStubChain(_ptrTracker->slideP(pAddr));
                    if (auto set = _symbolizer->symbolizeAddr(*ptrTarget);
                        set) {
                        for (auto &sym : set->symbols) {
                            addToCache(sym.name.c_str(), pAddr);
                        }
                        continue;
                    }

                    // Skip special cases like __csbitmaps in CoreFoundation
                    if (_mCtx.containsAddr(pAddr)) {
                        continue;
                    }

                    SPDLOG_LOGGER_WARN(_logger,
                                       "Unable to symbolize pointer at 0x{:x}, "
                                       "with indirect entry index 0x{:x}, and "
                                       "with target function at 0x{:x}.",
                                       pAddr, sect->reserved1 + i, *ptrTarget);
                }
            }
        }
    }
}

template <class A>
std::optional<uint64_t> StubFixer<A>::_resolveStubChain(const uint64_t addr) {
    if constexpr (std::is_same_v<A, Utils::Arch::arm64>) {
        return _arm64Utils->resolveStubChain(addr);
    }

    return std::nullopt;
}

template <class A>
char *StubFixer<A>::_lookupIndirectEntry(const uint64_t index) {
    const auto indirectEntry =
        *((uint32_t *)(_linkeditFile + _dysymtab->indirectsymoff) + index);
    if (indirectEntry != 0 && indirectEntry != INDIRECT_SYMBOL_ABS &&
        indirectEntry != INDIRECT_SYMBOL_LOCAL &&
        indirectEntry != (INDIRECT_SYMBOL_ABS | INDIRECT_SYMBOL_LOCAL)) {
        // Indirect entry is an index into the symbol entries
        const auto symbolEntry =
            (Macho::Loader::nlist<P> *)(_linkeditFile + _symtab->symoff) +
            indirectEntry;
        return (char *)(_linkeditFile + _symtab->stroff +
                        symbolEntry->n_un.n_strx);
    }

    return nullptr;
}

template <class A>
StubFixer<A>::_PtrSectType
StubFixer<A>::_getPtrSectType(const auto sect) const {
    const bool _isLazy = (sect->flags & SECTION_TYPE) == S_LAZY_SYMBOL_POINTERS;
    const bool _isAuth = strstr(sect->sectname, "auth");
    if (_isLazy) {
        if (_isAuth) {
            SPDLOG_LOGGER_ERROR(_logger, "Unexpected section type.");
            return _PtrSectType::nonLazy;
        } else {
            return _PtrSectType::lazy;
        }
    } else {
        if (_isAuth) {
            return _PtrSectType::nonLazyAuth;
        } else {
            return _PtrSectType::nonLazy;
        }
    }
}

#pragma region StubFixer_arm64
template <class A> void StubFixer<A>::_arm64FixStubHelpers() {
    static const uint64_t STUB_BINDER_SIZE = 0x18;
    static const uint64_t REG_HELPER_SIZE = 0xc;

    const auto helperSect = _mCtx.getSection("__TEXT", "__stub_helper");
    if (!helperSect || !_dyldInfo) {
        return;
    } else if (!_dyldInfo->lazy_bind_size) {
        SPDLOG_LOGGER_WARN(_logger,
                           "Unable to fix stub helpers without lazy bind info");
        return;
    }

    _activity->update(std::nullopt, "Fixing Stub Helpers");

    const auto lazyBindStart =
        (const uint8_t *)(_linkeditFile + _dyldInfo->lazy_bind_off);
    const auto lazyBindEnd = lazyBindStart + _dyldInfo->lazy_bind_size;

    // The stub helper sect starts with a binder, skip it
    uint64_t helperAddr = helperSect->addr + STUB_BINDER_SIZE;
    const uint64_t helperEnd = helperSect->addr + helperSect->size;
    while (helperAddr < helperEnd) {
        _activity->update();

        if (const auto bindOff = _arm64Utils->getStubHelperData(helperAddr);
            bindOff) {
            auto record = Macho::BindInfoReader<P>(lazyBindStart + *bindOff,
                                                   lazyBindEnd)();

            // point the bind pointer to the stub helper
            const auto bindPtrP = _mCtx.convertAddrP(
                _mCtx.segments[record.segIndex].command->vmaddr +
                record.segOffset);
            *(uint64_t *)bindPtrP = helperAddr;
            helperAddr += REG_HELPER_SIZE;
            continue;
        }

        // It may be a resolver
        if (const auto resolverInfo = _arm64Utils->getResolverData(helperAddr);
            resolverInfo) {
            // shouldn't need fixing but check just in case
            if (!_mCtx.containsAddr(resolverInfo->first)) {
                SPDLOG_LOGGER_WARN(
                    _logger, "Stub resolver at 0x{:x} points outside of image.",
                    helperAddr);
            }

            helperAddr += resolverInfo->second;
            continue;
        }

        SPDLOG_LOGGER_ERROR(_logger, "Unknown stub helper format at 0x{:x}",
                            helperAddr);
        helperAddr += REG_HELPER_SIZE; // Try to recover, will probably fail
    }
}

template <class A> void StubFixer<A>::_arm64FixStubs() {
    _activity->update(std::nullopt, "Fixing Stubs");

    for (const auto &seg : _mCtx.segments) {
        for (const auto &sect : seg.sections) {
            if ((sect->flags & SECTION_TYPE) == S_SYMBOL_STUBS) {
                auto sectData = _mCtx.convertAddrP(sect->addr);

                for (uint64_t i = 0; i < (sect->size / sect->reserved2); i++) {
                    _activity->update();

                    const auto stubLoc = sectData + i * sect->reserved2;
                    const auto stubAddr = sect->addr + i * sect->reserved2;
                    const auto stubData = _arm64Utils->resolveStub(stubAddr);
                    if (!stubData) {
                        SPDLOG_LOGGER_ERROR(
                            _logger, "Unknown arm64 stub format at 0x{:x}",
                            stubAddr);
                        continue;
                    }
                    const auto [stubTarget, stubFormat] = *stubData;

                    // First symbolize the stub
                    std::string name;

                    // Though indirect entries
                    if (const auto sym =
                            _lookupIndirectEntry(sect->reserved1 + i);
                        sym) {
                        name = sym;
                    }

                    // though its pointer if not optimized
                    if (name.empty() &&
                        stubFormat == Arm64Utils::StubFormat::StubNormal) {
                        const auto targetPtr =
                            _arm64Utils->getStubLdrAddr(stubAddr);
                        if (auto names = _reverseLazySymPtrs.find(*targetPtr);
                            names != _reverseLazySymPtrs.end()) {
                            name = names->second;
                        }
                    }

                    // though its pointer if not optimized
                    if (name.empty() &&
                        stubFormat == Arm64Utils::StubFormat::AuthStubNormal) {
                        const auto targetPtr =
                            _arm64Utils->getAuthStubLdrAddr(stubAddr);
                        if (auto names =
                                _reverseNonLazyAuthSymPtrs.find(*targetPtr);
                            names != _reverseNonLazyAuthSymPtrs.end()) {
                            name = names->second;
                        }
                    }

                    // though its target
                    if (name.empty()) {
                        const auto targetFunc =
                            _arm64Utils->resolveStubChain(stubAddr);
                        const auto names =
                            _symbolizer->symbolizeAddr(targetFunc);
                        if (names != nullptr) {
                            name = names->preferredSymbol().name;
                        }
                    }

                    if (name.empty()) {
                        SPDLOG_LOGGER_WARN(_logger,
                                           "Unable to symbolize stub at 0x{:x}",
                                           stubAddr);
                        continue;
                    }

                    // Add to stub map
                    _stubMap.emplace(name, stubAddr);
                    _reverseStubMap.emplace(stubAddr, name);

                    // Fix the stub
                    switch (stubFormat) {
                    case Arm64Utils::StubFormat::StubNormal: {
                        // No fix needed
                        break;
                    }

                    case Arm64Utils::StubFormat::StubOptimized: {
                        if (const auto ptrs = _lazySymPtrs.find(name);
                            ptrs != _lazySymPtrs.end()) {
                            _arm64Utils->writeNormalStub(stubLoc, stubAddr,
                                                         ptrs->second);
                        } else if (const auto ptrs =
                                       _nonLazyAuthSymPtrs.find(name);
                                   sect->reserved2 == 0x10 &&
                                   ptrs != _nonLazyAuthSymPtrs.end()) {
                            // In older caches, optimized auth stubs resemble
                            // regular auth stubs
                            const auto ptrAddr = ptrs->second;
                            const auto ptrLoc = _mCtx.convertAddrP(ptrAddr);
                            _arm64Utils->writeNormalAuthStub(stubLoc, stubAddr,
                                                             ptrAddr);
                            *(uint64_t *)ptrLoc = stubAddr;
                        } else if (const auto ptrs = _nonLazySymPtrs.find(name);
                                   ptrs != _nonLazySymPtrs.end()) {
                            // Sometimes it's in the non lazy section?
                            _arm64Utils->writeNormalStub(stubLoc, stubAddr,
                                                         ptrs->second);
                        } else {
                            SPDLOG_LOGGER_ERROR(
                                _logger,
                                "Unable to find a pointer for an optimized "
                                "stub at 0x{:x}, with possible name, {}.",
                                stubAddr, name);
                        }
                        break;
                    }

                    case Arm64Utils::StubFormat::AuthStubNormal: {
                        if (const auto ptrAddr =
                                *_arm64Utils->getAuthStubLdrAddr(stubAddr);
                            _mCtx.containsAddr(ptrAddr)) {
                            // Only need to point the pointer to the stub
                            const auto ptrLoc = _mCtx.convertAddrP(ptrAddr);
                            // TODO: Shouldn't this be in PointerTracker
                            *(uint64_t *)ptrLoc = stubAddr;
                        } else {
                            // Find a pointer
                            if (const auto ptrs =
                                    _nonLazyAuthSymPtrs.find(name);
                                ptrs != _nonLazyAuthSymPtrs.end()) {
                                // Rewrite the stub and re-point the pointer
                                const auto ptrAddr = ptrs->second;
                                const auto ptrLoc = _mCtx.convertAddrP(ptrAddr);
                                _arm64Utils->writeNormalAuthStub(
                                    stubLoc, stubAddr, ptrAddr);
                                *(uint64_t *)ptrLoc = stubAddr;
                            } else {
                                SPDLOG_LOGGER_ERROR(
                                    _logger,
                                    "Unable to find a pointer for a normal "
                                    "auth stub at 0x{:x}, with possible name, "
                                    "{}.",
                                    stubAddr, name);
                            }
                        }
                        break;
                    }

                    case Arm64Utils::StubFormat::AuthStubOptimized: {
                        if (const auto ptrs = _nonLazyAuthSymPtrs.find(name);
                            ptrs != _nonLazyAuthSymPtrs.end()) {
                            const auto ptrAddr = ptrs->second;
                            const auto ptrLoc = _mCtx.convertAddrP(ptrAddr);
                            _arm64Utils->writeNormalAuthStub(stubLoc, stubAddr,
                                                             ptrAddr);
                            *(uint64_t *)ptrLoc = stubAddr;
                        } else {
                            SPDLOG_LOGGER_ERROR(
                                _logger,
                                "Unable to find a pointer for an optimized "
                                "stub at 0x{:x}, with possible name, {}.",
                                stubAddr, name);
                        }
                        break;
                    }

                    case Arm64Utils::StubFormat::AuthStubResolver: {
                        // Shouldn't need to fix but check just in case
                        if (!_mCtx.containsAddr(stubTarget)) {
                            SPDLOG_LOGGER_ERROR(
                                _logger, "Unable to fix auth stub resolver");
                        }
                        break;
                    }

                    case Arm64Utils::StubFormat::Resolver: {
                        // This shouldn't be here!?
                        SPDLOG_LOGGER_WARN(
                            _logger,
                            "Encountered a resolver in stubs section at 0x{:x}",
                            stubAddr);
                    }

                    default: {
                        SPDLOG_LOGGER_ERROR(
                            _logger, "Unknown stub format at 0x{:x}", stubAddr);
                        break;
                    }
                    }
                }
            }
        }
    }
}

template <class A> void StubFixer<A>::_arm64FixCallsites() {
    _activity->update(std::nullopt, "Fixing Callsites");

    const auto textSect = _mCtx.getSection("__TEXT", "__text");
    if (textSect == nullptr) {
        SPDLOG_LOGGER_WARN(_logger, "Unable to find text section");
        return;
    }

    const auto textAddr = textSect->addr;
    const auto textData = _mCtx.convertAddrP(textAddr);
    for (uint64_t sectOff = 0; sectOff < textSect->size; sectOff += 4) {
        /**
         * We are only looking for bl and b instructions only.
         * Theses instructions are only identical by their top
         * most byte.By only looking at the top byte, we can
         * save a lot of time.
         */
        const auto instrTop = (textData + sectOff + 3) & 0xFC;
        if (instrTop != 0x94 && instrTop != 0x14) {
            continue;
        }

        const auto brInstr = (uint32_t *)(textData + sectOff);
        const int64_t brOff =
            _arm64Utils->signExtend<int64_t, 28>((*brInstr & 0x3FFFFFF) << 2);
        const auto brTarget = textAddr + sectOff + brOff;

        // Check if it needs fixing
        if (_mCtx.containsAddr(brTarget)) {
            continue;
        }

        const auto brAddr = textAddr + sectOff;

        // Find a stub for the branch
        const auto names =
            _symbolizer->symbolizeAddr(_arm64Utils->resolveStubChain(brTarget));
        if (_stubMap.contains(names->preferredSymbol())) {
            const auto stubAddr =
                (*_stubMap.find(names->preferredSymbol().name)).second;
            const auto imm26 = ((int64_t)stubAddr - brAddr) >> 2;
            *brInstr = instrTop | imm26;
        } else {
            /**
             * Sometimes there are bytes of data in the text section
             * that match the bl and b filter, these seem to follow a
             * BR or other branch, skip these.
             */
            const auto lastInstrTop = (textData + sectOff - 1) & 0xFC;
            if (lastInstrTop == 0x94 || lastInstrTop == 0x14 ||
                lastInstrTop == 0xD6) {
                continue;
            }

            SPDLOG_LOGGER_WARN(
                _logger, "Unable to fix branch at 0x{:x}, targeting 0x{:x}",
                brAddr, brTarget);
        }

        _activity->update();
    }
}
#pragma endregion StubFixer_arm64

template <class A> void StubFixer<A>::_fixIndirectSymbols() {
    /**
     * Some files have indirect symbols that are redacted,
     * These are then pointed to the "redacted" symbol entry.
     * But disassemblers like Ghidra use these to symbolize
     * stubs and other pointers.
     */

    if (!_eCtx.redactedIndirectCount) {
        return;
    }

    _activity->update(std::nullopt, "Fixing Indirect Symbols");

    // S_NON_LAZY_SYMBOL_POINTERS
    // S_LAZY_SYMBOL_POINTERS
    // S_SYMBOL_STUBS
    // S_MOD_INIT_FUNC_POINTERS
    // S_MOD_TERM_FUNC_POINTERS
    // S_COALESCED
    // S_GB_ZEROFILL
    // S_INTERPOSING
    // S_16BYTE_LITERALS
    // S_DTRACE_DOF
    // S_LAZY_DYLIB_SYMBOL_POINTER

    auto indirectEntries =
        (uint32_t *)(_linkeditFile + _dysymtab->indirectsymoff);

    uint8_t *newEntries = (uint8_t *)calloc(_eCtx.redactedIndirectCount,
                                            sizeof(Macho::Loader::nlist<P>));
    uint32_t newEntriesHead = 0;
    std::vector<std::string> newStrings;
    uint32_t entryIndex = _dysymtab->iundefsym + _dysymtab->nundefsym;
    uint32_t stringsIndex = _symtab->strsize;

    for (const auto seg : _mCtx.segments) {
        for (const auto sect : seg.sections) {
            switch (sect->flags & SECTION_TYPE) {
            case S_NON_LAZY_SYMBOL_POINTERS:
            case S_LAZY_SYMBOL_POINTERS: {
                const auto sectType = _getPtrSectType(sect);

                auto ptrData = (ptr_t *)_mCtx.convertAddrP(sect->addr);
                auto ptrAddr = sect->addr;
                for (uint64_t i = 0; i < sect->size / sizeof(ptr_t);
                     i++, ptrAddr += 8, ptrData++) {
                    auto indirectEntry = indirectEntries + sect->reserved1 + i;
                    if (*indirectEntry != 0) {
                        continue;
                    }

                    std::optional<std::string> name;
                    switch (sectType) {
                    case _PtrSectType::lazy: {
                        if (auto names = _reverseLazySymPtrs.find(ptrAddr);
                            names != _reverseLazySymPtrs.end()) {
                            name = names->second;
                        }
                        break;
                    }
                    case _PtrSectType::nonLazy: {
                        if (auto names = _reverseNonLazySymPtrs.find(ptrAddr);
                            names != _reverseNonLazySymPtrs.end()) {
                            name = names->second;
                        }
                        break;
                    }
                    case _PtrSectType::nonLazyAuth: {
                        if (auto names =
                                _reverseNonLazyAuthSymPtrs.find(ptrAddr);
                            names != _reverseNonLazyAuthSymPtrs.end()) {
                            name = names->second;
                        }
                        break;
                    }
                    }
                    if (!name) {
                        SPDLOG_LOGGER_WARN(
                            _logger,
                            "Unable to symbolize pointer at 0x{:x}, for "
                            "redacted indirect entry with index {}",
                            ptrAddr, sect->reserved1 + i);
                        continue;
                    }

                    // Create new entry and add string
                    Macho::Loader::nlist<P> entry = {};
                    entry.n_type = 1;
                    entry.n_un.n_strx = stringsIndex;
                    const auto entryData = (uint8_t *)(&entry);

                    memcpy(newEntries + newEntriesHead, &entry,
                           sizeof(Macho::Loader::nlist<P>));
                    newStrings.push_back(*name);
                    *indirectEntry = entryIndex;

                    newEntriesHead += sizeof(Macho::Loader::nlist<P>);
                    entryIndex++;
                    stringsIndex += (uint32_t)name->length() + 1;
                }
                break;
            }

            case S_SYMBOL_STUBS: {
                auto stubAddr = sect->addr;
                for (uint64_t i = 0; i < sect->size / sect->reserved2;
                     i++, stubAddr += sect->reserved2) {
                    auto indirectEntry = indirectEntries + sect->reserved1 + i;
                    if (*indirectEntry != 0) {
                        continue;
                    }

                    std::string name;
                    if (const auto names = _reverseStubMap.find(stubAddr);
                        names != _reverseStubMap.end()) {
                        name = names->second;
                    } else {
                        SPDLOG_LOGGER_WARN(
                            _logger,
                            "Unable to symbolize stub at 0x{:x} for redacted "
                            "indirect entry with index {}",
                            stubAddr, sect->reserved1 + i);
                        continue;
                    }

                    // Create new entry and add string
                    Macho::Loader::nlist<P> entry = {};
                    entry.n_type = 1;
                    entry.n_un.n_strx = stringsIndex;
                    const auto entryData = (uint8_t *)(&entry);

                    memcpy(newEntries + newEntriesHead, &entry,
                           sizeof(Macho::Loader::nlist<P>));
                    newStrings.push_back(name);
                    *indirectEntry = entryIndex;

                    newEntriesHead += sizeof(Macho::Loader::nlist<P>);
                    entryIndex++;
                    stringsIndex += (uint32_t)name.length() + 1;
                }
                break;
            }

            case S_DTRACE_DOF: {
                break;
            }

            case S_MOD_INIT_FUNC_POINTERS:
            case S_MOD_TERM_FUNC_POINTERS:
            case S_COALESCED:
            case S_GB_ZEROFILL:
            case S_INTERPOSING:
            case S_16BYTE_LITERALS:
            case S_LAZY_DYLIB_SYMBOL_POINTERS: {
                SPDLOG_LOGGER_WARN(
                    _logger,
                    "Unable to indirect entries for section with type 0x{:x}",
                    sect->flags & SECTION_TYPE);
                break;
            }

            default:
                break;
            }
        }
    }

    // extend the
    const auto newStringsSize = stringsIndex - _symtab->strsize;
    auto stringData = _linkeditTracker->getLinkeditData(
        (uint8_t *)_symtab + offsetof(Macho::Loader::symtab_command, stroff));
    _linkeditTracker->resizeLinkeditData(*stringData,
                                         stringData->dataSize + newStringsSize);

    // Copy the new entries and strings
    memcpy((void *)(_linkeditFile + _symtab->symoff +
                    (_symtab->nsyms * sizeof(Macho::Loader::nlist<P>))),
           newEntries, newEntriesHead);

    uint32_t newStringsHead = 0;
    const uint8_t *newStringsData =
        _linkeditFile + _symtab->stroff + _symtab->strsize;
    for (const auto s : newStrings) {
        memcpy((void *)(newStringsData + newStringsHead), s.c_str(),
               s.size() + 1);
        newStringsHead += (uint32_t)s.size() + 1;
    }

    const uint32_t newEntriesCount =
        newEntriesHead / sizeof(Macho::Loader::nlist<P>);
    _symtab->nsyms += newEntriesCount;
    _symtab->strsize += newStringsSize;
    _dysymtab->nundefsym += newEntriesCount;

    auto linkeditSeg = _mCtx.getSegment("__LINKEDIT");
    linkeditSeg->command->vmsize += newStringsSize;
    linkeditSeg->command->filesize += newStringsSize;

    free(newEntries);
}

#pragma endregion StubFixer

template <class A>
void Converter::fixStubs(Utils::ExtractionContext<typename A::P> &eCtx) {
    eCtx.activity->update("Stub Fixer", "Starting Up");

    if (!eCtx.pointerTracker) {
        SPDLOG_LOGGER_ERROR(
            eCtx.logger,
            "Fixing stubs requires PointerTracker from processing slide info.");
        return;
    }

    if constexpr (std::is_same<A, Utils::Arch::arm>::value ||
                  std::is_same<A, Utils::Arch::arm64>::value ||
                  std::is_same<A, Utils::Arch::arm64_32>::value) {
        StubFixer<A>(eCtx).run();
    }

    // No stub fixing needed for x86_64
}

template class Symbolizer<Utils::Pointer32>;
template class Symbolizer<Utils::Pointer64>;

#define X(T)                                                                   \
    template void Converter::fixStubs<T>(Utils::ExtractionContext<T::P> & eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X
