#include "Stubs.h"

using namespace Converter;

template <class P>
Symbolizer<P>::Symbolizer(Utils::ExtractionContext<P> &eCtx)
    : _eCtx(eCtx), _dCtx(eCtx.dCtx), _mCtx(eCtx.mCtx) {}

template <class P> void Symbolizer<P>::enumerate() { enumerateSymbols(); }

template <class P> void Symbolizer<P>::enumerateSymbols() {
    auto linkeditFile =
        _mCtx.convertAddr(_mCtx.getSegment("__LINKEDIT").command->vmaddr)
            .second;

    auto symtab = _mCtx.getLoadCommand<false, Macho::Loader::symtab_command>();
    auto symbols = (Macho::Loader::nlist<P> *)(linkeditFile + symtab->symoff);
    auto symbolsEnd = symbols + symtab->nsyms;
    uint8_t *strings = linkeditFile + symtab->stroff;

    for (auto sym = symbols; sym < symbolsEnd; sym++) {
        _eCtx.activity->update();

        auto symAddr = sym->n_value;
        auto str = std::string(strings + sym->n_un.n_strx);

        if (symAddr == 0) {
            continue;
        } else if (!_mCtx.containsAddr(symAddr)) {
            _eCtx.logger->warn(std::format(
                "Invalid address: {}, for string: {}", symAddr, str));
        }

        if (_symbols.contains(symAddr)) {
            _symbols[symAddr].push_back(str);
        } else {
            _symbols[symAddr] = {str};
        }
    }
};

template <class P> void Converter::fixStubs(Utils::ExtractionContext<P> &eCtx) {
    eCtx.symbolizer = Symbolizer<P>(eCtx);
    eCtx.symbolizer->enumerate();
}