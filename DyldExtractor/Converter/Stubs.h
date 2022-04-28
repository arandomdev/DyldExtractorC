#ifndef __CONVERTER_STUBS__
#define __CONVERTER_STUBS__

#include <Utils/ExtractionContext.h>
#include <map>

namespace Converter {

template <class P> class Symbolizer {
  public:
    Symbolizer(Utils::ExtractionContext<P> &eCtx);

    void enumerate();

  private:
    void enumerateSymbols();
    void enumerateExports();

    Utils::ExtractionContext<P> &_eCtx;
    Dyld::Context &_dCtx;
    Macho::Context<false, P> &_mCtx;

    std::map<uint64_t, std::vector<std::string>> _symbols;
};

template <class P> void fixStubs(Utils::ExtractionContext<P> &eCtx);

} // namespace Converter

#endif // __CONVERTER_STUBS__