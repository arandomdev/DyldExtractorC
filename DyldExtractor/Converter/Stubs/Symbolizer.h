#ifndef __CONVERTER_STUBS_SYMBOLIZER__
#define __CONVERTER_STUBS_SYMBOLIZER__

#include "SymbolicInfo.h"
#include <Utils/ExtractionContext.h>

namespace Converter {

template <class A> class Symbolizer {
  using P = A::P;

public:
  Symbolizer(const Utils::ExtractionContext<A> &eCtx);

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

  const Dyld::Context &dCtx;
  Macho::Context<false, P> &mCtx;
  ActivityLogger &activity;
  std::shared_ptr<spdlog::logger> logger;
  Utils::Accelerator<P> &accelerator;

  std::map<uint64_t, SymbolicInfo> symbols;
};

} // namespace Converter

#endif // __CONVERTER_STUBS_SYMBOLIZER__