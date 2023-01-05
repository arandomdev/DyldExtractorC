#include "MetadataGenerator.h"

#include "Encoder/Encoder.h"
#include <Macho/Context.h>
#include <Objc/Abstraction.h>
#include <Utils/Utils.h>

using namespace DyldExtractor;
using namespace Converter;
using namespace Linkedit;

/// @brief Writes strings and symbol tables in the tracker
/// @tparam A
/// @param eCtx
template <class A> void writeSymbols(Utils::ExtractionContext<A> &eCtx) {
  using P = A::P;
  using PtrT = P::PtrT;
  using LETrackerMetadata = Provider::LinkeditTracker<P>::Metadata;
  using LETrackerTag = Provider::LinkeditTracker<P>::Tag;
  using STTrackerSymbolType = Provider::SymbolTableTracker<P>::SymbolType;

  eCtx.activity->update(std::nullopt, "Writing symbols");

  auto &mCtx = *eCtx.mCtx;
  auto logger = eCtx.logger;
  auto &leTracker = eCtx.leTracker.value();
  auto &stTracker = eCtx.stTracker.value();

  auto symtab = mCtx.getFirstLC<Macho::Loader::symtab_command>();
  auto dysymtab = mCtx.getFirstLC<Macho::Loader::dysymtab_command>();

  // Create string pool
  // Get size of pool and assign indicies
  auto &strings = stTracker.getStrings();

  uint32_t strSize = 0;
  uint32_t currentI = 1; // first string is \x00
  std::map<const std::string *, uint32_t> strIndicies;
  for (auto it = strings.cbegin(); it != strings.cend(); it++) {
    strIndicies[&(*it)] = currentI;
    strSize += (uint32_t)it->size();
    currentI += (uint32_t)it->size() + 1; // include null terminator
  }

  // add null terminator for each string, and 1 for the beginning \x00
  strSize += (uint32_t)strings.size() + 1;
  std::vector<uint8_t> strBuf(strSize, 0x0);
  auto strBufData = strBuf.data();

  // Copy strings
  for (auto &[it, offset] : strIndicies) {
    memcpy(strBufData + offset, it->c_str(), it->size());
  }

  // Create symbol table
  auto &syms = stTracker.getSymbolCaches();
  auto _symTypeOffset = [&syms](auto symType) -> uint32_t {
    switch (symType) {
    case STTrackerSymbolType::other:
      return 0;
    case STTrackerSymbolType::local:
      return (uint32_t)syms.other.size();
    case STTrackerSymbolType::external:
      return (uint32_t)(syms.other.size() + syms.local.size());
    case STTrackerSymbolType::undefined:
      return (uint32_t)(syms.other.size() + syms.local.size() +
                        syms.external.size());
    default:
      Utils::unreachable();
    }
  };

  const uint32_t nlistSize = (uint32_t)sizeof(Macho::Loader::nlist<P>);
  uint32_t nSyms = (uint32_t)(syms.other.size() + syms.local.size() +
                              syms.external.size() + syms.undefined.size());
  std::vector<Macho::Loader::nlist<P>> symsBuf;
  symsBuf.reserve(nSyms);

  // Write symbols
  auto _writeSyms = [&](auto &syms) {
    for (auto &[strIt, sym] : syms) {
      symsBuf.push_back(sym);
      symsBuf.back().n_un.n_strx = strIndicies[&(*strIt)];
    }
  };
  _writeSyms(syms.other);
  _writeSyms(syms.local);
  _writeSyms(syms.external);
  _writeSyms(syms.undefined);

  // Create indirect symbol table
  auto &indirectSymtab = stTracker.indirectSyms;
  std::vector<uint32_t> indirectSymtabBuf;
  indirectSymtabBuf.reserve(indirectSymtab.size());
  for (const auto &sym : indirectSymtab) {
    indirectSymtabBuf.push_back(_symTypeOffset(sym.first) + sym.second);
  }

  // Add new data to tracking
  LETrackerMetadata stringPoolMeta(
      LETrackerTag::stringPool, nullptr,
      Utils::align(strSize, (uint32_t)sizeof(PtrT)),
      reinterpret_cast<Macho::Loader::load_command *>(symtab));
  if (!leTracker.addData(stringPoolMeta, strBufData, strSize).second) {
    SPDLOG_LOGGER_ERROR(logger, "Not enough space to add string pool.");
    return;
  }
  symtab->strsize = strSize;

  LETrackerMetadata symtabMeta(
      LETrackerTag::symtab, nullptr,
      Utils::align(nSyms * nlistSize, (uint32_t)sizeof(PtrT)),
      reinterpret_cast<Macho::Loader::load_command *>(symtab));
  if (!leTracker
           .addData(symtabMeta, reinterpret_cast<uint8_t *>(symsBuf.data()),
                    nSyms * nlistSize)
           .second) {
    SPDLOG_LOGGER_ERROR(logger, "Not enough space to add symbol table.");
    return;
  }
  symtab->nsyms = nSyms;

  LETrackerMetadata indirectSymtabMeta(
      LETrackerTag::indirectSymtab, nullptr,
      Utils::align((uint32_t)(indirectSymtabBuf.size() * sizeof(uint32_t)),
                   (uint32_t)sizeof(PtrT)),
      reinterpret_cast<Macho::Loader::load_command *>(dysymtab));
  if (!leTracker
           .addData(indirectSymtabMeta,
                    reinterpret_cast<uint8_t *>(indirectSymtabBuf.data()),
                    (uint32_t)(indirectSymtabBuf.size() * sizeof(uint32_t)))
           .second) {
    SPDLOG_LOGGER_ERROR(logger,
                        "Not enough space to add indirect symbol table.");
    return;
  }
  dysymtab->nindirectsyms = (uint32_t)indirectSymtabBuf.size();

  // Set symbol indicies
  dysymtab->ilocalsym = _symTypeOffset(STTrackerSymbolType::local);
  dysymtab->nlocalsym = (uint32_t)syms.local.size();
  dysymtab->iextdefsym = _symTypeOffset(STTrackerSymbolType::external);
  dysymtab->nextdefsym = (uint32_t)syms.external.size();
  dysymtab->iundefsym = _symTypeOffset(STTrackerSymbolType::undefined);
  dysymtab->nundefsym = (uint32_t)syms.undefined.size();
}

template <class A>
void Converter::generateMetadata(Utils::ExtractionContext<A> &eCtx) {
  using P = A::P;

  eCtx.activity->update("Metadata Generator", "Starting Up");
  auto dyldInfo = eCtx.mCtx->getFirstLC<Macho::Loader::dyld_info_command>();

  if (!eCtx.leTracker || !eCtx.stTracker) {
    SPDLOG_LOGGER_ERROR(eCtx.logger,
                        "Metadata Generator depends on Linkedit Optimizer.");
    return;
  }

  // Check if new-style encoding can be used
  if constexpr (std::is_same_v<A, Utils::Arch::arm64>) {
    if (!dyldInfo) {
      Encoder::ChainedEncoder(eCtx).generateMetadata();
      writeSymbols(eCtx);
      eCtx.activity->update(std::nullopt, "Done");
      return;
    }
  }

  Encoder::generateLegacyMetadata(eCtx);
  writeSymbols(eCtx);
  eCtx.activity->update(std::nullopt, "Done");
}

#define X(T)                                                                   \
  template void Converter::generateMetadata<T>(Utils::ExtractionContext<T> &   \
                                               eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X