#include "SymbolTableTracker.h"

#include <Utils/Utils.h>

using namespace DyldExtractor;
using namespace Provider;

template <class P>
const std::string &SymbolTableTracker<P>::addString(const std::string &str) {
  return *strings.insert(str).first;
}

template <class P>
SymbolTableTracker<P>::SymbolIndex
SymbolTableTracker<P>::addSym(SymbolType type, const std::string &str,
                              const Macho::Loader::nlist<P> &sym) {
  auto it = strings.find(str);
  uint32_t index;
  switch (type) {
  case SymbolType::other:
    index = (uint32_t)syms.other.size();
    syms.other.emplace_back(it, sym);
    break;
  case SymbolType::local:
    index = (uint32_t)syms.local.size();
    syms.local.emplace_back(it, sym);
    break;
  case SymbolType::external:
    index = (uint32_t)syms.external.size();
    syms.external.emplace_back(it, sym);
    break;
  case SymbolType::undefined:
    index = (uint32_t)syms.undefined.size();
    syms.undefined.emplace_back(it, sym);
    break;
  default:
    Utils::unreachable();
  }

  return std::make_pair(type, index);
}

template <class P>
const std::pair<std::set<std::string>::const_iterator, Macho::Loader::nlist<P>>
    &SymbolTableTracker<P>::getSymbol(const SymbolIndex &index) const {
  switch (index.first) {
  case SymbolType::other:
    return syms.other.at(index.second);
  case SymbolType::local:
    return syms.local.at(index.second);
  case SymbolType::external:
    return syms.external.at(index.second);
  case SymbolType::undefined:
    return syms.undefined.at(index.second);
  default:
    Utils::unreachable();
  }
}

template <class P>
const typename SymbolTableTracker<P>::StringCache &
SymbolTableTracker<P>::getStrings() const {
  return strings;
}

template <class P>
const typename SymbolTableTracker<P>::SymbolCaches &
SymbolTableTracker<P>::getSymbolCaches() const {
  return syms;
}

template <class P>
typename SymbolTableTracker<P>::SymbolIndex &
SymbolTableTracker<P>::getOrMakeRedactedSymIndex() {
  if (redactedSymIndex) {
    return *redactedSymIndex;
  }

  auto &str = addString("<redacted>");
  Macho::Loader::nlist<P> sym = {0};
  sym.n_type = 1;
  return redactedSymIndex.emplace(addSym(SymbolType::other, str, sym));
}

template <class P>
const std::optional<typename SymbolTableTracker<P>::SymbolIndex> &
SymbolTableTracker<P>::getRedactedSymIndex() const {
  return redactedSymIndex;
}

template class SymbolTableTracker<Utils::Arch::Pointer32>;
template class SymbolTableTracker<Utils::Arch::Pointer64>;