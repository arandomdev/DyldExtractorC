#include "SymbolicInfo.h"

#include <mach-o/loader.h>
#include <ranges>

using namespace Converter;

bool SymbolicInfo::Symbol::isReExport() const {
  if (exportFlags && *exportFlags & EXPORT_SYMBOL_FLAGS_REEXPORT) {
    return true;
  }

  return false;
}

std::strong_ordering
SymbolicInfo::Symbol::operator<=>(const Symbol &rhs) const {
  if (auto cmp = this->isReExport() <=> rhs.isReExport(); cmp != 0) {
    return cmp;
  } else if (cmp = this->name <=> rhs.name; cmp != 0) {
    return cmp;
  } else if (cmp = this->ordinal <=> rhs.ordinal; cmp != 0) {
    return cmp;
  } else {
    return std::strong_ordering::equal;
  }
}

SymbolicInfo::SymbolicInfo(Symbol first) { symbols.insert(first); }

SymbolicInfo::SymbolicInfo(std::set<Symbol> &symbols) : symbols(symbols) {}
SymbolicInfo::SymbolicInfo(std::set<Symbol> &&symbols) : symbols(symbols) {}

void SymbolicInfo::addSymbol(Symbol sym) { symbols.insert(sym); }

const SymbolicInfo::Symbol &SymbolicInfo::preferredSymbol() const {
  /**
   * There are 3 comparisons, in the following order, Normal or ReExport, name,
   * And ordinal. Normal is preferred, names are reverse compared, and highest
   * ordinal is preferred.
   */

  const Symbol *current = &(*symbols.begin());

  for (const auto &sym : symbols | std::views::drop(1)) {
    if (!current->isReExport() && sym.isReExport()) {
      current = &sym;
      continue;
    }

    if (current->name < sym.name) {
      current = &sym;
      continue;
    }

    // uniqueness is guaranteed by set
    if (current->ordinal < sym.ordinal) {
      current = &sym;
    }
  }

  return *current;
}