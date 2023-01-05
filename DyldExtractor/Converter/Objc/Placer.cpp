#include "Placer.h"

#include "../OffsetOptimizer.h"

using namespace DyldExtractor;
using namespace Converter;
using namespace ObjcFixer;

template <class A>
Placer<A>::Placer(Utils::ExtractionContext<A> &eCtx, Walker<A> &walker)
    : mCtx(*eCtx.mCtx), logger(eCtx.logger), ptrTracker(eCtx.ptrTracker),
      leTracker(eCtx.leTracker.value()), stTracker(eCtx.stTracker.value()),
      walker(walker) {}

template <class A>
std::optional<Provider::ExtraData<typename A::P>> Placer<A>::placeAll() {
  auto [extendsSeg, exDataAddr] = allocateDataRegion();
  if (!exDataAddr) {
    return std::nullopt;
  }

  // Place atoms and update lc size
  PtrT exDataSize = placeAtoms(exDataAddr);
  Provider::ExtraData<P> exData(extendsSeg, exDataAddr, exDataSize);

  propagateAtoms();
  writeAtoms(exData);
  trackAtoms(exData);
  return exData;
}

template <class A>
std::pair<std::string, typename Placer<A>::PtrT>
Placer<A>::allocateDataRegion() {
  // Sort segments by address
  auto segs = mCtx.segments;
  std::sort(segs.begin(), segs.end(), [](const auto &a, const auto &b) {
    return a.command->vmaddr < b.command->vmaddr;
  });

  if (leTracker.freeLCSpace() >= sizeof(Macho::Loader::segment_command<P>)) {
    // Create a new segment, and insert it before the linkedit segment
    const auto &targetSeg = *std::next(segs.crbegin());
    PtrT dataStart = targetSeg.command->vmaddr + targetSeg.command->vmsize;
    Utils::align(&dataStart, SEGMENT_ALIGNMENT);

    Macho::Loader::segment_command<P> exObjcSeg = {0};
    if constexpr (std::is_same_v<P, Utils::Arch::Pointer32>) {
      exObjcSeg.cmd = LC_SEGMENT;
    } else {
      exObjcSeg.cmd = LC_SEGMENT_64;
    }
    exObjcSeg.cmdsize = sizeof(Macho::Loader::segment_command<P>); // no sects
    memcpy(exObjcSeg.segname, SEG_OBJC_EXTRA, sizeof(SEG_OBJC_EXTRA));
    exObjcSeg.vmaddr = dataStart;
    exObjcSeg.maxprot = 3;  // read and write
    exObjcSeg.initprot = 3; // read and write

    // Insert
    if (!leTracker
             .insertLC(
                 reinterpret_cast<Macho::Loader::load_command *>(
                     segs.crbegin()->command),
                 reinterpret_cast<Macho::Loader::load_command *>(&exObjcSeg))
             .second) {
      SPDLOG_LOGGER_ERROR(logger,
                          "Unable to insert extra ObjC segment load command.");
      return std::make_pair("", 0);
    }
    return std::make_pair(std::string(SEG_OBJC_EXTRA), dataStart);
  }

  // Find highest segment with read and write permissions, should not be
  // Linkedit
  Macho::Loader::segment_command<P> *targetSeg = nullptr;
  for (auto it = std::next(segs.crbegin()); it != segs.crend(); it++) {
    if ((it->command->maxprot & 1) && (it->command->maxprot & 2) &&
        (it->command->initprot & 1) && (it->command->initprot & 2)) {
      targetSeg = it->command;
      break;
    }
  }
  if (targetSeg == nullptr) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to find segment with read and write "
                                "permissions for extra objc data.");
    return std::make_pair("", 0);
  }

  // Set the start address after the target segment
  PtrT dataStart = targetSeg->vmaddr + targetSeg->vmsize;
  Utils::align(&dataStart, sizeof(PtrT)); // only pointer align
  return std::make_pair(std::string(targetSeg->segname, 16), dataStart);
}

template <class A>
Placer<A>::PtrT Placer<A>::placeAtoms(const PtrT exDataAddr) {
  /**
   * Order of placed atoms, Arbitrary
   *  CacheT<ClassAtom<A>> classes;
   *  CacheT<ClassDataAtom<A>> classData;
   *  CacheT<SmallMethodListAtom<P>> smallMethodLists;
   *  CacheT<LargeMethodListAtom<P>> largeMethodLists;
   *  CacheT<ProtocolListAtom<A>> protocolLists;
   *  CacheT<PropertyListAtom<P>> propertyLists;
   *  CacheT<IvarListAtom<A>> ivarLists;
   *  CacheT<ExtendedMethodTypesAtom<P>> extendedMethodTypes;
   *  CacheT<ProtocolAtom<A>> protocols;
   *  CacheT<CategoryAtom<A>> categories;
   *  CacheT<PointerAtom<P, StringAtom<P>>> smallMethodSelRefs;
   *
   *  CacheT<StringAtom<P>> strings;
   *  CacheT<IvarLayoutAtom<P>> ivarLayouts;
   *  CacheT<IvarOffsetAtom<A>> ivarOffsets;
   */

  PtrT currentAddr = exDataAddr;

  // Place All atoms
  auto placeAtoms = [&](auto &atoms, bool alignAtoms = true,
                        bool forceExtraData = false) {
    for (auto &[origAddr, atom] : atoms) {
      if (mCtx.containsAddr(origAddr) && !forceExtraData) {
        atom.setFinalAddr(origAddr);
        atom.placedInImage = true;
      } else {
        atom.setFinalAddr(currentAddr);
        auto atomSize = atom.encodedSize();
        currentAddr +=
            alignAtoms ? Utils::align(atomSize, sizeof(PtrT)) : atomSize;
      }
    }

    // Final align
    Utils::align(&currentAddr, sizeof(PtrT));
  };

  placeAtoms(walker.atoms.classes);
  placeAtoms(walker.atoms.classData);
  placeAtoms(walker.atoms.smallMethodLists);
  placeAtoms(walker.atoms.largeMethodLists);
  placeAtoms(walker.atoms.protocolLists);
  placeAtoms(walker.atoms.propertyLists);
  placeAtoms(walker.atoms.ivarLists);
  placeAtoms(walker.atoms.extendedMethodTypes);
  placeAtoms(walker.atoms.protocols);
  placeAtoms(walker.atoms.categories);
  placeAtoms(walker.atoms.smallMethodSelRefs, true, true);

  placeAtoms(walker.atoms.strings, false);
  placeAtoms(walker.atoms.ivarLayouts, false);
  placeAtoms(walker.atoms.ivarOffsets, false);

  return currentAddr - exDataAddr;
}

template <class A> void Placer<A>::propagateAtoms() {
  auto propagateAtoms = [](auto &atoms) {
    for (auto &[origAddr, atom] : atoms) {
      atom.propagate();
    }
  };

  propagateAtoms(walker.atoms.classes);
  propagateAtoms(walker.atoms.classData);
  propagateAtoms(walker.atoms.smallMethodLists);
  propagateAtoms(walker.atoms.largeMethodLists);
  propagateAtoms(walker.atoms.protocolLists);
  propagateAtoms(walker.atoms.propertyLists);
  propagateAtoms(walker.atoms.ivarLists);
  propagateAtoms(walker.atoms.extendedMethodTypes);
  propagateAtoms(walker.atoms.protocols);
  propagateAtoms(walker.atoms.categories);
  propagateAtoms(walker.atoms.smallMethodSelRefs);
  propagateAtoms(walker.atoms.strings);
  propagateAtoms(walker.atoms.ivarLayouts);
  propagateAtoms(walker.atoms.ivarOffsets);

  propagateAtoms(walker.pointers.classes);
  propagateAtoms(walker.pointers.categories);
  propagateAtoms(walker.pointers.protocols);
  propagateAtoms(walker.pointers.selectorRefs);
  propagateAtoms(walker.pointers.protocolRefs);
  propagateAtoms(walker.pointers.classRefs);
  propagateAtoms(walker.pointers.superRefs);
}

template <class A> void Placer<A>::writeAtoms(Provider::ExtraData<P> &exData) {
  auto exDataLoc = exData.getData();
  auto exDataStart = exData.getBaseAddr();
  auto exDataEnd = exData.getEndAddr();

  // Write simple atoms
  auto writeAtoms = [&](auto &atoms) {
    for (auto &[origAddr, atom] : atoms) {
      auto finalAddr = atom.finalAddr();
      uint8_t *atomLoc;
      if (finalAddr >= exDataStart && finalAddr < exDataEnd) {
        atomLoc = exDataLoc + (finalAddr - exDataStart);
      } else {
        atomLoc = mCtx.convertAddrP(finalAddr);
      }

      memcpy(atomLoc, (uint8_t *)&atom.data, atom.encodedSize());
    }
  };

  // Write an atom with a list after it
  auto writeAtomLists = [&](auto &atoms, PtrT headerSize) {
    for (auto &[origAddr, atom] : atoms) {
      auto finalAddr = atom.finalAddr();

      uint8_t *atomLoc;
      if (atom.placedInImage) {
        atomLoc = mCtx.convertAddrP(finalAddr);
      } else {
        assert(finalAddr >= exDataStart && finalAddr < exDataEnd);
        atomLoc = exDataLoc + (finalAddr - exDataStart);
      }

      // Write header atom
      memcpy(atomLoc, (uint8_t *)&atom.data, headerSize);

      // Write entries
      for (auto &entry : atom.entries) {
        auto entryFinalAddr = entry.finalAddr();

        auto entryLoc = atomLoc + (entryFinalAddr - finalAddr);
        memcpy(entryLoc, (uint8_t *)&entry.data, entry.encodedSize());
      }
    }
  };

  writeAtoms(walker.atoms.classes);
  writeAtoms(walker.atoms.classData);

  writeAtomLists(walker.atoms.smallMethodLists, sizeof(Objc::method_list_t));
  writeAtomLists(walker.atoms.largeMethodLists, sizeof(Objc::method_list_t));
  writeAtomLists(walker.atoms.protocolLists, sizeof(Objc::protocol_list_t<P>));
  writeAtomLists(walker.atoms.propertyLists, sizeof(Objc::property_list_t));
  writeAtomLists(walker.atoms.ivarLists, sizeof(Objc::ivar_list_t));
  writeAtomLists(walker.atoms.extendedMethodTypes, 0);

  writeAtoms(walker.atoms.protocols);
  writeAtoms(walker.atoms.categories);
  writeAtoms(walker.atoms.smallMethodSelRefs);
  writeAtoms(walker.atoms.ivarOffsets);

  for (auto &[origAddr, atom] : walker.atoms.strings) {
    if (!atom.placedInImage) {
      auto finalAddr = atom.finalAddr();
      assert(finalAddr >= exDataStart && finalAddr < exDataEnd);
      uint8_t *atomLoc = exDataLoc + (finalAddr - exDataStart);
      memcpy(atomLoc, atom.data, atom.encodedSize());
    }
  }

  for (auto &[origAddr, atom] : walker.atoms.ivarLayouts) {
    if (!atom.placedInImage) {
      auto finalAddr = atom.finalAddr();
      assert(finalAddr >= exDataStart && finalAddr < exDataEnd);
      uint8_t *atomLoc = exDataLoc + (finalAddr - exDataStart);
      memcpy(atomLoc, atom.data, atom.encodedSize());
    }
  }
}

template <class A> void Placer<A>::trackAtoms(Provider::ExtraData<P> &exData) {
  // evict all tracked pointers in extra data region
  ptrTracker.removePointers(exData.getBaseAddr(), exData.getEndAddr());

  /// @brief tracks pointers in an atom, must be an objc struct
  auto trackAtoms = [&](auto &atoms) {
    for (auto &[origAddr, atom] : atoms) {
      auto finalAddr = atom.finalAddr();
      ptrTracker.addS(finalAddr, atom.data);
      ptrTracker.copyAuthS<decltype(atom.data)>(finalAddr, origAddr);
    }
  };

  /// @brief tracks pointers in an atom list, header and entry must be objc
  ///   structs
  auto trackPointerLists = [&](auto &atoms) {
    for (auto &[origAddr, atom] : atoms) {
      auto finalAddr = atom.finalAddr();
      ptrTracker.addS(finalAddr, atom.data);
      ptrTracker.copyAuthS<decltype(atom.data)>(finalAddr, origAddr);

      for (auto &entry : atom.entries) {
        auto entryFinalAddr = entry.finalAddr();
        PtrT entryOrigAddr = origAddr + entryFinalAddr - finalAddr;
        ptrTracker.addS(entryFinalAddr, entry.data);
        ptrTracker.copyAuthS<decltype(atom.data)>(entryFinalAddr,
                                                  entryOrigAddr);
      }
    }
  };

  trackAtoms(walker.atoms.classes);
  trackAtoms(walker.atoms.classData);
  trackAtoms(walker.atoms.protocols);
  trackAtoms(walker.atoms.categories);

  trackPointerLists(walker.atoms.smallMethodLists);
  trackPointerLists(walker.atoms.largeMethodLists);
  trackPointerLists(walker.atoms.propertyLists);
  trackPointerLists(walker.atoms.ivarLists);

  for (auto &[origAddr, atom] : walker.atoms.smallMethodSelRefs) {
    auto finalAddr = atom.finalAddr();
    ptrTracker.add(finalAddr, atom.data);
    ptrTracker.copyAuth(finalAddr, origAddr);
  }

  for (auto &[origAddr, atom] : walker.atoms.protocolLists) {
    auto finalAddr = atom.finalAddr();

    for (auto &entry : atom.entries) {
      auto entryFinalAddr = entry.finalAddr();
      PtrT entryOrigAddr = origAddr + entryFinalAddr - finalAddr;
      ptrTracker.add(entryFinalAddr, entry.data);
      ptrTracker.copyAuth(entryFinalAddr, entryOrigAddr);
    }
  }

  for (auto &[origAddr, atom] : walker.atoms.extendedMethodTypes) {
    auto finalAddr = atom.finalAddr();

    for (auto &entry : atom.entries) {
      auto entryFinalAddr = entry.finalAddr();
      PtrT entryOrigAddr = origAddr + entryFinalAddr - finalAddr;
      ptrTracker.add(entryFinalAddr, entry.data);
      ptrTracker.copyAuth(entryFinalAddr, entryOrigAddr);
    }
  }

  // Add in-image pointers
  auto trackPointers = [&](auto &atoms) {
    for (auto &[pAddr, pAtom] : atoms) {
      ptrTracker.add(pAddr, pAtom.data);
    }
  };

  trackPointers(walker.pointers.classes);
  trackPointers(walker.pointers.categories);
  trackPointers(walker.pointers.protocols);
  trackPointers(walker.pointers.selectorRefs);
  trackPointers(walker.pointers.protocolRefs);

  for (auto &[pAddr, pAtom] : walker.pointers.classRefs) {
    ptrTracker.add(pAddr, pAtom.data);

    if (pAtom.bind) {
      ptrTracker.addBind(pAddr, pAtom.bind);
      checkBind(pAtom.bind);
    }
  }

  for (auto &[pAddr, pAtom] : walker.pointers.superRefs) {
    ptrTracker.add(pAddr, pAtom.data);

    if (pAtom.bind) {
      ptrTracker.addBind(pAddr, pAtom.bind);
      checkBind(pAtom.bind);
    }
  }

  // Add binds for structures
  for (auto &[origAddr, atom] : walker.atoms.classes) {
    if (atom.isa.bind) {
      ptrTracker.addBind(atom.isa.finalAddr(), atom.isa.bind);
      checkBind(atom.isa.bind);
    }
    if (atom.superclass.bind) {
      ptrTracker.addBind(atom.superclass.finalAddr(), atom.superclass.bind);
      checkBind(atom.superclass.bind);
    }
  }

  for (auto &[origAddr, atom] : walker.atoms.protocols) {
    if (atom.isa.bind) {
      ptrTracker.addBind(atom.isa.finalAddr(), atom.isa.bind);
      checkBind(atom.isa.bind);
    }
  }

  for (auto &[origAddr, atom] : walker.atoms.categories) {
    if (atom.cls.bind) {
      ptrTracker.addBind(atom.cls.finalAddr(), atom.cls.bind);
      checkBind(atom.cls.bind);
    }
  }
}

template <class A>
void Placer<A>::checkBind(const std::shared_ptr<Provider::SymbolicInfo> &bind) {
  auto &sym = bind->preferredSymbol();
  if (!stTracker.getStrings().contains(sym.name)) {
    auto &str = stTracker.addString(sym.name);

    /// TODO: Check if symbol type is correct
    Macho::Loader::nlist<P> entry{};
    entry.n_type = 1;
    SET_LIBRARY_ORDINAL(entry.n_desc, (uint16_t)sym.ordinal);
    stTracker.addSym(Provider::SymbolTableTracker<P>::SymbolType::external, str,
                     entry);
  }
}

#define X(T) template class Placer<T>;
X(Utils::Arch::x86_64)
X(Utils::Arch::arm) X(Utils::Arch::arm64) X(Utils::Arch::arm64_32)
#undef X