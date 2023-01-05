#include "Walker.h"

using namespace DyldExtractor;
using namespace Converter;
using namespace ObjcFixer;

template <class A>
Walker<A>::Walker(Utils::ExtractionContext<A> &eCtx)
    : dCtx(*eCtx.dCtx), mCtx(*eCtx.mCtx), activity(*eCtx.activity),
      logger(eCtx.logger), bindInfo(eCtx.bindInfo), ptrTracker(eCtx.ptrTracker),
      symbolizer(eCtx.symbolizer.value()) {}

template <class A> bool Walker<A>::walkAll() {
  if (auto sect = mCtx.getSection(nullptr, "__objc_imageinfo").second; sect) {
    auto info = (Objc::image_info *)mCtx.convertAddrP(sect->addr);
    if (info->flags & Objc::image_info::HasCategoryClassProperties) {
      hasCategoryClassProperties = true;
    }
  } else {
    SPDLOG_LOGGER_ERROR(logger, "Unable to get __objc_imageinfo");
    return false;
  }

  if (!parseOptInfo()) {
    return false;
  }

  // Create a map of binds
  std::map<PtrT, const Provider::BindRecord *> bindRecords;
  for (const auto &bind : bindInfo.getWeakBinds()) {
    bindRecords[(PtrT)bind.address] = &bind;
  }
  for (const auto &bind : bindInfo.getBinds()) {
    bindRecords[(PtrT)bind.address] = &bind;
  }

  mCtx.enumerateSections([this, &bindRecords](const auto seg, const auto sect) {
    PtrT sectAddr = sect->addr;
    PtrT sectEnd = sectAddr + sect->size;

    if (memcmp(sect->sectname, "__objc_classlist", 16) == 0) {
      activity.update(std::nullopt, "Processing classes");
      for (PtrT pAddr = sectAddr; pAddr < sectEnd; pAddr += sizeof(PtrT)) {
        activity.update();
        auto cAddr = ptrTracker.slideP(pAddr);

        if (mCtx.containsAddr(cAddr)) {
          auto &ptr = pointers.classes.try_emplace(pAddr).first->second;
          ptr.ref = walkClass(cAddr);
          ptr.setFinalAddr(pAddr);
        } else {
          SPDLOG_LOGGER_WARN(
              logger, "Class pointer at {:#x} points outside of image.", pAddr);
        }
      }
    }

    else if (memcmp(sect->sectname, "__objc_catlist", 15) == 0) {
      activity.update(std::nullopt, "Processing categories");
      for (PtrT pAddr = sectAddr; pAddr < sectEnd; pAddr += sizeof(PtrT)) {
        activity.update();
        auto cAddr = ptrTracker.slideP(pAddr);

        if (mCtx.containsAddr(cAddr)) {
          auto &ptr = pointers.categories.try_emplace(pAddr).first->second;
          ptr.ref = walkCategory(cAddr);
          ptr.setFinalAddr(pAddr);
        } else {
          SPDLOG_LOGGER_WARN(
              logger, "Category pointer at {:#x} points outside of image.",
              pAddr);
        }
      }
    }

    else if (memcmp(sect->sectname, "__objc_protolist", 16) == 0) {
      activity.update(std::nullopt, "Processing categories");
      for (PtrT pAddr = sectAddr; pAddr < sectEnd; pAddr += sizeof(PtrT)) {
        activity.update();
        auto protoAddr = ptrTracker.slideP(pAddr);

        if (mCtx.containsAddr(protoAddr)) {
          auto &ptr = pointers.protocols.try_emplace(pAddr).first->second;
          ptr.ref = walkProtocol(protoAddr);
          ptr.setFinalAddr(pAddr);
        } else {
          SPDLOG_LOGGER_WARN(
              logger, "Protocol pointer at {:#x} points outside of image.",
              pAddr);
        }
      }
    }

    else if (memcmp(sect->sectname, "__objc_selrefs", 15) == 0) {
      activity.update(std::nullopt, "Processing selector references");
      for (PtrT pAddr = sectAddr; pAddr < sectEnd; pAddr += sizeof(PtrT)) {
        activity.update();
        auto stringAddr = ptrTracker.slideP(pAddr);

        auto &ptr = pointers.selectorRefs.try_emplace(pAddr).first->second;
        ptr.ref = walkString(stringAddr);
        ptr.setFinalAddr(pAddr);
      }
    }

    else if (memcmp(sect->sectname, "__objc_protorefs", 16) == 0) {
      activity.update(std::nullopt, "Processing protocol references");
      for (PtrT pAddr = sectAddr; pAddr < sectEnd; pAddr += sizeof(PtrT)) {
        activity.update();
        auto protoAddr = ptrTracker.slideP(pAddr);

        auto &ptr = pointers.protocolRefs.try_emplace(pAddr).first->second;
        ptr.ref = walkProtocol(protoAddr);
        ptr.setFinalAddr(pAddr);
      }
    }

    else if (memcmp(sect->sectname, "__objc_classrefs", 16) == 0) {
      activity.update(std::nullopt, "Processing class references");
      for (PtrT pAddr = sectAddr; pAddr < sectEnd; pAddr += sizeof(PtrT)) {
        activity.update();
        auto classAddr = ptrTracker.slideP(pAddr);

        auto &ptr = pointers.classRefs.try_emplace(pAddr).first->second;
        ptr.setFinalAddr(pAddr);

        if (mCtx.containsAddr(classAddr)) {
          ptr.ref = walkClass(classAddr);
        } else if (symbolizer.containsAddr(classAddr)) {
          ptr.bind = symbolizer.shareInfo(classAddr);
        } else if (bindRecords.contains(pAddr)) {
          auto record = bindRecords.at(pAddr);
          ptr.bind = std::make_shared<Provider::SymbolicInfo>(
              Provider::SymbolicInfo::Symbol{std::string(record->symbolName),
                                             (uint64_t)record->libOrdinal,
                                             std::nullopt},
              Provider::SymbolicInfo::Encoding::None);
        } else {
          SPDLOG_LOGGER_WARN(logger,
                             "Unable to fix class ref at {:#x} -> {:#x}.",
                             pAddr, classAddr);
          pointers.classRefs.erase(pAddr);
        }
      }
    }

    else if (memcmp(sect->sectname, "__objc_superrefs", 16) == 0) {
      activity.update(std::nullopt, "Processing super class references");
      for (PtrT pAddr = sectAddr; pAddr < sectEnd; pAddr += sizeof(PtrT)) {
        activity.update();
        auto superAddr = ptrTracker.slideP(pAddr);

        auto &ptr = pointers.superRefs.try_emplace(pAddr).first->second;
        ptr.setFinalAddr(pAddr);

        if (mCtx.containsAddr(superAddr)) {
          ptr.ref = walkClass(superAddr);
        } else if (symbolizer.containsAddr(superAddr)) {
          ptr.bind = symbolizer.shareInfo(superAddr);
        } else {
          SPDLOG_LOGGER_WARN(logger,
                             "Unable to fix super class ref at {:#x} -> {:#x}.",
                             pAddr, superAddr);
          pointers.superRefs.erase(pAddr);
        }
      }
    }

    return true;
  });

  return true;
}

template <class A> bool Walker<A>::parseOptInfo() {
  // Get libobjc
  const dyld_cache_image_info *libobjcImageInfo;
  for (const auto info : dCtx.images) {
    if (strstr((const char *)dCtx.file + info->pathFileOffset, "/libobjc.") !=
        nullptr) {
      libobjcImageInfo = info;
      break;
    }
  }
  if (!libobjcImageInfo) {
    SPDLOG_LOGGER_WARN(logger, "Unable to find image info for libobjc.");
    return false;
  }
  auto libobjcImage = dCtx.createMachoCtx<true, P>(libobjcImageInfo);

  // Get __objc_opt_data
  auto optRoSect = libobjcImage.getSection(nullptr, "__objc_opt_ro").second;
  if (!optRoSect) {
    SPDLOG_LOGGER_ERROR(logger, "unable to find __objc_opt_data.");
    return false;
  }
  auto optData = (Objc::objc_opt_t *)libobjcImage.convertAddrP(optRoSect->addr);

  std::optional<uint64_t> relMethodSelBaseOff;
  uint32_t headerOptOffset;

  switch (optData->version) {
  case 12: {
    headerOptOffset = optData->v12.headeropt_offset;
    break;
  }
  case 13: {
    headerOptOffset = optData->v13.headeropt_offset;
    break;
  }
  case 15: {
    headerOptOffset = optData->v15a.headeropt_ro_offset;
    break;
  }
  case 16: {
    headerOptOffset = optData->v16.headeropt_ro_offset;
    relMethodSelBaseOff = optData->v16.relativeMethodSelectorBaseAddressOffset;
    break;
  }

  default:
    SPDLOG_LOGGER_ERROR(logger, "Unknown opt_data_t version: {}",
                        optData->version);
    return false;
  }

  // Selectors
  if (relMethodSelBaseOff && *relMethodSelBaseOff) {
    // Check magic selector
    auto addr = optRoSect->addr + (PtrT)*relMethodSelBaseOff;
    auto loc = libobjcImage.convertAddrP(addr);
    if (memcmp(RELATIVE_METHOD_MAGIC_SELECTOR, loc,
               sizeof(RELATIVE_METHOD_MAGIC_SELECTOR)) != 0) {
      SPDLOG_LOGGER_ERROR(
          logger, "Relative methods cache does not start with magic selector.");
      return false;
    }

    relMethodSelBaseAddr = addr;
  }

  // objc image index
  if (!headerOptOffset) {
    SPDLOG_LOGGER_ERROR(logger, "opt_data_t does not have header opt.");
    return false;
  }

  auto headerOptAddr = optRoSect->addr + headerOptOffset;
  auto headerOpt =
      (Objc::objc_headeropt_ro_t *)libobjcImage.convertAddrP(headerOptAddr);

  auto imageAddr = mCtx.getSegment(SEG_TEXT)->command->vmaddr;
  std::optional<uint16_t> foundImageIndex;

  auto headerAddr = headerOptAddr + sizeof(Objc::objc_headeropt_ro_t);
  for (uint32_t i = 0; i < headerOpt->count;
       i++, headerAddr += headerOpt->entsize) {
    auto header =
        (Objc::objc_header_info_ro_t<P> *)libobjcImage.convertAddrP(headerAddr);
    if (headerAddr + header->mhdr_offset == imageAddr) {
      foundImageIndex = i;
      break;
    }
  }

  if (!foundImageIndex) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to find objc image index.");
    return false;
  } else {
    imageIndex = *foundImageIndex;
  }

  return true;
}

template <class A> ClassAtom<A> *Walker<A>::walkClass(const PtrT addr) {
  if (atoms.classes.contains(addr)) {
    return &atoms.classes.at(addr);
  }

  // Make new atom
  auto &atom =
      atoms.classes.try_emplace(addr, ptrTracker.slideS<Objc::class_t<P>>(addr))
          .first->second;

  // Walk data
  if (auto isaAddr = atom.data.isa; isaAddr) {
    if (mCtx.containsAddr(isaAddr)) {
      // Process
      atom.isa.ref = walkClass(isaAddr);
    } else {
      // Bind
      if (symbolizer.containsAddr(isaAddr)) {
        atom.isa.bind = symbolizer.shareInfo(isaAddr);
      } else {
        SPDLOG_LOGGER_WARN(
            logger, "Unable to symbolize isa for class_t at {:#x}.", addr);
      }
    }
  } else {
    SPDLOG_LOGGER_WARN(logger, "class_t at {:#x} doesn't have an isa.", addr);
  }

  if (auto superAddr = atom.data.superclass; superAddr) {
    if (mCtx.containsAddr(superAddr)) {
      // Process
      atom.superclass.ref = walkClass(superAddr);
    } else {
      // Bind
      if (symbolizer.containsAddr(superAddr)) {
        atom.superclass.bind = symbolizer.shareInfo(superAddr);
      } else {
        // This might be a root class, check
        if (atom.data.data) {
          auto flags = *(uint32_t *)dCtx.convertAddrP(
              atom.data.data & ~Objc::class_t<P>::bitsMask);
          if (flags & Objc::class_data_t<P>::rootClassFlag) {
            // Leave as null ref
          } else {
            SPDLOG_LOGGER_WARN(logger,
                               "Unable to symbolize superclass ({:#x}) for non "
                               "root class_t at {:#x}.",
                               superAddr, addr);
          }
        } else {
          SPDLOG_LOGGER_WARN(logger,
                             "Potential root class_t at {:#x} does not have "
                             "class data to verify.",
                             addr);
        }
      }
    }
  }

  /// TODO: Check if this needs to be process
  atom.data.method_cache = 0;
  atom.data.vtable = 0;

  if (auto dataAddr = atom.data.data; dataAddr) {
    atom.classData.ref = walkClassData(dataAddr & ~Objc::class_t<P>::bitsMask);
  } else {
    SPDLOG_LOGGER_WARN(logger, "class_t at {:#x} doesn't have class data.",
                       addr);
  }

  return &atom;
}

template <class A> ClassDataAtom<A> *Walker<A>::walkClassData(const PtrT addr) {
  if (atoms.classData.contains(addr)) {
    return &atoms.classData.at(addr);
  }

  // Make new atom
  auto &atom =
      atoms.classData
          .try_emplace(addr, ptrTracker.slideS<Objc::class_data_t<P>>(addr))
          .first->second;

  // Walk data
  if (atom.data.ivarLayout) {
    atom.ivarLayout.ref = walkIvarLayout(atom.data.ivarLayout);
  }

  if (atom.data.name) {
    atom.name.ref = walkString(atom.data.name);
  } else {
    SPDLOG_LOGGER_WARN(logger, "class_data_t at {:#x} doesn't have a name.",
                       addr);
  }

  if (atom.data.baseMethods) {
    if (atom.data.baseMethods & 0x1) {
      // Pre-attached categories
      PtrT relListListAddr = atom.data.baseMethods & ~0x1;
      if (auto listAddr = findInImageRelList(relListListAddr); listAddr) {
        atom.baseMethods.ref = walkMethodList(*listAddr);
      } else {
        atom.data.baseMethods = 0;
      }
    } else {
      atom.baseMethods.ref = walkMethodList(atom.data.baseMethods);
    }
  }

  if (atom.data.baseProtocols) {
    if (atom.data.baseProtocols & 0x1) {
      // Pre-attached categories
      PtrT relListListAddr = atom.data.baseProtocols & ~0x1;
      if (auto listAddr = findInImageRelList(relListListAddr); listAddr) {
        atom.baseProtocols.ref = walkProtocolList(*listAddr);
      } else {
        atom.data.baseProtocols = 0;
      }
    } else {
      atom.baseProtocols.ref = walkProtocolList(atom.data.baseProtocols);
    }
  }

  if (atom.data.ivars) {
    atom.ivars.ref = walkIvarList(atom.data.ivars);
  }

  if (atom.data.weakIvarLayout) {
    atom.weakIvarLayout.ref = walkIvarLayout(atom.data.weakIvarLayout);
  }

  if (atom.data.baseProperties) {
    if (atom.data.baseProperties & 0x1) {
      // Pre-attached categories
      PtrT relListListAddr = atom.data.baseProperties & ~0x1;
      if (auto listAddr = findInImageRelList(relListListAddr); listAddr) {
        atom.baseProperties.ref = walkPropertyList(*listAddr);
      } else {
        atom.data.baseProperties = 0;
      }
    } else {
      atom.baseProperties.ref = walkPropertyList(atom.data.baseProperties);
    }
  }

  return &atom;
}

template <class A>
IvarLayoutAtom<typename A::P> *Walker<A>::walkIvarLayout(const PtrT addr) {
  if (atoms.ivarLayouts.contains(addr)) {
    return &atoms.ivarLayouts.at(addr);
  }

  // Make new atom
  return &atoms.ivarLayouts.try_emplace(addr, dCtx.convertAddrP(addr))
              .first->second;
}

template <class A>
StringAtom<typename A::P> *Walker<A>::walkString(const PtrT addr) {
  if (atoms.strings.contains(addr)) {
    return &atoms.strings.at(addr);
  }

  // Make new atom
  return &atoms.strings.try_emplace(addr, (const char *)dCtx.convertAddrP(addr))
              .first->second;
}

template <class A>
MethodListAtom<typename A::P> *Walker<A>::walkMethodList(const PtrT addr) {
  auto data = ptrTracker.slideS<Objc::method_list_t>(addr);
  if (data.usesRelativeMethods()) {
    return walkSmallMethodList(addr, data);
  } else {
    return walkLargeMethodList(addr, data);
  }
}

template <class A>
SmallMethodListAtom<typename A::P> *
Walker<A>::walkSmallMethodList(const PtrT addr, Objc::method_list_t data) {
  if (atoms.smallMethodLists.contains(addr)) {
    return &atoms.smallMethodLists.at(addr);
  }

  // Make new atom
  auto &atom = atoms.smallMethodLists.try_emplace(addr, data).first->second;

  // Remove flag
  if (atom.data.entsizeAndFlags &
      Objc::method_list_t::relativeMethodSelectorsAreDirectFlag) {
    atom.data.entsizeAndFlags &=
        ~Objc::method_list_t::relativeMethodSelectorsAreDirectFlag;
  } else {
    SPDLOG_LOGGER_WARN(logger,
                       "Small style method_list_t at {:#x} doesn't have "
                       "relativeMethodSelectorsAreDirectFlag set.",
                       addr);
    return &atom;
  }

  // walk methods
  using MethodT = Objc::method_small_t;
  PtrT entsize = atom.data.getEntsize();
  if (entsize != sizeof(MethodT)) {
    SPDLOG_LOGGER_ERROR(logger,
                        "Small style method_list_t at {:#x} has an entsize "
                        "that doesn't match a small method.",
                        addr);
    return &atom;
  }

  PtrT methodAddr = addr + sizeof(Objc::method_list_t);
  for (uint32_t i = 0; i < atom.data.count; i++, methodAddr += entsize) {
    auto &methodAtom =
        atom.entries.emplace_back(ptrTracker.slideS<MethodT>(methodAddr));

    // Walk data
    if (auto nameAddr = methodAtom.data.name; nameAddr) {
      PtrT targetAddr;
      if (relMethodSelBaseAddr) {
        targetAddr = *relMethodSelBaseAddr + nameAddr;
      } else {
        targetAddr = methodAddr + (PtrT)offsetof(MethodT, name) + nameAddr;
      }

      methodAtom.name.ref = makeSmallMethodSelRef(targetAddr);
    } else {
      SPDLOG_LOGGER_WARN(logger, "Method at {:#x} doesn't have a name.",
                         methodAddr);
    }

    if (auto typesAddr = methodAtom.data.types; typesAddr) {
      PtrT targetAddr = methodAddr + (PtrT)offsetof(MethodT, types) + typesAddr;
      methodAtom.types.ref = walkString(targetAddr);
    } else {
      SPDLOG_LOGGER_WARN(logger, "Method at {:#x} doesn't have a type.",
                         methodAddr);
    }

    if (methodAtom.data.imp) {
      PtrT targetAddr =
          methodAddr + (PtrT)offsetof(MethodT, imp) + methodAtom.data.imp;
      if (mCtx.containsAddr(targetAddr)) {
        methodAtom.imp.ref = walkImp(targetAddr);
      } else {
        SPDLOG_LOGGER_WARN(
            logger,
            "Method at {:#x} has an implementation outside the MachOContext.",
            methodAddr);
      }
    }
  }

  return &atom;
}

template <class A>
LargeMethodListAtom<typename A::P> *
Walker<A>::walkLargeMethodList(const PtrT addr, Objc::method_list_t data) {
  assert(!data.usesRelativeMethods());

  if (atoms.largeMethodLists.contains(addr)) {
    return &atoms.largeMethodLists.at(addr);
  }

  // make new atom
  auto &atom = atoms.largeMethodLists.try_emplace(addr, data).first->second;

  // walk methods
  using MethodT = Objc::method_large_t<P>;
  PtrT entsize = atom.data.getEntsize();
  if (entsize != sizeof(MethodT)) {
    SPDLOG_LOGGER_ERROR(logger,
                        "Large style method_list_t at {:#x} has an entsize "
                        "that doesn't match a large method.",
                        addr);
    return &atom;
  }

  PtrT methodAddr = addr + sizeof(Objc::method_list_t);
  for (uint32_t i = 0; i < atom.data.count; i++, methodAddr += entsize) {
    auto &methodAtom =
        atom.entries.emplace_back(ptrTracker.slideS<MethodT>(methodAddr));

    // Walk data
    if (methodAtom.data.name) {
      methodAtom.name.ref = walkString(methodAtom.data.name);
    } else {
      SPDLOG_LOGGER_WARN(logger, "Method at {:#x} doesn't have a name.",
                         methodAddr);
    }

    if (methodAtom.data.types) {
      methodAtom.types.ref = walkString(methodAtom.data.types);
    } else {
      SPDLOG_LOGGER_WARN(logger, "Method at {:#x} doesn't have a type.",
                         methodAddr);
    }

    if (methodAtom.data.imp) {
      if (mCtx.containsAddr(methodAtom.data.imp)) {
        methodAtom.imp.ref = walkImp(methodAtom.data.imp);
      } else {
        SPDLOG_LOGGER_WARN(
            logger,
            "Method at {:#x} has an implementation outside the MachOContext.",
            methodAddr);
      }
    }
  }

  return &atom;
}

template <class A>
ProtocolListAtom<A> *Walker<A>::walkProtocolList(const PtrT addr) {
  if (atoms.protocolLists.contains(addr)) {
    return &atoms.protocolLists.at(addr);
  }

  // Make new atom
  auto &atom =
      atoms.protocolLists
          .try_emplace(addr, ptrTracker.slideS<Objc::protocol_list_t<P>>(addr))
          .first->second;

  // Walk data
  PtrT protoRefAddr = addr + sizeof(Objc::protocol_list_t<P>);
  for (PtrT i = 0; i < atom.data.count; i++, protoRefAddr += sizeof(PtrT)) {
    PtrT protoAddr = ptrTracker.slideP(protoRefAddr);
    atom.entries.emplace_back().ref = walkProtocol(protoAddr);
  }

  return &atom;
}

template <class A> ProtocolAtom<A> *Walker<A>::walkProtocol(const PtrT addr) {
  if (atoms.protocols.contains(addr)) {
    return &atoms.protocols.at(addr);
  }

  // Make new atom
  auto &atom =
      atoms.protocols
          .try_emplace(addr, ptrTracker.slideS<Objc::protocol_t<P>>(addr))
          .first->second;

  // Walk data
  if (auto isaAddr = atom.data.isa; isaAddr) {
    if (mCtx.containsAddr(isaAddr)) {
      // Fix
      atom.isa.ref = walkClass(isaAddr);
    } else {
      // Bind
      if (symbolizer.containsAddr(isaAddr)) {
        atom.isa.bind = symbolizer.shareInfo(isaAddr);
      } else {
        SPDLOG_LOGGER_WARN(
            logger, "Unable to symbolize isa ({:#x}) for protocol_t at {:#x}.",
            isaAddr, addr);
      }
    }
  }

  if (atom.data.name) {
    atom.name.ref = walkString(atom.data.name);
  } else {
    SPDLOG_LOGGER_WARN(logger, "protocol_t at {:#x} doesn't have an name.",
                       addr);
  }

  if (atom.data.protocols) {
    atom.protocols.ref = walkProtocolList(atom.data.protocols);
  }

  uint32_t methodCount = 0;
  if (atom.data.instanceMethods) {
    atom.instanceMethods.ref = walkMethodList(atom.data.instanceMethods);
    methodCount += atom.instanceMethods.ref->data.count;
  }

  if (atom.data.classMethods) {
    atom.classMethods.ref = walkMethodList(atom.data.classMethods);
    methodCount += atom.classMethods.ref->data.count;
  }

  if (atom.data.optionalInstanceMethods) {
    atom.optionalInstanceMethods.ref =
        walkMethodList(atom.data.optionalInstanceMethods);
    methodCount += atom.optionalInstanceMethods.ref->data.count;
  }

  if (atom.data.optionalClassMethods) {
    atom.optionalClassMethods.ref =
        walkMethodList(atom.data.optionalClassMethods);
    methodCount += atom.optionalClassMethods.ref->data.count;
  }

  if (atom.data.instanceProperties) {
    atom.instanceProperties.ref =
        walkPropertyList(atom.data.instanceProperties);
  }

  if (atom.data.hasExtendedMethodTypes() && atom.data.extendedMethodTypes) {
    atom.extendedMethodTypes.ref =
        walkExtendedMethodTypes(atom.data.extendedMethodTypes, methodCount);
  }

  if (atom.data.hasDemangledName() && atom.data.demangledName) {
    atom.demangledName.ref = walkString(atom.data.demangledName);
  }

  if (atom.data.hasClassProperties() && atom.data.classProperties) {
    atom.classProperties.ref = walkPropertyList(atom.data.classProperties);
  }

  return &atom;
}

template <class A>
PropertyListAtom<typename A::P> *Walker<A>::walkPropertyList(const PtrT addr) {
  if (atoms.propertyLists.contains(addr)) {
    return &atoms.propertyLists.at(addr);
  }

  // Make new atom
  auto &atom =
      atoms.propertyLists
          .try_emplace(addr, ptrTracker.slideS<Objc::property_list_t>(addr))
          .first->second;

  auto entsize = atom.data.entsize;
  if (entsize != sizeof(Objc::property_t<P>)) {
    SPDLOG_LOGGER_ERROR(logger,
                        "property_list_t at {:#x} has an entsize ({}) that "
                        "doesn't match a property_t.",
                        addr, atom.data.entsize);
    return &atom;
  }

  // Walk data
  PtrT propertyAddr = addr + sizeof(Objc::property_list_t);
  for (uint32_t i = 0; i < atom.data.count; i++, propertyAddr += entsize) {
    auto &property = atom.entries.emplace_back(
        ptrTracker.slideS<Objc::property_t<P>>(propertyAddr));

    if (property.data.name) {
      property.name.ref = walkString(property.data.name);
    } else {
      SPDLOG_LOGGER_WARN(logger, "property_t at {:#x} doesn't have a name.",
                         propertyAddr);
    }

    if (property.data.attributes) {
      property.attributes.ref = walkString(property.data.attributes);
    } else {
      SPDLOG_LOGGER_WARN(logger, "property_t at {:#x} doesn't have attributes.",
                         propertyAddr);
    }
  }

  return &atom;
}

template <class A>
ExtendedMethodTypesAtom<typename A::P> *
Walker<A>::walkExtendedMethodTypes(const PtrT addr, const uint32_t count) {
  if (atoms.extendedMethodTypes.contains(addr)) {
    auto &atom = atoms.extendedMethodTypes.at(addr);
    if (atom.entries.size() != count) {
      SPDLOG_LOGGER_WARN(
          logger, "Conflicting count for extendedMethodTypes at {:#x}.", addr);
      return &atom;
    }
  }

  // Make new atom
  auto &atom = atoms.extendedMethodTypes.try_emplace(addr).first->second;

  // walk data
  PtrT pAddr = addr;
  for (uint32_t i = 0; i < count; i++, pAddr += sizeof(PtrT)) {
    atom.entries.emplace_back().ref = walkString(ptrTracker.slideP(pAddr));
  }

  return &atom;
}

template <class A> IvarListAtom<A> *Walker<A>::walkIvarList(const PtrT addr) {
  if (atoms.ivarLists.contains(addr)) {
    return &atoms.ivarLists.at(addr);
  }

  // Make new atom
  auto &atom =
      atoms.ivarLists
          .try_emplace(addr, ptrTracker.slideS<Objc::ivar_list_t>(addr))
          .first->second;

  auto entsize = atom.data.entsize;
  if (entsize != sizeof(Objc::ivar_t<P>)) {
    SPDLOG_LOGGER_ERROR(
        logger,
        "ivar_list_t at {:#x} has an entsize that doesn't match a ivar_t.",
        addr);
    return &atom;
  }

  // Walk data
  PtrT ivarAddr = addr + sizeof(Objc::ivar_list_t);
  for (uint32_t i = 0; i < atom.data.count; i++, ivarAddr += entsize) {
    auto &ivar =
        atom.entries.emplace_back(ptrTracker.slideS<Objc::ivar_t<P>>(ivarAddr));

    // Process data
    if (ivar.data.offset) {
      ivar.offset.ref = walkIvarOffset(ivar.data.offset);
    } else {
      SPDLOG_LOGGER_WARN(logger, "ivar_t at {:#x} doesn't have an offset.",
                         ivarAddr);
    }

    if (ivar.data.name) {
      ivar.name.ref = walkString(ivar.data.name);
    } else {
      SPDLOG_LOGGER_WARN(logger, "ivar_t at {:#x} doesn't have a name.",
                         ivarAddr);
    }

    if (ivar.data.type) {
      ivar.type.ref = walkString(ivar.data.type);
    } else {
      SPDLOG_LOGGER_WARN(logger, "ivar_t at {:#x} doesn't have a type.",
                         ivarAddr);
    }
  }

  return &atom;
}

template <class A>
IvarOffsetAtom<A> *Walker<A>::walkIvarOffset(const PtrT addr) {
  if (atoms.ivarOffsets.contains(addr)) {
    return &atoms.ivarOffsets.at(addr);
  }

  // Make new atom
  return &atoms.ivarOffsets
              .try_emplace(addr, *(IvarOffsetType<A> *)dCtx.convertAddrP(addr))
              .first->second;
}

template <class A> CategoryAtom<A> *Walker<A>::walkCategory(const PtrT addr) {
  if (atoms.categories.contains(addr)) {
    return &atoms.categories.at(addr);
  }

  // Make new atom
  auto &atom =
      atoms.categories
          .try_emplace(addr, ptrTracker.slideS<Objc::category_t<P>>(addr),
                       hasCategoryClassProperties)
          .first->second;

  // walk data
  if (atom.data.name) {
    atom.name.ref = walkString(atom.data.name);
  } else {
    SPDLOG_LOGGER_WARN(logger, "category_t at {:#x} doesn't have a name.",
                       addr);
  }

  if (auto clsAddr = atom.data.cls; clsAddr) {
    if (mCtx.containsAddr(clsAddr)) {
      // Fix
      atom.cls.ref = walkClass(clsAddr);
    } else {
      // Bind
      if (symbolizer.containsAddr(clsAddr)) {
        atom.cls.bind = symbolizer.shareInfo(clsAddr);
      } else {
        SPDLOG_LOGGER_WARN(
            logger, "Unable to symbolize cls ({:#x}) for category_t at {:#x}.",
            clsAddr, addr);
      }
    }
  } else {
    SPDLOG_LOGGER_WARN(logger, "category_t at {:#x} doesn't have a cls.", addr);
  }

  if (atom.data.instanceMethods) {
    atom.instanceMethods.ref = walkMethodList(atom.data.instanceMethods);
  }

  if (atom.data.classMethods) {
    atom.classMethods.ref = walkMethodList(atom.data.classMethods);
  }

  if (atom.data.protocols) {
    atom.protocols.ref = walkProtocolList(atom.data.protocols);
  }

  if (atom.data.instanceProperties) {
    atom.instanceProperties.ref =
        walkPropertyList(atom.data.instanceProperties);
  }

  if (atom.hasClassProperties && atom.data._classProperties) {
    atom._classProperties.ref = walkPropertyList(atom.data._classProperties);
  }

  return &atom;
}

template <class A> ImpAtom<typename A::P> *Walker<A>::walkImp(const PtrT addr) {
  if (atoms.imps.contains(addr)) {
    return &atoms.imps.at(addr);
  }

  // Make atom
  auto &atom =
      atoms.imps.try_emplace(addr, (const uint8_t *)dCtx.convertAddrP(addr))
          .first->second;

  // Set finalAddr now
  atom.setFinalAddr(addr);
  return &atom;
}

template <class A>
PointerAtom<typename A::P, StringAtom<typename A::P>> *
Walker<A>::makeSmallMethodSelRef(const PtrT stringAddr) {
  if (atoms.smallMethodSelRefs.contains(stringAddr)) {
    return &atoms.smallMethodSelRefs.at(stringAddr);
  }

  // Make new atom
  auto &atom = atoms.smallMethodSelRefs.try_emplace(stringAddr).first->second;
  atom.ref = walkString(stringAddr);
  return &atom;
}

template <class A>
std::optional<typename Walker<A>::PtrT>
Walker<A>::findInImageRelList(const PtrT addr) const {
  auto relListList = ptrTracker.slideS<Objc::relative_list_list_t>(addr);

  // check entsize
  if (relListList.entsize != sizeof(Objc::relative_list_t)) {
    SPDLOG_LOGGER_WARN(logger,
                       "relative_list_list_t at {:#x} has entsize that does "
                       "not match the size of relative_list_t.",
                       addr);
    return std::nullopt;
  }

  // Iterate in reverse, seems like the target is always at the end
  auto relListsAddr = addr + (PtrT)sizeof(Objc::relative_list_list_t);
  auto relLists = (Objc::relative_list_t *)mCtx.convertAddrP(relListsAddr);
  for (auto i = relListList.count - 1; i >= 0; i--) {
    auto entry = relLists + i;
    if (entry->getImageIndex() == imageIndex && entry->getOffset()) {
      return (PtrT)(relListsAddr + (i * sizeof(Objc::relative_list_t)) +
                    entry->getOffset());
    }
  }

  return std::nullopt;
}

#define X(T) template class Walker<T>;
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X