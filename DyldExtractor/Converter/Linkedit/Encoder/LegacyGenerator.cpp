#include "LegacyGenerator.h"

#include "BindingV1.h"
#include "RebaseV1.h"
#include <Objc/Abstraction.h>

using namespace DyldExtractor;
using namespace Converter;
using namespace Linkedit;
using namespace Encoder;

template <class A> bool addDyldInfo(Utils::ExtractionContext<A> &eCtx) {
  using P = A::P;
  using LETrackerTag = Provider::LinkeditTracker<P>::Tag;

  eCtx.activity->update(std::nullopt, "Adding dyld info command");

  auto &mCtx = *eCtx.mCtx;
  auto logger = eCtx.logger;
  auto &leTracker = eCtx.leTracker;

  Macho::Loader::dyld_info_command dyldInfo = {0};
  dyldInfo.cmd = LC_DYLD_INFO_ONLY;
  dyldInfo.cmdsize = sizeof(Macho::Loader::dyld_info_command);

  // Insert dyld info command before symtab command
  auto symtab = mCtx.getFirstLC<Macho::Loader::symtab_command>();
  auto [dyldInfoLc, success] = leTracker.insertLC(
      reinterpret_cast<Macho::Loader::load_command *>(symtab),
      reinterpret_cast<Macho::Loader::load_command *>(&dyldInfo));
  if (!success) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to add dyld_info_command");
    return false;
  }

  // Move the export trie info into dyld info
  auto exportTrieCmd = mCtx.getFirstLC<Macho::Loader::linkedit_data_command>(
      {LC_DYLD_EXPORTS_TRIE});
  auto exportTrieMetaIt = leTracker.findTag(LETrackerTag::exportTrie);
  if (!exportTrieCmd || exportTrieMetaIt == leTracker.metadataEnd()) {
    return true;
  }

  auto trueSize = exportTrieCmd->datasize;
  auto linkeditSize = exportTrieMetaIt->dataSize;
  reinterpret_cast<Macho::Loader::dyld_info_command *>(dyldInfoLc)
      ->export_size = trueSize;
  std::vector<uint8_t> exportTrieData(exportTrieMetaIt->data,
                                      exportTrieMetaIt->data + trueSize);

  // Remove old data
  leTracker.removeData(exportTrieMetaIt);
  leTracker.removeLC(
      reinterpret_cast<Macho::Loader::load_command *>(exportTrieCmd));

  // insert before the symbol entries
  auto symbolEntriesIt = leTracker.findTag(LETrackerTag::symbolEntries);
  if (symbolEntriesIt == leTracker.metadataEnd()) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to find symbol entries");
    return false;
  }

  // need to get dyld info command again because removeLC invalidates it.
  typename Provider::LinkeditTracker<P>::Metadata exportInfoMeta(
      LETrackerTag::exportInfo, nullptr, linkeditSize,
      reinterpret_cast<uint8_t *>(
          mCtx.getFirstLC<Macho::Loader::dyld_info_command>()));
  success = leTracker
                .insertData(symbolEntriesIt, exportInfoMeta,
                            exportTrieData.data(), trueSize)
                .second;
  if (!success) {
    SPDLOG_LOGGER_ERROR(logger, "Unable to add export info");
    return false;
  }

  return true;
}

/// @brief Updates all tracked pointers to their targets
template <class A> void applyFixups(Utils::ExtractionContext<A> &eCtx) {
  using PtrT = A::P::PtrT;

  auto &mCtx = *eCtx.mCtx;
  eCtx.activity->update(std::nullopt, "Fixing pointers");

  auto &pointers = eCtx.ptrTracker.getPointers();
  for (auto seg : mCtx.segments) {
    eCtx.activity->update();

    auto command = seg.command;
    uint8_t *segData;
    if (strcmp(command->segname, SEG_OBJC_EXTRA) == 0) {
      segData = eCtx.exObjc.get<uint8_t>(command->vmaddr);
    } else {
      segData = mCtx.convertAddrP(command->vmaddr);
    }

    // process all pointers within the segment
    auto beginIt = pointers.lower_bound(command->vmaddr);
    auto endIt = pointers.lower_bound(command->vmaddr + command->vmsize);
    for (auto it = beginIt; it != endIt; it++) {
      auto [addr, target] = *it;
      // Note: classic rebase does not have auth info
      *(PtrT *)(segData + (addr - command->vmaddr)) = target;
    }
  }
}

/// @brief Returns a copy of all pointers within segments
template <class P, class T>
std::map<typename P::PtrT, T>
filterPointers(const Macho::Context<false, P> &mCtx,
               std::map<typename P::PtrT, T> pointers) {
  std::map<typename P::PtrT, T> filtered;
  for (const auto &seg : mCtx.segments) {
    auto beginIt = pointers.lower_bound(seg.command->vmaddr);
    auto endIt =
        pointers.lower_bound(seg.command->vmaddr + seg.command->vmsize);
    filtered.insert(beginIt, endIt);
  }
  return filtered;
}

template <class A>
std::vector<uint8_t> encodeRebaseInfo(Utils::ExtractionContext<A> &eCtx) {
  auto pointers = filterPointers(*eCtx.mCtx, eCtx.ptrTracker.getPointers());
  std::vector<Encoder::RebaseV1Info> rebaseInfo;
  rebaseInfo.reserve(pointers.size());
  for (const auto pointer : pointers) {
    rebaseInfo.emplace_back(REBASE_TYPE_POINTER, pointer.first);
  }

  auto encodedData = Encoder::encodeRebaseV1(rebaseInfo, *eCtx.mCtx);

  // Pointer align
  if (auto pad = Utils::align(encodedData.size(), sizeof(A::P::PtrT)) -
                 encodedData.size();
      pad != 0) {
    encodedData.insert(encodedData.end(), pad, 0x0);
  }
  return encodedData;
}

template <class A>
std::vector<uint8_t> encodeBindInfo(Utils::ExtractionContext<A> &eCtx) {
  using PtrT = A::P::PtrT;
  const auto &mCtx = *eCtx.mCtx;

  auto binds = filterPointers(mCtx, eCtx.ptrTracker.getBinds());
  std::map<PtrT, Encoder::BindingV1Info> bindInfo;

  // get ordinals of weak dylibs
  const auto dylibs = mCtx.getAllLCs<Macho::Loader::dylib_command>();
  std::set<uint64_t> weakDylibOrdinals;
  for (int i = 0; i < dylibs.size(); i++) {
    if (dylibs.at(i)->cmd == LC_LOAD_WEAK_DYLIB) {
      weakDylibOrdinals.insert(i);
    }
  }

  for (const auto &[addr, bind] : binds) {
    auto &sym = bind->preferredSymbol();
    bindInfo.emplace(addr,
                     Encoder::BindingV1Info(
                         BIND_TYPE_POINTER, (int)sym.ordinal, sym.name.c_str(),
                         weakDylibOrdinals.contains(sym.ordinal), addr, 0));
  }

  // Add binds from opcodes
  for (const auto &bind : eCtx.bindInfo.getBinds()) {
    bindInfo.insert_or_assign(
        (PtrT)bind.address,
        Encoder::BindingV1Info(bind.type, bind.flags, 0, bind.libOrdinal,
                               bind.symbolName, bind.address, bind.addend));
  }

  std::vector<Encoder::BindingV1Info> bindInfoVec;
  bindInfoVec.reserve(bindInfo.size());
  for (const auto &b : bindInfo) {
    bindInfoVec.push_back(b.second);
  }

  auto encodedData = Encoder::encodeBindingV1(bindInfoVec, mCtx);

  // Pointer align
  if (auto pad = Utils::align(encodedData.size(), sizeof(A::P::PtrT)) -
                 encodedData.size();
      pad != 0) {
    encodedData.insert(encodedData.end(), pad, 0x0);
  }
  return encodedData;
}

template <class A>
bool addRebaseInfo(Utils::ExtractionContext<A> &eCtx,
                   std::vector<uint8_t> data) {
  using LETrackerTag = Provider::LinkeditTracker<typename A::P>::Tag;

  uint32_t size = (uint32_t)data.size();
  auto &leTracker = eCtx.leTracker;
  auto dyldInfo = eCtx.mCtx->getFirstLC<Macho::Loader::dyld_info_command>();
  auto rebaseInfoMetaIt = leTracker.findTag(LETrackerTag::rebaseInfo);

  if (!size) {
    // remove any data if necessary
    if (rebaseInfoMetaIt != leTracker.metadataEnd()) {
      leTracker.removeData(rebaseInfoMetaIt);
    }
    dyldInfo->rebase_off = 0;
    dyldInfo->rebase_size = 0;
    return true;
  }

  if (rebaseInfoMetaIt != leTracker.metadataEnd()) {
    // Resize data and overwrite
    if (auto newIt = leTracker.resizeData(rebaseInfoMetaIt, size);
        newIt != leTracker.metadataEnd()) {
      memcpy(newIt->data, data.data(), size);
    } else {
      SPDLOG_LOGGER_ERROR(eCtx.logger,
                          "Unable resize data region for new rebase info");
      return false;
    }

  } else {
    // Find position to insert rebase data, should be at the beginning of dyld
    // info data
    auto pos = leTracker.findTag(
        {LETrackerTag::bindInfo, LETrackerTag::weakBindInfo,
         LETrackerTag::lazyBindInfo, LETrackerTag::exportInfo});
    if (pos == leTracker.metadataEnd()) {
      pos = leTracker.metadataBegin();
    }

    if (!leTracker
             .insertData(pos,
                         {LETrackerTag::rebaseInfo, nullptr, size,
                          reinterpret_cast<uint8_t *>(dyldInfo)},
                         data.data(), size)
             .second) {
      SPDLOG_LOGGER_ERROR(eCtx.logger, "Unable to insert new rebase info");
      return false;
    }
  }

  dyldInfo->rebase_size = size;
  return true;
}

template <class A>
bool addBindInfo(Utils::ExtractionContext<A> &eCtx, std::vector<uint8_t> data) {
  using LETrackerTag = Provider::LinkeditTracker<typename A::P>::Tag;

  uint32_t size = (uint32_t)data.size();
  auto &leTracker = eCtx.leTracker;
  auto dyldInfo = eCtx.mCtx->getFirstLC<Macho::Loader::dyld_info_command>();
  auto bindInfoMetaIt = leTracker.findTag(LETrackerTag::bindInfo);

  if (!size) {
    // remove any data if necessary
    if (bindInfoMetaIt != leTracker.metadataEnd()) {
      leTracker.removeData(bindInfoMetaIt);
    }
    dyldInfo->bind_off = 0;
    dyldInfo->bind_size = 0;
    return true;
  }

  if (bindInfoMetaIt != leTracker.metadataEnd()) {
    // resize data and overwrite
    if (auto newIt = leTracker.resizeData(bindInfoMetaIt, size);
        newIt != leTracker.metadataEnd()) {
      memcpy(newIt->data, data.data(), size);
    } else {
      SPDLOG_LOGGER_ERROR(eCtx.logger,
                          "Unable resize data region for new bind info");
      return false;
    }
  } else {
    // Is placed after the rebase info
    auto pos = leTracker.findTag(LETrackerTag::rebaseInfo);
    if (pos == leTracker.metadataEnd()) {
      SPDLOG_LOGGER_ERROR(eCtx.logger, "Unable to find rebase info metadata");
      return false;
    } else {
      if (!leTracker
               .insertData(std::next(pos),
                           {LETrackerTag::bindInfo, nullptr, size,
                            reinterpret_cast<uint8_t *>(dyldInfo)},
                           data.data(), size)
               .second) {
        SPDLOG_LOGGER_ERROR(eCtx.logger, "Unable to insert new rebase info");
        return false;
      }
    }
  }

  dyldInfo->bind_size = size;
  return true;
}

/// @brief Generates and adds linkedit metadata
template <class A> void addMetadata(Utils::ExtractionContext<A> &eCtx) {
  eCtx.activity->update(std::nullopt, "Generating Rebase Info");
  auto rebaseInfo = encodeRebaseInfo(eCtx);
  eCtx.activity->update(std::nullopt, "Generating Bind Info");
  auto bindInfo = encodeBindInfo(eCtx);

  if (!addRebaseInfo(eCtx, rebaseInfo)) {
    return;
  }
  if (!addBindInfo(eCtx, bindInfo)) {
    return;
  }
}

template <class A>
void Encoder::generateLegacyMetadata(Utils::ExtractionContext<A> &eCtx) {
  if (!eCtx.mCtx->getFirstLC<Macho::Loader::dyld_info_command>()) {
    if (!addDyldInfo(eCtx)) {
      return;
    }
  }

  applyFixups(eCtx);
  addMetadata(eCtx);
}

#define X(T)                                                                   \
  template void Encoder::generateLegacyMetadata<T>(                            \
      Utils::ExtractionContext<T> & eCtx);
X(Utils::Arch::x86_64)
X(Utils::Arch::arm)
X(Utils::Arch::arm64)
X(Utils::Arch::arm64_32)
#undef X