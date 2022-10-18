#include "LinkeditTracker.h"

using namespace DyldExtractor;
using namespace Provider;

template <class P>
LinkeditTracker<P>::Metadata::Metadata(LinkeditTracker<P>::Tag tag,
                                       uint8_t *data, uint32_t dataSize,
                                       uint8_t *loadCommand)
    : tag(tag), data(data), dataSize(dataSize),
      offsetField(
          (uint32_t *)(loadCommand + LinkeditTracker<P>::lcOffsetForTag(tag))) {
  if (!dataSize) {
    throw std::invalid_argument("Linkedit data cannot be zero sized");
  }
}

template <class P> uint8_t *LinkeditTracker<P>::Metadata::end() const {
  return data + dataSize;
}

template <class P>
std::strong_ordering
LinkeditTracker<P>::Metadata::operator<=>(const Metadata &o) const {
  return this->data <=> o.data;
}

template <class P>
LinkeditTracker<P>::LinkeditTracker(Macho::Context<false, P> &mCtx)
    : mCtx(&mCtx) {
  auto linkeditSegData = mCtx.getSegment(SEG_LINKEDIT);
  auto [textSeg, textSect] = mCtx.getSection(SEG_TEXT, SECT_TEXT);

  linkeditSeg = linkeditSegData->command;

  auto [off, file] = mCtx.convertAddr(linkeditSeg->vmaddr);
  linkeditFile = file;
  linkeditOffset = off;
  linkeditStart = file + off;
  linkeditEnd = linkeditStart + linkeditSeg->vmsize;
  commandsStart =
      (uint8_t *)mCtx.header + sizeof(Macho::Context<false, P>::HeaderT);
  commandsEnd = commandsStart + mCtx.header->sizeofcmds;
  maxCommandsSize = textSect->addr - textSeg->command->vmaddr -
                    sizeof(Macho::Loader::mach_header<P>);
}

template <class P>
LinkeditTracker<P>::LinkeditTracker(Macho::Context<false, P> &mCtx,
                                    uint64_t linkeditSize,
                                    std::set<Metadata> initialData)
    : LinkeditTracker(mCtx) {
  const auto boundsCheck = [this](const Metadata &m) {
    if (m.dataSize % sizeof(PtrT)) {
      throw std::invalid_argument("Data size is not pointer aligned");
    }
    if (m.data < linkeditStart || m.end() > linkeditEnd) {
      throw std::invalid_argument("Data is outside the linkedit region");
    }
    if ((uint8_t *)m.offsetField < commandsStart ||
        (uint8_t *)m.offsetField + sizeof(uint32_t) > commandsEnd) {
      throw std::invalid_argument(
          "Data offset field is outside the load command region");
    }
  };

  linkeditEnd = linkeditStart + linkeditSize;
  if (!initialData.size()) {
    return;
  }

  // Perform checks
  boundsCheck(*initialData.cbegin());
  for (auto it = std::next(initialData.cbegin()); it != initialData.cend();
       it++) {
    boundsCheck(*it);

    // Check if the start and end align
    if (std::prev(it)->end() != it->data) {
      throw std::invalid_argument("Data does not make up a continuous range");
    }
  }

  // Set offsets incase they're out of sync
  for (auto &meta : initialData) {
    uint32_t offset = (uint32_t)(meta.data - linkeditFile);
    *meta.offsetField = offset;
  }

  metadata = initialData;
}

template <class P>
LinkeditTracker<P>::MetadataIt LinkeditTracker<P>::metadataBegin() const {
  return metadata.begin();
}

template <class P>
LinkeditTracker<P>::MetadataIt LinkeditTracker<P>::metadataEnd() const {
  return metadata.end();
}

template <class P>
LinkeditTracker<P>::MetadataIt LinkeditTracker<P>::findTag(Tag tag) const {
  for (auto it = metadata.begin(); it != metadata.end(); it++) {
    if (it->tag == tag) {
      return it;
    }
  }
  return metadata.end();
}

template <class P>
LinkeditTracker<P>::MetadataIt
LinkeditTracker<P>::findTag(const std::vector<Tag> &tags) const {
  for (const auto tag : tags) {
    if (auto it = findTag(tag); it != metadata.end()) {
      return it;
    }
  }

  return metadata.end();
}

template <class P>
LinkeditTracker<P>::MetadataIt
LinkeditTracker<P>::resizeData(MetadataIt metaIt, uint32_t newSize) {
  if (newSize % sizeof(PtrT)) {
    throw std::invalid_argument("New size is not pointer aligned");
  }

  int32_t shiftAmount = newSize - metaIt->dataSize;

  // Check if we have enough space
  if (metadata.crbegin()->end() + shiftAmount > linkeditEnd) {
    return metadata.end();
  }

  const auto afterIt = std::next(metaIt);
  if (afterIt != metadata.end()) {
    // move all data after target
    const auto shiftStart = afterIt->data;
    const auto shiftEnd = metadata.crbegin()->end();
    memmove(shiftStart + shiftAmount, shiftStart, shiftEnd - shiftStart);

    // Update all metadata
    std::set<Metadata> intermidiate;
    for (auto it = afterIt; it != metadata.end();) {
      auto target = metadata.extract(it++);
      target.value().data += shiftAmount;
      *target.value().offsetField += shiftAmount;
      intermidiate.insert(std::move(target));
    }
    metadata.merge(intermidiate);
  }

  // zero out new space if needed, and update target
  if (shiftAmount > 0) {
    memset(metaIt->end(), 0, shiftAmount);
  }
  auto metaH = metadata.extract(metaIt);
  metaH.value().dataSize = newSize;
  auto newMetaIt = metadata.insert(std::move(metaH)).position;

  // update segment data
  linkeditSeg->vmsize += shiftAmount;
  linkeditSeg->filesize += shiftAmount;
  return newMetaIt;
}

template <class P>
std::pair<typename LinkeditTracker<P>::MetadataIt, bool>
LinkeditTracker<P>::insertData(MetadataIt pos, Metadata meta,
                               const uint8_t *const data, uint32_t copySize) {
  // Validate
  if (meta.dataSize % sizeof(PtrT)) {
    throw std::invalid_argument(
        "Data size for the new data region must be pointer aligned.");
  }
  if (copySize > meta.dataSize) {
    throw std::invalid_argument(
        "Copy size must be less than or equal to the new data region size.");
  }
  if ((uint8_t *)meta.offsetField < commandsStart ||
      (uint8_t *)meta.offsetField + sizeof(uint32_t) > commandsEnd) {
    throw std::invalid_argument(
        "Data offset field is outside the load command region");
  }

  auto dataEnd = metadata.crbegin() != metadata.crend()
                     ? metadata.crbegin()->end()
                     : linkeditStart;
  if (dataEnd + meta.dataSize > linkeditEnd) {
    return std::make_pair(metadata.end(), false);
  }

  const auto shiftStart = pos->data;
  if (metadata.size()) {
    // Move data starting from pos
    const auto shiftSize = metadata.crbegin()->end() - shiftStart;
    memmove(shiftStart + meta.dataSize, shiftStart, shiftSize);
  }

  // Update metadata for shifted data
  std::set<Metadata> intermidiate;
  for (auto it = pos; it != metadata.end();) {
    auto itHandle = metadata.extract(it++);
    itHandle.value().data += meta.dataSize;
    *itHandle.value().offsetField += meta.dataSize;
    intermidiate.insert(std::move(itHandle));
  }
  metadata.merge(intermidiate);

  // copy in new data
  memcpy(shiftStart, data, copySize);

  // update metadata and insert
  meta.data = shiftStart;
  *meta.offsetField = (uint32_t)(linkeditOffset + (shiftStart - linkeditStart));
  auto newMetaIt = metadata.insert(meta).first;

  // Update segment
  linkeditSeg->vmsize += meta.dataSize;
  linkeditSeg->filesize += meta.dataSize;
  return std::make_pair(newMetaIt, true);
}

template <class P> void LinkeditTracker<P>::removeData(MetadataIt pos) {
  // shift data back
  uint8_t *shiftStart = pos->end();
  uint8_t *shiftEnd = metadata.rbegin()->end();
  uint64_t shiftSize = shiftEnd - shiftStart;
  memmove(pos->data, shiftStart, shiftSize);

  // Zero out blank data
  uint8_t *zeroStart = pos->data + shiftSize;
  memset(zeroStart, 0, shiftEnd - zeroStart);

  // Update segment
  linkeditSeg->vmsize -= pos->dataSize;
  linkeditSeg->filesize -= pos->dataSize;

  // Update tracked metadata
  std::set<Metadata> intermidiate;
  for (auto it = std::next(pos); it != metadata.end();) {
    auto itHandle = metadata.extract(it++);
    itHandle.value().data -= pos->dataSize;
    *itHandle.value().offsetField -= pos->dataSize;
    intermidiate.insert(std::move(itHandle));
  }
  metadata.erase(pos);
  metadata.merge(intermidiate);
}

template <class P>
std::pair<Macho::Loader::load_command *, bool>
LinkeditTracker<P>::insertLC(Macho::Loader::load_command *pos,
                             Macho::Loader::load_command *lc) {
  // Check if there is enough space
  uint64_t newSize = commandsEnd - commandsStart + lc->cmdsize;
  if (newSize > maxCommandsSize) {
    return std::make_pair(nullptr, false);
  }

  // Verify pos
  auto posData = reinterpret_cast<uint8_t *>(pos);
  if (posData < commandsStart || posData >= commandsEnd) {
    throw std::invalid_argument("Pos is outside of load command region");
  }

  if (pos) {
    // Need to shift all commands starting at pos
    uint8_t *shiftStart = reinterpret_cast<uint8_t *>(pos);
    uint8_t *shiftEnd = commandsEnd;
    memmove(shiftStart + lc->cmdsize, shiftStart, shiftEnd - shiftStart);

    // update offset fields
    for (auto it = metadata.begin(); it != metadata.end();) {
      uint8_t *offsetField = reinterpret_cast<uint8_t *>(it->offsetField);
      if (offsetField >= shiftStart && offsetField < shiftEnd) {
        auto node = metadata.extract(it++);
        node.value().offsetField =
            reinterpret_cast<uint32_t *>(offsetField + lc->cmdsize);
        metadata.insert(std::move(node));
      } else {
        it++;
      }
    }
  }

  // Insert new lc
  if (!pos) {
    // Insert at end
    pos = reinterpret_cast<Macho::Loader::load_command *>(commandsEnd);
  }
  memcpy(reinterpret_cast<uint8_t *>(pos), reinterpret_cast<uint8_t *>(lc),
         lc->cmdsize);

  //  Update header
  commandsEnd += lc->cmdsize;
  mCtx->header->sizeofcmds += lc->cmdsize;
  mCtx->header->ncmds++;
  mCtx->reloadHeader();

  return std::make_pair(pos, true);
}

template <class P>
void LinkeditTracker<P>::removeLC(Macho::Loader::load_command *lc) {
  // Validate
  uint8_t *lcData = (uint8_t *)lc;
  if (lcData < commandsStart || lcData >= commandsEnd) {
    throw std::invalid_argument("Load command is outside load command region");
  }

  for (const auto &meta : metadata) {
    uint8_t *offsetField = (uint8_t *)meta.offsetField;
    if (offsetField >= lcData && offsetField < lcData + lc->cmdsize) {
      throw std::invalid_argument("Metadata is tracking load command");
    }
  }

  auto cmdsize = lc->cmdsize;

  // Shift lcs back
  uint8_t *shiftStart = lcData + cmdsize;
  uint8_t *shiftEnd = commandsEnd;
  uint64_t shiftSize = shiftEnd - shiftStart;
  memmove(lcData, shiftStart, shiftSize);

  // update offset fields
  for (auto it = metadata.begin(); it != metadata.end();) {
    uint8_t *offsetField = reinterpret_cast<uint8_t *>(it->offsetField);
    if (offsetField >= shiftStart && offsetField < shiftEnd) {
      auto node = metadata.extract(it++);
      node.value().offsetField =
          reinterpret_cast<uint32_t *>(offsetField - cmdsize);
      metadata.insert(std::move(node));
    } else {
      it++;
    }
  }

  // zero out blank data
  uint8_t *zeroStart = lcData + shiftSize;
  memset(zeroStart, 0, shiftEnd - zeroStart);

  //  Update header
  commandsEnd -= cmdsize;
  mCtx->header->sizeofcmds -= cmdsize;
  mCtx->header->ncmds--;
  mCtx->reloadHeader();
}

template <class P> uint32_t LinkeditTracker<P>::lcOffsetForTag(Tag tag) {
  switch (tag) {
  case Tag::rebaseInfo:
    return offsetof(dyld_info_command, rebase_off);
  case Tag::bindInfo:
    return offsetof(dyld_info_command, bind_off);
  case Tag::weakBindInfo:
    return offsetof(dyld_info_command, weak_bind_off);
  case Tag::lazyBindInfo:
    return offsetof(dyld_info_command, lazy_bind_off);
  case Tag::exportInfo:
    return offsetof(dyld_info_command, export_off);
  case Tag::symbolEntries:
    return offsetof(symtab_command, symoff);
  case Tag::stringPool:
    return offsetof(symtab_command, stroff);
  case Tag::indirectSymtab:
    return offsetof(dysymtab_command, indirectsymoff);
  case Tag::exportTrie:
  case Tag::functionStarts:
  case Tag::dataInCode:
  case Tag::chainedFixups:
    return offsetof(linkedit_data_command, dataoff);
  default:
    throw std::invalid_argument("Unknown tag type");
  }
}

template class LinkeditTracker<Utils::Arch::Pointer32>;
template class LinkeditTracker<Utils::Arch::Pointer64>;
