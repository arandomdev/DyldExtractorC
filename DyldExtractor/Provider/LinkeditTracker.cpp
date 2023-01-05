#include "LinkeditTracker.h"

#include <Utils/Utils.h>

using namespace DyldExtractor;
using namespace Provider;

template <class P>
LinkeditTracker<P>::Metadata::Metadata(LinkeditTracker<P>::Tag tag,
                                       uint8_t *data, uint32_t dataSize,
                                       Macho::Loader::load_command *lc)
    : tag(tag), data(data), dataSize(dataSize),
      offsetField((uint32_t *)(reinterpret_cast<uint8_t *>(lc) +
                               LinkeditTracker<P>::lcOffsetForTag(tag))) {}

template <class P> uint8_t *LinkeditTracker<P>::Metadata::end() const {
  return data + dataSize;
}

template <class P>
LinkeditTracker<P>::LinkeditTracker(Macho::Context<false, P> &mCtx,
                                    uint64_t linkeditSize,
                                    std::vector<Metadata> initialData)
    : mCtx(&mCtx) {
  // Initialize basic variables
  leSeg = mCtx.getSegment(SEG_LINKEDIT)->command;
  auto [textSeg, textSect] = mCtx.getSection(SEG_TEXT, SECT_TEXT);

  auto [off, linkeditFile] = mCtx.convertAddr(leSeg->vmaddr);
  leOffset = off;
  leData = linkeditFile + off;
  leDataEnd = leData + linkeditSize;
  cmdsData = (uint8_t *)mCtx.header + sizeof(Macho::Context<false, P>::HeaderT);
  cmdsDataEnd = cmdsData + mCtx.header->sizeofcmds;
  cmdsMaxSize = textSect->addr - textSeg->command->vmaddr -
                sizeof(Macho::Loader::mach_header<P>);

  if (!initialData.size()) {
    return;
  }

  // Check that the tags are sorted
  bool sorted = std::is_sorted(
      initialData.begin(), initialData.end(),
      [](const Metadata &a, const Metadata &b) { return a.tag < b.tag; });
  if (!sorted) {
    throw std::invalid_argument("Data tags are not sorted.");
  }

  // Perform checks
  const auto boundsCheck = [this](const Metadata &m) {
    if (m.dataSize % sizeof(PtrT)) {
      throw std::invalid_argument("Data size is not pointer aligned.");
    }
    if (m.data < leData || m.end() > leDataEnd) {
      throw std::invalid_argument("Data is outside the linkedit region.");
    }
    if ((uint8_t *)m.offsetField < cmdsData ||
        (uint8_t *)m.offsetField + sizeof(uint32_t) > cmdsDataEnd) {
      throw std::invalid_argument(
          "Data offset field is outside the load command region.");
    }
  };

  // Check first one
  auto firstIt = initialData.cbegin();
  boundsCheck(*firstIt);
  if (firstIt->data != leData) {
    throw std::invalid_argument(
        "Data does not start at the beginning of the linkedit region.");
  }

  for (auto it = std::next(firstIt); it != initialData.cend(); it++) {
    boundsCheck(*it);

    // Check if the start and end align
    if (std::prev(it)->end() != it->data) {
      throw std::invalid_argument("Data does not make up a continuous range.");
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
LinkeditTracker<P>::MetadataIt LinkeditTracker<P>::metadataBegin() {
  return metadata.begin();
}

template <class P>
LinkeditTracker<P>::MetadataIt LinkeditTracker<P>::metadataEnd() {
  return metadata.end();
}

template <class P> Macho::Loader::load_command *LinkeditTracker<P>::lcBegin() {
  return reinterpret_cast<Macho::Loader::load_command *>(cmdsData);
}

template <class P> Macho::Loader::load_command *LinkeditTracker<P>::lcEnd() {
  return reinterpret_cast<Macho::Loader::load_command *>(cmdsDataEnd);
}

template <class P> const uint8_t *LinkeditTracker<P>::getData() const {
  return leData;
}

template <class P>
LinkeditTracker<P>::MetadataIt LinkeditTracker<P>::findTag(Tag tag) {
  for (auto it = metadata.begin(); it != metadata.end(); it++) {
    if (it->tag == tag) {
      return it;
    }
  }
  return metadata.end();
}

template <class P>
bool LinkeditTracker<P>::resizeData(MetadataIt metaIt, uint32_t newSize) {
  if (newSize % sizeof(PtrT)) {
    throw std::invalid_argument("New size is not pointer aligned.");
  }

  int32_t shiftAmount = newSize - metaIt->dataSize;

  // Check if we have enough space
  if (metadata.crbegin()->end() + shiftAmount > leDataEnd) {
    return false;
  }

  const auto afterIt = std::next(metaIt);
  if (afterIt != metadata.end()) {
    // move all data after target
    const auto shiftStart = afterIt->data;
    const auto shiftEnd = metadata.crbegin()->end();
    memmove(shiftStart + shiftAmount, shiftStart, shiftEnd - shiftStart);

    // Update all metadata
    for (auto it = afterIt; it != metadata.end(); it++) {
      it->data += shiftAmount;
      *it->offsetField += shiftAmount;
    }
  }

  // zero out new space if needed, and update target
  if (shiftAmount > 0) {
    memset(metaIt->end(), 0, shiftAmount);
  }
  metaIt->dataSize = newSize;

  // update segment data
  leSeg->vmsize += shiftAmount;
  leSeg->filesize += shiftAmount;
  return true;
}

template <class P>
std::pair<typename LinkeditTracker<P>::MetadataIt, bool>
LinkeditTracker<P>::addData(Metadata meta, const uint8_t *const data,
                            uint32_t copySize) {
  // Validate
  if (meta.dataSize % sizeof(PtrT)) {
    throw std::invalid_argument(
        "Data size for the new data region must be pointer aligned.");
  }
  if (copySize > meta.dataSize) {
    throw std::invalid_argument(
        "Copy size must be less than or equal to the new data region size.");
  }
  if ((uint8_t *)meta.offsetField < cmdsData ||
      (uint8_t *)meta.offsetField + sizeof(uint32_t) > cmdsDataEnd) {
    throw std::invalid_argument(
        "Data offset field is outside the load command region.");
  }

  // Get insert position
  auto pos = std::lower_bound(
      metadata.begin(), metadata.end(), meta,
      [](const Metadata &a, const Metadata &b) { return a.tag < b.tag; });
  auto posDataStart = pos == metadata.end() ? std::prev(pos)->end() : pos->data;

  // Get end of all data
  auto dataEnd = metadata.crbegin() != metadata.crend()
                     ? metadata.crbegin()->end()
                     : leData;
  if (dataEnd + meta.dataSize > leDataEnd) {
    return std::make_pair(metadata.end(), false);
  }

  if (metadata.size()) {
    // Move data starting from pos
    const auto shiftSize = metadata.crbegin()->end() - posDataStart;
    memmove(posDataStart + meta.dataSize, posDataStart, shiftSize);
  }

  // Update metadata for shifted data
  for (auto it = pos; it != metadata.end(); it++) {
    it->data += meta.dataSize;
    *it->offsetField += meta.dataSize;
  }

  // copy in new data
  memcpy(posDataStart, data, copySize);

  // Zero out any non copied data
  memset(posDataStart + copySize, 0x0, meta.dataSize - copySize);

  // update added metadata and insert
  meta.data = posDataStart;
  *meta.offsetField = (uint32_t)(leOffset + (posDataStart - leData));
  auto newMetaIt = metadata.insert(pos, meta);

  // Update segment
  leSeg->vmsize += meta.dataSize;
  leSeg->filesize += meta.dataSize;
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
  leSeg->vmsize -= pos->dataSize;
  leSeg->filesize -= pos->dataSize;

  // Update tracked metadata
  for (auto it = std::next(pos); it != metadata.end(); it++) {
    it->data -= pos->dataSize;
    *it->offsetField -= pos->dataSize;
  }
  metadata.erase(pos);
}

template <class P>
std::pair<Macho::Loader::load_command *, bool>
LinkeditTracker<P>::insertLC(Macho::Loader::load_command *pos,
                             Macho::Loader::load_command *lc) {
  // Check if there is enough space
  uint64_t newSize = cmdsDataEnd - cmdsData + lc->cmdsize;
  if (newSize > cmdsMaxSize) {
    return std::make_pair(nullptr, false);
  }

  // Verify pos
  auto posData = reinterpret_cast<uint8_t *>(pos);
  if (posData < cmdsData || posData >= cmdsDataEnd) {
    throw std::invalid_argument("Pos is outside of load command region.");
  }

  // Need to shift all commands starting at pos
  uint8_t *shiftStart = reinterpret_cast<uint8_t *>(pos);
  uint8_t *shiftEnd = cmdsDataEnd;
  memmove(shiftStart + lc->cmdsize, shiftStart, shiftEnd - shiftStart);

  // update offset fields
  for (auto it = metadata.begin(); it != metadata.end(); it++) {
    uint8_t *offsetField = reinterpret_cast<uint8_t *>(it->offsetField);
    if (offsetField >= shiftStart && offsetField < shiftEnd) {
      it->offsetField = reinterpret_cast<uint32_t *>(offsetField + lc->cmdsize);
    }
  }

  // Insert new lc
  memcpy(reinterpret_cast<uint8_t *>(pos), reinterpret_cast<uint8_t *>(lc),
         lc->cmdsize);

  //  Update header
  cmdsDataEnd += lc->cmdsize;
  mCtx->header->sizeofcmds += lc->cmdsize;
  mCtx->header->ncmds++;
  mCtx->reloadHeader();
  leSeg = mCtx->getSegment(SEG_LINKEDIT)->command;

  return std::make_pair(pos, true);
}

template <class P>
void LinkeditTracker<P>::removeLC(Macho::Loader::load_command *lc) {
  // Validate
  uint8_t *lcData = (uint8_t *)lc;
  if (lcData < cmdsData || lcData >= cmdsDataEnd) {
    throw std::invalid_argument("Load command is outside load command region.");
  }

  for (const auto &meta : metadata) {
    uint8_t *offsetField = (uint8_t *)meta.offsetField;
    if (offsetField >= lcData && offsetField < lcData + lc->cmdsize) {
      throw std::invalid_argument("Metadata is tracking load command.");
    }
  }

  auto cmdsize = lc->cmdsize;

  // Shift lcs back
  uint8_t *shiftStart = lcData + cmdsize;
  uint8_t *shiftEnd = cmdsDataEnd;
  uint64_t shiftSize = shiftEnd - shiftStart;
  memmove(lcData, shiftStart, shiftSize);

  // update offset fields
  for (auto it = metadata.begin(); it != metadata.end(); it++) {
    uint8_t *offsetField = reinterpret_cast<uint8_t *>(it->offsetField);
    if (offsetField >= shiftStart && offsetField < shiftEnd) {
      it->offsetField = reinterpret_cast<uint32_t *>(offsetField - cmdsize);
    }
  }

  // zero out blank data
  uint8_t *zeroStart = lcData + shiftSize;
  memset(zeroStart, 0, shiftEnd - zeroStart);

  //  Update header
  cmdsDataEnd -= cmdsize;
  mCtx->header->sizeofcmds -= cmdsize;
  mCtx->header->ncmds--;
  mCtx->reloadHeader();
  leSeg = mCtx->getSegment(SEG_LINKEDIT)->command;
}

template <class P> uint32_t LinkeditTracker<P>::freeLCSpace() const {
  return (uint32_t)(cmdsMaxSize - (cmdsDataEnd - cmdsData));
}

template <class P> void LinkeditTracker<P>::changeOffset(uint32_t offset) {
  for (auto it = metadata.begin(); it != metadata.end(); it++) {
    *it->offsetField = offset + (uint32_t)(it->data - leData);
  }

  leOffset = offset;
  leSeg->fileoff = offset;
}

template <class P> uint32_t LinkeditTracker<P>::lcOffsetForTag(Tag tag) {
  switch (tag) {
  case Tag::rebase:
    return offsetof(dyld_info_command, rebase_off);
  case Tag::binding:
    return offsetof(dyld_info_command, bind_off);
  case Tag::weakBinding:
    return offsetof(dyld_info_command, weak_bind_off);
  case Tag::lazyBinding:
    return offsetof(dyld_info_command, lazy_bind_off);
  case Tag::exportTrie:
    return offsetof(dyld_info_command, export_off);
  case Tag::symtab:
    return offsetof(symtab_command, symoff);
  case Tag::stringPool:
    return offsetof(symtab_command, stroff);
  case Tag::indirectSymtab:
    return offsetof(dysymtab_command, indirectsymoff);
  case Tag::detachedExportTrie:
  case Tag::functionStarts:
  case Tag::dataInCode:
  case Tag::chained:
    return offsetof(linkedit_data_command, dataoff);
  default:
    Utils::unreachable();
  }
}

template class LinkeditTracker<Utils::Arch::Pointer32>;
template class LinkeditTracker<Utils::Arch::Pointer64>;
