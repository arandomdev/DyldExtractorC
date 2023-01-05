#include "Context.h"

#include <exception>

using namespace DyldExtractor;
using namespace Macho;

MappingInfo::MappingInfo(const dyld_cache_mapping_info *info)
    : address(info->address), size(info->size), fileOffset(info->fileOffset) {}

template <bool ro, class P>
SegmentContext<ro, P>::SegmentContext(SegmentCommandT *segment)
    : command(segment) {
  auto *sectStart =
      (typename c_const<ro, uint8_t>::T *)segment + sizeof(SegmentCommandT);
  for (uint32_t i = 0; i < segment->nsects; i++) {
    auto sect = (SectionT *)(sectStart + (i * sizeof(SectionT)));
    sections.emplace_back(sect);
  }
}

template class SegmentContext<true, Utils::Arch::Pointer32>;
template class SegmentContext<true, Utils::Arch::Pointer64>;
template class SegmentContext<false, Utils::Arch::Pointer32>;
template class SegmentContext<false, Utils::Arch::Pointer64>;

template <bool ro, class P>
Context<ro, P>::Context(
    uint64_t fileOffset, bio::mapped_file mainFile,
    std::vector<MappingInfo> mainMappings,
    std::vector<std::tuple<bio::mapped_file, std::vector<MappingInfo>>>
        subFiles)
    : headerOffset(fileOffset) {
  // Store files
  if constexpr (ro) {
    file = (FileT *)mainFile.const_data();
  } else {
    file = (FileT *)mainFile.data();
  }

  files.emplace_back(file, mainMappings);
  fileMaps.push_back(std::move(mainFile));
  for (auto &[fileMap, mapping] : subFiles) {
    FileT *subFile;
    if constexpr (ro) {
      subFile = (FileT *)fileMap.const_data();
    } else {
      subFile = (FileT *)fileMap.data();
    }

    files.emplace_back(subFile, mapping);
    fileMaps.push_back(std::move(fileMap));
  }
  if (ownFiles) {
    filesOpen = true;
  }

  reloadHeader();
}

template <bool ro, class P>
Context<ro, P>::Context(
    uint64_t fileOffset, fs::path mainPath,
    std::vector<MappingInfo> mainMappings,
    std::vector<std::tuple<fs::path, std::vector<MappingInfo>>> subFiles)
    : Context(fileOffset, openFile(mainPath), mainMappings,
              openFiles(subFiles)) {
  ownFiles = true;
}

template <bool ro, class P> Context<ro, P>::~Context() {
  if (filesOpen) {
    for (auto &file : fileMaps) {
      file.close();
    }
    filesOpen = false;
  }
}

template <bool ro, class P>
Context<ro, P>::Context(Context<ro, P> &&other)
    : file(other.file), header(other.header), ownFiles(other.ownFiles),
      filesOpen(other.filesOpen), fileMaps(std::move(other.fileMaps)),
      files(std::move(other.files)) {
  other.file = nullptr;
  other.header = nullptr;
  other.ownFiles = false;
  other.filesOpen = false;
}

template <bool ro, class P>
Context<ro, P> &Context<ro, P>::operator=(Context<ro, P> &&other) {
  this->file = other.file;
  this->header = other.header;
  this->ownFiles = other.ownFiles;
  this->filesOpen = other.filesOpen;

  this->fileMaps = std::move(other.fileMaps);
  this->files = std::move(other.files);

  other.file = nullptr;
  other.header = nullptr;
  other.ownFiles = false;
  other.filesOpen = false;
  return *this;
}

template <bool ro, class P> void Context<ro, P>::reloadHeader() {
  loadCommands.clear();
  segments.clear();

  header = (HeaderT *)(file + headerOffset);

  if (header->magic != HeaderT::MAGIC && header->magic != HeaderT::CIGAM) {
    throw std::invalid_argument("Mach-o header has an invalid magic.");
  } else if (header->magic == HeaderT::CIGAM) {
    throw std::invalid_argument(
        "Host system endianness incompatible with mach-o file.");
  }

  loadCommands.reserve(header->ncmds);
  FileT *cmdStart = (FileT *)header + sizeof(HeaderT);
  for (uint32_t cmdOff = 0; cmdOff < header->sizeofcmds;) {
    auto cmd = (LoadCommandT *)(cmdStart + cmdOff);
    loadCommands.emplace_back(cmd);
    cmdOff += cmd->cmdsize;
  }

  for (auto const seg : getAllLCs<Loader::segment_command<P>>()) {
    segments.emplace_back(seg);
  }
}

template <bool ro, class P>
std::pair<uint64_t, typename Context<ro, P>::FileT *>
Context<ro, P>::convertAddr(uint64_t addr) const {
  for (auto &[file, mappings] : files) {
    for (auto &mapping : mappings) {
      if (addr >= mapping.address && addr < mapping.address + mapping.size) {
        return std::make_pair((addr - mapping.address) + mapping.fileOffset,
                              file);
      }
    }
  }

  return std::make_pair(0, nullptr);
}

template <bool ro, class P>
typename Context<ro, P>::FileT *
Context<ro, P>::convertAddrP(uint64_t addr) const {
  auto [offset, file] = convertAddr(addr);
  return file ? file + offset : nullptr;
}

template <bool ro, class P>
const SegmentContext<ro, P> *
Context<ro, P>::getSegment(const char *segName) const {
  auto nameSize = strlen(segName) + 1;
  if (nameSize > 16) {
    throw std::invalid_argument("Segment name is too long.");
  }

  for (auto &seg : segments) {
    if (memcmp(segName, seg.command->segname, nameSize) == 0) {
      return &seg;
    }
  }

  return nullptr;
}

template <bool ro, class P>
std::pair<const SegmentContext<ro, P> *,
          const typename SegmentContext<ro, P>::SectionT *>
Context<ro, P>::getSection(const char *segName, const char *sectName) const {
  std::size_t segSize = 0;
  if (segName != nullptr) {
    segSize = strlen(segName);
    if (segSize < 16) {
      // Include null terminator
      segSize++;
    } else if (segSize > 16) {
      throw std::invalid_argument("Segment name is too long.");
    }
  }

  std::size_t sectSize = strlen(sectName);
  if (sectSize < 16) {
    // Include null terminator
    sectSize++;
  } else if (sectSize > 16) {
    throw std::invalid_argument("Section name is too long.");
  }

  for (auto &seg : segments) {
    if (segSize == 0 || memcmp(segName, seg.command->segname, segSize) == 0) {
      for (auto sect : seg.sections) {
        if (memcmp(sectName, sect->sectname, sectSize) == 0) {
          return std::make_pair(&seg, sect);
        }
      }
    }
  }

  return std::make_pair(nullptr, nullptr);
}

template <bool ro, class P>
bool Context<ro, P>::containsAddr(const uint64_t addr) const {
  /// TODO: Binary search?
  for (auto &seg : segments) {
    if (addr >= seg.command->vmaddr &&
        addr < seg.command->vmaddr + seg.command->vmsize) {
      return true;
    }
  }

  return false;
}

template <bool ro, class P>
std::vector<typename Context<ro, P>::LoadCommandT *>
Context<ro, P>::_getAllLCs(const uint32_t (&targetCmds)[],
                           std::size_t ncmds) const {
  auto matchLoadCommands = [&targetCmds, ncmds](uint32_t cmd) {
    // magic value for load_command, match all.
    if (ncmds == 2 && targetCmds[0] == 0x00 && targetCmds[1] == 0x00) {
      return true;
    }

    for (int i = 0; i < ncmds; i++) {
      if (cmd == targetCmds[i]) {
        return true;
      }
    }
    return false;
  };

  std::vector<LoadCommandT *> lcs;
  for (auto lc : loadCommands) {
    if (matchLoadCommands(lc->cmd)) {
      lcs.push_back(lc);
    }
  }

  return lcs;
}

template <bool ro, class P>
typename Context<ro, P>::LoadCommandT *
Context<ro, P>::_getFirstLC(const uint32_t (&targetCmds)[],
                            std::size_t ncmds) const {
  auto matchLoadCommands = [&targetCmds, ncmds](uint32_t cmd) {
    // magic value for load_command, match all.
    if (ncmds == 2 && targetCmds[0] == 0x00 && targetCmds[1] == 0x00) {
      return true;
    }

    for (int i = 0; i < ncmds; i++) {
      if (cmd == targetCmds[i]) {
        return true;
      }
    }
    return false;
  };

  for (auto lc : loadCommands) {
    if (matchLoadCommands(lc->cmd)) {
      return lc;
    }
  }

  return nullptr;
}

template <bool ro, class P>
void Context<ro, P>::enumerateSections(EnumerationCallback pred,
                                       EnumerationCallback callback) {
  for (auto &seg : segments) {
    for (auto sect : seg.sections) {
      if (pred(seg, sect)) {
        if (!callback(seg, sect)) {
          return;
        }
      }
    }
  }
}

template <bool ro, class P>
void Context<ro, P>::enumerateSections(EnumerationCallback callback) {
  enumerateSections([](...) { return true; }, callback);
}

template <bool ro, class P>
bio::mapped_file Context<ro, P>::openFile(fs::path path) {
  return bio::mapped_file(path.string(), bio::mapped_file::mapmode::priv);
}

template <bool ro, class P>
std::vector<std::tuple<bio::mapped_file, std::vector<MappingInfo>>>
Context<ro, P>::openFiles(
    std::vector<std::tuple<fs::path, std::vector<MappingInfo>>> paths) {
  std::vector<std::tuple<bio::mapped_file, std::vector<MappingInfo>>> files(
      paths.size());
  for (auto &[path, mappings] : paths) {
    files.emplace_back(
        bio::mapped_file(path.string(), bio::mapped_file::mapmode::priv),
        mappings);
  }

  return files;
}

template class Context<true, Utils::Arch::Pointer32>;
template class Context<true, Utils::Arch::Pointer64>;
template class Context<false, Utils::Arch::Pointer32>;
template class Context<false, Utils::Arch::Pointer64>;