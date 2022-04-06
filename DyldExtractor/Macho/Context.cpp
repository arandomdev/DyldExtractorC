#include "Context.h"

#include <exception>

using namespace Macho;

MappingInfo::MappingInfo(const dyld_cache_mapping_info *info)
    : address(info->address), size(info->size), fileOffset(info->fileOffset) {}

template <bool ro, class P>
SegmentContext<ro, P>::SegmentContext(_SegmentCommandT *segment)
    : command(segment) {
    auto *sectStart =
        (typename c_const<ro, char>::T *)segment + sizeof(_SegmentCommandT);
    for (uint32_t i = 0; i < segment->nsects; i++) {
        auto sect = (_SectionT *)(sectStart + (i * sizeof(_SectionT)));
        sections.emplace_back(sect);
    }
}

template class SegmentContext<true, Utils::Pointer32>;
template class SegmentContext<true, Utils::Pointer64>;
template class SegmentContext<false, Utils::Pointer32>;
template class SegmentContext<false, Utils::Pointer64>;

template <bool ro, class P>
Context<ro, P>::Context(
    uint64_t fileOffset, bio::mapped_file mainFile,
    std::vector<MappingInfo> mainMappings,
    std::vector<std::tuple<bio::mapped_file, std::vector<MappingInfo>>>
        subFiles) {
    // Store files
    if constexpr (ro) {
        file = mainFile.const_data();
    } else {
        file = mainFile.data();
    }

    _files.emplace_back(file, mainMappings);
    _fileMaps.push_back(std::move(mainFile));
    for (auto &[fileMap, mapping] : subFiles) {
        _FileT *subFile;
        if constexpr (ro) {
            subFile = fileMap.const_data();
        } else {
            subFile = fileMap.data();
        }

        _files.emplace_back(subFile, mapping);
        _fileMaps.push_back(std::move(fileMap));
    }
    if (_ownFiles) {
        _filesOpen = true;
    }

    // get data
    header = (_HeaderT *)(file + fileOffset);

    if (header->magic != _HeaderT::MAGIC && header->magic != _HeaderT::CIGAM) {
        throw std::invalid_argument("Mach-o header has an invalid magic.");
    } else if (header->magic == _HeaderT::CIGAM) {
        throw std::invalid_argument(
            "Host system endianness incompatible with mach-o file.");
    }

    loadCommands.reserve(header->ncmds);
    _FileT *cmdStart = (_FileT *)header + sizeof(_HeaderT);
    for (uint32_t cmdOff = 0; cmdOff < header->sizeofcmds;) {
        auto cmd = (_LoadCommandT *)(cmdStart + cmdOff);
        loadCommands.emplace_back(cmd);
        cmdOff += cmd->cmdsize;
    }

    for (auto const seg : getLoadCommand<true, Loader::segment_command<P>>()) {
        segments.emplace_back(seg);
    }
}

template <bool ro, class P>
Context<ro, P>::Context(
    uint64_t fileOffset, fs::path mainPath,
    std::vector<MappingInfo> mainMappings,
    std::vector<std::tuple<fs::path, std::vector<MappingInfo>>> subFiles)
    : Context(fileOffset, openFile(mainPath), mainMappings,
              openFiles(subFiles)) {
    _ownFiles = true;
}

template <bool ro, class P> Context<ro, P>::~Context() {
    if (_filesOpen) {
        for (auto &file : _fileMaps) {
            file.close();
        }
        _filesOpen = false;
    }
}

template <bool ro, class P>
Context<ro, P>::Context(Context<ro, P> &&other)
    : file(other.file), header(other.header), _ownFiles(other._ownFiles),
      _filesOpen(other._filesOpen), _fileMaps(std::move(other._fileMaps)),
      _files(std::move(other._files)) {
    other.file = nullptr;
    other.header = nullptr;
    other._ownFiles = false;
    other._filesOpen = false;
}

template <bool ro, class P>
Context<ro, P> &Context<ro, P>::operator=(Context<ro, P> &&other) {
    this->file = other.file;
    this->header = other.header;
    this->_ownFiles = other._ownFiles;
    this->_filesOpen = other._filesOpen;

    this->_fileMaps = std::move(other._fileMaps);
    this->_files = std::move(other._files);

    other.file = nullptr;
    other.header = nullptr;
    other._ownFiles = false;
    other._filesOpen = false;
    return *this;
}

template <bool ro, class P>
std::tuple<uint64_t, typename Context<ro, P>::_FileT *>
Context<ro, P>::convertAddr(uint64_t addr) const {
    for (auto &[file, mappings] : _files) {
        for (auto &mapping : mappings) {
            if (addr >= mapping.address &&
                addr < mapping.address + mapping.size) {
                return std::make_tuple(
                    (addr - mapping.address) + mapping.fileOffset, file);
            }
        }
    }

    return std::make_tuple(0, nullptr);
}

template <bool ro, class P>
std::vector<typename c_const<ro, Loader::load_command>::T *>
Context<ro, P>::_getLoadCommands(const uint32_t (&targetCmds)[],
                                 std::size_t ncmds) const {
    auto matchLoadComands = [&targetCmds, ncmds](uint32_t cmd) {
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

    std::vector<typename c_const<ro, Loader::load_command>::T *> lcs;
    for (auto lc : loadCommands) {
        if (matchLoadComands(lc->cmd)) {
            lcs.push_back(lc);
        }
    }

    return lcs;
}

template <bool ro, class P>
typename c_const<ro, Loader::load_command>::T *
Context<ro, P>::_getLoadCommand(const uint32_t (&targetCmds)[],
                                std::size_t ncmds) const {
    auto matchLoadComands = [&targetCmds, ncmds](uint32_t cmd) {
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
        if (matchLoadComands(lc->cmd)) {
            return lc;
        }
    }

    return nullptr;
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

template class Context<true, Utils::Pointer32>;
template class Context<true, Utils::Pointer64>;
template class Context<false, Utils::Pointer32>;
template class Context<false, Utils::Pointer64>;