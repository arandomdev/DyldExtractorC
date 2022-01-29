#include "Context.h"

#include <exception>

using namespace Macho;

MappingInfo::MappingInfo(const dyld_cache_mapping_info *info)
    : address(info->address), size(info->size), fileOffset(info->fileOffset) {}

template <bool _ro>
SegmentContext<_ro>::SegmentContext(_SegmentCommandT *segment)
    : command(segment) {
    auto *sectStart =
        (typename c_const<_ro, char>::T *)segment + sizeof(segment_command_64);
    for (uint32_t i = 0; i < segment->nsects; i++) {
        auto sect = (_SectionT *)(sectStart + (i * sizeof(section_64)));
        sections.emplace_back(sect);
    }
}

template class SegmentContext<true>;
template class SegmentContext<false>;

template <bool _ro>
Context<_ro>::Context(
    uint64_t fileOffset, bio::mapped_file mainFile,
    std::vector<MappingInfo> mainMappings,
    std::vector<std::tuple<bio::mapped_file, std::vector<MappingInfo>>>
        subFiles) {
    // Store files
    if constexpr (_ro) {
        file = mainFile.const_data();
    } else {
        file = mainFile.data();
    }

    _files.emplace_back(file, mainMappings);
    _fileMaps.push_back(std::move(mainFile));
    for (auto &[fileMap, mapping] : subFiles) {
        _FileT *subFile;
        if constexpr (_ro) {
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

    if (header->magic != MH_MAGIC_64 && header->magic != MH_CIGAM_64) {
        throw std::invalid_argument("Can't handle 32-bit files");
    } else if (header->magic == MH_CIGAM_64) {
        throw std::invalid_argument("Host system incompatible with files");
    }

    loadCommands.reserve(header->ncmds);
    _FileT *cmdStart = (_FileT *)header + sizeof(mach_header_64);
    for (uint32_t cmdOff = 0; cmdOff < header->sizeofcmds;) {
        auto cmd = (_LoadCommandT *)(cmdStart + cmdOff);
        loadCommands.emplace_back(cmd);
        cmdOff += cmd->cmdsize;
    }

    for (auto const seg : getLoadCommand<true, segment_command_64>()) {
        segments.emplace_back(seg);
    }
}

template <bool _ro>
Context<_ro>::Context(
    uint64_t fileOffset, fs::path mainPath,
    std::vector<MappingInfo> mainMappings,
    std::vector<std::tuple<fs::path, std::vector<MappingInfo>>> subFiles)
    : Context(fileOffset, openFile(mainPath), mainMappings,
              openFiles(subFiles)) {
    _ownFiles = true;
}

template <bool _ro> Context<_ro>::~Context() {
    if (_filesOpen) {
        for (auto &file : _fileMaps) {
            file.close();
        }
        _filesOpen = false;
    }
}

template <bool _ro>
Context<_ro>::Context(Context<_ro> &&other)
    : file(other.file), header(other.header), _ownFiles(other._ownFiles),
      _filesOpen(other._filesOpen), _fileMaps(std::move(other._fileMaps)),
      _files(std::move(other._files)) {
    other.file = nullptr;
    other.header = nullptr;
    other._ownFiles = false;
    other._filesOpen = false;
}

template <bool _ro>
Context<_ro> &Context<_ro>::operator=(Context<_ro> &&other) {
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

template <bool _ro>
std::tuple<uint64_t, typename Context<_ro>::_FileT *>
Context<_ro>::convertAddr(uint64_t addr) const {
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

template <bool _ro>
std::vector<typename c_const<_ro, load_command>::T *>
Context<_ro>::_getLoadCommands(const uint32_t (&targetCmds)[],
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

    std::vector<typename c_const<_ro, load_command>::T *> lcs;
    for (auto lc : loadCommands) {
        if (matchLoadComands(lc->cmd)) {
            lcs.push_back(lc);
        }
    }

    return lcs;
}

template <bool _ro>
typename c_const<_ro, load_command>::T *
Context<_ro>::_getLoadCommand(const uint32_t (&targetCmds)[],
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

template <bool _ro> bio::mapped_file Context<_ro>::openFile(fs::path path) {
    return bio::mapped_file(path.string(), bio::mapped_file::mapmode::priv);
}

template <bool _ro>
std::vector<std::tuple<bio::mapped_file, std::vector<MappingInfo>>>
Context<_ro>::openFiles(
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

template class Context<true>;
template class Context<false>;