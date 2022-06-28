#include "Context.h"

#include <fmt/core.h>
#include <iostream>
#include <stdexcept>

using namespace Dyld;

Context::Context(fs::path sharedCachePath, const uint8_t *subCacheUUID)
    : _cachePath(sharedCachePath), _cacheOpen(true) {
    _cacheFile.open(_cachePath.string(), bio::mapped_file::mapmode::readonly);
    file = (uint8_t *)_cacheFile.const_data();

    _preflightCache(subCacheUUID);

    if (!subCacheUUID) {
        // open subcaches if there are any
        if (!headerContainsMember(
                offsetof(dyld_cache_header, subCacheArrayCount))) {
            return;
        }

        bool _usesNewerSubCacheInfo = header->cacheType == 2;
        const std::string pathBase = sharedCachePath.string();
        for (uint32_t i = 0; i < header->subCacheArrayCount; i++) {
            std::string fullPath;
            const uint8_t *subCacheUUID;
            if (_usesNewerSubCacheInfo) {
                auto subCacheInfo =
                    (dyld_subcache_entry2 *)(file +
                                             header->subCacheArrayOffset) +
                    i;
                subCacheUUID = subCacheInfo->uuid;
                fullPath = pathBase + std::string(subCacheInfo->fileExtension);
            } else {
                auto subCacheInfo =
                    (dyld_subcache_entry *)(file +
                                            header->subCacheArrayOffset) +
                    i;
                subCacheUUID = subCacheInfo->uuid;
                fullPath = pathBase + fmt::format(".{}", i + 1);
            }
            subcaches.emplace_back(fullPath, subCacheUUID);
        }

        // symbols cache
        if (headerContainsMember(offsetof(dyld_cache_header, symbolFileUUID))) {
            // Check for null uuid
            uint8_t summary = 0;
            for (int i = 0; i < 16; i++) {
                summary |= header->symbolFileUUID[i];
            }
            if (summary == 0) {
                return;
            }

            subcaches.emplace_back(pathBase + ".symbols",
                                   header->symbolFileUUID);
        }
    }
}

Context::~Context() {
    if (_cacheOpen && _cacheFile.is_open()) {
        _cacheFile.close();
        _cacheOpen = false;
    }
}

Context::Context(Context &&other)
    : file(other.file), header(other.header),
      _cacheFile(std::move(other._cacheFile)),
      _cachePath(std::move(other._cachePath)), _cacheOpen(other._cacheOpen),
      subcaches(std::move(other.subcaches)),
      _mappings(std::move(other._mappings)) {
    other.file = nullptr;
    other.header = nullptr;
    other._cacheOpen = false;
}

Context &Context::operator=(Context &&other) {
    this->file = other.file;
    this->header = other.header;
    this->_cacheOpen = other._cacheOpen;

    this->_cacheFile = std::move(other._cacheFile);
    this->_cachePath = std::move(other._cachePath);
    this->subcaches = std::move(other.subcaches);
    this->_mappings = std::move(other._mappings);

    other.file = nullptr;
    other.header = nullptr;
    other._cacheOpen = false;

    return *this;
}

std::pair<uint64_t, const Context *> Context::convertAddr(uint64_t addr) const {
    for (auto const &mapping : _mappings) {
        if (addr >= mapping->address &&
            addr < mapping->address + mapping->size) {
            return std::make_pair(
                (addr - mapping->address) + mapping->fileOffset, this);
        }
    }

    for (auto const &subcache : subcaches) {
        auto convert = subcache.convertAddr(addr);
        if (convert.second != nullptr) {
            return convert;
        }
    }

    return std::make_pair(0, nullptr);
}

const uint8_t *Context::convertAddrP(uint64_t addr) const {
    auto [offset, ctx] = convertAddr(addr);
    return ctx ? ctx->file + offset : nullptr;
}

bool Context::headerContainsMember(std::size_t memberOffset) const {
    // Use mapping offset as the cutoff point.
    return memberOffset < header->mappingOffset;
}

template <bool ro, class P>
Macho::Context<ro, P>
Context::createMachoCtx(const dyld_cache_image_info *imageInfo) const {
    auto getMappings = [](std::vector<const dyld_cache_mapping_info *> info) {
        std::vector<Macho::MappingInfo> mappings(info.size());
        for (auto i : info) {
            mappings.emplace_back(i);
        }
        return mappings;
    };

    auto [imageOffset, mainCache] = convertAddr(imageInfo->address);
    auto mainMappings = getMappings(mainCache->_mappings);

    if constexpr (ro) {
        // Make a read only macho context with the files already open
        std::vector<
            std::tuple<bio::mapped_file, std::vector<Macho::MappingInfo>>>
            subFiles;
        subFiles.reserve(subcaches.size());

        // Add this cache if necessary
        if (file != mainCache->file) {
            subFiles.emplace_back(_cacheFile, getMappings(_mappings));
        }

        // Add subcaches
        for (auto &cache : subcaches) {
            if (cache.file != mainCache->file) {
                subFiles.emplace_back(cache._cacheFile,
                                      getMappings(cache._mappings));
            }
        }

        return Macho::Context<true, P>(imageOffset, mainCache->_cacheFile,
                                       mainMappings, subFiles);
    } else {
        // Make a writable macho context by giving the paths
        std::vector<std::tuple<fs::path, std::vector<Macho::MappingInfo>>>
            subFiles;
        subFiles.reserve(subcaches.size());

        // Add this cache if necessary
        if (file != mainCache->file) {
            subFiles.emplace_back(_cachePath, getMappings(_mappings));
        }

        // Add subcaches
        for (auto &cache : subcaches) {
            if (cache.file != mainCache->file) {
                subFiles.emplace_back(cache._cachePath,
                                      getMappings(cache._mappings));
            }
        }

        return Macho::Context<false, P>(imageOffset, mainCache->_cachePath,
                                        mainMappings, subFiles);
    }
}

template Macho::Context<true, Utils::Pointer32>
Context::createMachoCtx<true, Utils::Pointer32>(
    const dyld_cache_image_info *imageInfo) const;
template Macho::Context<true, Utils::Pointer64>
Context::createMachoCtx<true, Utils::Pointer64>(
    const dyld_cache_image_info *imageInfo) const;
template Macho::Context<false, Utils::Pointer32>
Context::createMachoCtx<false, Utils::Pointer32>(
    const dyld_cache_image_info *imageInfo) const;
template Macho::Context<false, Utils::Pointer64>
Context::createMachoCtx<false, Utils::Pointer64>(
    const dyld_cache_image_info *imageInfo) const;

const Context *Context::getSymbolsCache() const {
    if (!subcaches.size()) {
        return this;
    }

    for (auto &cache : subcaches) {
        if (memcmp(header->symbolFileUUID, cache.header->uuid, 16) == 0) {
            return &cache;
        }
    }

    return nullptr;
}

void Context::_preflightCache(const uint8_t *subCacheUUID) {
    // validate cache
    if (_cacheFile.size() < sizeof(dyld_cache_header)) {
        throw std::invalid_argument("Cache file is too small.");
    }

    header = (dyld_cache_header *)file;

    if (memcmp(&"dyld", header->magic, 4)) {
        throw std::invalid_argument("Magic does not start with dyld.");
    }
    if (subCacheUUID) {
        if (memcmp(subCacheUUID, header->uuid, 16) != 0) {
            throw std::invalid_argument("Subcache UUID Mismatch.");
        }
    }

    // get additional info
    _mappings.reserve(header->mappingCount);
    for (uint32_t i = 0; i < header->mappingCount; i++) {
        _mappings.emplace_back(
            (dyld_cache_mapping_info *)(file + header->mappingOffset +
                                        (i * sizeof(dyld_cache_mapping_info))));
    }

    bool usesNewerImages =
        headerContainsMember(offsetof(dyld_cache_header, imagesOffset));
    uint32_t imagesOffset =
        usesNewerImages ? header->imagesOffset : header->imagesOffsetOld;
    uint32_t imagesCount =
        usesNewerImages ? header->imagesCount : header->imagesCountOld;
    images.reserve(imagesCount);
    for (uint32_t i = 0; i < imagesCount; i++) {
        images.emplace_back(
            (dyld_cache_image_info *)(file + imagesOffset +
                                      (i * sizeof(dyld_cache_image_info))));
    }
}