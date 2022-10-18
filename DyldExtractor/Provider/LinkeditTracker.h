#ifndef __PROVIDER_LINKEDITTRACKER__
#define __PROVIDER_LINKEDITTRACKER__

#include <Macho/Context.h>
#include <set>

namespace DyldExtractor::Provider {

template <class P> class LinkeditTracker {
  using PtrT = P::PtrT;

public:
  enum class Tag {
    rebaseInfo,     // dyld_info_command->rebase
    bindInfo,       // dyld_info_command->bind
    weakBindInfo,   // dyld_info_command->weak_bind
    lazyBindInfo,   // dyld_info_command->lazy_bind
    exportInfo,     // dyld_info_command->export
    symbolEntries,  // symtab_command->sym
    stringPool,     // symtab->str
    indirectSymtab, // dysymtab_command->indirect syms
    exportTrie,     // LC_DYLD_EXPORTS_TRIE
    functionStarts, // LC_FUNCTION_STARTS
    dataInCode,     // LC_DATA_IN_CODE
    chainedFixups,  // LC_DYLD_CHAINED_FIXUPS
  };

  /// @brief Describes tracked data
  struct Metadata {
    Tag tag;
    uint8_t *data;
    uint32_t dataSize;
    uint32_t *offsetField;

    Metadata(Tag tag, uint8_t *data, uint32_t dataSize, uint8_t *loadCommand);
    uint8_t *end() const;
    std::strong_ordering operator<=>(const Metadata &o) const;
  };

  using MetadataIt = std::set<Metadata>::iterator;

  /// @brief Create a tracker without any tracked data
  /// @param mCtx The macho context
  LinkeditTracker(Macho::Context<false, P> &mCtx);
  LinkeditTracker(const LinkeditTracker<P> &) = delete;
  LinkeditTracker(LinkeditTracker<P> &&) = default;
  LinkeditTracker<P> &operator=(const LinkeditTracker<P> &) = delete;
  LinkeditTracker<P> &operator=(LinkeditTracker<P> &&) = default;

  /// @brief Create a tracker with a set of tracked data
  ///
  /// Throws an exception in any of the following cases.
  /// * Data is not pointer aligned.
  /// * Data does not make up a continuous range.
  /// * Data is outside the linkedit or load command regions.
  ///
  /// @param mCtx The macho context
  /// @param linkeditSize The initial max size of the linkedit region
  /// @param initialData The initial set of data to manage
  LinkeditTracker(Macho::Context<false, P> &mCtx, uint64_t linkeditSize,
                  std::set<Metadata> initialData);

  MetadataIt metadataBegin() const;
  MetadataIt metadataEnd() const;

  /// @brief Find metadata with a tag
  /// @param tag The tag to search for
  /// @return A iterator to the metadata or the past end iterator
  MetadataIt findTag(Tag tag) const;

  /// @brief Find metadata with a list of tags
  /// @param tags The tags to look for, searches for tags in order given
  /// @return A iterator to the metadata or the past end iterator
  MetadataIt findTag(const std::vector<Tag> &tags) const;

  /// @brief Resize the given tracked data
  /// @param metaIt Iterator to the metadata
  /// @param newSize The new size, must be pointer aligned
  /// @return The new iterator if enough space, or the pass end iterator
  MetadataIt resizeData(MetadataIt metaIt, uint32_t newSize);

  /// @brief Insert data into the linkedit
  /// @param pos The position for the new data
  /// @param meta The metadata for the data, the data size must be pointer
  ///   aligned. Data pointer and offset field does not have to be valid.
  /// @param data Pointer to the source of data
  /// @param copySize The size of data to copy into the region. Must be less
  ///   than or equal to size in data.
  /// @return An iterator to the new tracked data, and a boolean indicating if
  ///   there was enough space for the operation.
  std::pair<MetadataIt, bool> insertData(MetadataIt pos, Metadata meta,
                                         const uint8_t *const data,
                                         uint32_t copySize);

  /// @brief Remove data from the linkedit
  /// @param pos The data to remove.
  void removeData(MetadataIt pos);

  /// @brief Insert a load command into the header, triggers a reload on the
  ///   MachOContext.
  /// @param pos The position of the new load command. nullptr for the end.
  /// @param lc The load command to insert
  /// @return An pointer to the inserted load command, and a boolean indicating
  ///   if there was enough space for the operation.
  std::pair<Macho::Loader::load_command *, bool>
  insertLC(Macho::Loader::load_command *pos, Macho::Loader::load_command *lc);

  /// @brief Remove a load command from the header, triggers a reload on the
  ///   MachOContext.
  /// @param lc The load command to remove.
  void removeLC(Macho::Loader::load_command *lc);

private:
  Macho::Context<false, P> *mCtx;
  std::set<Metadata> metadata;

  Macho::Loader::segment_command<P> *linkeditSeg;
  uint8_t *linkeditFile;    // file containing the linkedit segment
  uint64_t linkeditOffset;  // file offset to the start of linkedit data region
  uint8_t *linkeditStart;   // pointer to start of linkedit data region
  uint8_t *linkeditEnd;     // pointer to end of linkedit data region
  uint8_t *commandsStart;   // pointer to start of load commands data region
  uint8_t *commandsEnd;     // pointer to end of load commands data region
  uint64_t maxCommandsSize; // Maximum space allowed for load commands

  static uint32_t lcOffsetForTag(Tag tag);
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER_LINKEDITTRACKER__