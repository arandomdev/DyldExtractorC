#ifndef __PROVIDER_LINKEDITTRACKER__
#define __PROVIDER_LINKEDITTRACKER__

#include <Macho/Context.h>

namespace DyldExtractor::Provider {

/// @brief Manages the linkedit region during extraction. Keeps the load
/// command offsets synced with the tracked data, unless changeOffset is called.
template <class P> class LinkeditTracker {
  using PtrT = P::PtrT;

public:
  enum class Tag {
    chained = 0,            // Chained fixups
    detachedExportTrie = 1, // Detached export trie
    rebase = 2,             // Rebase info
    binding = 3,            // Binding info
    weakBinding = 4,        // Weak binding info
    lazyBinding = 5,        // Lazy binding info
    exportTrie = 6,         // Export trie in dyld_info_command
    functionStarts = 7,     // Function starts
    dataInCode = 8,         // Data in code
    symtab = 9,             // Symbol table entries
    indirectSymtab = 10,    // Indirect symbol table
    stringPool = 11,        // String pool
  };

  /// @brief Describes tracked data
  struct Metadata {
    Tag tag;
    uint8_t *data;
    uint32_t dataSize;
    uint32_t *offsetField;

    Metadata(Tag tag, uint8_t *data, uint32_t dataSize,
             Macho::Loader::load_command *lc);
    uint8_t *end() const;
  };

  using MetadataIt = std::vector<Metadata>::iterator;

  /// @brief Create a tracker with a set of tracked data
  ///
  /// Throws an exception in any of the following cases.
  /// * Data is not pointer aligned.
  /// * Data does not make up a continuous range.
  /// * Data is outside the linkedit or load command regions.
  ///
  /// @param mCtx The macho context
  /// @param linkeditSize The max size of the linkedit region
  /// @param initialData The initial set of data to manage
  LinkeditTracker(Macho::Context<false, P> &mCtx, uint64_t linkeditSize,
                  std::vector<Metadata> initialData);
  LinkeditTracker(const LinkeditTracker<P> &) = delete;
  LinkeditTracker(LinkeditTracker<P> &&) = default;
  LinkeditTracker<P> &operator=(const LinkeditTracker<P> &) = delete;
  LinkeditTracker<P> &operator=(LinkeditTracker<P> &&) = default;

  MetadataIt metadataBegin();
  MetadataIt metadataEnd();
  Macho::Loader::load_command *lcBegin();
  Macho::Loader::load_command *lcEnd();

  /// @brief Get a pointer to the beginning of Linkedit data.
  const uint8_t *getData() const;

  /// @brief Find metadata with a tag
  /// @param tag The tag to search for
  /// @return An iterator to the metadata or the past end iterator
  MetadataIt findTag(Tag tag);

  /// @brief Resize the given tracked data
  /// @param metaIt Iterator to the metadata, is still valid after the operation
  /// @param newSize The new size, must be pointer aligned
  /// @returns If there was enough space for the operation.
  bool resizeData(MetadataIt metaIt, uint32_t newSize);

  /// @brief Add data into the linkedit
  /// @param meta The metadata for the data, the data size must be pointer
  ///   aligned. Data pointer and offset field does not have to be valid.
  /// @param data Pointer to the source of data
  /// @param copySize The size of data to copy into the region. Must be less
  ///   than or equal to size in data.
  /// @return An iterator to the new tracked data, and a boolean indicating if
  ///   there was enough space for the operation.
  std::pair<MetadataIt, bool> addData(Metadata meta, const uint8_t *const data,
                                      uint32_t copySize);

  /// @brief Remove data from the linkedit
  /// @param pos The data to remove.
  void removeData(MetadataIt pos);

  /// @brief Insert a load command into the header, triggers a reload on the
  ///   MachOContext.
  /// @param pos The position of the new load command.
  /// @param lc The load command to insert
  /// @return An pointer to the inserted load command, and a boolean indicating
  ///   if there was enough space for the operation.
  std::pair<Macho::Loader::load_command *, bool>
  insertLC(Macho::Loader::load_command *pos, Macho::Loader::load_command *lc);

  /// @brief Remove a load command from the header, triggers a reload on the
  ///   MachOContext.
  /// @param lc The load command to remove.
  void removeLC(Macho::Loader::load_command *lc);

  /// @brief Get the amount of bytes available for new load commands.
  uint32_t freeLCSpace() const;

  /// @brief Change the linkedit region offset, doesn't shift any data but load
  ///   commands are updated. Causes de-sync with the load commands, meaning
  ///   that all offsets in the load commands are invalidated!
  /// @param offset The new offset
  void changeOffset(uint32_t offset);

private:
  Macho::Context<false, P> *mCtx;
  std::vector<Metadata> metadata;

  Macho::Loader::segment_command<P> *leSeg;
  uint64_t leOffset;  // file offset to the start of linkedit data region
  uint8_t *leData;    // pointer to start of linkedit data region
  uint8_t *leDataEnd; // pointer to end of the entire data region

  uint8_t *cmdsData;    // pointer to start of load commands data region
  uint8_t *cmdsDataEnd; // pointer to the past the end load command
  uint64_t cmdsMaxSize; // Maximum space allowed for load commands

  static uint32_t lcOffsetForTag(Tag tag);
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER_LINKEDITTRACKER__