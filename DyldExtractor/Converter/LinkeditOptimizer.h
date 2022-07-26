#ifndef __CONVERTER_LINKEDITOPTIMIZER__
#define __CONVERTER_LINKEDITOPTIMIZER__

#include <Macho/Context.h>
#include <Utils/ExtractionContext.h>

namespace Converter {

template <class P> class LinkeditTracker {
public:
  enum class Tag {
    bindInfo,       // dyld_info_command->bind
    weakBindInfo,   // dyld_info_command->weak_bind
    lazyBindInfo,   // dyld_info_command->lazy_bind
    exportInfo,     // export info trie
    symbolEntries,  // symtab_command->syms
    functionStarts, // LC_FUNCTION_STARTS
    dataInCode,     // LC_DATA_IN_CODE
    indirectSymtab, // dysymtab_command->indirect syms
    stringPool,     // symtab->strings
    generic
  };
  struct TrackedData {
    uint8_t *data;
    uint32_t *offsetField;
    uint32_t dataSize;
    Tag tag;

    uint8_t *end() const;
    auto operator<=>(const TrackedData &o) const;
    bool operator==(const TrackedData &o) const;
  };

  LinkeditTracker(Macho::Context<false, P> &mCtx);

  /// Add data to tracking
  ///
  /// Data must be inside the linkedit segment, the offset field must be within
  /// the commands, and data size must be pointer aligned. Should be added in a
  /// way that ensures a continuous range of data.
  ///
  /// @param data The data to track
  /// @return if the operation was successful
  bool addTrackingData(TrackedData data);

  /// Insert data into the linkedit
  ///
  /// Segment command will be updated.
  ///
  /// @param metadata Info about the data to insert, must conform to the same
  /// requirements in `addTrackingData`.
  /// @param after Where to insert the data after, or nullptr for the beginning.
  /// @param data Data to insert.
  /// @returns If the operation was successfully.
  bool insertData(TrackedData metadata, TrackedData *after,
                  const uint8_t *data);

  /// Resize a data region
  ///
  /// Segment command will be updated.
  ///
  /// @param data The data to resize.
  /// @param newSize The new size of the data, needs to be pointer aligned.
  /// @returns If the operation was successful
  bool resizeData(TrackedData *data, uint32_t newSize);

  /// Find the first data with the tag
  ///
  /// @param tag The tag to search for.
  /// @returns A pointer to the data or nullptr if not found.
  TrackedData *findTag(Tag tag);

  std::vector<TrackedData> trackedData;

private:
  bool preflightData(TrackedData &data);
  std::vector<TrackedData>::iterator
  insertDataIntoStore(const TrackedData &data);

  Macho::Context<false, P> &mCtx;
  Macho::Context<false, P>::HeaderT *mCtxHeader;

  Macho::Loader::segment_command<P> *linkeditSeg;
  uint8_t *linkeditStart;
  uint8_t *linkeditEnd;
  uint8_t *commandsStart;
  uint8_t *commandsEnd;
};

bool isRedactedIndirect(uint32_t entry);
template <class A> void optimizeLinkedit(Utils::ExtractionContext<A> &eCtx);

} // namespace Converter

#endif // __CONVERTER_LINKEDITOPTIMIZER__