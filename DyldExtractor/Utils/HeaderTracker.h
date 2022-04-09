#ifndef __UTILS_HEADERTRACKER__
#define __UTILS_HEADERTRACKER__

#include <Macho/Context.h>
#include <Macho/Loader.h>

namespace Utils {

// Describes data in the linkedit
struct LinkeditData {
    uint8_t *offset;
    uint8_t *data;
    uint32_t dataSize;

    bool operator==(const LinkeditData &a) const = default;
};

// Tracks and manages offsets from load commands and data.
template <class P> class HeaderTracker {
  public:
    HeaderTracker(Macho::Context<false, P> *machoCtx);

    /// Insert data into the header.
    ///
    /// @param after The load command to insert after.
    /// @param lc The load command to insert.
    /// @return If the operational was successful.
    bool insertLoadCommand(Macho::Loader::load_command *after,
                           Macho::Loader::load_command *lc);

    /// Insert data into the linkedit.
    ///
    /// @param after Optional data to insert after, data will be inserted at the
    ///   beginning if not given.
    /// @param data Data to insert, is copied into the linkedit.
    /// @returns If the operational was successful, if there was enough space.
    bool insertLinkeditData(std::optional<LinkeditData> after,
                            LinkeditData data);

    /// Add data already in the linkedit to tracking.
    ///
    /// @param data The data to track.
    void trackData(LinkeditData data);

    // Data that is being tracked, is ordered based on the location of the data.
    std::vector<LinkeditData> trackingData;

  private:
    typename Macho::Context<false, P>::HeaderT *_header;
    uint8_t *_commandsStart;
    uint32_t _headerSpaceAvailable;

    uint8_t *_linkeditStart;
    uint8_t *_linkeditEnd;
};

} // namespace Utils

#endif // __UTILS_HEADERTRACKER__