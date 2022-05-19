#ifndef __UTILS_ACCELERATOR__
#define __UTILS_ACCELERATOR__

#include <map>
#include <string_view>

namespace Converter {
template <class P> class Symbolizer;
}; // namespace Converter

namespace Utils {

/// Accelerate modules when processing more than one image.
template <class P> class Accelerator {
  public:
    std::map<std::string, typename Converter::Symbolizer<P>::_EntryMapT>
        exportsCache;

    std::map<uint64_t, uint64_t> arm64ResolvedChains;
};

}; // namespace Utils

#endif // __UTILS_ACCELERATOR__