#ifndef __PROVIDER_VALIDATOR__
#define __PROVIDER_VALIDATOR__

#include <Macho/Context.h>

namespace DyldExtractor::Provider {

/***
 * @brief Validate assumptions used in converters and providers. Should be ran
 * before creating the ExtractionContext
 *
 * If any of the following conditions are not met an exception is thrown.
 *  * MachO Context
 *    * Contains a linkedit segment
 *    * Contains a text segment
 *    * Contains a symtab command
 *    * Contains a dysymtab command
 * */
template <class P> class Validator {
public:
  Validator(const Macho::Context<false, P> &mCtx);

  void validate();

private:
  const Macho::Context<false, P> *mCtx;
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER_VALIDATOR__