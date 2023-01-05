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
 *    * Contains a text segment and section
 *    * Contains a symtab command
 *    * Contains a dysymtab command
 *    * Linkedit segment
 *      * Is the last load command
 *      * Highest in address
 *      * Address is aligned to 0x4000
 *    * Contains a function starts command
 * */
template <class P> class Validator {
  using PtrT = P::PtrT;

public:
  Validator(const Macho::Context<false, P> &mCtx);

  void validate();

private:
  const Macho::Context<false, P> *mCtx;
};

} // namespace DyldExtractor::Provider

#endif // __PROVIDER_VALIDATOR__