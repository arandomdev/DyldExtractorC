# Providers
Providers are classes that provide services, like pointer tracking or disassembly.

## Specification
* Constructed and contained within an ExtractionContext.
* Should be at least movable.
* Cannot take ExtractionContext as an argument.
* Data can be preloaded or loaded manually.
* Copy constructors and assignments should be deleted