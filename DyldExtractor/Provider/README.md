# Providers
Providers are classes that provide services, like pointer tracking or disassembly.

## Specification
* Constructed and contained within an ExtractionContext.
* Should be movable if it is contained in the extraction context.
* Copy constructors and assignments should be deleted
* Cannot take ExtractionContext as an argument.
* Data can be preloaded or loaded manually. With a `load` method.
* Should protect against multiple calls to the load function

## Notes
Be very careful of holding pointers to load commands, and data into the linkedit. Pointers may be invalidated unexpectedly.