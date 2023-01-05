cmake_minimum_required(VERSION 3.12)

add_library(DyldExtractor
	Converter/Linkedit/Encoder/BindingV1.cpp
	Converter/Linkedit/Encoder/Chained.cpp
	Converter/Linkedit/Encoder/LegacyGenerator.cpp
	Converter/Linkedit/Encoder/RebaseV1.cpp
	Converter/Linkedit/MetadataGenerator.cpp
	Converter/Linkedit/Optimizer.cpp
	Converter/Objc/Objc.cpp
	Converter/Objc/Placer.cpp
	Converter/Objc/Walker.cpp
	Converter/Stubs/Arm64Fixer.cpp
	Converter/Stubs/Arm64Utils.cpp
	Converter/Stubs/ArmFixer.cpp
	Converter/Stubs/ArmUtils.cpp
	Converter/Stubs/Fixer.cpp
	Converter/Stubs/SymbolPointerCache.cpp
	Converter/OffsetOptimizer.cpp
	Converter/Slide.cpp
	Dyld/Context.cpp
	Macho/Context.cpp
	Provider/ActivityLogger.cpp
	Provider/BindInfo.cpp
	Provider/Disassembler.cpp
	Provider/ExtraData.cpp
	Provider/FunctionTracker.cpp
	Provider/LinkeditTracker.cpp
	Provider/PointerTracker.cpp
	Provider/Symbolizer.cpp
	Provider/SymbolTableTracker.cpp
	Provider/Validator.cpp
	Utils/ExtractionContext.cpp
	Utils/Leb128.cpp
)

target_link_libraries(DyldExtractor PUBLIC ${Boost_LIBRARIES})
target_include_directories(DyldExtractor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(DyldExtractor PUBLIC .)

target_link_libraries(DyldExtractor PRIVATE spdlog::spdlog)
target_link_libraries(DyldExtractor PRIVATE fmt::fmt)
target_link_libraries(DyldExtractor PRIVATE capstone::capstone)
