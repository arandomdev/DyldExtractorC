cmake_minimum_required(VERSION 3.12)

add_library(DyldExtractor
	Converter/Objc/ObjcFixer.cpp
	Converter/Rebase/RebaseGenerator.cpp
	Converter/Rebase/RebaseV1.cpp
	Converter/Stubs/Arm64Utils.cpp
	Converter/Stubs/ArmUtils.cpp
	Converter/Stubs/StubFixer.cpp
	Converter/LinkeditOptimizer.cpp
	Converter/OffsetOptimizer.cpp
	Converter/Slide.cpp
	Dyld/Context.cpp
	Logger/ActivityLogger.cpp
	Macho/BindInfo.cpp
	Macho/Context.cpp
	Provider/Disassembler.cpp
	Provider/ExtraData.cpp
	Provider/PointerTracker.cpp
	Provider/Symbolizer.cpp
	Utils/ExtractionContext.cpp
	Utils/Uleb128.cpp
)

target_link_libraries(DyldExtractor PUBLIC ${Boost_LIBRARIES})
target_include_directories(DyldExtractor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(DyldExtractor PUBLIC .)

target_link_libraries(DyldExtractor PRIVATE spdlog::spdlog)
target_link_libraries(DyldExtractor PRIVATE fmt::fmt)
target_link_libraries(DyldExtractor PRIVATE capstone::capstone)
