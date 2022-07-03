cmake_minimum_required(VERSION 3.12)

add_library(DyldExtractor
	Converter/LinkeditOptimizer.cpp
	Converter/OffsetOptimizer.cpp
	Converter/Slide.cpp
	Converter/Stubs/SymbolicInfo.cpp
	Converter/Stubs/Symbolizer.cpp
	Converter/Stubs/Arm64Utils.cpp
	Converter/Stubs/Fixer.cpp
	Logger/ActivityLogger.cpp
	Dyld/Context.cpp
	Macho/BindInfo.cpp
	Macho/Context.cpp
	Provider/PointerTracker.cpp
	Utils/ExtractionContext.cpp
)

target_link_libraries(DyldExtractor PUBLIC ${Boost_LIBRARIES})
target_include_directories(DyldExtractor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories(DyldExtractor PUBLIC .)

target_link_libraries(DyldExtractor PRIVATE spdlog::spdlog)
target_link_libraries(DyldExtractor PRIVATE fmt::fmt)
