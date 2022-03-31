cmake_minimum_required (VERSION 3.8)

add_library (DyldExtractor
	Converter/OffsetOptimizer.cpp
	Dyld/Context.cpp
	Macho/Context.cpp
	Logger/ActivityLogger.cpp
)

target_link_libraries (DyldExtractor PUBLIC ${Boost_LIBRARIES})
target_include_directories (DyldExtractor PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

target_include_directories (DyldExtractor PUBLIC .)

target_link_libraries (DyldExtractor PRIVATE spdlog::spdlog)
target_link_libraries (DyldExtractor PRIVATE fmt::fmt)