cmake_minimum_required (VERSION 3.8)

add_executable (DyldExtractorCTests
	main.cpp
	DyldExtractor/Stubs.cpp
)

target_link_libraries (DyldExtractorCTests
	PRIVATE gtest
	PRIVATE DyldExtractor
	PRIVATE spdlog::spdlog
)