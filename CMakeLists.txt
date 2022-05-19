# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)

project ("DyldExtractorC")

# Check endianness
include (TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)
if(IS_BIG_ENDIAN)
	message(FATAL_ERROR "Big Endian hosts are not supported.")
endif()

# Set c++ 23
set (CMAKE_CXX_STANDARD 23)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Find boost iostreams
set (Boost_NO_WARN_NEW_VERSIONS ON)
find_package (Boost REQUIRED COMPONENTS iostreams)
include_directories (${Boost_INCLUDE_DIRS})

# External
add_compile_definitions(SPDLOG_ACTIVE_LEVEL=0) # Allow all logging, define at runtime
include_directories ("External/headers")
add_subdirectory ("External/spdlog")
add_subdirectory ("External/argparse")

set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
add_subdirectory("External/googletest")

# Include sub-projects.
add_subdirectory ("DyldExtractor")
add_subdirectory ("DyldEx")
add_subdirectory ("Tests")