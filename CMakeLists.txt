# CMakeList.txt : Top-level CMake project file, do global configuration
# and include sub-projects here.
#
cmake_minimum_required (VERSION 3.8)
message("CMAKE_PROJECT_VERSION = ${CMAKE_VERSION}")

project ("DyldExtractorC")

# Set c++ 20
set (CMAKE_CXX_STANDARD 20)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

# Find boost iostreams
set (Boost_NO_WARN_NEW_VERSIONS ON)
find_package (Boost REQUIRED COMPONENTS iostreams)
include_directories (${Boost_INCLUDE_DIRS})

# External
include_directories ("External/headers")
add_subdirectory ("External/spdlog")
add_subdirectory ("External/fmt")
add_subdirectory ("External/argparse")


# Include sub-projects.
add_subdirectory ("DyldExtractor")
add_subdirectory ("DyldEx")