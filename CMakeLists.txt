cmake_minimum_required(VERSION 3.12)
project("DyldExtractorC" VERSION 0.0.1)

# Check endianness
include(TestBigEndian)
TEST_BIG_ENDIAN(IS_BIG_ENDIAN)

if(IS_BIG_ENDIAN)
	message(FATAL_ERROR "Big Endian hosts are not supported.")
endif()

# Set c++ 20
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(WIN32)
	# We have to set _WIN32_WINNT for boost
	if(${CMAKE_SYSTEM_VERSION} EQUAL 10) # Windows 10
		add_definitions(-D _WIN32_WINNT=0x0A00)
	elseif(${CMAKE_SYSTEM_VERSION} EQUAL 6.3) # Windows 8.1
		add_definitions(-D _WIN32_WINNT=0x0603)
	elseif(${CMAKE_SYSTEM_VERSION} EQUAL 6.2) # Windows 8
		add_definitions(-D _WIN32_WINNT=0x0602)
	elseif(${CMAKE_SYSTEM_VERSION} EQUAL 6.1) # Windows 7
		add_definitions(-D _WIN32_WINNT=0x0601)
	elseif(${CMAKE_SYSTEM_VERSION} EQUAL 6.0) # Windows Vista
		add_definitions(-D _WIN32_WINNT=0x0600)
	else() # Windows XP (5.1)
		add_definitions(-D _WIN32_WINNT=0x0501)
	endif()
endif()

# Boost
set(Boost_NO_WARN_NEW_VERSIONS ON)
find_package(Boost REQUIRED COMPONENTS iostreams filesystem)
include_directories(${Boost_INCLUDE_DIRS})

# External
include_directories(External/headers)
add_subdirectory(External/fmt)

add_compile_definitions(SPDLOG_ACTIVE_LEVEL=0) # Allow all logging, define at runtime
add_subdirectory(External/spdlog)

set(ARGPARSE_LONG_VERSION_ARG_ONLY ON)
add_subdirectory(External/argparse)

set(CAPSTONE_ARCHITECTURE_DEFAULT OFF)
set(CAPSTONE_ARM_SUPPORT ON)
set(CAPSTONE_ARM64_SUPPORT ON)
set(CAPSTONE_X86_SUPPORT ON)
add_subdirectory(External/capstone)
set_target_properties(capstone PROPERTIES COMPILE_OPTIONS "-w")

# Include sub-projects.
add_subdirectory(DyldExtractor)
add_subdirectory(DyldEx)