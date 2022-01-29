cmake_minimum_required (VERSION 3.8)

add_executable (dyldex main.cpp)

target_link_libraries (dyldex PRIVATE DyldExtractor)
target_link_libraries (dyldex PRIVATE spdlog::spdlog)
target_link_libraries (dyldex PRIVATE argparse::argparse)