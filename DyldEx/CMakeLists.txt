cmake_minimum_required (VERSION 3.8)

add_executable (dyldex dyldex.cpp)

target_link_libraries (dyldex PRIVATE DyldExtractor)
target_link_libraries (dyldex PRIVATE spdlog::spdlog)
target_link_libraries (dyldex PRIVATE argparse::argparse)

add_executable (dyldex_all dyldex_all.cpp)
target_link_libraries (dyldex_all PRIVATE DyldExtractor)
target_link_libraries (dyldex_all PRIVATE spdlog::spdlog)
target_link_libraries (dyldex_all PRIVATE argparse::argparse)