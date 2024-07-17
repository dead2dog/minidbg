cmake_minimum_required (VERSION 3.0)
project (MiniDbg)

add_compile_options(-std=c++14)

include_directories(ext/libelfin ext/linenoise inc)

add_executable(minidbg src/minidbg.cpp ext/linenoise/linenoise.c)

add_executable(demo1 demo/demo1.cpp)
set_target_properties(demo1
                      PROPERTIES COMPILE_FLAGS "-gdwarf-2 -g -O0")

add_custom_target(
   libelfin
   COMMAND make
   WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/ext/libelfin
)

target_link_libraries(minidbg
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/dwarf/libdwarf++.so
                      ${PROJECT_SOURCE_DIR}/ext/libelfin/elf/libelf++.so)
add_dependencies(minidbg libelfin)